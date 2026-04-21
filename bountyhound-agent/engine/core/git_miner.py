#!/usr/bin/env python3
"""
git_miner.py — Mine git history for security issues.

Scans commit messages, diffs, and git objects for:
- Security-weakening commits (auth/validation removal)
- Secrets added and later removed (still live in history)
- Disabled checks (if False:, if 0:)
- TODO/FIXME near security code

CLI:
    python git_miner.py <repo_path> [--out <file>]

Output JSON:
    {
        "flagged_commits": [{"hash", "message", "type", "diff_excerpt"}],
        "secrets_found":   [{"type", "value_masked", "commit", "file"}],
        "risky_removals":  [{"what_removed", "commit"}]
    }
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_COMMITS: int = 500

# Commit message patterns that suggest security weakening
_RISKY_MSG_PATTERNS: list[tuple[str, str]] = [
    (r"fix.*auth",              "auth_fix"),
    (r"revert.*security",       "security_revert"),
    (r"remove.*check",          "check_removed"),
    (r"disable.*validation",    "validation_disabled"),
    (r"todo.*security",         "security_todo"),
    (r"\bhack\b",               "hack"),
    (r"\bworkaround\b",         "workaround"),
    (r"\bbypass\b",             "bypass"),
    (r"\btemp(?:orary)?\b",     "temp"),
]

# Lines in diffs that suggest auth/validation was removed
_REMOVAL_PATTERNS: list[str] = [
    r"authenticate",
    r"authorize",
    r"validate",
    r"check_permission",
    r"require_auth",
    r"verify",
]
_REMOVAL_RE = re.compile("|".join(_REMOVAL_PATTERNS), re.IGNORECASE)

# Patterns that suggest a check was disabled
_DISABLED_CHECK_RE = re.compile(
    r"^\+\s*if\s+(?:False|0)\s*:",
    re.MULTILINE,
)

# Secret detection patterns (applied to git log -p output)
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS_ACCESS_KEY",    re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS_SECRET_KEY",    re.compile(r"[A-Za-z0-9+/]{40}")),  # broad; narrowed by context
    ("PRIVATE_KEY",       re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("PASSWORD",          re.compile(r'(?:password|passwd|pwd)\s*=\s*["\']([^"\']{8,})["\']', re.IGNORECASE)),
    ("API_KEY",           re.compile(r'(?:api_?key|apiKey|api_secret)\s*=\s*["\']([A-Za-z0-9+/_.~@#$%^&*!-]{12,})["\']', re.IGNORECASE)),
    ("TOKEN",             re.compile(r'(?:token|secret|auth_?key)\s*=\s*["\']([A-Za-z0-9+/_.~@#$%^&*!-]{16,})["\']', re.IGNORECASE)),
]

# Files of interest for the deep secret scan
_SECRET_SCAN_GLOBS: list[str] = ["*.env", "*.yml", "*.yaml", "*.json", "*.config", "*.conf", "*.ini"]

# ---------------------------------------------------------------------------
# Git subprocess helpers
# ---------------------------------------------------------------------------


def _git(repo_path: str, *args: str, timeout: int = 60) -> str:
    """Run a git command in repo_path; return stdout as str."""
    cmd = ["git", "-C", repo_path, *args]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _git_log_oneline(repo_path: str) -> list[tuple[str, str]]:
    """Return [(hash, message), ...] for all commits, capped at MAX_COMMITS."""
    output = _git(repo_path, "log", "--oneline", "--all", f"--max-count={MAX_COMMITS}")
    commits: list[tuple[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(" ", 1)
        if len(parts) == 2:
            commits.append((parts[0], parts[1]))
        else:
            commits.append((parts[0], ""))
    return commits


def _git_show_diff(repo_path: str, commit_hash: str) -> str:
    """Return the full diff for a commit."""
    return _git(repo_path, "show", commit_hash, "--unified=3", timeout=30)


def _git_show_stat(repo_path: str, commit_hash: str) -> str:
    """Return the --stat output for a commit."""
    return _git(repo_path, "show", "--stat", commit_hash)


# ---------------------------------------------------------------------------
# Commit message classification
# ---------------------------------------------------------------------------


def _classify_message(message: str) -> str | None:
    """
    Return the first matching type label if the commit message matches
    any risky pattern; otherwise return None.
    """
    msg_lower = message.lower()
    for pattern, label in _RISKY_MSG_PATTERNS:
        if re.search(pattern, msg_lower):
            return label
    return None


# ---------------------------------------------------------------------------
# Diff analysis
# ---------------------------------------------------------------------------


def _analyze_diff(
    diff: str,
    commit_hash: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Analyse a diff string.
    Returns (risky_removals, secrets_found).

    risky_removals: [{what_removed, commit}]
    secrets_found:  [{type, value_masked, commit, file}]
    """
    risky_removals: list[dict[str, Any]] = []
    secrets_found: list[dict[str, Any]] = []

    current_file = "unknown"

    for line in diff.splitlines():
        # Track current file
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue
        if line.startswith("--- ") or line.startswith("+++ "):
            continue

        # Removed lines (lines starting with '-' in diff)
        if line.startswith("-") and not line.startswith("---"):
            content = line[1:]
            if _REMOVAL_RE.search(content):
                risky_removals.append({
                    "what_removed": content.strip()[:200],
                    "commit": commit_hash,
                    "file": current_file,
                })

        # Added lines — check for disabled checks and secrets
        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]

            # Disabled checks
            if re.match(r"\s*if\s+(?:False|0)\s*:", content):
                risky_removals.append({
                    "what_removed": f"Check disabled: {content.strip()[:200]}",
                    "commit": commit_hash,
                    "file": current_file,
                })

            # TODO/FIXME near the word "security", "auth", "permission"
            if re.search(r"\b(?:TODO|FIXME|HACK)\b", content, re.IGNORECASE):
                if re.search(r"\b(?:security|auth|permission|validate|bypass)\b", content, re.IGNORECASE):
                    risky_removals.append({
                        "what_removed": f"Security TODO: {content.strip()[:200]}",
                        "commit": commit_hash,
                        "file": current_file,
                    })

            # Secret scanning on added lines
            for secret_type, pattern in _SECRET_PATTERNS:
                match = pattern.search(content)
                if match:
                    value = match.group(0) if not match.lastindex else match.group(1)
                    masked = value[:4] + "***" if len(value) > 4 else "***"
                    secrets_found.append({
                        "type": secret_type,
                        "value_masked": masked,
                        "commit": commit_hash,
                        "file": current_file,
                    })
                    break  # One match per line is enough

    return risky_removals, secrets_found


# ---------------------------------------------------------------------------
# Deep secret scan across all git objects for sensitive files
# ---------------------------------------------------------------------------


def _deep_secret_scan(repo_path: str) -> list[dict[str, Any]]:
    """
    Run `git log -p --all -- <globs>` and scan for secrets in the full
    patch output. This catches credentials added in any commit, even if
    the file was later deleted.
    """
    secrets_found: list[dict[str, Any]] = []

    glob_args: list[str] = []
    for g in _SECRET_SCAN_GLOBS:
        glob_args.append("--")
        glob_args.append(g)

    # Run one combined command with all globs
    cmd_args = ["log", "-p", "--all", f"--max-count={MAX_COMMITS}"]
    for g in _SECRET_SCAN_GLOBS:
        cmd_args.append(f"--glob=*/{g}")

    output = _git(repo_path, *cmd_args, timeout=120)

    current_commit = "unknown"
    current_file = "unknown"

    for line in output.splitlines():
        if line.startswith("commit "):
            current_commit = line.split()[1] if len(line.split()) > 1 else "unknown"
            continue
        if line.startswith("+++ b/"):
            current_file = line[6:]
            continue
        if not line.startswith("+"):
            continue

        content = line[1:]
        for secret_type, pattern in _SECRET_PATTERNS:
            match = pattern.search(content)
            if match:
                value = match.group(0) if not match.lastindex else match.group(1)
                masked = value[:4] + "***" if len(value) > 4 else "***"
                secrets_found.append({
                    "type": secret_type,
                    "value_masked": masked,
                    "commit": current_commit,
                    "file": current_file,
                })
                break

    return secrets_found


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------


def mine(repo_path: str) -> dict[str, Any]:
    """
    Mine the git repository at repo_path for security issues.
    Returns the result dict.
    """
    # Validate it's a git repo
    check = _git(repo_path, "rev-parse", "--is-inside-work-tree")
    if "true" not in check.lower():
        return {
            "error": f"Not a git repository: {repo_path}",
            "flagged_commits": [],
            "secrets_found": [],
            "risky_removals": [],
        }

    all_commits = _git_log_oneline(repo_path)

    flagged_commits: list[dict[str, Any]] = []
    all_risky_removals: list[dict[str, Any]] = []
    all_secrets: list[dict[str, Any]] = []

    # Deduplicate risky removals and secrets by content
    _seen_removals: set[str] = set()
    _seen_secrets: set[str] = set()

    for commit_hash, message in all_commits:
        commit_type = _classify_message(message)
        if not commit_type:
            continue

        diff = _git_show_diff(repo_path, commit_hash)
        if not diff:
            continue

        risky_removals, secrets = _analyze_diff(diff, commit_hash)

        # Collect unique risky removals
        for removal in risky_removals:
            key = removal["what_removed"] + removal["commit"]
            if key not in _seen_removals:
                _seen_removals.add(key)
                all_risky_removals.append(removal)

        # Collect unique secrets
        for secret in secrets:
            key = secret["type"] + secret["value_masked"] + secret["commit"]
            if key not in _seen_secrets:
                _seen_secrets.add(key)
                all_secrets.append(secret)

        # Build excerpt: first 10 lines of diff after the header
        diff_lines = diff.splitlines()
        excerpt_lines: list[str] = []
        in_diff = False
        for dl in diff_lines:
            if dl.startswith("@@"):
                in_diff = True
            if in_diff:
                excerpt_lines.append(dl)
            if len(excerpt_lines) >= 10:
                break
        excerpt = "\n".join(excerpt_lines)

        flagged_commits.append({
            "hash": commit_hash,
            "message": message,
            "type": commit_type,
            "diff_excerpt": excerpt,
        })

    # Deep scan for secrets in sensitive file types across all history
    deep_secrets = _deep_secret_scan(repo_path)
    for secret in deep_secrets:
        key = secret["type"] + secret["value_masked"] + secret["commit"]
        if key not in _seen_secrets:
            _seen_secrets.add(key)
            all_secrets.append(secret)

    return {
        "flagged_commits": flagged_commits,
        "secrets_found": all_secrets,
        "risky_removals": all_risky_removals,
    }


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mine git history for security issues."
    )
    parser.add_argument(
        "repo_path",
        help="Path to the cloned git repository",
    )
    parser.add_argument(
        "--out",
        metavar="FILE",
        help="Write JSON output to FILE instead of stdout",
    )
    args = parser.parse_args()

    repo = str(Path(args.repo_path).resolve())
    result = mine(repo)
    output = json.dumps(result, indent=2)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output, encoding="utf-8")
        print(
            f"Flagged commits: {len(result['flagged_commits'])}, "
            f"Secrets: {len(result['secrets_found'])}, "
            f"Risky removals: {len(result['risky_removals'])}. "
            f"Written to {args.out}",
            file=sys.stderr,
        )
    else:
        print(output)


if __name__ == "__main__":
    main()
