#!/usr/bin/env python3
"""
BountyHound sync: desktop source → plugin cache
Run before hunting to push edits from Desktop to the plugin that loads.

Usage: python sync.py [--dry-run]
"""

import shutil
import sys
import os
from pathlib import Path
from datetime import datetime

SRC  = Path("C:/Users/vaugh/Desktop/BountyHound/bountyhound-agent")
DEST = Path("C:/Users/vaugh/.claude/plugins/cache/bountyhound-marketplace/bountyhound-agent/6.1.0")

# Only sync these directories + root files (skip Python packages, test artifacts, etc.)
SYNC_DIRS  = ["agents", "commands", "skills", "memory"]
SYNC_FILES = ["CLAUDE.md"]

DRY_RUN = "--dry-run" in sys.argv

def sync_path(src: Path, dst: Path) -> list[str]:
    """Mirror src to dst: copy new/changed files, delete stale files from dst."""
    changed = []
    if src.is_file():
        if not dst.exists() or src.read_bytes() != dst.read_bytes():
            if not DRY_RUN:
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
            changed.append(str(dst.relative_to(DEST)))
    elif src.is_dir():
        # Copy new/changed files from src → dst
        for item in src.rglob("*"):
            if item.is_file():
                rel = item.relative_to(src)
                dst_file = dst / rel
                if not dst_file.exists() or item.read_bytes() != dst_file.read_bytes():
                    if not DRY_RUN:
                        dst_file.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(item, dst_file)
                    changed.append(str(dst_file.relative_to(DEST)))
        # Delete stale files in dst that no longer exist in src
        if dst.exists():
            for dst_file in dst.rglob("*"):
                if dst_file.is_file():
                    rel = dst_file.relative_to(dst)
                    if not (src / rel).exists():
                        if not DRY_RUN:
                            dst_file.unlink()
                        changed.append(f"- {dst_file.relative_to(DEST)} (deleted)")
            # Remove empty directories left behind
            if not DRY_RUN:
                for dst_dir in sorted(dst.rglob("*"), reverse=True):
                    if dst_dir.is_dir() and not any(dst_dir.iterdir()):
                        dst_dir.rmdir()
    return changed

def main():
    if not SRC.exists():
        print(f"ERROR: Source not found: {SRC}")
        sys.exit(1)
    if not DEST.exists():
        print(f"ERROR: Destination not found: {DEST}")
        sys.exit(1)

    prefix = "[DRY RUN] " if DRY_RUN else ""
    print(f"{prefix}BountyHound sync - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  SRC : {SRC}")
    print(f"  DEST: {DEST}")
    print()

    all_changed = []
    for d in SYNC_DIRS:
        changed = sync_path(SRC / d, DEST / d)
        all_changed.extend(changed)
    for f in SYNC_FILES:
        changed = sync_path(SRC / f, DEST / f)
        all_changed.extend(changed)

    if all_changed:
        print(f"{prefix}Synced {len(all_changed)} file(s):")
        for f in all_changed:
            print(f"  + {f}")
    else:
        print("Already in sync -- nothing to copy.")

if __name__ == "__main__":
    main()
