"""
Scope Validator - Pre-Test Scope Verification Gate

Validates targets against bug bounty program scope before testing.
Prevents accidental out-of-scope testing which can result in bans.
"""

import re
import json
import socket
import fnmatch
from typing import Dict, List, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_network
from engine.core.config import BountyHoundConfig


SCOPE_DIR = BountyHoundConfig.FINDINGS_DIR


@dataclass
class ScopeRule:
    """Represents a single scope rule."""
    pattern: str
    rule_type: str  # domain, wildcard, ip, ip_range, url
    in_scope: bool = True
    asset_type: str = "web"  # web, api, mobile, network, other
    max_severity: Optional[str] = None  # cap on severity
    notes: str = ""


@dataclass
class ProgramScope:
    """Complete scope definition for a bug bounty program."""
    program_name: str
    platform: str  # hackerone, bugcrowd, intigriti, private
    in_scope: List[ScopeRule] = field(default_factory=list)
    out_of_scope: List[ScopeRule] = field(default_factory=list)
    excluded_vuln_types: List[str] = field(default_factory=list)
    safe_harbor: bool = False
    notes: str = ""
    last_updated: str = ""


class ScopeValidator:
    """Validates targets and actions against program scope."""

    def __init__(self, target: str):
        self.target = target
        self.scope: Optional[ProgramScope] = None
        self._scope_file = SCOPE_DIR / target / "scope.json"
        self._load_scope()

    def _load_scope(self) -> None:
        """Load scope from saved file if exists."""
        if self._scope_file.exists():
            try:
                with open(self._scope_file) as f:
                    data = json.load(f)
                self.scope = ProgramScope(
                    program_name=data.get('program_name', self.target),
                    platform=data.get('platform', 'unknown'),
                    in_scope=[ScopeRule(**r) for r in data.get('in_scope', [])],
                    out_of_scope=[ScopeRule(**r) for r in data.get('out_of_scope', [])],
                    excluded_vuln_types=data.get('excluded_vuln_types', []),
                    safe_harbor=data.get('safe_harbor', False),
                    notes=data.get('notes', ''),
                    last_updated=data.get('last_updated', '')
                )
            except Exception:
                self.scope = None

    def save_scope(self, scope: ProgramScope) -> None:
        """Save scope definition to file."""
        self.scope = scope
        self._scope_file.parent.mkdir(parents=True, exist_ok=True)
        data = {
            'program_name': scope.program_name,
            'platform': scope.platform,
            'in_scope': [vars(r) for r in scope.in_scope],
            'out_of_scope': [vars(r) for r in scope.out_of_scope],
            'excluded_vuln_types': scope.excluded_vuln_types,
            'safe_harbor': scope.safe_harbor,
            'notes': scope.notes,
            'last_updated': scope.last_updated,
        }
        with open(self._scope_file, 'w') as f:
            json.dump(data, f, indent=2)

    def is_domain_in_scope(self, domain: str) -> Tuple[bool, str]:
        """Check if a domain is in scope."""
        if not self.scope:
            return True, "No scope defined - proceeding with caution"

        domain = domain.lower().strip()

        # Check out-of-scope first (exclusions take priority)
        for rule in self.scope.out_of_scope:
            if self._matches_domain(domain, rule):
                return False, f"OUT OF SCOPE: {domain} matches exclusion '{rule.pattern}'"

        # Check in-scope
        for rule in self.scope.in_scope:
            if self._matches_domain(domain, rule):
                severity_note = f" (max severity: {rule.max_severity})" if rule.max_severity else ""
                return True, f"IN SCOPE: {domain} matches '{rule.pattern}'{severity_note}"

        return False, f"NOT IN SCOPE: {domain} does not match any in-scope rules"

    def is_url_in_scope(self, url: str) -> Tuple[bool, str]:
        """Check if a URL is in scope."""
        # Extract domain from URL
        domain_match = re.match(r'https?://([^/:]+)', url)
        if not domain_match:
            return False, f"Invalid URL: {url}"

        domain = domain_match.group(1).lower()

        # Check domain scope
        in_scope, reason = self.is_domain_in_scope(domain)
        if not in_scope:
            return False, reason

        # Check URL-specific exclusions
        if self.scope:
            for rule in self.scope.out_of_scope:
                if rule.rule_type == 'url' and rule.pattern in url:
                    return False, f"OUT OF SCOPE: URL matches exclusion '{rule.pattern}'"

        return True, reason

    def is_ip_in_scope(self, ip: str) -> Tuple[bool, str]:
        """Check if an IP address is in scope."""
        if not self.scope:
            return True, "No scope defined"

        try:
            addr = ip_address(ip)
        except ValueError:
            return False, f"Invalid IP: {ip}"

        # Check out-of-scope IPs
        for rule in self.scope.out_of_scope:
            if rule.rule_type in ('ip', 'ip_range'):
                if self._matches_ip(addr, rule):
                    return False, f"OUT OF SCOPE: {ip} matches exclusion '{rule.pattern}'"

        # Check in-scope IPs
        for rule in self.scope.in_scope:
            if rule.rule_type in ('ip', 'ip_range'):
                if self._matches_ip(addr, rule):
                    return True, f"IN SCOPE: {ip} matches '{rule.pattern}'"

        # If no IP rules, try resolving to domain
        return False, f"NOT IN SCOPE: {ip} not covered by scope rules"

    def is_vuln_type_allowed(self, vuln_type: str) -> Tuple[bool, str]:
        """Check if a vulnerability type is allowed by the program."""
        if not self.scope:
            return True, "No scope defined"

        vuln_type_lower = vuln_type.lower()
        for excluded in self.scope.excluded_vuln_types:
            if excluded.lower() in vuln_type_lower or vuln_type_lower in excluded.lower():
                return False, f"EXCLUDED: {vuln_type} is excluded by program scope"

        return True, f"ALLOWED: {vuln_type} is not excluded"

    def validate_target_list(self, targets: List[str]) -> Dict[str, Dict]:
        """Validate a list of targets and return scope status for each."""
        results = {}
        for target in targets:
            if re.match(r'\d+\.\d+\.\d+\.\d+', target):
                in_scope, reason = self.is_ip_in_scope(target)
            elif '://' in target:
                in_scope, reason = self.is_url_in_scope(target)
            else:
                in_scope, reason = self.is_domain_in_scope(target)

            results[target] = {
                'in_scope': in_scope,
                'reason': reason
            }
        return results

    def get_max_severity(self, domain: str) -> Optional[str]:
        """Get maximum allowed severity for a domain."""
        if not self.scope:
            return None

        domain = domain.lower()
        for rule in self.scope.in_scope:
            if self._matches_domain(domain, rule) and rule.max_severity:
                return rule.max_severity
        return None

    def _matches_domain(self, domain: str, rule: ScopeRule) -> bool:
        """Check if a domain matches a scope rule."""
        pattern = rule.pattern.lower().strip()
        domain = domain.lower().strip()

        if rule.rule_type == 'domain':
            return domain == pattern or domain.endswith('.' + pattern)

        if rule.rule_type == 'wildcard':
            # *.example.com matches sub.example.com but not example.com itself
            if pattern.startswith('*.'):
                base = pattern[2:]
                return domain == base or domain.endswith('.' + base)
            return fnmatch.fnmatch(domain, pattern)

        if rule.rule_type == 'url':
            return pattern in domain

        return False

    def _matches_ip(self, addr, rule: ScopeRule) -> bool:
        """Check if an IP matches a scope rule."""
        try:
            if rule.rule_type == 'ip':
                return addr == ip_address(rule.pattern)
            if rule.rule_type == 'ip_range':
                return addr in ip_network(rule.pattern, strict=False)
        except ValueError:
            pass
        return False

    def scope_report(self) -> str:
        """Generate human-readable scope report."""
        if not self.scope:
            return f"No scope defined for {self.target}. Use save_scope() to define."

        lines = [
            f"Scope Report: {self.scope.program_name}",
            f"Platform: {self.scope.platform}",
            f"Safe Harbor: {'Yes' if self.scope.safe_harbor else 'No'}",
            f"Last Updated: {self.scope.last_updated or 'unknown'}",
            "",
            "IN SCOPE:",
        ]
        for rule in self.scope.in_scope:
            sev = f" (max: {rule.max_severity})" if rule.max_severity else ""
            lines.append(f"  + {rule.pattern} [{rule.asset_type}]{sev}")

        lines.append("")
        lines.append("OUT OF SCOPE:")
        for rule in self.scope.out_of_scope:
            lines.append(f"  - {rule.pattern} [{rule.rule_type}]")

        if self.scope.excluded_vuln_types:
            lines.append("")
            lines.append("EXCLUDED VULNERABILITY TYPES:")
            for vt in self.scope.excluded_vuln_types:
                lines.append(f"  x {vt}")

        if self.scope.notes:
            lines.append("")
            lines.append(f"NOTES: {self.scope.notes}")

        return '\n'.join(lines)


def create_scope_from_dict(target: str, scope_data: dict) -> ProgramScope:
    """Helper to create scope from a simple dictionary format."""
    in_scope = []
    for item in scope_data.get('in_scope', []):
        if isinstance(item, str):
            rule_type = 'wildcard' if '*' in item else 'domain'
            in_scope.append(ScopeRule(pattern=item, rule_type=rule_type))
        elif isinstance(item, dict):
            in_scope.append(ScopeRule(
                pattern=item['pattern'],
                rule_type=item.get('type', 'domain'),
                asset_type=item.get('asset_type', 'web'),
                max_severity=item.get('max_severity'),
                notes=item.get('notes', '')
            ))

    out_of_scope = []
    for item in scope_data.get('out_of_scope', []):
        if isinstance(item, str):
            rule_type = 'wildcard' if '*' in item else 'domain'
            out_of_scope.append(ScopeRule(pattern=item, rule_type=rule_type, in_scope=False))
        elif isinstance(item, dict):
            out_of_scope.append(ScopeRule(
                pattern=item['pattern'],
                rule_type=item.get('type', 'domain'),
                in_scope=False,
                notes=item.get('notes', '')
            ))

    return ProgramScope(
        program_name=scope_data.get('program_name', target),
        platform=scope_data.get('platform', 'unknown'),
        in_scope=in_scope,
        out_of_scope=out_of_scope,
        excluded_vuln_types=scope_data.get('excluded_vuln_types', []),
        safe_harbor=scope_data.get('safe_harbor', False),
        notes=scope_data.get('notes', ''),
        last_updated=scope_data.get('last_updated', '')
    )
