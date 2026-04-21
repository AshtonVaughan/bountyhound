"""Maps RBAC by comparing responses across privilege levels to find escalation paths."""

import json
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from engine.core.http_client import HttpClient
from engine.core.response_diff import ResponseDiff


@dataclass
class PermissionEntry:
    """Permission state for one endpoint + role combination."""
    endpoint: str
    role: str
    status_code: int
    has_data: bool
    response_keys: List[str] = field(default_factory=list)
    data_count: int = 0
    error_message: str = ''

    def to_dict(self) -> Dict:
        return {
            'endpoint': self.endpoint,
            'role': self.role,
            'status_code': self.status_code,
            'has_data': self.has_data,
            'response_keys': self.response_keys,
            'data_count': self.data_count,
            'error_message': self.error_message,
        }


@dataclass
class EscalationPath:
    """A detected privilege escalation path."""
    endpoint: str
    low_role: str
    high_role: str
    escalation_type: str  # 'data_access', 'action_access', 'field_exposure'
    evidence: str
    severity: str = 'high'

    def to_dict(self) -> Dict:
        return {
            'endpoint': self.endpoint,
            'low_role': self.low_role,
            'high_role': self.high_role,
            'escalation_type': self.escalation_type,
            'evidence': self.evidence,
            'severity': self.severity,
        }


# Role hierarchy (higher index = higher privilege)
DEFAULT_ROLE_HIERARCHY = ['unauthenticated', 'user', 'moderator', 'admin', 'superadmin']


class PermissionMapper:
    """Maps RBAC permissions by comparing responses across privilege levels."""

    def __init__(self, target: str, role_hierarchy: Optional[List[str]] = None):
        self.target = target
        self.role_hierarchy = role_hierarchy or DEFAULT_ROLE_HIERARCHY
        self.matrix: Dict[str, Dict[str, PermissionEntry]] = {}  # endpoint -> {role -> entry}
        self.escalation_paths: List[EscalationPath] = []
        self.differ = ResponseDiff()

    def _make_request(self, endpoint: str, token: Optional[str], role: str) -> PermissionEntry:
        """Make a request with the given token and analyze the response."""
        headers = {}
        if token:
            headers['Authorization'] = token if token.startswith('Bearer ') else f'Bearer {token}'

        client = HttpClient(target=self.target, timeout=10, headers=headers)
        resp = client.get(endpoint)

        # Parse response
        has_data = False
        response_keys: List[str] = []
        data_count = 0
        error_message = ''

        try:
            body = json.loads(resp.body)
            if isinstance(body, dict):
                response_keys = list(body.keys())
                # Check for data vs error
                if 'error' in body or 'errors' in body:
                    error_message = str(body.get('error', body.get('errors', '')))[:200]
                elif 'data' in body:
                    has_data = True
                    data_val = body['data']
                    if isinstance(data_val, list):
                        data_count = len(data_val)
                    elif isinstance(data_val, dict):
                        data_count = len(data_val)
                        has_data = bool(data_val)
                else:
                    has_data = resp.status_code == 200 and len(resp.body) > 50
            elif isinstance(body, list):
                has_data = len(body) > 0
                data_count = len(body)
                response_keys = ['[array]']
        except (json.JSONDecodeError, ValueError):
            has_data = resp.status_code == 200 and len(resp.body) > 50

        return PermissionEntry(
            endpoint=endpoint,
            role=role,
            status_code=resp.status_code,
            has_data=has_data,
            response_keys=response_keys,
            data_count=data_count,
            error_message=error_message,
        )

    def map_permissions(self, endpoints: List[str], tokens: Dict[str, Optional[str]]) -> Dict[str, Dict[str, PermissionEntry]]:
        """Map permissions for all endpoints across all roles.

        Args:
            endpoints: List of endpoint URLs to test
            tokens: Dict of {role_name: auth_token} (None for unauthenticated)

        Returns:
            Permission matrix: {endpoint: {role: PermissionEntry}}
        """
        self.matrix = {}

        for endpoint in endpoints:
            self.matrix[endpoint] = {}
            for role, token in tokens.items():
                entry = self._make_request(endpoint, token, role)
                self.matrix[endpoint][role] = entry

        return self.matrix

    def find_escalation_paths(self) -> List[EscalationPath]:
        """Analyze permission matrix to find privilege escalation paths.

        Looks for cases where a lower-privilege role gets the same access
        as a higher-privilege role.
        """
        escalations = []

        for endpoint, role_entries in self.matrix.items():
            roles = sorted(
                role_entries.keys(),
                key=lambda r: self.role_hierarchy.index(r) if r in self.role_hierarchy else -1,
            )

            # Compare each pair of roles (lower vs higher)
            for i, low_role in enumerate(roles):
                for high_role in roles[i + 1:]:
                    low_entry = role_entries[low_role]
                    high_entry = role_entries[high_role]

                    # Case 1: Lower role gets same data as higher role
                    if low_entry.has_data and high_entry.has_data:
                        if low_entry.status_code == high_entry.status_code:
                            # Check if response keys overlap significantly
                            if low_entry.response_keys and high_entry.response_keys:
                                overlap = set(low_entry.response_keys) & set(high_entry.response_keys)
                                if len(overlap) >= len(high_entry.response_keys) * 0.8:
                                    escalations.append(EscalationPath(
                                        endpoint=endpoint,
                                        low_role=low_role,
                                        high_role=high_role,
                                        escalation_type='data_access',
                                        evidence=f'{low_role} gets same data as {high_role} '
                                                 f'(keys overlap: {overlap})',
                                        severity='high',
                                    ))

                    # Case 2: Lower role should get 401/403 but gets 200
                    if high_entry.status_code == 200 and low_entry.status_code == 200:
                        if high_entry.has_data and low_entry.has_data:
                            if low_entry.data_count > 0 and high_entry.data_count > 0:
                                escalations.append(EscalationPath(
                                    endpoint=endpoint,
                                    low_role=low_role,
                                    high_role=high_role,
                                    escalation_type='action_access',
                                    evidence=f'{low_role} (status={low_entry.status_code}, '
                                             f'data_count={low_entry.data_count}) has same access '
                                             f'as {high_role} (data_count={high_entry.data_count})',
                                    severity='high',
                                ))

                    # Case 3: Lower role sees fields that should be restricted
                    if low_entry.response_keys and high_entry.response_keys:
                        extra_keys = set(low_entry.response_keys) - set(high_entry.response_keys)
                        if extra_keys:
                            escalations.append(EscalationPath(
                                endpoint=endpoint,
                                low_role=low_role,
                                high_role=high_role,
                                escalation_type='field_exposure',
                                evidence=f'{low_role} sees extra fields: {extra_keys}',
                                severity='medium',
                            ))

        self.escalation_paths = escalations
        return escalations

    def get_matrix_table(self) -> List[Dict]:
        """Return permission matrix as a flat table for display."""
        rows = []
        for endpoint, role_entries in self.matrix.items():
            for role, entry in role_entries.items():
                rows.append({
                    'endpoint': endpoint,
                    'role': role,
                    'status': entry.status_code,
                    'has_data': entry.has_data,
                    'data_count': entry.data_count,
                    'keys': ', '.join(entry.response_keys[:5]),
                })
        return rows

    def summary(self) -> Dict:
        """Return summary of permission mapping."""
        total_entries = sum(len(roles) for roles in self.matrix.values())
        return {
            'endpoints_tested': len(self.matrix),
            'roles_tested': len(set(
                role for roles in self.matrix.values() for role in roles
            )),
            'total_checks': total_entries,
            'escalation_paths': len(self.escalation_paths),
            'escalations_by_type': {
                etype: len([e for e in self.escalation_paths if e.escalation_type == etype])
                for etype in ('data_access', 'action_access', 'field_exposure')
            },
        }
