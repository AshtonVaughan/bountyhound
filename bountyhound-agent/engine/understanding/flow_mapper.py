"""Maps business logic flows from request log history to find bypass points."""

import json
import re
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse

from engine.core.request_logger import RequestLogger
from engine.core.evidence_vault import EvidenceVault
from engine.core.database import BountyHoundDB


@dataclass
class FlowStep:
    """A single step in a business logic flow."""
    url: str
    method: str
    status_code: int
    sets_cookie: bool = False
    sets_token: bool = False
    redirects_to: str = ''
    request_id: int = 0

    def to_dict(self) -> Dict:
        return {
            'url': self.url,
            'method': self.method,
            'status_code': self.status_code,
            'sets_cookie': self.sets_cookie,
            'sets_token': self.sets_token,
            'redirects_to': self.redirects_to,
        }


@dataclass
class Flow:
    """A reconstructed business logic flow."""
    name: str
    flow_type: str  # 'auth', 'payment', 'registration', 'password_reset', 'upload', 'custom'
    steps: List[FlowStep] = field(default_factory=list)
    bypass_points: List[Dict] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'flow_type': self.flow_type,
            'steps': [s.to_dict() for s in self.steps],
            'step_count': len(self.steps),
            'bypass_points': self.bypass_points,
        }


# URL pattern → flow type mapping
FLOW_PATTERNS = {
    'auth': {
        'indicators': ['/login', '/signin', '/authenticate', '/auth/', '/oauth', '/token', '/verify', '/mfa', '/2fa'],
        'sequence': ['login', 'verify', 'token', 'me'],
    },
    'payment': {
        'indicators': ['/cart', '/checkout', '/pay', '/payment', '/order', '/purchase', '/billing', '/invoice'],
        'sequence': ['cart', 'checkout', 'pay', 'confirm'],
    },
    'registration': {
        'indicators': ['/register', '/signup', '/create-account', '/onboard', '/activate', '/confirm-email'],
        'sequence': ['register', 'verify', 'activate', 'profile'],
    },
    'password_reset': {
        'indicators': ['/forgot', '/reset-password', '/recovery', '/reset-token', '/new-password'],
        'sequence': ['forgot', 'token', 'reset', 'confirm'],
    },
    'upload': {
        'indicators': ['/upload', '/file', '/media', '/attachment', '/document', '/import'],
        'sequence': ['select', 'upload', 'process', 'confirm'],
    },
}


class FlowMapper:
    """Maps business logic flows from HTTP request history."""

    def __init__(self, target: str):
        self.target = target
        self.logger = RequestLogger()
        self.vault = EvidenceVault(target)
        self.flows: List[Flow] = []

    def _get_request_log(self) -> List[Dict]:
        """Get all logged requests for this target."""
        return self.logger.get_requests(self.target, limit=500)

    def _classify_request(self, url: str) -> Optional[str]:
        """Classify a URL into a flow type based on patterns."""
        path = urlparse(url).path.lower()
        for flow_type, config in FLOW_PATTERNS.items():
            if any(indicator in path for indicator in config['indicators']):
                return flow_type
        return None

    def _extract_flow_metadata(self, request: Dict) -> Dict:
        """Extract metadata from a request relevant to flow analysis."""
        resp_headers = request.get('resp_headers', '') or ''
        if isinstance(resp_headers, str):
            headers_lower = resp_headers.lower()
        else:
            headers_lower = json.dumps(resp_headers).lower()

        return {
            'sets_cookie': 'set-cookie' in headers_lower,
            'sets_token': any(tok in headers_lower for tok in ['authorization', 'x-auth-token', 'x-csrf-token']),
            'has_redirect': request.get('status_code', 0) in (301, 302, 303, 307, 308),
        }

    def _build_flow(self, requests: List[Dict], flow_type: str) -> Flow:
        """Build a Flow object from a list of related requests."""
        flow = Flow(
            name=f"{flow_type}_flow",
            flow_type=flow_type,
        )

        for req in requests:
            meta = self._extract_flow_metadata(req)
            step = FlowStep(
                url=req.get('url', ''),
                method=req.get('method', 'GET'),
                status_code=req.get('status_code', 0),
                sets_cookie=meta['sets_cookie'],
                sets_token=meta['sets_token'],
                request_id=req.get('id', 0),
            )
            flow.steps.append(step)

        return flow

    def map_auth_flow(self) -> Optional[Flow]:
        """Map the authentication flow from request history."""
        return self._map_flow_type('auth')

    def map_payment_flow(self) -> Optional[Flow]:
        """Map the payment/checkout flow from request history."""
        return self._map_flow_type('payment')

    def map_registration_flow(self) -> Optional[Flow]:
        """Map the user registration flow from request history."""
        return self._map_flow_type('registration')

    def _map_flow_type(self, flow_type: str) -> Optional[Flow]:
        """Generic flow mapper for a given type."""
        requests = self._get_request_log()
        if not requests:
            return None

        # Filter requests matching this flow type
        matching = []
        for req in requests:
            url = req.get('url', '')
            if self._classify_request(url) == flow_type:
                matching.append(req)

        if not matching:
            return None

        # Sort by timestamp/id
        matching.sort(key=lambda r: r.get('id', 0))

        flow = self._build_flow(matching, flow_type)
        flow.bypass_points = self.find_bypass_points(flow)

        self.flows.append(flow)
        return flow

    def map_all_flows(self) -> List[Flow]:
        """Discover and map all business logic flows from request history."""
        requests = self._get_request_log()
        if not requests:
            return []

        # Group requests by flow type
        grouped: Dict[str, List[Dict]] = {}
        for req in requests:
            url = req.get('url', '')
            flow_type = self._classify_request(url)
            if flow_type:
                grouped.setdefault(flow_type, []).append(req)

        flows = []
        for flow_type, reqs in grouped.items():
            reqs.sort(key=lambda r: r.get('id', 0))
            flow = self._build_flow(reqs, flow_type)
            flow.bypass_points = self.find_bypass_points(flow)
            flows.append(flow)

        self.flows = flows

        # Save to evidence vault
        if flows:
            self.vault.save_raw(
                'flow-maps.json',
                json.dumps([f.to_dict() for f in flows], indent=2),
            )

        return flows

    def find_bypass_points(self, flow: Flow) -> List[Dict]:
        """Identify steps in a flow that might be skippable.

        A bypass point is a step where:
        1. The step performs verification/validation (e.g., MFA, email confirm)
        2. The next step might accept requests without the verification
        3. The step sets a token/cookie that could be predicted or reused
        """
        bypass_points = []

        for i, step in enumerate(flow.steps):
            path = urlparse(step.url).path.lower()

            # Verification steps are common bypass targets
            verification_indicators = [
                'verify', 'confirm', 'validate', 'check', 'mfa', '2fa',
                'otp', 'captcha', 'challenge', 'approve',
            ]
            is_verification = any(ind in path for ind in verification_indicators)

            if is_verification and i < len(flow.steps) - 1:
                next_step = flow.steps[i + 1]
                bypass_points.append({
                    'type': 'skip_verification',
                    'step_index': i,
                    'skip_url': step.url,
                    'target_url': next_step.url,
                    'description': f'Try accessing {next_step.url} directly, skipping {step.url}',
                    'risk': 'high',
                })

            # Token-setting steps might use predictable tokens
            if step.sets_token and i > 0:
                bypass_points.append({
                    'type': 'token_prediction',
                    'step_index': i,
                    'url': step.url,
                    'description': f'Check if token from {step.url} is predictable or reusable',
                    'risk': 'medium',
                })

            # POST endpoints that return 200 without prior GET might skip CSRF
            if step.method == 'POST' and step.status_code == 200:
                has_prior_get = any(
                    s.method == 'GET' and urlparse(s.url).path == urlparse(step.url).path
                    for s in flow.steps[:i]
                )
                if not has_prior_get:
                    bypass_points.append({
                        'type': 'csrf_missing',
                        'step_index': i,
                        'url': step.url,
                        'description': f'POST to {step.url} without prior GET - possible CSRF',
                        'risk': 'medium',
                    })

        return bypass_points

    def summary(self) -> Dict:
        """Return summary of mapped flows."""
        return {
            'total_flows': len(self.flows),
            'flows': [
                {
                    'name': f.name,
                    'type': f.flow_type,
                    'steps': len(f.steps),
                    'bypass_points': len(f.bypass_points),
                }
                for f in self.flows
            ],
            'total_bypass_points': sum(len(f.bypass_points) for f in self.flows),
        }
