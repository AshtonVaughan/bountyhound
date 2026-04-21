"""
BountyHound Centralized HTTP Client

Provides a unified interface for HTTP requests across all modules,
replacing inline subprocess+curl calls with consistent error handling and retry.
Auto-logs all requests via RequestLogger when a target is set.
"""

import json
import subprocess
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from engine.core.retry import CurlRetry


@dataclass
class HttpResponse:
    """Structured HTTP response."""
    body: str
    status_code: int
    ok: bool  # True if 200-399

    def json(self) -> Any:
        """Parse response body as JSON."""
        return json.loads(self.body)


class HttpClient:
    """Centralized HTTP client using curl with retry support.

    Set target= to enable auto-logging of all requests via RequestLogger.
    """

    def __init__(self, timeout: int = 15, max_retries: int = 3,
                 headers: Optional[Dict[str, str]] = None,
                 target: Optional[str] = None):
        self.timeout = timeout
        self.max_retries = max_retries
        self.default_headers = headers or {}
        self._target = target
        self._logger = None
        if target:
            try:
                from engine.core.request_logger import RequestLogger
                self._logger = RequestLogger()
            except Exception:
                pass  # Logging is optional - don't break HTTP if logger fails

    def _build_header_args(self, extra_headers: Optional[Dict[str, str]] = None) -> List[str]:
        """Build curl -H arguments from default + extra headers."""
        args = []
        all_headers = {**self.default_headers}
        if extra_headers:
            all_headers.update(extra_headers)
        for key, value in all_headers.items():
            args.extend(['-H', f'{key}: {value}'])
        return args

    def _execute(self, cmd: List[str], method: str = 'GET', url: str = '',
                 request_body: Optional[str] = None) -> HttpResponse:
        """Execute curl command and return structured response."""
        output, exit_code = CurlRetry.execute(cmd, max_retries=self.max_retries, timeout=self.timeout)

        # Extract status code from output if we appended -w
        body = output
        status_code = 0
        if output:
            lines = output.strip().rsplit('\n', 1)
            if len(lines) == 2 and lines[-1].strip().isdigit():
                body = lines[0]
                status_code = int(lines[-1].strip())
            elif lines[-1].strip().isdigit():
                body = ''
                status_code = int(lines[-1].strip())

        response = HttpResponse(
            body=body,
            status_code=status_code,
            ok=200 <= status_code < 400
        )

        # Auto-log if target is set
        if self._logger and url and self._target:
            try:
                self._logger.log_request(
                    target=self._target,
                    method=method,
                    url=url,
                    status_code=status_code,
                    req_body=request_body,
                    resp_body=body[:5000] if body else None,
                    req_headers=self.default_headers or None
                )
            except Exception:
                pass  # Never let logging break the request

        return response

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        """HTTP GET request."""
        cmd = ['curl', '-s', '-m', str(self.timeout), '-w', '\n%{http_code}']
        cmd.extend(self._build_header_args(headers))
        cmd.append(url)
        return self._execute(cmd, method='GET', url=url)

    def post_json(self, url: str, data: Any, headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        """HTTP POST request with JSON body."""
        body_str = json.dumps(data) if not isinstance(data, str) else data
        cmd = ['curl', '-s', '-m', str(self.timeout), '-w', '\n%{http_code}',
               '-X', 'POST', '-H', 'Content-Type: application/json',
               '-d', body_str]
        cmd.extend(self._build_header_args(headers))
        cmd.append(url)
        return self._execute(cmd, method='POST', url=url, request_body=body_str)

    def head(self, url: str, headers: Optional[Dict[str, str]] = None) -> HttpResponse:
        """HTTP HEAD request (returns headers only)."""
        cmd = ['curl', '-sI', '-m', str(self.timeout), '-w', '\n%{http_code}']
        cmd.extend(self._build_header_args(headers))
        cmd.append(url)
        return self._execute(cmd, method='HEAD', url=url)

    def get_status_code(self, url: str) -> int:
        """Quick check - returns just the HTTP status code."""
        try:
            result = subprocess.run(
                ['curl', '-so', '/dev/null', '-w', '%{http_code}', '-m', str(self.timeout), url],
                capture_output=True, text=True, timeout=self.timeout + 5
            )
            code = result.stdout.strip()
            return int(code) if code.isdigit() else 0
        except Exception:
            return 0
