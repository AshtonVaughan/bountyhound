"""
CAPTCHA Solving Integration

Integrates with CAPTCHA solving services for automated account creation.
Supports: reCAPTCHA v2/v3, hCaptcha, image CAPTCHA, Turnstile.
"""

import os
import time
import json
import subprocess
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class CaptchaType(Enum):
    RECAPTCHA_V2 = "recaptcha_v2"
    RECAPTCHA_V3 = "recaptcha_v3"
    HCAPTCHA = "hcaptcha"
    IMAGE = "image"
    TURNSTILE = "turnstile"
    FUNCAPTCHA = "funcaptcha"


class SolverService(Enum):
    TWO_CAPTCHA = "2captcha"
    ANTI_CAPTCHA = "anti-captcha"
    CAPSOLVER = "capsolver"


@dataclass
class CaptchaTask:
    """Represents a CAPTCHA solving task."""
    captcha_type: CaptchaType
    site_key: str
    page_url: str
    task_id: Optional[str] = None
    solution: Optional[str] = None
    cost: float = 0.0
    solve_time: float = 0.0
    service: Optional[SolverService] = None


class CaptchaSolver:
    """Multi-service CAPTCHA solving integration."""

    def __init__(self, service: SolverService = SolverService.TWO_CAPTCHA):
        self.service = service
        self.api_key = self._get_api_key()
        self._base_urls = {
            SolverService.TWO_CAPTCHA: "https://2captcha.com",
            SolverService.ANTI_CAPTCHA: "https://api.anti-captcha.com",
            SolverService.CAPSOLVER: "https://api.capsolver.com",
        }

    def _get_api_key(self) -> str:
        """Get API key from environment variables."""
        key_map = {
            SolverService.TWO_CAPTCHA: 'TWOCAPTCHA_API_KEY',
            SolverService.ANTI_CAPTCHA: 'ANTICAPTCHA_API_KEY',
            SolverService.CAPSOLVER: 'CAPSOLVER_API_KEY',
        }
        env_var = key_map.get(self.service, '')
        return os.environ.get(env_var, '')

    def _curl(self, url: str, data: dict = None, method: str = 'GET', timeout: int = 30) -> str:
        """Execute curl request."""
        cmd = ['curl', '-s', '-m', str(timeout)]
        if data:
            cmd.extend(['-X', 'POST', '-H', 'Content-Type: application/json',
                       '-d', json.dumps(data)])
        elif method == 'POST':
            cmd.extend(['-X', 'POST'])
        cmd.append(url)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            return result.stdout
        except Exception:
            return ''

    def solve_recaptcha_v2(self, site_key: str, page_url: str,
                            invisible: bool = False) -> CaptchaTask:
        """Solve reCAPTCHA v2."""
        task = CaptchaTask(
            captcha_type=CaptchaType.RECAPTCHA_V2,
            site_key=site_key,
            page_url=page_url,
            service=self.service
        )

        if not self.api_key:
            return task

        start_time = time.time()

        if self.service == SolverService.TWO_CAPTCHA:
            task = self._solve_2captcha_recaptcha(task, invisible)
        elif self.service == SolverService.ANTI_CAPTCHA:
            task = self._solve_anticaptcha_recaptcha(task, invisible)
        elif self.service == SolverService.CAPSOLVER:
            task = self._solve_capsolver_recaptcha(task)

        task.solve_time = time.time() - start_time
        return task

    def solve_hcaptcha(self, site_key: str, page_url: str) -> CaptchaTask:
        """Solve hCaptcha."""
        task = CaptchaTask(
            captcha_type=CaptchaType.HCAPTCHA,
            site_key=site_key,
            page_url=page_url,
            service=self.service
        )

        if not self.api_key:
            return task

        start_time = time.time()

        if self.service == SolverService.TWO_CAPTCHA:
            task = self._solve_2captcha_hcaptcha(task)
        elif self.service == SolverService.ANTI_CAPTCHA:
            task = self._solve_anticaptcha_hcaptcha(task)
        elif self.service == SolverService.CAPSOLVER:
            task = self._solve_capsolver_hcaptcha(task)

        task.solve_time = time.time() - start_time
        return task

    def solve_turnstile(self, site_key: str, page_url: str) -> CaptchaTask:
        """Solve Cloudflare Turnstile."""
        task = CaptchaTask(
            captcha_type=CaptchaType.TURNSTILE,
            site_key=site_key,
            page_url=page_url,
            service=self.service
        )

        if not self.api_key:
            return task

        start_time = time.time()

        if self.service == SolverService.TWO_CAPTCHA:
            # Submit
            submit_url = (f"{self._base_urls[self.service]}/in.php?"
                         f"key={self.api_key}&method=turnstile"
                         f"&sitekey={site_key}&pageurl={page_url}&json=1")
            response = self._curl(submit_url)
            task = self._poll_2captcha(task, response)

        task.solve_time = time.time() - start_time
        return task

    # === 2Captcha Implementation ===

    def _solve_2captcha_recaptcha(self, task: CaptchaTask, invisible: bool = False) -> CaptchaTask:
        """Solve reCAPTCHA via 2Captcha."""
        inv_param = "&invisible=1" if invisible else ""
        submit_url = (f"{self._base_urls[self.service]}/in.php?"
                     f"key={self.api_key}&method=userrecaptcha"
                     f"&googlekey={task.site_key}&pageurl={task.page_url}"
                     f"&json=1{inv_param}")
        response = self._curl(submit_url)
        return self._poll_2captcha(task, response)

    def _solve_2captcha_hcaptcha(self, task: CaptchaTask) -> CaptchaTask:
        """Solve hCaptcha via 2Captcha."""
        submit_url = (f"{self._base_urls[self.service]}/in.php?"
                     f"key={self.api_key}&method=hcaptcha"
                     f"&sitekey={task.site_key}&pageurl={task.page_url}&json=1")
        response = self._curl(submit_url)
        return self._poll_2captcha(task, response)

    def _poll_2captcha(self, task: CaptchaTask, submit_response: str,
                       max_wait: int = 180, poll_interval: int = 5) -> CaptchaTask:
        """Poll 2Captcha for solution."""
        try:
            data = json.loads(submit_response)
            if data.get('status') != 1:
                return task
            task.task_id = data['request']
        except Exception:
            return task

        # Poll for result
        result_url = (f"{self._base_urls[self.service]}/res.php?"
                     f"key={self.api_key}&action=get&id={task.task_id}&json=1")

        elapsed = 0
        time.sleep(15)  # Initial wait
        elapsed += 15

        while elapsed < max_wait:
            response = self._curl(result_url)
            try:
                data = json.loads(response)
                if data.get('status') == 1:
                    task.solution = data['request']
                    task.cost = 0.003  # ~$0.003 per reCAPTCHA solve
                    return task
                elif 'CAPCHA_NOT_READY' not in data.get('request', ''):
                    return task  # Error
            except Exception:
                pass
            time.sleep(poll_interval)
            elapsed += poll_interval

        return task

    # === Anti-Captcha Implementation ===

    def _solve_anticaptcha_recaptcha(self, task: CaptchaTask, invisible: bool = False) -> CaptchaTask:
        """Solve reCAPTCHA via Anti-Captcha."""
        create_data = {
            "clientKey": self.api_key,
            "task": {
                "type": "RecaptchaV2TaskProxyless",
                "websiteURL": task.page_url,
                "websiteKey": task.site_key,
                "isInvisible": invisible
            }
        }
        response = self._curl(
            f"{self._base_urls[self.service]}/createTask",
            data=create_data
        )
        return self._poll_anticaptcha(task, response)

    def _solve_anticaptcha_hcaptcha(self, task: CaptchaTask) -> CaptchaTask:
        """Solve hCaptcha via Anti-Captcha."""
        create_data = {
            "clientKey": self.api_key,
            "task": {
                "type": "HCaptchaTaskProxyless",
                "websiteURL": task.page_url,
                "websiteKey": task.site_key
            }
        }
        response = self._curl(
            f"{self._base_urls[self.service]}/createTask",
            data=create_data
        )
        return self._poll_anticaptcha(task, response)

    def _poll_anticaptcha(self, task: CaptchaTask, create_response: str,
                          max_wait: int = 180, poll_interval: int = 5) -> CaptchaTask:
        """Poll Anti-Captcha for solution."""
        try:
            data = json.loads(create_response)
            if data.get('errorId') != 0:
                return task
            task.task_id = str(data['taskId'])
        except Exception:
            return task

        elapsed = 0
        time.sleep(10)
        elapsed += 10

        while elapsed < max_wait:
            response = self._curl(
                f"{self._base_urls[self.service]}/getTaskResult",
                data={"clientKey": self.api_key, "taskId": int(task.task_id)}
            )
            try:
                data = json.loads(response)
                if data.get('status') == 'ready':
                    solution = data.get('solution', {})
                    task.solution = solution.get('gRecaptchaResponse') or solution.get('token')
                    task.cost = data.get('cost', 0)
                    return task
            except Exception:
                pass
            time.sleep(poll_interval)
            elapsed += poll_interval

        return task

    # === CapSolver Implementation ===

    def _solve_capsolver_recaptcha(self, task: CaptchaTask) -> CaptchaTask:
        """Solve reCAPTCHA via CapSolver."""
        create_data = {
            "clientKey": self.api_key,
            "task": {
                "type": "ReCaptchaV2TaskProxyLess",
                "websiteURL": task.page_url,
                "websiteKey": task.site_key,
            }
        }
        response = self._curl(
            f"{self._base_urls[self.service]}/createTask",
            data=create_data
        )
        return self._poll_capsolver(task, response)

    def _solve_capsolver_hcaptcha(self, task: CaptchaTask) -> CaptchaTask:
        """Solve hCaptcha via CapSolver."""
        create_data = {
            "clientKey": self.api_key,
            "task": {
                "type": "HCaptchaTaskProxyLess",
                "websiteURL": task.page_url,
                "websiteKey": task.site_key,
            }
        }
        response = self._curl(
            f"{self._base_urls[self.service]}/createTask",
            data=create_data
        )
        return self._poll_capsolver(task, response)

    def _poll_capsolver(self, task: CaptchaTask, create_response: str,
                        max_wait: int = 180, poll_interval: int = 3) -> CaptchaTask:
        """Poll CapSolver for solution."""
        try:
            data = json.loads(create_response)
            if data.get('errorId') != 0:
                return task
            task.task_id = data['taskId']
        except Exception:
            return task

        elapsed = 0
        time.sleep(5)
        elapsed += 5

        while elapsed < max_wait:
            response = self._curl(
                f"{self._base_urls[self.service]}/getTaskResult",
                data={"clientKey": self.api_key, "taskId": task.task_id}
            )
            try:
                data = json.loads(response)
                if data.get('status') == 'ready':
                    solution = data.get('solution', {})
                    task.solution = solution.get('gRecaptchaResponse') or solution.get('token')
                    return task
            except Exception:
                pass
            time.sleep(poll_interval)
            elapsed += poll_interval

        return task

    def get_balance(self) -> float:
        """Check account balance."""
        if not self.api_key:
            return 0.0

        if self.service == SolverService.TWO_CAPTCHA:
            url = f"{self._base_urls[self.service]}/res.php?key={self.api_key}&action=getbalance&json=1"
            response = self._curl(url)
            try:
                return float(json.loads(response).get('request', 0))
            except Exception:
                return 0.0

        elif self.service in (SolverService.ANTI_CAPTCHA, SolverService.CAPSOLVER):
            response = self._curl(
                f"{self._base_urls[self.service]}/getBalance",
                data={"clientKey": self.api_key}
            )
            try:
                return float(json.loads(response).get('balance', 0))
            except Exception:
                return 0.0

        return 0.0

    def status(self) -> Dict:
        """Get solver status."""
        return {
            'service': self.service.value,
            'has_api_key': bool(self.api_key),
            'balance': self.get_balance() if self.api_key else 0.0,
        }


def detect_captcha_type(page_source: str) -> Optional[Tuple[CaptchaType, str]]:
    """Detect CAPTCHA type and site key from page source."""
    import re

    # reCAPTCHA v2
    match = re.search(r'data-sitekey=["\']([^"\']+)', page_source)
    if match:
        return CaptchaType.RECAPTCHA_V2, match.group(1)

    # reCAPTCHA v3
    match = re.search(r'grecaptcha\.execute\(["\']([^"\']+)', page_source)
    if match:
        return CaptchaType.RECAPTCHA_V3, match.group(1)

    # hCaptcha
    match = re.search(r'data-sitekey=["\']([0-9a-f-]{36})', page_source)
    if match and 'hcaptcha' in page_source.lower():
        return CaptchaType.HCAPTCHA, match.group(1)

    # Turnstile
    match = re.search(r'cf-turnstile.*?data-sitekey=["\']([^"\']+)', page_source, re.DOTALL)
    if match:
        return CaptchaType.TURNSTILE, match.group(1)

    # Generic captcha indicators
    if 'captcha' in page_source.lower():
        return CaptchaType.IMAGE, ''

    return None
