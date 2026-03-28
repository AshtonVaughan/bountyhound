"""
AWS Rate Limiter Mixin

Shared rate limiting with exponential backoff for all AWS service testers.
Eliminates triplicated _rate_limited_call() implementations.
"""

import time
from botocore.exceptions import ClientError

try:
    from colorama import Fore, Style
except ImportError:
    # Fallback if colorama not available
    class Fore:
        YELLOW = RED = ""
    class Style:
        RESET_ALL = ""


class AWSRateLimiterMixin:
    """Mixin providing rate-limited AWS API calls with exponential backoff.

    Classes using this mixin must set:
        self.rate_limit: float  (seconds between requests)
        self.max_retries: int
        self._last_request_time: Optional[float]  (init to None)
    """

    def _rate_limited_call(self, func, *args, **kwargs):
        """
        Execute an AWS API function with rate limiting and exponential backoff.

        Returns:
            Function result or None on failure
        """
        for attempt in range(self.max_retries):
            try:
                if attempt > 0:
                    backoff_time = min(2 ** attempt, 30)  # Max 30s
                    print(f"{Fore.YELLOW}[*] Retry {attempt}, waiting {backoff_time}s...{Style.RESET_ALL}")
                    time.sleep(backoff_time)
                elif self._last_request_time is not None:
                    elapsed = time.time() - self._last_request_time
                    if elapsed < self.rate_limit:
                        time.sleep(self.rate_limit - elapsed)

                result = func(*args, **kwargs)
                self._last_request_time = time.time()
                return result

            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')

                if error_code in ['429', 'ThrottlingException', 'RequestLimitExceeded', 'TooManyRequestsException']:
                    if attempt < self.max_retries - 1:
                        print(f"{Fore.YELLOW}[!] Rate limited ({error_code}), retrying...{Style.RESET_ALL}")
                        continue
                    else:
                        print(f"{Fore.RED}[!] Max retries reached{Style.RESET_ALL}")
                        return None

                if error_code != 'NoSuchBucket':
                    print(f"{Fore.YELLOW}[*] Error: {error_code}{Style.RESET_ALL}")
                return None

        return None
