"""
Auto-Retry with Exponential Backoff

Provides retry mechanisms for phased hunter phases and agent execution.
Supports configurable max retries, backoff strategies, and error classification.
"""

import time
import random
import functools
import subprocess
import traceback
from typing import Any, Callable, Dict, List, Optional, Tuple, Type
from dataclasses import dataclass, field
from enum import Enum


class RetryStrategy(Enum):
    """Backoff strategy types."""
    EXPONENTIAL = "exponential"
    LINEAR = "linear"
    CONSTANT = "constant"
    JITTERED = "jittered"  # Exponential + random jitter


class ErrorCategory(Enum):
    """Classification of errors for retry decisions."""
    TRANSIENT = "transient"      # Network timeout, 429, 503 - RETRY
    PERMANENT = "permanent"      # 404, 401, invalid input - DON'T RETRY
    RATE_LIMITED = "rate_limited" # 429 - RETRY with longer backoff
    UNKNOWN = "unknown"          # Unknown error - RETRY with caution


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_retries: int = 3
    base_delay: float = 1.0  # seconds
    max_delay: float = 60.0  # seconds
    strategy: RetryStrategy = RetryStrategy.JITTERED
    retry_on: List[Type[Exception]] = field(default_factory=lambda: [Exception])
    dont_retry_on: List[Type[Exception]] = field(default_factory=list)
    on_retry: Optional[Callable] = None  # Callback on each retry


@dataclass
class RetryResult:
    """Result of a retried operation."""
    success: bool
    result: Any = None
    attempts: int = 0
    total_delay: float = 0.0
    errors: List[str] = field(default_factory=list)
    final_error: Optional[str] = None


class RetryEngine:
    """Core retry engine with configurable strategies."""

    def __init__(self, config: Optional[RetryConfig] = None):
        self.config = config or RetryConfig()

    def calculate_delay(self, attempt: int) -> float:
        """Calculate delay for a given attempt number."""
        if self.config.strategy == RetryStrategy.CONSTANT:
            delay = self.config.base_delay

        elif self.config.strategy == RetryStrategy.LINEAR:
            delay = self.config.base_delay * attempt

        elif self.config.strategy == RetryStrategy.EXPONENTIAL:
            delay = self.config.base_delay * (2 ** (attempt - 1))

        elif self.config.strategy == RetryStrategy.JITTERED:
            base = self.config.base_delay * (2 ** (attempt - 1))
            delay = base * (0.5 + random.random())  # 50-150% of exponential

        else:
            delay = self.config.base_delay

        return min(delay, self.config.max_delay)

    def classify_error(self, error: Exception) -> ErrorCategory:
        """Classify an error to determine retry behavior."""
        error_str = str(error).lower()

        # Rate limiting
        if '429' in error_str or 'rate limit' in error_str or 'too many' in error_str:
            return ErrorCategory.RATE_LIMITED

        # Transient errors (should retry)
        transient_indicators = [
            'timeout', 'timed out', 'connection reset', 'connection refused',
            'temporary', '503', '502', '504', 'gateway', 'unavailable',
            'network', 'dns', 'resolve', 'econnreset', 'econnrefused',
            'broken pipe', 'connection aborted'
        ]
        if any(ind in error_str for ind in transient_indicators):
            return ErrorCategory.TRANSIENT

        # Permanent errors (don't retry)
        permanent_indicators = [
            '401', '403', '404', 'not found', 'unauthorized', 'forbidden',
            'invalid', 'malformed', 'bad request', 'not allowed',
            'permission denied', 'authentication'
        ]
        if any(ind in error_str for ind in permanent_indicators):
            return ErrorCategory.PERMANENT

        return ErrorCategory.UNKNOWN

    def should_retry(self, error: Exception, attempt: int) -> bool:
        """Determine if an error should be retried."""
        if attempt >= self.config.max_retries:
            return False

        # Check explicit don't-retry list
        for exc_type in self.config.dont_retry_on:
            if isinstance(error, exc_type):
                return False

        # Check error category
        category = self.classify_error(error)
        if category == ErrorCategory.PERMANENT:
            return False

        # Check explicit retry list
        for exc_type in self.config.retry_on:
            if isinstance(error, exc_type):
                return True

        return category != ErrorCategory.PERMANENT

    def execute(self, func: Callable, *args, **kwargs) -> RetryResult:
        """Execute a function with retry logic."""
        result = RetryResult(success=False)

        for attempt in range(1, self.config.max_retries + 1):
            result.attempts = attempt
            try:
                ret = func(*args, **kwargs)
                result.success = True
                result.result = ret
                return result

            except Exception as e:
                error_msg = f"Attempt {attempt}: {type(e).__name__}: {str(e)}"
                result.errors.append(error_msg)
                result.final_error = str(e)

                if not self.should_retry(e, attempt):
                    return result

                delay = self.calculate_delay(attempt)

                # Rate limited gets extra delay
                if self.classify_error(e) == ErrorCategory.RATE_LIMITED:
                    delay = min(delay * 3, self.config.max_delay)

                result.total_delay += delay

                if self.config.on_retry:
                    self.config.on_retry(attempt, delay, e)

                time.sleep(delay)

        return result


def with_retry(max_retries: int = 3, base_delay: float = 1.0,
               strategy: RetryStrategy = RetryStrategy.JITTERED,
               max_delay: float = 60.0):
    """Decorator for adding retry logic to functions."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            config = RetryConfig(
                max_retries=max_retries,
                base_delay=base_delay,
                strategy=strategy,
                max_delay=max_delay
            )
            engine = RetryEngine(config)
            result = engine.execute(func, *args, **kwargs)
            if result.success:
                return result.result
            raise Exception(
                f"Failed after {result.attempts} attempts. "
                f"Errors: {'; '.join(result.errors)}"
            )
        return wrapper
    return decorator


class PhaseRetryManager:
    """Manages retry logic for phased hunter phases."""

    # Phase-specific retry configurations
    PHASE_CONFIGS = {
        'recon': RetryConfig(max_retries=3, base_delay=5.0, strategy=RetryStrategy.EXPONENTIAL),
        'discovery': RetryConfig(max_retries=2, base_delay=2.0, strategy=RetryStrategy.CONSTANT),
        'auth_boundary': RetryConfig(max_retries=2, base_delay=3.0, strategy=RetryStrategy.LINEAR),
        'parallel_scan': RetryConfig(max_retries=3, base_delay=10.0, strategy=RetryStrategy.JITTERED),
        'quality_gate': RetryConfig(max_retries=1, base_delay=1.0, strategy=RetryStrategy.CONSTANT),
        'poc_validation': RetryConfig(max_retries=3, base_delay=2.0, strategy=RetryStrategy.JITTERED),
    }

    def __init__(self):
        self.phase_results: Dict[str, RetryResult] = {}

    def execute_phase(self, phase_name: str, func: Callable, *args, **kwargs) -> RetryResult:
        """Execute a hunt phase with appropriate retry configuration."""
        config = self.PHASE_CONFIGS.get(phase_name, RetryConfig())

        def on_retry(attempt, delay, error):
            category = RetryEngine(config).classify_error(error)
            print(f"  Phase '{phase_name}' attempt {attempt} failed ({category.value}). "
                  f"Retrying in {delay:.1f}s...")

        config.on_retry = on_retry
        engine = RetryEngine(config)
        result = engine.execute(func, *args, **kwargs)
        self.phase_results[phase_name] = result
        return result

    def get_summary(self) -> str:
        """Get retry summary for all phases."""
        lines = ["Phase Retry Summary:", ""]
        for phase, result in self.phase_results.items():
            status = "OK" if result.success else "FAILED"
            retry_info = f" ({result.attempts} attempts, {result.total_delay:.1f}s delay)" if result.attempts > 1 else ""
            lines.append(f"  [{status}] {phase}{retry_info}")
            if result.errors:
                for error in result.errors:
                    lines.append(f"    - {error}")
        return '\n'.join(lines)


class CurlRetry:
    """Retry wrapper specifically for curl commands."""

    @staticmethod
    def execute(cmd: List[str], max_retries: int = 3, timeout: int = 15) -> Tuple[str, int]:
        """Execute a curl command with retry logic."""
        config = RetryConfig(
            max_retries=max_retries,
            base_delay=2.0,
            strategy=RetryStrategy.JITTERED,
            max_delay=30.0
        )
        engine = RetryEngine(config)

        def run_curl():
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout
            stderr = result.stderr

            # Check for curl errors
            if result.returncode != 0 and not output:
                raise Exception(f"curl failed (exit {result.returncode}): {stderr[:200]}")

            # Check for HTTP errors that should retry
            if output:
                lines = output.strip().split('\n')
                last_line = lines[-1].strip()
                if last_line.isdigit():
                    status = int(last_line)
                    if status in (429, 502, 503, 504):
                        raise Exception(f"HTTP {status} - transient error")

            return output

        retry_result = engine.execute(run_curl)
        if retry_result.success:
            return retry_result.result, retry_result.attempts
        return '', retry_result.attempts
