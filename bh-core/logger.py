"""Unified logging configuration."""

import logging
import sys


def setup_logging(name: str, level: int = logging.INFO) -> logging.Logger:
    """Set up logging for a module.

    Args:
        name: Logger name (typically __name__).
        level: Logging level (default INFO).

    Returns:
        Configured logger instance.
    """
    log = logging.getLogger(name)

    if not log.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(level)
        formatter = logging.Formatter(
            "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
            datefmt="%H:%M:%S",
        )
        handler.setFormatter(formatter)
        log.addHandler(handler)
        log.setLevel(level)

    return log


def setup_root_logging(level: int = logging.INFO) -> None:
    """Configure root logger for all modules."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stdout,
    )
