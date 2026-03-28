"""Zeek state manager."""

from __future__ import annotations

import sys
import os
from typing import Union

_bh_core_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core"))
sys.path.insert(0, _bh_core_path)

from state import BaseStateManager as _BaseStateManager

sys.path.pop(0)

from models import ZeekAnalyzeJob, ZeekQueryJob

BaseStateManager = _BaseStateManager
AnyZeekJob = Union[ZeekAnalyzeJob, ZeekQueryJob]


class ZeekStateManager(BaseStateManager[AnyZeekJob]):
    """State manager for Zeek analysis and query jobs."""

    async def get_analyze_jobs(self) -> list[ZeekAnalyzeJob]:
        """Return only PCAP/live analysis jobs."""
        async with self._lock:
            return [j for j in self.jobs.values() if isinstance(j, ZeekAnalyzeJob)]
