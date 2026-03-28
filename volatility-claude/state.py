"""Volatility state manager."""

from __future__ import annotations

import sys
import os
from typing import Union

_bh_core_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core"))
sys.path.insert(0, _bh_core_path)

from state import BaseStateManager as _BaseStateManager

sys.path.pop(0)

from models import VolatilityPluginJob, VolatilityBatchJob

BaseStateManager = _BaseStateManager
AnyVolJob = Union[VolatilityPluginJob, VolatilityBatchJob]


class VolatilityStateManager(BaseStateManager[AnyVolJob]):
    """State manager for Volatility plugin and batch jobs."""

    async def get_plugin_jobs(self) -> list[VolatilityPluginJob]:
        """Return only single-plugin jobs."""
        async with self._lock:
            return [j for j in self.jobs.values() if isinstance(j, VolatilityPluginJob)]

    async def get_batch_jobs(self) -> list[VolatilityBatchJob]:
        """Return only batch analysis jobs."""
        async with self._lock:
            return [j for j in self.jobs.values() if isinstance(j, VolatilityBatchJob)]
