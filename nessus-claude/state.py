"""Nessus state manager."""

from __future__ import annotations

import sys
import os
from typing import Union

_bh_core_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core"))
sys.path.insert(0, _bh_core_path)

from state import BaseStateManager as _BaseStateManager

sys.path.pop(0)

from models import NessusScanJob, NessusExportJob

BaseStateManager = _BaseStateManager
AnyNessusJob = Union[NessusScanJob, NessusExportJob]


class NessusStateManager(BaseStateManager[AnyNessusJob]):
    """State manager for Nessus scan and export jobs."""

    async def get_scan_jobs(self) -> list[NessusScanJob]:
        """Return only scan jobs."""
        async with self._lock:
            return [j for j in self.jobs.values() if isinstance(j, NessusScanJob)]
