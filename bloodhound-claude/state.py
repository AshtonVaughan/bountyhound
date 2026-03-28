"""BloodHound state manager — tracks collect, query, and path-finding jobs."""

from __future__ import annotations

import sys
import os
import asyncio
import logging
from typing import Union

# Properly import from bh-core
_bh_core_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "bh-core"))
sys.path.insert(0, _bh_core_path)

from state import BaseStateManager as _BaseStateManager

sys.path.pop(0)

from models import BloodHoundCollectJob, BloodHoundQueryJob, BloodHoundPathJob

log = logging.getLogger("bloodhound-claude.state")

BaseStateManager = _BaseStateManager

# Union type for all BloodHound job types
AnyBHJob = Union[BloodHoundCollectJob, BloodHoundQueryJob, BloodHoundPathJob]


class BloodHoundStateManager(BaseStateManager[AnyBHJob]):
    """State manager for all BloodHound job types.

    Stores collect, query, and path jobs in a single registry keyed by job_id.
    """

    async def get_collect_jobs(self) -> list[BloodHoundCollectJob]:
        """Return only collection jobs."""
        async with self._lock:
            return [j for j in self.jobs.values() if isinstance(j, BloodHoundCollectJob)]

    async def get_query_jobs(self) -> list[BloodHoundQueryJob]:
        """Return only query jobs."""
        async with self._lock:
            return [j for j in self.jobs.values() if isinstance(j, BloodHoundQueryJob)]

    async def get_path_jobs(self) -> list[BloodHoundPathJob]:
        """Return only path analysis jobs."""
        async with self._lock:
            return [j for j in self.jobs.values() if isinstance(j, BloodHoundPathJob)]
