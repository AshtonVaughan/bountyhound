"""Metasploit state manager — tracks run, search, and session jobs."""

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

from models import MetasploitRunJob, MetasploitSearchJob, MetasploitSessionJob

log = logging.getLogger("metasploit-claude.state")

BaseStateManager = _BaseStateManager

AnyMsfJob = Union[MetasploitRunJob, MetasploitSearchJob, MetasploitSessionJob]


class MetasploitStateManager(BaseStateManager[AnyMsfJob]):
    """State manager for all Metasploit job types."""

    async def get_run_jobs(self) -> list[MetasploitRunJob]:
        """Return only module execution jobs."""
        async with self._lock:
            return [j for j in self.jobs.values() if isinstance(j, MetasploitRunJob)]

    async def get_active_sessions(self) -> list[dict]:
        """Aggregate all opened sessions across run jobs."""
        async with self._lock:
            sessions = []
            for j in self.jobs.values():
                if isinstance(j, MetasploitRunJob) and j.sessions_opened:
                    sessions.extend(
                        [s.model_dump() for s in j.sessions_opened]
                    )
            return sessions
