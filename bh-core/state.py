"""Abstract state manager for job tracking."""

from __future__ import annotations

import asyncio
import logging
from typing import TypeVar, Generic

from models import BaseJob

log = logging.getLogger("bh-core.state")

T = TypeVar("T", bound=BaseJob)


class BaseStateManager(Generic[T]):
    """Thread-safe state manager with job tracking and cleanup."""

    def __init__(self):
        self._lock = asyncio.Lock()
        self.jobs: dict[str, T] = {}

    async def add_job(self, job: T) -> None:
        """Store a job."""
        async with self._lock:
            self.jobs[job.job_id] = job

    async def get_job(self, job_id: str) -> T | None:
        """Retrieve a job by ID."""
        async with self._lock:
            return self.jobs.get(job_id)

    async def update_job(self, job: T) -> None:
        """Update an existing job."""
        async with self._lock:
            self.jobs[job.job_id] = job

    async def cancel_job(self, job_id: str) -> bool:
        """Mark a job as cancelled."""
        async with self._lock:
            job = self.jobs.get(job_id)
            if job:
                job.status = "cancelled"
                return True
            return False

    async def all_jobs(self) -> list[T]:
        """Get all jobs."""
        async with self._lock:
            return list(self.jobs.values())

    async def job_count(self) -> dict[str, int]:
        """Count jobs by status."""
        async with self._lock:
            counts = {
                "running": 0,
                "completed": 0,
                "error": 0,
                "cancelled": 0,
            }
            for job in self.jobs.values():
                counts[job.status] = counts.get(job.status, 0) + 1
            return counts

    def cleanup_completed_jobs(self, max_completed: int = 100) -> int:
        """Remove old completed jobs to bound memory.

        Args:
            max_completed: Maximum number of completed/error/cancelled jobs to keep.

        Returns:
            Number of jobs removed.
        """
        completed_jobs = [
            (k, j) for k, j in self.jobs.items()
            if j.is_completed()
        ]

        if len(completed_jobs) > max_completed:
            # Keep the most recent `max_completed` jobs
            completed_jobs.sort(key=lambda x: x[1].completed_at, reverse=True)
            to_remove = completed_jobs[max_completed:]
            for job_id, _ in to_remove:
                self.jobs.pop(job_id, None)
            removed = len(to_remove)
            log.info(f"Cleanup: removed {removed} old jobs")
            return removed

        return 0
