"""Persistence utilities for saving/loading state."""

from __future__ import annotations

import json
import logging
import pickle
from pathlib import Path
from typing import Any

from models import BaseJob, BaseFinding

log = logging.getLogger("bh-core.persistence")


def save_state_json(jobs: dict[str, BaseJob], filepath: Path) -> dict[str, Any]:
    """Save job state to JSON file.

    Args:
        jobs: Dictionary of jobs to save.
        filepath: Path to save to.

    Returns:
        Summary dict with saved count.
    """
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        data = {
            job_id: job.model_dump()
            for job_id, job in jobs.items()
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        log.info(f"Saved {len(jobs)} jobs to {filepath}")
        return {"saved": len(jobs), "path": str(filepath)}
    except Exception as e:
        log.error(f"Error saving state: {e}")
        return {"error": str(e)}


def load_state_json(filepath: Path) -> dict[str, dict[str, Any]]:
    """Load job state from JSON file.

    Args:
        filepath: Path to load from.

    Returns:
        Dictionary of job data.
    """
    if not filepath.exists():
        return {}

    try:
        with open(filepath, "r") as f:
            data = json.load(f)
        log.info(f"Loaded {len(data)} jobs from {filepath}")
        return data
    except Exception as e:
        log.error(f"Error loading state: {e}")
        return {}


def save_state_pickle(jobs: dict[str, BaseJob], filepath: Path) -> dict[str, Any]:
    """Save job state to pickle file (binary).

    Args:
        jobs: Dictionary of jobs to save.
        filepath: Path to save to.

    Returns:
        Summary dict with saved count.
    """
    try:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "wb") as f:
            pickle.dump(jobs, f)
        log.info(f"Saved {len(jobs)} jobs to {filepath}")
        return {"saved": len(jobs), "path": str(filepath)}
    except Exception as e:
        log.error(f"Error saving state: {e}")
        return {"error": str(e)}


def load_state_pickle(filepath: Path) -> dict[str, BaseJob]:
    """Load job state from pickle file.

    Args:
        filepath: Path to load from.

    Returns:
        Dictionary of jobs.
    """
    if not filepath.exists():
        return {}

    try:
        with open(filepath, "rb") as f:
            jobs = pickle.load(f)
        log.info(f"Loaded {len(jobs)} jobs from {filepath}")
        return jobs
    except Exception as e:
        log.error(f"Error loading state: {e}")
        return {}
