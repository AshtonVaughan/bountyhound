import pytest
from engine.core.scheduler import Scheduler
from engine.core.database import BountyHoundDB

@pytest.fixture
def scheduler():
    db = BountyHoundDB(":memory:")
    return Scheduler(db=db)

def test_schedule_task(scheduler):
    """Test scheduling a task"""
    task_id = scheduler.schedule_task(
        target="example.com",
        task_type="rescan",
        schedule_time=None  # Immediate
    )

    assert task_id is not None

def test_get_pending_tasks(scheduler):
    """Test getting pending tasks"""
    scheduler.schedule_task("example.com", "rescan")

    pending = scheduler.get_pending_tasks()

    assert len(pending) > 0

def test_execute_task(scheduler):
    """Test executing a scheduled task"""
    task_id = scheduler.schedule_task("example.com", "rescan")

    result = scheduler.execute_task(task_id)

    assert isinstance(result, dict)
