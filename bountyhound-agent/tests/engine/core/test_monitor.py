import pytest
from datetime import datetime, timedelta
from engine.core.monitor import ContinuousMonitor
from engine.core.database import BountyHoundDB

@pytest.fixture
def monitor():
    db = BountyHoundDB(":memory:")
    return ContinuousMonitor(db=db)

def test_add_target(monitor):
    """Test adding target to monitoring list"""
    monitor.add_target("example.com", check_interval=3600)

    targets = monitor.get_monitored_targets()
    assert len(targets) > 0
    assert targets[0]["target"] == "example.com"

def test_check_for_changes(monitor):
    """Test checking target for changes"""
    monitor.add_target("example.com")

    changes = monitor.check_for_changes("example.com")

    assert isinstance(changes, dict)
    assert "new_endpoints" in changes or "tech_stack_changes" in changes

def test_schedule_rescans(monitor):
    """Test automatic re-scan scheduling"""
    # Add targets with different intervals
    monitor.add_target("target1.com", check_interval=3600)
    monitor.add_target("target2.com", check_interval=7200)

    scheduled = monitor.schedule_rescans()

    assert isinstance(scheduled, list)

def test_alert_on_findings(monitor):
    """Test alerting when new findings discovered"""
    findings = [
        {"title": "XSS", "severity": "HIGH"},
        {"title": "SQLi", "severity": "CRITICAL"}
    ]

    result = monitor.alert_on_findings("example.com", findings)

    assert isinstance(result, bool)
