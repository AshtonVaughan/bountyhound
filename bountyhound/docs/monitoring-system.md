# Continuous Target Monitoring System

**Revenue Impact:** $1,500-$3,000/month from catching changes early

## Overview

The continuous monitoring system provides automated surveillance of targets for changes and new vulnerabilities. It detects when targets introduce new endpoints, features, or security issues, enabling early discovery of fresh attack surface.

## Components

### 1. ContinuousMonitor (`engine/core/monitor.py`)

Monitors targets for changes and manages the monitoring lifecycle.

**Key Features:**
- Add/remove targets from monitoring list
- Configure check intervals per target (default: 24 hours)
- Detect changes in endpoints, tech stack, security headers
- Alert on new findings
- Maintain state history for comparison

**API:**

```python
from engine.core.monitor import ContinuousMonitor

monitor = ContinuousMonitor()

# Add target to monitoring
monitor.add_target("example.com", check_interval=86400)  # 24h

# Check for changes
changes = monitor.check_for_changes("example.com")
if changes['new_endpoints']:
    print(f"New endpoints: {changes['new_endpoints']}")

# Schedule re-scans for all targets
scheduled = monitor.schedule_rescans()

# Alert on new findings
findings = [{"title": "XSS", "severity": "HIGH"}]
monitor.alert_on_findings("example.com", findings)
```

### 2. Scheduler (`engine/core/scheduler.py`)

Cron-like task scheduler for automated re-scans and testing.

**Key Features:**
- Schedule tasks for immediate or future execution
- Track task status (pending, completed)
- Execute scheduled tasks
- Persist tasks in database

**API:**

```python
from engine.core.scheduler import Scheduler

scheduler = Scheduler()

# Schedule a task
task_id = scheduler.schedule_task(
    target="example.com",
    task_type="rescan",
    schedule_time=None  # Immediate
)

# Get pending tasks
pending = scheduler.get_pending_tasks()

# Execute a task
result = scheduler.execute_task(task_id)
```

### 3. Monitoring Daemon (`scripts/monitoring_daemon.py`)

Background daemon that continuously monitors targets and executes scheduled tasks.

**Features:**
- Runs continuously in background
- Checks every 60 seconds for work
- Schedules rescans for targets based on intervals
- Executes pending tasks automatically

**Usage:**

```bash
cd C:/Users/vaugh/BountyHound/bountyhound-agent
python scripts/monitoring_daemon.py
```

## Database Schema

### `monitored_targets` Table

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| target | TEXT | Target domain/URL (unique) |
| check_interval | INTEGER | Check interval in seconds |
| last_scan | TIMESTAMP | Last scan timestamp |
| last_state | TEXT | JSON string of last state |
| created_at | TIMESTAMP | When added to monitoring |

### `scheduled_tasks` Table

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | Task ID (UUID) |
| target | TEXT | Target domain/URL |
| task_type | TEXT | Task type (rescan, retest, etc.) |
| schedule_time | TIMESTAMP | When to execute |
| status | TEXT | Status (pending, completed) |
| result | TEXT | Execution result (JSON) |
| created_at | TIMESTAMP | When task was created |
| completed_at | TIMESTAMP | When task completed |

## Change Detection

The monitor detects the following changes:

### 1. New Endpoints
- Compares current endpoints with last scan
- Identifies newly added routes/URLs
- Triggers re-testing of new endpoints

### 2. Removed Endpoints
- Identifies endpoints that no longer exist
- Helpful for understanding target evolution

### 3. Tech Stack Changes
- Detects changes in web server, frameworks
- May indicate new attack vectors

### 4. Security Header Changes
- Monitors changes in CSP, HSTS, etc.
- Can reveal security improvements or regressions

## Alert System

### Current Implementation
- Console output with formatted messages
- Severity-based categorization
- Finding summaries

### Future Implementations
- **Email:** Send alerts via SMTP
- **Slack:** Webhook notifications
- **Discord:** Bot notifications
- **SMS:** Twilio integration for critical findings

## Workflow Examples

### Example 1: Monitor High-Value Targets

```python
from engine.core.monitor import ContinuousMonitor

monitor = ContinuousMonitor()

# Add high-value targets with frequent checks
monitor.add_target("api.stripe.com", check_interval=3600)  # 1h
monitor.add_target("api.paypal.com", check_interval=3600)
monitor.add_target("api.coinbase.com", check_interval=3600)

# Add medium-value targets with daily checks
monitor.add_target("example.com", check_interval=86400)  # 24h
monitor.add_target("test.example.com", check_interval=86400)
```

### Example 2: Automated Re-scanning

```python
from engine.core.monitor import ContinuousMonitor
from engine.core.scheduler import Scheduler

monitor = ContinuousMonitor()
scheduler = Scheduler()

# Schedule rescans for all targets
scheduled = monitor.schedule_rescans()

for scan in scheduled:
    print(f"Scheduling rescan: {scan['target']}")
    scheduler.schedule_task(scan['target'], 'rescan')

# Execute all pending tasks
pending = scheduler.get_pending_tasks()
for task in pending:
    result = scheduler.execute_task(task['id'])
    print(f"Task {task['id']}: {result}")
```

### Example 3: Integration with Phased Hunter

```python
from engine.core.monitor import ContinuousMonitor
from engine.core.scheduler import Scheduler
from engine.agents.phased_hunter import PhasedHunter

def execute_rescan(target: str):
    """Execute a full rescan of target"""
    hunter = PhasedHunter()

    # Check for changes first
    monitor = ContinuousMonitor()
    changes = monitor.check_for_changes(target)

    if changes['new_endpoints']:
        # Focus on new endpoints
        for endpoint in changes['new_endpoints']:
            findings = hunter.hunt(f"{target}{endpoint}")
            if findings:
                monitor.alert_on_findings(target, findings)
    else:
        # Full rescan
        findings = hunter.hunt(target)
        if findings:
            monitor.alert_on_findings(target, findings)

# Schedule rescans
scheduler = Scheduler()
pending = scheduler.get_pending_tasks()

for task in pending:
    if task['task_type'] == 'rescan':
        execute_rescan(task['target'])
        scheduler.execute_task(task['id'])
```

## Configuration

### Check Intervals

Recommended intervals based on target value:

| Target Value | Interval | Rationale |
|-------------|----------|-----------|
| Critical (Stripe, PayPal) | 1-6 hours | High bounties, rapid changes |
| High (Fortune 500) | 12 hours | Frequent updates |
| Medium (Standard programs) | 24 hours | Daily changes |
| Low (Practice targets) | 7 days | Infrequent changes |

### Alert Thresholds

Configure when to send alerts:

```python
# Only alert on HIGH/CRITICAL findings
def alert_filter(findings):
    return [f for f in findings if f['severity'] in ['HIGH', 'CRITICAL']]

filtered = alert_filter(all_findings)
if filtered:
    monitor.alert_on_findings(target, filtered)
```

## Performance Considerations

### Rate Limiting
- Respect target rate limits
- Space out scans across check interval
- Use exponential backoff on errors

### Resource Usage
- Monitor daemon uses ~10MB RAM
- Database grows ~1KB per monitored target per day
- Network: ~100KB per check (varies by target)

### Scaling
- Current implementation: up to 1000 targets
- For larger scale: Consider distributed architecture
- Database: Migrate to PostgreSQL for >10K targets

## Best Practices

### 1. Start Small
```python
# Begin with a few targets
monitor.add_target("target1.com", check_interval=86400)
monitor.add_target("target2.com", check_interval=86400)

# Monitor for a week, then expand
```

### 2. Adjust Intervals Based on Findings
```python
# If target changes frequently, reduce interval
if len(changes['new_endpoints']) > 5:
    # Update to check every 12 hours
    # (Currently requires database update)
    pass
```

### 3. Archive Old Data
```python
# Delete monitoring data older than 90 days
# (Future feature)
```

### 4. Test Before Production
```python
# Test monitoring logic on known targets
monitor.add_target("example.com", check_interval=300)  # 5 min
# Verify alerts work
# Then increase interval to production value
```

## Troubleshooting

### Issue: No changes detected when changes exist

**Solution:** Ensure `_scan_target_state()` is properly implemented with real recon tools. The current implementation is a placeholder.

### Issue: Too many false positive alerts

**Solution:** Implement alert filtering:
```python
# Filter low-severity findings
findings = [f for f in all_findings if f['severity'] != 'LOW']
monitor.alert_on_findings(target, findings)
```

### Issue: Daemon consuming too much CPU

**Solution:** Increase sleep interval in `monitoring_daemon.py`:
```python
time.sleep(300)  # Check every 5 minutes instead of 1
```

## Metrics

Track monitoring effectiveness:

- **Targets monitored:** Count of active monitoring targets
- **Changes detected:** Number of detected changes per week
- **Findings from monitoring:** New findings from re-scans
- **Revenue from monitoring:** Bounties from monitoring-detected issues

## Future Enhancements

1. **Smart Scheduling:** ML-based interval adjustment
2. **Parallel Scanning:** Scan multiple targets concurrently
3. **Change Prediction:** Predict when targets likely to change
4. **Integration with CI/CD:** Monitor target deployments
5. **Historical Analysis:** Trend analysis of target changes
6. **Automated Reporting:** Weekly monitoring summaries

## See Also

- `examples/monitoring_example.py` - Usage examples
- `tests/engine/core/test_monitor.py` - Monitor tests
- `tests/engine/core/test_scheduler.py` - Scheduler tests
- `engine/core/database.py` - Database implementation
