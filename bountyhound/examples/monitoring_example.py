"""
Example: Using Continuous Monitoring System

Demonstrates how to set up and use the continuous target monitoring infrastructure.
"""

from engine.core.monitor import ContinuousMonitor
from engine.core.scheduler import Scheduler
from engine.core.database import BountyHoundDB

def example_basic_monitoring():
    """Example: Basic target monitoring"""
    print("="*60)
    print("EXAMPLE 1: Basic Target Monitoring")
    print("="*60)

    monitor = ContinuousMonitor()

    # Add targets with different check intervals
    monitor.add_target("example.com", check_interval=86400)  # 24 hours
    monitor.add_target("api.example.com", check_interval=43200)  # 12 hours
    monitor.add_target("staging.example.com", check_interval=3600)  # 1 hour

    # List all monitored targets
    targets = monitor.get_monitored_targets()
    print(f"\n[*] Monitoring {len(targets)} targets:")
    for target in targets:
        print(f"  - {target['target']} (every {target['check_interval']}s)")

def example_change_detection():
    """Example: Detect changes in target"""
    print("\n" + "="*60)
    print("EXAMPLE 2: Change Detection")
    print("="*60)

    monitor = ContinuousMonitor()

    # First check establishes baseline
    print("\n[*] First check (baseline):")
    changes = monitor.check_for_changes("example.com")
    print(f"  {changes.get('note', 'No changes')}")

    # Subsequent checks detect changes
    print("\n[*] Second check (detect changes):")
    changes = monitor.check_for_changes("example.com")

    if changes['new_endpoints']:
        print(f"  New endpoints: {changes['new_endpoints']}")
    if changes['removed_endpoints']:
        print(f"  Removed endpoints: {changes['removed_endpoints']}")
    if changes['tech_stack_changes']:
        print(f"  Tech stack changes: {changes['tech_stack_changes']}")

    if not any([changes['new_endpoints'], changes['removed_endpoints'],
                changes['tech_stack_changes']]):
        print("  No changes detected")

def example_automated_rescanning():
    """Example: Automatic re-scan scheduling"""
    print("\n" + "="*60)
    print("EXAMPLE 3: Automated Re-scanning")
    print("="*60)

    monitor = ContinuousMonitor()
    scheduler = Scheduler()

    # Add targets
    monitor.add_target("target1.com", check_interval=60)  # 1 min for demo
    monitor.add_target("target2.com", check_interval=120)  # 2 min for demo

    # Schedule rescans for targets due
    scheduled = monitor.schedule_rescans()

    print(f"\n[*] Scheduled {len(scheduled)} re-scans:")
    for scan in scheduled:
        print(f"  - {scan['target']}: {scan['reason']}")
        # Actually schedule the task
        scheduler.schedule_task(scan['target'], 'rescan')

    # Get pending tasks
    pending = scheduler.get_pending_tasks()
    print(f"\n[*] Pending tasks: {len(pending)}")
    for task in pending:
        print(f"  - {task['target']}: {task['task_type']} ({task['status']})")

def example_finding_alerts():
    """Example: Alert on new findings"""
    print("\n" + "="*60)
    print("EXAMPLE 4: Finding Alerts")
    print("="*60)

    monitor = ContinuousMonitor()

    # Simulate finding new vulnerabilities
    findings = [
        {
            "title": "SQL Injection in /api/users",
            "severity": "CRITICAL",
            "impact": "Database access"
        },
        {
            "title": "XSS in search parameter",
            "severity": "HIGH",
            "impact": "Account takeover"
        },
        {
            "title": "Missing rate limit on /api/login",
            "severity": "MEDIUM",
            "impact": "Brute force attacks"
        }
    ]

    # Alert on findings
    success = monitor.alert_on_findings("example.com", findings)

    if success:
        print("\n[+] Alert sent successfully")
    else:
        print("\n[-] No findings to alert")

def example_task_execution():
    """Example: Execute scheduled tasks"""
    print("\n" + "="*60)
    print("EXAMPLE 5: Task Execution")
    print("="*60)

    scheduler = Scheduler()

    # Schedule some tasks
    task1 = scheduler.schedule_task("example.com", "rescan")
    task2 = scheduler.schedule_task("api.example.com", "retest")

    print(f"\n[*] Scheduled 2 tasks")

    # Execute pending tasks
    pending = scheduler.get_pending_tasks()
    print(f"[*] Executing {len(pending)} pending tasks...\n")

    for task in pending:
        result = scheduler.execute_task(task['id'])
        print(f"  Task {task['id'][:8]}... ({task['task_type']} on {task['target']})")
        print(f"  Result: {result}")

if __name__ == "__main__":
    # Run all examples
    example_basic_monitoring()
    example_change_detection()
    example_automated_rescanning()
    example_finding_alerts()
    example_task_execution()

    print("\n" + "="*60)
    print("All examples completed!")
    print("="*60)
