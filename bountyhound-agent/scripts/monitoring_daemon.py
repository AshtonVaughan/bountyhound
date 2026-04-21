"""
Continuous Monitoring Daemon

Runs in background to monitor targets and trigger re-scans.
"""

import time
from engine.core.monitor import ContinuousMonitor
from engine.core.scheduler import Scheduler
from engine.core.database import BountyHoundDB

def main():
    db = BountyHoundDB()
    monitor = ContinuousMonitor(db=db)
    scheduler = Scheduler(db=db)

    print("[*] Starting BountyHound monitoring daemon...")

    while True:
        # Check for scheduled rescans
        scheduled = monitor.schedule_rescans()

        for scan in scheduled:
            print(f"[*] Scheduling rescan for {scan['target']}")
            scheduler.schedule_task(scan['target'], 'rescan')

        # Execute pending tasks
        pending = scheduler.get_pending_tasks()

        for task in pending:
            print(f"[*] Executing task {task['id']}: {task['task_type']} on {task['target']}")
            result = scheduler.execute_task(task['id'])
            print(f"[+] Result: {result}")

        # Sleep for 1 minute before next check
        time.sleep(60)

if __name__ == "__main__":
    main()
