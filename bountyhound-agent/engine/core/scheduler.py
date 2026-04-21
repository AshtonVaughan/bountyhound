"""
Task Scheduler

Cron-like scheduling for automated re-scans and monitoring tasks.
"""

from typing import List, Dict, Optional
from datetime import datetime, timedelta
from engine.core.database import BountyHoundDB
import uuid


class Scheduler:
    """Schedule and execute automated tasks"""

    def __init__(self, db: Optional[BountyHoundDB] = None):
        self.db = db if db else BountyHoundDB.get_instance()
        self._init_tables()

    def _init_tables(self):
        """Initialize scheduler tables"""
        with self.db._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scheduled_tasks (
                    id TEXT PRIMARY KEY,
                    target TEXT,
                    task_type TEXT,
                    schedule_time TIMESTAMP,
                    status TEXT DEFAULT 'pending',
                    result TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP
                )
            """)
            conn.commit()

    def schedule_task(
        self,
        target: str,
        task_type: str,
        schedule_time: Optional[datetime] = None
    ) -> str:
        """
        Schedule a task for execution

        Args:
            target: Target domain/URL
            task_type: Type of task (rescan, retest, etc.)
            schedule_time: When to execute (None = immediate)

        Returns:
            Task ID
        """
        task_id = str(uuid.uuid4())

        if schedule_time is None:
            schedule_time = datetime.now()

        with self.db._get_connection() as conn:
            conn.execute("""
                INSERT INTO scheduled_tasks (id, target, task_type, schedule_time)
                VALUES (?, ?, ?, ?)
            """, (task_id, target, task_type, schedule_time.isoformat()))
            conn.commit()

        print(f"[+] Scheduled {task_type} for {target} (ID: {task_id})")
        return task_id

    def get_pending_tasks(self) -> List[Dict]:
        """Get all pending tasks ready for execution"""
        with self.db._get_connection() as conn:
            cursor = conn.execute("""
                SELECT * FROM scheduled_tasks
                WHERE status = 'pending'
                AND schedule_time <= ?
                ORDER BY schedule_time ASC
            """, (datetime.now().isoformat(),))

            return [dict(row) for row in cursor.fetchall()]

    def execute_task(self, task_id: str) -> Dict:
        """
        Execute a scheduled task

        Args:
            task_id: Task ID to execute

        Returns:
            Execution result dictionary
        """
        # Get task details
        with self.db._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM scheduled_tasks WHERE id = ?",
                (task_id,)
            )
            task = cursor.fetchone()

            if not task:
                return {"success": False, "error": "Task not found"}

            task = dict(task)

        # Execute based on task type
        result = {"success": False}

        if task["task_type"] == "rescan":
            # Trigger rescan (would integrate with phased_hunter in practice)
            result = {"success": True, "action": "rescan_triggered"}

        # Update task status
        with self.db._get_connection() as conn:
            conn.execute("""
                UPDATE scheduled_tasks
                SET status = 'completed',
                    result = ?,
                    completed_at = ?
                WHERE id = ?
            """, (str(result), datetime.now().isoformat(), task_id))
            conn.commit()

        return result
