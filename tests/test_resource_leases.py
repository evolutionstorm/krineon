from __future__ import annotations

import json
import sqlite3
import unittest

from scripts.research_harness import (
    acquire_resource_leases,
    finalize_resource_leases,
    future_time,
    initialize_orchestration_schema,
    orchestration_snapshot,
    recover_tasks,
    resources_available,
    utc_now,
)


def requirement(mode: str, *, cleanup: bool = False) -> dict:
    return {
        "type": "owned-object",
        "id": "fixture-record-1",
        "mode": mode,
        "cleanupRequired": cleanup,
    }


class ResourceLeaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        initialize_orchestration_schema(self.connection)
        now = utc_now()
        for worker in ("worker-a", "worker-b"):
            self.connection.execute(
                "INSERT INTO workers(worker_id,agent,role,status,registered_at,updated_at) VALUES(?,?,?,?,?,?)",
                (worker, worker, "worker", "active", now, now),
            )

    def tearDown(self) -> None:
        self.connection.close()

    def insert_task(self, task_id: str, requirements: list[dict]) -> sqlite3.Row:
        now = utc_now()
        self.connection.execute(
            "INSERT INTO tasks(task_id,wave,lane,title,packet,state,priority,depends_json,"
            "resource_requirements_json,max_attempts,timeout_seconds,created_at,updated_at) "
            "VALUES(?,?,?,?,?,'running',0,'[]',?,2,3600,?,?)",
            (task_id, 1, "test", task_id, "task.md", json.dumps(requirements), now, now),
        )
        return self.connection.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()

    def test_shared_reads_parallelize_but_exclusive_mutation_serializes(self) -> None:
        self.insert_task("read-a", [requirement("shared-read")])
        acquire_resource_leases(
            self.connection,
            task_id="read-a",
            worker_id="worker-a",
            lease_token="lease-a",
            lease_expires_at=future_time(300),
            requirements=[requirement("shared-read")],
        )
        self.assertTrue(resources_available(self.connection, [requirement("shared-read")])[0])
        self.assertFalse(
            resources_available(
                self.connection, [requirement("exclusive", cleanup=True)]
            )[0]
        )

    def test_failed_cleanup_blocks_further_mutation(self) -> None:
        task = self.insert_task("mutate-a", [requirement("exclusive", cleanup=True)])
        acquire_resource_leases(
            self.connection,
            task_id="mutate-a",
            worker_id="worker-a",
            lease_token="lease-a",
            lease_expires_at=future_time(300),
            requirements=[requirement("exclusive", cleanup=True)],
        )
        failed, _ = finalize_resource_leases(
            self.connection,
            task=task,
            result={
                "resourceLeaseOutcome": {
                    "checkpoints": [
                        {
                            "type": "owned-object",
                            "id": "fixture-record-1",
                            "setupCheckpoint": {"evidence": "setup.json"},
                            "authoritativeReadback": {"evidence": "readback.json"},
                            "cleanup": {"status": "failed", "evidence": "cleanup.json"},
                        }
                    ]
                }
            },
        )
        self.assertTrue(failed)
        self.assertFalse(
            resources_available(
                self.connection, [requirement("exclusive", cleanup=True)]
            )[0]
        )

    def test_lost_worker_blocks_mutable_resource_until_authoritative_recovery(self) -> None:
        self.insert_task("mutate-lost", [requirement("exclusive", cleanup=True)])
        expired = future_time(-60)
        self.connection.execute(
            "UPDATE tasks SET lease_owner=?,lease_token=?,lease_expires_at=?,started_at=? "
            "WHERE task_id=?",
            ("worker-a", "lease-lost", expired, utc_now(), "mutate-lost"),
        )
        acquire_resource_leases(
            self.connection,
            task_id="mutate-lost",
            worker_id="worker-a",
            lease_token="lease-lost",
            lease_expires_at=expired,
            requirements=[requirement("exclusive", cleanup=True)],
        )
        self.connection.execute(
            "UPDATE resource_leases SET checkpoint_json=? WHERE task_id=?",
            ('{"phase":"before-effect","secret":"not-for-status"}', "mutate-lost"),
        )

        recovered = recover_tasks(self.connection)

        task = self.connection.execute(
            "SELECT state FROM tasks WHERE task_id='mutate-lost'"
        ).fetchone()
        self.assertEqual(task["state"], "blocked")
        self.assertEqual(recovered["blocked"], 1)
        self.assertFalse(resources_available(self.connection, [requirement("exclusive")])[0])
        snapshot = orchestration_snapshot(self.connection)
        self.assertNotIn("checkpoint_json", snapshot["resourceBlocks"][0])
        self.assertNotIn("not-for-status", json.dumps(snapshot))


if __name__ == "__main__":
    unittest.main()
