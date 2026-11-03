from __future__ import annotations

import json
import sqlite3
import unittest
from pathlib import Path

from scripts.research_harness import (
    alternate_exploration_and_focus,
    rank_by_family_share_limits,
    set_metadata,
)


class SchedulerModeTests(unittest.TestCase):
    def test_web_access_control_family_is_limited_to_access_control_lanes(self) -> None:
        project = Path(__file__).resolve().parents[1]
        profile = json.loads(
            (project / "profiles" / "web-app.json").read_text(encoding="utf-8")
        )
        limit = profile["schedulingPolicy"]["familyShareLimits"][
            "web-authorization-isolation"
        ]
        self.assertEqual(limit["maxActiveShare"], 0.2)
        self.assertFalse(limit["focusedEvidenceSlotExempt"])
        self.assertFalse(profile["schedulingPolicy"]["fixedWorkersPerLane"])
        registry = json.loads(
            (project / "profiles" / "approach-families.json").read_text(
                encoding="utf-8"
            )
        )
        mapping = registry["profileMappings"]["web-app"]
        access_control_lanes = {
            lane_id
            for lane_id, families in mapping.items()
            if "web-authorization-isolation" in families
        }
        self.assertEqual(
            access_control_lanes,
            {"web-identity-resource-inventory", "web-authorization-oracles"},
        )

    def test_access_control_share_limit_defers_auth_when_alternatives_are_ready(self) -> None:
        rows = [
            {"task_id": "auth-second"},
            {"task_id": "parser"},
            {"task_id": "cache"},
        ]
        ranked, redirect = rank_by_family_share_limits(
            rows,
            task_families={
                "auth-second": ["web-authorization-isolation"],
                "parser": ["representation-parser"],
                "cache": ["web-cache-partition"],
            },
            family_active_agents={"web-authorization-isolation": 1},
            active_exploration_agents=3,
            limits={
                "web-authorization-isolation": {
                    "maxActiveShare": 0.34,
                    "whenAlternativesReady": "defer",
                }
            },
        )
        self.assertEqual(ranked[0]["task_id"], "parser")
        self.assertEqual(redirect["fromTaskId"], "auth-second")
        self.assertFalse(redirect["fixedWorkerAssignment"])

    def test_share_limit_never_blocks_the_only_runnable_family(self) -> None:
        rows = [{"task_id": "auth-one"}, {"task_id": "auth-two"}]
        ranked, redirect = rank_by_family_share_limits(
            rows,
            task_families={
                "auth-one": ["web-authorization-isolation"],
                "auth-two": ["web-authorization-isolation"],
            },
            family_active_agents={"web-authorization-isolation": 2},
            active_exploration_agents=2,
            limits={
                "web-authorization-isolation": {
                    "maxActiveShare": 0.34,
                    "whenAlternativesReady": "defer",
                }
            },
        )
        self.assertEqual(ranked, rows)
        self.assertIsNone(redirect)

    def test_one_focused_slot_is_followed_by_exploration(self) -> None:
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("CREATE TABLE tasks(task_id TEXT, task_kind TEXT)")
        connection.executemany(
            "INSERT INTO tasks VALUES(?, ?)",
            [
                ("focus", "focused-chain-investigation"),
                ("explore", "route-development"),
            ],
        )
        rows = connection.execute("SELECT * FROM tasks ORDER BY task_id").fetchall()
        ranked, _, mode = alternate_exploration_and_focus(connection, rows)
        self.assertEqual((ranked[0]["task_id"], mode), ("focus", "focused"))
        set_metadata(connection, "lastSchedulingMode", "focused")
        ranked, _, mode = alternate_exploration_and_focus(connection, rows)
        self.assertEqual((ranked[0]["task_id"], mode), ("explore", "exploration"))
        connection.close()


if __name__ == "__main__":
    unittest.main()
