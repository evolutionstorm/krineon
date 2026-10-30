from __future__ import annotations

import sqlite3
import unittest

from scripts.research_harness import alternate_exploration_and_focus, set_metadata


class SchedulerModeTests(unittest.TestCase):
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
