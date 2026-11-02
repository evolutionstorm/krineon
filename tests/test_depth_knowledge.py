import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from scripts.depth_knowledge import (
    compact_graph,
    continuation_for_task,
    ensure_schema,
    expand_digest,
    ingest_submission,
    search_observations,
    status,
    steer_worker,
)


class DepthKnowledgeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "evidence").mkdir()
        (self.root / "evidence" / "runtime.json").write_text(
            '{"observed":true}\n', encoding="utf-8"
        )
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        ensure_schema(self.connection)

    def tearDown(self) -> None:
        self.connection.close()
        self.temporary.cleanup()

    def test_observation_unlocks_typed_chain_and_retains_continuation(self) -> None:
        result = {
            "taskResult": {
                "observations": [
                    {
                        "kind": "runtime-differential",
                        "mechanism": "checker-consumer-path-disagreement",
                        "summary": "checker and consumer resolve different resources",
                        "confidence": "coordinator-replayed",
                        "producesCapabilities": ["resource-resolution-disagreement"],
                        "evidence": ["evidence/runtime.json"],
                        "assetRefs": [
                            {
                                "type": "consumer",
                                "name": "production-dispatch",
                                "role": "consumer",
                            }
                        ],
                        "coverage": [
                            {
                                "boundary": "authorization-to-execution",
                                "consumer": "production-dispatch",
                                "state": "verified",
                            }
                        ],
                    }
                ],
                "attackChainTodos": [
                    {
                        "title": "resource confusion to privileged read",
                        "terminalCapability": "cross-tenant-private-read",
                        "steps": [
                            {
                                "title": "retain the resolution disagreement",
                                "capability": "resource-resolution-disagreement",
                                "successCriteria": ["coordinator replay proves the mismatch"],
                            },
                            {
                                "title": "cross the tenant boundary",
                                "capability": "cross-tenant-private-read",
                                "requires": ["resource-resolution-disagreement"],
                                "successCriteria": ["independent owner readback proves disclosure"],
                            },
                        ],
                    }
                ],
                "workerContinuation": {
                    "sessionId": "session-1",
                    "state": "blocked",
                    "hypothesis": "the mismatch can select another tenant's record",
                    "competingExplanations": ["the response is a public artifact"],
                    "eliminatedMechanisms": ["error-page substitution"],
                    "blocker": "second owned tenant fixture is missing",
                    "nextExperiment": "create the second fixture and repeat one request",
                    "artifacts": ["evidence/runtime.json"],
                },
            }
        }
        update = ingest_submission(
            self.root,
            self.connection,
            task_id="task-1",
            worker_id="worker-1",
            result_path="results/task-1.json",
            result=result,
            validated_leads=[],
            maximum_confidence="coordinator-replayed",
        )
        self.assertEqual(len(update["observations"]), 1)
        self.assertEqual(len(update["chains"]), 1)
        self.assertEqual(len(update["plannerActions"]), 1)
        self.assertEqual(
            update["plannerActions"][0]["produces"], ["cross-tenant-private-read"]
        )
        matches = search_observations(self.connection, "checker consumer")
        self.assertEqual(matches[0]["confidence"], "coordinator-replayed")
        checkpoint = continuation_for_task(self.connection, "task-1")
        self.assertEqual(checkpoint["blocker"], "second owned tenant fixture is missing")
        self.assertEqual(steer_worker(self.connection, "task-1", "test the public-artifact control first"), 1)
        self.assertIn("public-artifact", continuation_for_task(self.connection, "task-1")["steerMessage"])
        state = status(self.connection)
        self.assertEqual(state["assets"]["consumer"], 1)
        self.assertEqual(state["coverage"]["verified"], 1)

    def test_graph_compaction_is_expandable_and_does_not_drop_members(self) -> None:
        observations = []
        for index in range(3):
            observations.append(
                {
                    "kind": "scoped-negative",
                    "mechanism": "same-refuted-family",
                    "summary": f"negative experiment {index}",
                    "confidence": "runtime-observed",
                    "state": "refuted",
                    "evidence": ["evidence/runtime.json"],
                }
            )
        ingest_submission(
            self.root,
            self.connection,
            task_id="task-negatives",
            worker_id="worker-2",
            result_path="results/task-negatives.json",
            result={"taskResult": {"observations": observations}},
            validated_leads=[],
        )
        digests = compact_graph(self.connection, minimum=3)
        self.assertEqual(len(digests), 1)
        digest = self.connection.execute(
            "SELECT * FROM depth_graph_digests WHERE digest_id=?", (digests[0],)
        ).fetchone()
        members = json.loads(digest["member_ids_json"])
        self.assertEqual(len(members), 3)
        retained = self.connection.execute(
            "SELECT COUNT(*) AS n FROM depth_observations WHERE digest_id=? AND state='compacted'",
            (digests[0],),
        ).fetchone()["n"]
        self.assertEqual(retained, 3)
        expanded = expand_digest(self.connection, digests[0])
        self.assertEqual(len(expanded["members"]), 3)
        search = search_observations(self.connection, "same-refuted-family")
        self.assertEqual(search[0]["kind"], "compacted-observation-digest")
        self.assertTrue(search[0]["losslessExpansion"])


if __name__ == "__main__":
    unittest.main()
