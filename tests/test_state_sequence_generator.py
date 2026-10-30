from __future__ import annotations

import unittest

from scripts.state_sequence_generator import generate


class StateSequenceGeneratorTests(unittest.TestCase):
    def test_only_emits_state_valid_history_and_marks_required_pairs(self) -> None:
        result = generate(
            {
                "schemaVersion": 1,
                "initialState": "anonymous",
                "operations": [
                    {
                        "id": "login",
                        "from": "anonymous",
                        "to": "authenticated",
                        "authority": "user",
                        "ownership": "attacker session",
                        "invariant": "session stays tenant-bound",
                    },
                    {
                        "id": "prime",
                        "from": "authenticated",
                        "to": "primed",
                        "authority": "user",
                        "ownership": "attacker cache entry",
                        "invariant": "cache entry stays tenant-bound",
                    },
                    {
                        "id": "invalid-first",
                        "from": "primed",
                        "to": "victim-read",
                        "authority": "victim",
                        "ownership": "victim response",
                        "invariant": "victim does not consume attacker state",
                    },
                ],
                "requiredTransitionPairs": [
                    ["authenticated", "primed"],
                    ["primed", "victim-read"],
                ],
            },
            3,
        )
        full = next(row for row in result["sequences"] if len(row["operationIds"]) == 3)
        self.assertEqual(full["operationIds"], ["login", "prime", "invalid-first"])
        self.assertEqual(full["missingRequiredPairs"], [])
        self.assertTrue(all(row["historyPreserved"] for row in result["sequences"]))

    def test_repeated_allocate_release_tracks_object_generation(self) -> None:
        result = generate(
            {
                "schemaVersion": 1,
                "initialState": "free",
                "maxRepetitionsPerOperation": 2,
                "operations": [
                    {
                        "id": "allocate",
                        "from": "free",
                        "to": "allocated",
                        "authority": "allocator",
                        "ownership": "new object",
                        "invariant": "generation increases on reuse",
                        "instance": {"identity": "slot", "action": "allocate"},
                    },
                    {
                        "id": "release",
                        "from": "allocated",
                        "to": "free",
                        "authority": "allocator",
                        "ownership": "released object",
                        "invariant": "released generations cannot be reused as live",
                        "instance": {"identity": "slot", "action": "release"},
                    },
                ],
                "requiredTransitionPairs": [
                    ["free", "allocated"],
                    ["allocated", "free"],
                ],
            },
            3,
        )
        reused = next(
            row
            for row in result["sequences"]
            if row["operationIds"] == ["allocate", "release", "allocate"]
        )
        self.assertEqual(reused["finalInstances"]["slot"]["generation"], 2)
        self.assertEqual(reused["finalInstances"]["slot"]["state"], "allocated")
        self.assertTrue(all(step["changed"] for step in reused["instanceHistory"]))

    def test_controlled_interleavings_respect_explicit_partial_order(self) -> None:
        result = generate(
            {
                "schemaVersion": 1,
                "initialState": "ready",
                "operations": [
                    {
                        "id": "publish",
                        "from": "ready",
                        "to": "ready",
                        "authority": "thread-a",
                        "ownership": "shared slot",
                        "invariant": "publication precedes consumption",
                        "thread": "A",
                    },
                    {
                        "id": "consume",
                        "from": "ready",
                        "to": "ready",
                        "authority": "thread-b",
                        "ownership": "shared slot",
                        "invariant": "consumer observes a published generation",
                        "thread": "B",
                        "happensAfter": ["publish"],
                    },
                ],
                "requiredTransitionPairs": [["ready", "ready"]],
            },
            2,
        )
        self.assertFalse(
            any(row["operationIds"][0] == "consume" for row in result["sequences"])
        )
        ordered = next(
            row
            for row in result["sequences"]
            if row["operationIds"] == ["publish", "consume"]
        )
        self.assertEqual(ordered["threads"], ["A", "B"])


if __name__ == "__main__":
    unittest.main()
