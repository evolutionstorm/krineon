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


if __name__ == "__main__":
    unittest.main()
