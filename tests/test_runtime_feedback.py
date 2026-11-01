from __future__ import annotations

import unittest

from scripts.runtime_feedback import decide


class RuntimeFeedbackTests(unittest.TestCase):
    def ir(self) -> dict:
        return {
            "securityPaths": [
                {
                    "id": "IR-P-1",
                    "status": "experiment-required",
                    "unknowns": ["dominance", "resource identity"],
                    "consumer": {"factId": "consumer-1"},
                }
            ]
        }

    def test_plateau_targets_unreached_security_consumer(self) -> None:
        result = decide(
            self.ir(),
            coverage={"coverage": {"plateauReached": True, "newEdges": 0}},
        )
        self.assertEqual(result["action"]["kind"], "change-harness-or-grammar")
        self.assertEqual(result["action"]["target"], "consumer-1")
        self.assertFalse(result["promotionAuthorized"])

    def test_native_fuzzer_nested_plateau_is_consumed(self) -> None:
        result = decide(
            self.ir(),
            coverage={
                "summary": {
                    "newEdges": 0,
                    "plateau": {"reached": True, "secondsWithoutNewEdge": 600},
                }
            },
        )
        self.assertEqual(result["action"]["kind"], "change-harness-or-grammar")

    def test_unique_replayed_crash_outranks_coverage(self) -> None:
        result = decide(
            self.ir(),
            coverage={"coverage": {"plateauReached": False, "newEdges": 12}},
            crashes=[
                {
                    "stack": {"clusterId": "SC-1"},
                    "minimizedSha256": "a" * 64,
                    "replayConfirmed": True,
                }
            ],
        )
        self.assertEqual(result["action"]["kind"], "minimize-and-independent-replay")
        self.assertEqual(result["action"]["target"], "SC-1")

    def test_native_forwarded_crash_contract_is_consumed(self) -> None:
        result = decide(
            self.ir(),
            crashes=[
                {
                    "externalCrashId": "external-1",
                    "forwarded": {
                        "confirmed": True,
                        "clusterId": "SC-native",
                        "minimized": {"sha256": "b" * 64, "path": "minimized.bin"},
                    },
                }
            ],
        )
        self.assertEqual(result["action"]["kind"], "minimize-and-independent-replay")
        self.assertEqual(result["action"]["target"], "SC-native")

    def test_missing_telemetry_requests_oracle_before_attack_task(self) -> None:
        result = decide(self.ir())
        self.assertEqual(result["action"]["kind"], "instrument-unreached-consumer")
        self.assertFalse(result["action"]["machineEvidence"])

    def test_web_inconclusive_auth_does_not_promote_or_use_crash_priority(self) -> None:
        ir = {"profile": "web-app", "web": {}, "experimentCandidates": []}
        result = decide(
            ir,
            crashes=[
                {
                    "stack": {"clusterId": "must-not-control-web-priority"},
                    "minimizedSha256": "a" * 64,
                    "replayConfirmed": True,
                }
            ],
            observations=[
                {
                    "outcome": "inconclusive",
                    "reason": "authentication-expiry-or-state",
                    "contractId": "web-1",
                }
            ],
        )
        self.assertEqual(result["action"]["kind"], "refresh-owned-auth-baseline")
        self.assertFalse(result["promotionAuthorized"])

    def test_web_sequence_oracle_result_drives_consistency_follow_up(self) -> None:
        ir = {"profile": "web-app", "web": {}, "experimentCandidates": []}
        result = decide(
            ir,
            observations=[
                {
                    "kind": "krineon-web-sequence-execution",
                    "oracleResult": {
                        "outcome": "inconclusive",
                        "reason": "consistency-window-unresolved",
                        "oracleId": "revocation-state",
                    },
                }
            ],
        )
        self.assertEqual(
            result["action"]["kind"], "wait-approved-consistency-window"
        )


if __name__ == "__main__":
    unittest.main()
