from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.web_composition_search import initial_state, search, state_key, validate_goal
from scripts.web_contract import WebContractError
from tests.test_web_business_logic import PREREQUISITE, operation, state_oracle


EPOCH = "owned-fixture-epoch-1"


def fixture_graph() -> dict:
    normal = operation(
        "owner-read", "actor-a", "record-a", "actor-a", "owner-readback", []
    )
    consumer = operation(
        "b-reads-a", "actor-b", "record-a", "actor-a", "cross-owner-readback", []
    )
    consumer["requires"] = {
        "operator": "fact",
        "type": "approval",
        "ref": "approval:record-a",
        "expected": True,
        "evidence": ["normal workflow requires an active approval"],
    }
    own = operation(
        "b-own-read",
        "actor-b",
        "record-b",
        "actor-b",
        "nonowner-own-readback",
        ["owner-read"],
    )
    invalid = operation(
        "invalid-read",
        "actor-b",
        "missing-record",
        "actor-a",
        "invalid-readback",
        ["b-own-read"],
    )
    observer = operation(
        "terminal-owner-read",
        "actor-a",
        "record-a",
        "actor-a",
        "terminal-owner-readback",
        [],
    )
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-sequence-graph",
        "prerequisiteVersion": PREREQUISITE,
        "operations": [normal, own, invalid, consumer, observer],
        "plans": [
            {
                "id": "normal-plan",
                "histories": {
                    "normal": ["owner-read", "b-own-read", "invalid-read"],
                    "counterfactual": ["b-reads-a"],
                },
                "executionState": {
                    "actors": {},
                    "resources": {},
                    "producedValues": {},
                    "invalidatedValues": [],
                    "consumedValues": [],
                    "completedOperations": [],
                },
                "cost": {
                    "normal": {
                        "maxRequests": 1,
                        "maxSteps": 1,
                        "maxBytes": 4096,
                        "maxPolling": 0,
                        "maxEffects": 0,
                        "maxConcurrencyParticipants": 1,
                    },
                    "counterfactual": {
                        "maxRequests": 1,
                        "maxSteps": 1,
                        "maxBytes": 4096,
                        "maxPolling": 0,
                        "maxEffects": 0,
                        "maxConcurrencyParticipants": 1,
                    },
                },
            }
        ],
    }


def goal() -> dict:
    return {
        "schemaVersion": 1,
        "prerequisiteVersion": PREREQUISITE,
        "id": "owned-cross-account-read",
        "title": "Actor B must not read actor A's record without approval",
        "compositionFamily": "approval-then-mutation",
        "normalPlanId": "normal-plan",
        "legitimateReplay": {
            "status": "confirmed",
            "observationEpoch": EPOCH,
            "beforeStateEvidence": ["evidence/normal-before.json"],
            "afterStateEvidence": ["evidence/normal-after.json"],
            "policyEvidence": ["owned fixture policy"],
        },
        "forbiddenTerminal": {
            "consumerOperationId": "b-reads-a",
            "observerOperationId": "terminal-owner-read",
            "prohibitedEffect": "actor B reads actor A's private record",
            "policyBasis": "owned fixture owner isolation rule",
            "attackerActorRef": "actor-b",
            "observerActorRef": "actor-a",
            "resourceId": "record-a",
            "tenant": "actor-a",
            "owner": "actor-a",
            "version": "v1",
            "generation": "g1",
            "action": "read",
            "observationEpoch": EPOCH,
        },
        "startingAuthority": {
            "actorRefs": ["actor-b"],
            "observerActorRefs": ["actor-a"],
            "resources": [
                {
                    "id": "record-a",
                    "tenant": "actor-a",
                    "owner": "actor-a",
                    "version": "v1",
                    "generation": "g1",
                    "relationship": "not-approved",
                    "observationEpoch": EPOCH,
                    "owned": True,
                }
            ],
            "serverValueRefs": [],
            "capabilityRefs": [],
            "invalidatedValueRefs": [],
            "consumptionCounts": {},
            "permissionVersions": {"actor-b": "application-permissions-v1"},
            "sessionRefreshVersions": {"actor-b": "session-refresh-v1"},
        },
        "candidateOperationIds": ["b-reads-a"],
        "operationSemantics": {
            "b-reads-a": {
                "attackerCanAttempt": True,
                "referencePolicy": "forbidden",
                "observationEpoch": EPOCH,
                "evidence": ["route observed in owned normal workflow"],
                "resourceTransitions": [],
                "permissionTransitions": [],
            }
        },
        "historyChange": {
            "kind": "omitted-prerequisite",
            "operationId": "b-reads-a",
            "reference": "approval:record-a",
        },
        "controlHistories": [
            {
                "id": "remove-disputed-operation",
                "purpose": "remove-disputed-binding",
                "disputedBinding": "approval:record-a",
                "operationIds": ["owner-read", "b-own-read", "invalid-read"],
                "expectedObservation": "normal isolation controls remain enforced",
            }
        ],
        "competingExplanations": [
            {
                "id": "H1",
                "statement": "the approval check is omitted",
                "expectedObservations": ["cross-owner body matches owner body"],
            },
            {
                "id": "H2",
                "statement": "the response is an error-page artifact",
                "expectedObservations": ["invalid control has the same body"],
            },
        ],
        "primitiveContributions": [],
        "stateOracle": state_oracle(),
        "counterfactualExceptions": {
            "unsatisfiedRequirementRefs": ["approval:record-a"],
            "invalidatedValueRefs": [],
            "replayedValueRefs": [],
        },
        "approvedLimits": {
            "maxPathLength": 8,
            "maxExecutionsPerOperation": 2,
            "maxRequests": 16,
            "maxPolling": 4,
            "maxWallSeconds": 60,
            "maxStateChangingEffects": 4,
            "maxFrontierStates": 500,
            "allowConcurrency": False,
        },
        "reviewedBudgetExtension": None,
        "priorOutcomes": [],
        "independentReplayRequirements": {
            "rebuildDisposableFixtures": True,
            "freshCredentialBindings": True,
            "replayEntireMinimalSequence": True,
            "rejectCopiedTerminalResponse": True,
            "rejectPrepopulatedState": True,
            "rejectStaleApproval": True,
            "rejectPrivateEvaluatorResource": True,
            "minimumIndependentReviewers": 1,
            "legitimateOtherActorActions": ["actor-a owns record-a"],
            "victimInteraction": "owned actor-a performs the normal read",
        },
    }


class ForbiddenCompositionSearchTests(unittest.TestCase):
    def test_search_finds_minimal_goal_directed_history(self) -> None:
        result = search(fixture_graph(), goal())
        self.assertFalse(result["search"]["arbitraryPermutationSearch"])
        self.assertEqual(result["backwardRelevantOperationIds"], ["b-reads-a"])
        self.assertEqual(result["plans"][0]["attackerSequence"], ["b-reads-a"])
        self.assertEqual(
            result["plans"][0]["histories"]["counterfactual"],
            [
                "owner-read",
                "b-own-read",
                "invalid-read",
                "b-reads-a",
                "terminal-owner-read",
            ],
        )
        self.assertEqual(result["plans"][0]["mechanismScope"], "single-step")
        self.assertEqual(result["experimentCandidates"][0]["executableOracle"], "owner-isolation")
        self.assertEqual(result["fixedExecutionCost"]["pathLength"], 4)

    def test_unrelated_operations_do_not_enter_backward_frontier(self) -> None:
        graph = fixture_graph()
        graph["operations"].append(
            operation("unrelated", "actor-b", "record-b", "actor-b", "other", [])
        )
        result = search(graph, goal())
        self.assertNotIn("unrelated", result["backwardRelevantOperationIds"])

    def test_typed_prerequisite_discovers_compatible_producer_without_candidate_hint(self) -> None:
        graph = fixture_graph()
        producer = operation(
            "issue-read-token",
            "actor-b",
            "record-a",
            "actor-a",
            "token-issued",
            [],
        )
        producer["produces"] = [
            {
                "id": "server-token:record-a",
                "kind": "server-value",
                "provenance": "owned fixture response",
                "actorBinding": "actor-b",
                "resourceBinding": "record-a",
                "version": "v1",
                "transferPolicy": "same-actor",
                "transferEvidence": [],
                "issuer": "actor-b",
                "intendedConsumer": "actor-b",
                "expiryPolicy": "operation-bounded",
                "expiryValue": None,
                "singleUse": False,
                "lifecycleExplicit": True,
            }
        ]
        graph["operations"].append(producer)
        consumer = next(
            item for item in graph["operations"] if item["id"] == "b-reads-a"
        )
        consumer["requires"] = {
            "operator": "and",
            "clauses": [
                {
                    "operator": "fact",
                    "type": "server-value",
                    "ref": "server-token:record-a",
                    "expected": True,
                    "evidence": ["normal route requires a server-issued token"],
                },
                {
                    "operator": "fact",
                    "type": "approval",
                    "ref": "approval:record-a",
                    "expected": True,
                    "evidence": ["normal workflow requires approval"],
                },
            ],
        }
        value = goal()
        value["operationSemantics"]["issue-read-token"] = {
            "attackerCanAttempt": True,
            "referencePolicy": "allowed",
            "observationEpoch": EPOCH,
            "evidence": ["owned fixture normal route"],
            "resourceTransitions": [],
            "permissionTransitions": [],
        }
        result = search(graph, value)
        self.assertIn("issue-read-token", result["backwardRelevantOperationIds"])
        self.assertNotIn("issue-read-token", value["candidateOperationIds"])
        self.assertEqual(
            result["plans"][0]["attackerSequence"],
            ["issue-read-token", "b-reads-a"],
        )

    def test_consumed_value_preserves_resource_and_version_compatibility(self) -> None:
        def value(version: str) -> dict:
            return {
                "id": "server-token:record-a",
                "kind": "server-value",
                "provenance": "owned fixture response",
                "actorBinding": "actor-b",
                "resourceBinding": "record-a",
                "version": version,
                "transferPolicy": "same-actor",
                "transferEvidence": [],
                "issuer": "actor-b",
                "intendedConsumer": "actor-b",
                "expiryPolicy": "operation-bounded",
                "expiryValue": None,
                "singleUse": False,
                "lifecycleExplicit": True,
            }

        graph = fixture_graph()
        producer = operation(
            "issue-read-token",
            "actor-b",
            "record-a",
            "actor-a",
            "token-issued",
            [],
        )
        producer["produces"] = [value("v1")]
        graph["operations"].append(producer)
        consumer = next(
            item for item in graph["operations"] if item["id"] == "b-reads-a"
        )
        consumer["consumes"] = [value("v1")]
        goal_value = goal()
        goal_value["operationSemantics"]["issue-read-token"] = {
            "attackerCanAttempt": True,
            "referencePolicy": "allowed",
            "observationEpoch": EPOCH,
            "evidence": ["owned fixture normal route"],
            "resourceTransitions": [],
            "permissionTransitions": [],
        }
        compatible = search(graph, goal_value)
        self.assertEqual(
            compatible["plans"][0]["attackerSequence"],
            ["issue-read-token", "b-reads-a"],
        )

        producer["produces"] = [value("v2")]
        incompatible = search(graph, goal_value)
        self.assertEqual(incompatible["plans"], [])

    def test_incompatible_generation_cannot_be_composed(self) -> None:
        value = goal()
        value["startingAuthority"]["resources"][0]["generation"] = "g2"
        result = search(fixture_graph(), value)
        self.assertEqual(result["plans"], [])

    def test_operation_from_another_epoch_is_rejected(self) -> None:
        value = goal()
        value["operationSemantics"]["b-reads-a"]["observationEpoch"] = "other-run"
        with self.assertRaisesRegex(WebContractError, "observation epochs"):
            search(fixture_graph(), value)

    def test_unattemptable_operation_is_not_scheduled(self) -> None:
        value = goal()
        value["operationSemantics"]["b-reads-a"]["attackerCanAttempt"] = False
        result = search(fixture_graph(), value)
        self.assertEqual(result["plans"], [])

    def test_complete_experiment_budget_includes_controls_and_observer(self) -> None:
        value = goal()
        value["approvedLimits"]["maxPathLength"] = 4
        result = search(fixture_graph(), value)
        self.assertEqual(result["plans"], [])

    def test_changed_budget_requires_checkpoint_bound_review(self) -> None:
        graph = fixture_graph()
        value = goal()
        first = search(graph, value)
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "checkpoint.json"
            checkpoint.write_text(json.dumps(first), encoding="utf-8")
            value["approvedLimits"]["maxPathLength"] = 9
            with self.assertRaisesRegex(WebContractError, "reviewed budget extension"):
                search(graph, value, resume=first, resume_path=checkpoint)

    def test_state_identity_preserves_budgets_consumption_and_permissions(self) -> None:
        validated = validate_goal(goal(), fixture_graph())
        baseline = initial_state(validated)
        consumed = json.loads(json.dumps(baseline))
        consumed["consumptionCounts"]["one-time-token"] = 1
        permission_changed = json.loads(json.dumps(baseline))
        permission_changed["permissionVersions"]["actor-b"] = "application-permissions-v2"
        budget_changed = json.loads(json.dumps(baseline))
        budget_changed["remaining"]["requests"] -= 1
        self.assertNotEqual(state_key(baseline), state_key(consumed))
        self.assertNotEqual(state_key(baseline), state_key(permission_changed))
        self.assertNotEqual(state_key(baseline), state_key(budget_changed))

    def test_exact_scoped_refutation_suppresses_only_that_state(self) -> None:
        graph = fixture_graph()
        value = goal()
        first = search(graph, value)
        value["priorOutcomes"] = [
            {
                "outcome": "refuted",
                "stateKey": first["plans"][0]["searchStateKey"],
                "mechanism": "omitted approval",
                "input": "owned record-a fixture",
                "configuration": "owned local production fixture",
                "state": "not-approved generation g1",
                "prerequisiteVersion": PREREQUISITE,
                "evidence": ["evidence/refutation.json"],
            }
        ]
        second = search(graph, value)
        self.assertEqual(second["plans"], [])
        self.assertEqual(len(second["knowledge"]["exactRefutationsSuppressed"]), 1)


if __name__ == "__main__":
    unittest.main()
