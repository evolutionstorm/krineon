from __future__ import annotations

import datetime as dt
import unittest

from scripts.web_business_logic import compile_business_logic
from scripts.web_contract import WebContractError
from scripts.web_sequence_planner import build_graph, validate_operation
from scripts.web_state_oracles import evaluate


PREREQUISITE = "web-prereq-owned-fixture-v1"


def state_oracle() -> dict:
    return {
        "schemaVersion": 1,
        "id": "owner-isolation",
        "family": "object-authorization",
        "claim": "actor B cannot read actor A's private record",
        "ruleBasis": "owned fixture authorization rule",
        "ruleBasisConfidence": "owner-specified",
        "prerequisiteVersion": PREREQUISITE,
        "consistencyWindowSeconds": 0,
        "requiredObservations": [
            "owner-readback",
            "nonowner-own-readback",
            "invalid-readback",
            "cross-owner-readback",
        ],
        "terminalObservations": ["cross-owner-readback"],
        "assertions": [
            {
                "id": "owner-control",
                "role": "baseline-control",
                "operator": "equals",
                "left": {"observation": "owner-readback", "field": "state.status"},
                "right": {"literal": 200},
                "expected": True,
            },
            {
                "id": "invalid-control",
                "role": "enforcing-negative",
                "operator": "equals",
                "left": {"observation": "invalid-readback", "field": "state.status"},
                "right": {"literal": 404},
                "expected": True,
            },
            {
                "id": "cross-owner-isolated",
                "role": "positive-invariant",
                "operator": "not-equals",
                "left": {
                    "observation": "cross-owner-readback",
                    "field": "state.bodySha256",
                },
                "right": {
                    "observation": "owner-readback",
                    "field": "state.bodySha256",
                },
                "expected": True,
            },
        ],
    }


def readback(
    observation_id: str,
    actor: str,
    resource: str,
    owner: str,
    status: int,
    body: str,
) -> dict:
    return {
        "id": observation_id,
        "kind": "authoritative-readback",
        "authenticatedActor": actor,
        "effectiveActor": actor,
        "resourceId": resource,
        "ownerId": owner,
        "tenantId": owner,
        "generation": "g1",
        "evidenceOrigin": "server-persisted-readback",
        "observedAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "state": {"status": status, "bodySha256": body},
        "authoritative": True,
        "evidence": [f"evidence/{observation_id}.json"],
    }


def operation(
    operation_id: str,
    actor: str,
    resource: str,
    owner: str,
    observation_id: str,
    after: list[str],
) -> dict:
    return {
        "id": operation_id,
        "actorRef": {
            "id": actor,
            "role": "member",
            "tenant": actor,
            "session": f"session-{actor}",
            "verified": True,
            "effectiveActor": actor,
            "capabilityVersion": "identities-v1",
            "sessionRefreshVersion": "session-refresh-v1",
            "permissionVersion": "application-permissions-v1",
        },
        "actionRef": {
            "runner": "krineon-http-broker-v1",
            "workflow": "web/owned-workflow.json",
            "signature": "web/owned-workflow.json.sig",
            "campaignContract": "web-campaign.json",
            "workflowId": "owned-workflow",
            "stepId": operation_id,
            "effectClass": "read-only",
        },
        "resourceBindings": [
            {
                "id": resource,
                "kind": "private-record",
                "parent": "root",
                "tenant": owner,
                "owner": owner,
                "version": "v1",
                "generation": "g1",
                "fixtureNamespace": "owned-business-fixture",
                "owned": True,
                "disposable": True,
            }
        ],
        "requires": {
            "operator": "fact",
            "type": "operation" if after else "state",
            "ref": after[-1] if after else "not-yet-read",
            "expected": True if after else False,
            "evidence": [],
        },
        "produces": [],
        "consumes": [],
        "invalidates": [],
        "authorityBinding": {
            "actor": actor,
            "resource": resource,
            "action": "read",
            "version": "v1",
        },
        "ordering": {
            "after": after,
            "before": [],
            "asyncBoundary": False,
            "sequencingHintOnly": False,
            "dependencyConfidence": "replay-confirmed",
            "evidence": ["owned normal workflow replay"],
        },
        "observations": [
            {
                "id": observation_id,
                "kind": "authoritative-readback",
                "authoritative": True,
                "evidenceOrigin": "server-response",
                "resourceBindingRef": resource,
                "stateSelectors": {
                    "status": "response.status",
                    "bodySha256": "response.bodySha256",
                },
            }
        ],
        "consistencyWindow": {
            "basis": "synchronous owned fixture",
            "maximumSeconds": 0,
        },
        "cleanup": {"hookRef": "none-read-only", "irreversible": False},
        "cost": {
            "maxRequests": 1,
            "maxSteps": 1,
            "maxBytes": 4096,
            "maxPolling": 0,
            "maxEffects": 0,
            "maxConcurrencyParticipants": 1,
        },
    }


class WebBusinessLogicTests(unittest.TestCase):
    def workflow_model(self) -> dict:
        return {
            "schemaVersion": 1,
            "kind": "krineon-web-workflow-model",
            "identityModel": [
                {"id": "actor-a", "tenant": "actor-a"},
                {"id": "actor-b", "tenant": "actor-b"},
            ],
            "resourceModel": [
                {"id": "record-a", "owner": "actor-a"},
                {"id": "record-b", "owner": "actor-b"},
            ],
            "workflowModel": [],
        }

    def rule_document(self) -> dict:
        return {
            "schemaVersion": 1,
            "prerequisiteVersion": PREREQUISITE,
            "rules": [
                {
                    "id": "private-record-owner-rule",
                    "title": "Private records remain owner-bound",
                    "family": "object-authorization",
                    "statement": "only the record owner can read a private record",
                    "basis": "owned fixture policy",
                    "basisConfidence": "owner-specified",
                    "attackerStartingAuthority": "ordinary actor-b member",
                    "actors": ["actor-a", "actor-b"],
                    "resources": ["record-a", "record-b"],
                    "normalWorkflow": ["owner-read", "b-own-read", "invalid-read"],
                    "counterfactual": [
                        "owner-read",
                        "b-own-read",
                        "invalid-read",
                        "b-reads-a",
                    ],
                    "fixture": {
                        "owned": True,
                        "namespace": "owned-business-fixture",
                        "irreversible": False,
                        "disposable": True,
                        "factoryRef": "app:create-private-record-pair",
                        "readbackRef": "app:read-private-record",
                        "cleanupRef": "app:delete-private-record-pair",
                        "version": "fixture-v1",
                    },
                    "stateOracle": state_oracle(),
                }
            ],
        }

    def test_explicit_rule_builds_multi_actor_graph(self) -> None:
        business = compile_business_logic(self.workflow_model(), self.rule_document())
        operations = [
            operation("owner-read", "actor-a", "record-a", "actor-a", "owner-readback", []),
            operation(
                "b-own-read",
                "actor-b",
                "record-b",
                "actor-b",
                "nonowner-own-readback",
                ["owner-read"],
            ),
            operation(
                "invalid-read",
                "actor-b",
                "missing-record",
                "actor-a",
                "invalid-readback",
                ["b-own-read"],
            ),
            operation(
                "b-reads-a",
                "actor-b",
                "record-a",
                "actor-a",
                "cross-owner-readback",
                ["invalid-read"],
            ),
        ]
        graph = build_graph(
            {"schemaVersion": 1, "operationContracts": operations}, business
        )
        plan = graph["plans"][0]
        self.assertEqual(set(plan["executionState"]["actors"]), {"actor-a", "actor-b"})
        self.assertIn("record-a", plan["executionState"]["resources"])
        self.assertTrue(plan["executable"])
        self.assertTrue(
            all(edge["status"] == "replay-confirmed" for edge in graph["edges"])
        )
        self.assertTrue(graph["semanticIRAdapter"]["facts"])

    def test_state_oracle_confirms_only_with_authoritative_controls(self) -> None:
        document = {
            "prerequisiteVersion": PREREQUISITE,
            "runState": "completed",
            "cleanupComplete": True,
            "observations": [
                readback("owner-readback", "actor-a", "record-a", "actor-a", 200, "owned-a"),
                readback("nonowner-own-readback", "actor-b", "record-b", "actor-b", 200, "owned-b"),
                readback("invalid-readback", "actor-b", "missing", "actor-a", 404, "missing"),
                readback("cross-owner-readback", "actor-b", "record-a", "actor-a", 200, "owned-a"),
            ],
        }
        result = evaluate(state_oracle(), document)
        self.assertEqual(result["outcome"], "confirmed-disagreement")
        document["observations"][-1]["evidenceOrigin"] = "dom-only"
        result = evaluate(state_oracle(), document)
        self.assertEqual(result["outcome"], "inconclusive")
        self.assertFalse(result["promotionEligible"])

    def test_consistency_window_must_mature_after_authoritative_transition(self) -> None:
        started = dt.datetime.now(dt.timezone.utc)
        document = {
            "prerequisiteVersion": PREREQUISITE,
            "runState": "completed",
            "cleanupComplete": True,
            "observations": [
                readback("owner-readback", "actor-a", "record-a", "actor-a", 200, "owned-a"),
                readback("nonowner-own-readback", "actor-b", "record-b", "actor-b", 200, "owned-b"),
                readback("invalid-readback", "actor-b", "missing", "actor-a", 404, "missing"),
                readback("cross-owner-readback", "actor-b", "record-a", "actor-a", 200, "owned-a"),
            ],
        }
        document["observations"][0]["observedAt"] = started.isoformat()
        document["observations"][-1]["observedAt"] = (
            started + dt.timedelta(seconds=5)
        ).isoformat()
        oracle = {
            **state_oracle(),
            "family": "state-invalidation",
            "consistencyWindowSeconds": 30,
            "consistencyStartObservation": "owner-readback",
        }
        result = evaluate(oracle, document)
        self.assertEqual(result["outcome"], "inconclusive")
        self.assertEqual(result["reason"], "consistency-window-unresolved")
        document["observations"][-1]["observedAt"] = (
            started + dt.timedelta(seconds=31)
        ).isoformat()
        result = evaluate(oracle, document)
        self.assertEqual(result["outcome"], "confirmed-disagreement")

    def test_generic_or_irreversible_fixture_is_rejected(self) -> None:
        rules = self.rule_document()
        rules["rules"][0]["fixture"]["factoryRef"] = "generic-endpoint-mutation"
        with self.assertRaisesRegex(WebContractError, "not a fixture factory"):
            compile_business_logic(self.workflow_model(), rules)
        operation_value = operation(
            "owner-read", "actor-a", "record-a", "actor-a", "owner-readback", []
        )
        operation_value["cleanup"]["irreversible"] = True
        with self.assertRaisesRegex(WebContractError, "safe and reversible"):
            validate_operation(operation_value)

    def test_bounded_concurrency_is_planned_but_not_simulated_sequentially(self) -> None:
        rules = self.rule_document()
        rule = rules["rules"][0]
        rule["family"] = "bounded-concurrency"
        rule["pairedConcurrencyApproved"] = True
        rule["stateOracle"] = {**state_oracle(), "family": "bounded-concurrency"}
        business = compile_business_logic(self.workflow_model(), rules)
        operations = [
            operation(
                "sequential-baseline",
                "actor-a",
                "record-a",
                "actor-a",
                "baseline-readback",
                [],
            ),
            {
                **operation(
                    "paired-first",
                    "actor-a",
                    "record-a",
                    "actor-a",
                    "owner-readback",
                    [],
                ),
                "cost": {
                    **operation(
                        "cost-source-a",
                        "actor-a",
                        "record-a",
                        "actor-a",
                        "cost-observation-a",
                        [],
                    )["cost"],
                    "maxConcurrencyParticipants": 2,
                },
            },
            {
                **operation(
                    "paired-second",
                    "actor-b",
                    "record-b",
                    "actor-b",
                    "other-owner-readback",
                    [],
                ),
                "cost": {
                    **operation(
                        "cost-source-b",
                        "actor-b",
                        "record-b",
                        "actor-b",
                        "cost-observation-b",
                        [],
                    )["cost"],
                    "maxConcurrencyParticipants": 2,
                },
            },
        ]
        business["hypotheses"][0]["normalWorkflow"] = ["sequential-baseline"]
        business["hypotheses"][0]["counterfactual"] = [
            "sequential-baseline",
            "paired-first",
            "paired-second",
        ]
        graph = build_graph(
            {"schemaVersion": 1, "operationContracts": operations}, business
        )
        plan = graph["plans"][0]
        self.assertTrue(plan["executable"])
        self.assertIsNone(plan["blockedReason"])

    def test_counterfactual_prerequisite_exception_must_be_named(self) -> None:
        rules = self.rule_document()
        rule = rules["rules"][0]
        rule["family"] = "workflow-prerequisites"
        rule["stateOracle"] = {
            **state_oracle(),
            "family": "workflow-prerequisites",
        }
        with self.assertRaisesRegex(WebContractError, "intentionally omitted"):
            compile_business_logic(self.workflow_model(), rules)
        rule["counterfactualExceptions"] = {
            "unsatisfiedRequirementRefs": ["approval:owned-record"],
            "invalidatedValueRefs": [],
            "replayedValueRefs": [],
        }
        business = compile_business_logic(self.workflow_model(), rules)
        self.assertEqual(
            business["hypotheses"][0]["counterfactualExceptions"]
            ["unsatisfiedRequirementRefs"],
            ["approval:owned-record"],
        )


if __name__ == "__main__":
    unittest.main()
