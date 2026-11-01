from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.research_harness import (
    complete_profile_experiment_frontier,
    connect_orchestration,
    scoped_negative_matches_experiment,
)
from scripts.web_hypothesis_loop import (
    derive_prerequisite_version,
    plan,
)
from scripts.web_oracles import admit_contract, evaluate_contract
from scripts.web_contract import WebContractError


def oracle(oracle_id: str) -> dict:
    return {
        "schemaVersion": 1,
        "id": oracle_id,
        "kind": "tenant-isolation",
        "claim": "actor A cannot read actor B's owned resource",
        "requiredObservations": [
            {"step": "baseline", "field": "response.bodySha256"},
            {"step": "negative", "field": "response.bodySha256"},
            {"step": "positive", "field": "response.bodySha256"},
        ],
        "assertions": [
            {
                "id": "baseline-ok",
                "role": "baseline-control",
                "operator": "equals",
                "left": {"step": "baseline", "field": "response.status"},
                "right": {"literal": 200},
                "expected": True,
            },
            {
                "id": "negative-blocked",
                "role": "enforcing-negative",
                "operator": "equals",
                "left": {"step": "negative", "field": "response.status"},
                "right": {"literal": 403},
                "expected": True,
            },
            {
                "id": "positive-isolated",
                "role": "positive-invariant",
                "operator": "not-equals",
                "left": {"step": "positive", "field": "response.bodySha256"},
                "right": {"step": "baseline", "field": "response.bodySha256"},
                "expected": True,
            },
        ],
        "evidenceRequirements": [
            {
                "purpose": "compare independently owned resource bodies",
                "selectors": [
                    {"step": "baseline", "field": "response.bodySha256"},
                    {"step": "positive", "field": "response.bodySha256"},
                ],
            }
        ],
    }


class WebHypothesisLoopTests(unittest.TestCase):
    def prerequisite_input(self) -> dict:
        return {
            "deploymentObservations": {
                "deploymentId": "owned-staging",
                "release": "1.2.3",
                "buildDigest": "a" * 64,
                "observationEpoch": "epoch-7",
            },
            "workflowContract": {
                "schemaVersion": 2,
                "contractSha256": "b" * 64,
                "workflowVersion": "wf-3",
            },
            "transportConfiguration": {
                "protocol": "http/1.1",
                "proxyChain": ["owned-edge", "owned-origin"],
                "tlsMode": "owned-fixture-http",
                "cacheLayer": "none",
                "browserEngine": "chrome-stable",
            },
            "identityCapabilityVersion": "identities-v2",
            "resourceFixtureVersion": "resources-v4",
        }

    def make_contract(
        self, root: Path, prerequisite: str, suffix: str
    ) -> dict:
        workflow = {
            "schemaVersion": 1,
            "id": f"workflow-{suffix}",
            "prerequisiteVersion": prerequisite,
            "steps": [
                {
                    "id": "baseline",
                    "identityId": "actor-b",
                    "effectClass": "read-only",
                    "resource": {"id": "resource-b"},
                },
                {
                    "id": "negative",
                    "identityId": "actor-a",
                    "effectClass": "read-only",
                    "resource": {"id": "resource-a"},
                },
                {
                    "id": "positive",
                    "identityId": "actor-a",
                    "effectClass": "read-only",
                    "resource": {"id": "resource-b"},
                },
            ],
            "cleanupSteps": [],
            "oracles": [oracle(f"oracle-{suffix}")],
        }
        workflow_path = root / f"workflow-{suffix}.json"
        workflow_path.write_text(json.dumps(workflow), encoding="utf-8")
        signature = root / f"workflow-{suffix}.json.sig"
        signature.write_text("test-signature", encoding="utf-8")
        campaign_contract = root / "web-campaign.json"
        campaign_contract.write_text("{}", encoding="utf-8")
        import hashlib

        workflow_sha = hashlib.sha256(workflow_path.read_bytes()).hexdigest()
        return {
            "schemaVersion": 1,
            "kind": "web-typed",
            "id": f"contract-{suffix}",
            "contractType": "http-differential",
            "registeredRunner": "krineon-http-broker-v1",
            "prerequisiteVersion": prerequisite,
            "workflowBinding": {
                "workflow": workflow_path.name,
                "signature": signature.name,
                "campaignContract": campaign_contract.name,
                "workflowSha256": workflow_sha,
            },
            "approvedActionSequence": ["baseline", "negative", "positive"],
            "actorFixtures": ["actor-a", "actor-b"],
            "resourceFixtures": ["resource-a", "resource-b"],
            "secretReferences": ["secret://actor-a", "secret://actor-b"],
            "budgets": {
                "maxOperations": 3,
                "maxRequests": 3,
                "maxEffects": 0,
                "maxWallSeconds": 30,
                "cleanupReservedRequests": 0,
            },
            "cases": [
                {"id": "c1", "role": "baseline", "steps": ["baseline"]},
                {
                    "id": "c2",
                    "role": "enforcing-negative",
                    "steps": ["negative"],
                },
                {"id": "c3", "role": "positive", "steps": ["positive"]},
            ],
            "assertion": {
                "engine": "krineon-web-oracle-v1",
                "oracleId": f"oracle-{suffix}",
            },
            "cleanup": {
                "required": False,
                "steps": [],
                "successPredicate": "read-only sequence has no persistent state",
            },
            "independentReplay": {
                "freshIdentityRequired": True,
                "freshResourceRequired": True,
                "prerequisites": ["new owned resource pair"],
            },
            "evidenceOutputs": ["observation.json", "budget-ledger.json"],
            "causalModel": {
                "kind": "isolated-variable",
                "variable": "request actor identity",
            },
            "experimentalScope": {
                "mechanism": f"tenant-resource-selection-{suffix}",
                "relevantInputs": ["actor identity", "resource id"],
                "configuration": ["owned staging"],
                "state": ["resource owned by actor-b"],
                "prerequisiteVersion": prerequisite,
            },
        }

    def hypothesis(self, contract: dict, suffix: str) -> dict:
        return {
            "id": f"H-{suffix}",
            "title": f"Owned resource isolation {suffix}",
            "observedBehavior": {
                "summary": "the API returned a resource under an alternate actor history",
                "confidence": "observed",
                "evidence": [f"observation-{suffix}.json"],
            },
            "securityInvariant": {
                "statement": f"actor A cannot read actor B resource through {suffix}",
                "basis": "owned fixture authorization contract",
            },
            "attackerStartingAuthority": "ordinary self-registered actor A",
            "setup": {
                "ownedActors": ["actor-a", "actor-b"],
                "ownedResources": ["resource-a", "resource-b"],
                "exactState": ["resource-b belongs to actor-b"],
            },
            "competingExplanations": [
                {
                    "id": "H1",
                    "statement": "authorization and resource selection disagree",
                    "expectedObservations": ["actor-a receives resource-b body"],
                },
                {
                    "id": "H2",
                    "statement": "the response is a public or error artifact",
                    "expectedObservations": ["owned resource discriminator is absent"],
                },
            ],
            "ranking": {
                "meaningfulImpact": 4,
                "constraintsRemoved": 4,
                "primitiveCompatibility": 3,
                "discrimination": 5,
                "attackerAcquisition": 5,
                "cost": 1,
                "cleanupRisk": 0,
            },
            "experiment": {
                "question": "Do authorization and resource selection bind the same owner?",
                "operationSequence": [
                    {
                        "id": "baseline",
                        "type": "http",
                        "actor": "actor-b",
                        "resource": "resource-b",
                        "effectClass": "read-only",
                    },
                    {
                        "id": "negative",
                        "type": "http",
                        "actor": "actor-a",
                        "resource": "unknown-resource",
                        "effectClass": "read-only",
                    },
                    {
                        "id": "positive",
                        "type": "http",
                        "actor": "actor-a",
                        "resource": "resource-b",
                        "effectClass": "read-only",
                    },
                ],
                "effectBudget": {
                    "maxOperations": 3,
                    "maxRequests": 3,
                    "maxEffects": 0,
                },
                "cases": {
                    "baseline": {"purpose": "owner read", "steps": ["baseline"]},
                    "enforcingNegative": {
                        "purpose": "invalid resource rejected",
                        "steps": ["negative"],
                    },
                    "positive": {
                        "purpose": "cross-owner discriminator",
                        "steps": ["positive"],
                    },
                },
                "observations": [
                    "response body digest",
                    "actor identity",
                    "selected resource identity",
                ],
                "oracle": "compare owned body digests and selected resource identities",
                "falsifier": "positive case does not expose the owner body discriminator",
                "uncertainty": ["selected resource identity"],
                "cleanup": {"required": False, "steps": []},
                "independentReplay": {
                    "freshIdentityRequired": True,
                    "freshResourceRequired": True,
                },
                "reopeningConditions": ["deployment or fixture version changes"],
                "experimentalScope": dict(contract["experimentalScope"]),
                "executableOracle": contract,
            },
        }

    def test_typed_oracle_has_three_valued_outcomes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prerequisite = derive_prerequisite_version(self.prerequisite_input())["id"]
            contract = admit_contract(root, self.make_contract(root, prerequisite, "one"))
            observation = {
                "workflowId": "workflow-one",
                "prerequisiteVersion": prerequisite,
                "runState": "completed",
                "cleanupErrors": [],
                "steps": [
                    {"id": "baseline", "response": {"status": 200, "bodySha256": "owned"}},
                    {"id": "negative", "response": {"status": 403, "bodySha256": "denied"}},
                    {"id": "positive", "response": {"status": 200, "bodySha256": "owned"}},
                ],
            }
            result = evaluate_contract(contract, observation)
            self.assertEqual(result["outcome"], "confirmed-disagreement")
            observation["runState"] = "auth-inconclusive"
            self.assertEqual(
                evaluate_contract(contract, observation)["outcome"], "inconclusive"
            )

    def test_worker_executable_and_token_material_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            document = self.prerequisite_input()
            prerequisite = derive_prerequisite_version(document)["id"]
            contract = self.make_contract(root, prerequisite, "reject")
            contract["executablePath"] = "/tmp/worker-selected"
            with self.assertRaisesRegex(WebContractError, "cannot select executable"):
                admit_contract(root, contract)
            document["identityCapabilityVersion"] = {
                "version": "v2",
                "accessToken": "must-not-enter-version",
            }
            with self.assertRaisesRegex(WebContractError, "token or credential"):
                derive_prerequisite_version(document)

    def test_unchanged_graph_advances_after_first_experiment_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tasks").mkdir()
            document = self.prerequisite_input()
            prerequisite = derive_prerequisite_version(document)["id"]
            first = self.make_contract(root, prerequisite, "first")
            second = self.make_contract(root, prerequisite, "second")
            document.update(
                {
                    "runId": "adaptive-test",
                    "hypotheses": [
                        self.hypothesis(first, "first"),
                        self.hypothesis(second, "second"),
                    ],
                    "webFacts": [
                        {
                            "id": "browser-op-1",
                            "kind": "browser-operation",
                            "confidence": "observed",
                            "actorId": "actor-a",
                            "resourceId": "resource-a",
                            "operation": "navigate",
                            "observationEpoch": "epoch-7",
                            "ownedIdentity": "actor-a",
                            "observationReference": "cdp:event:19",
                        }
                    ],
                    "webRelations": [],
                }
            )
            input_path = root / "hypotheses.json"
            input_path.write_text(json.dumps(document), encoding="utf-8")
            first_plan = plan(root, input_path, None)
            self.assertIsNotNone(first_plan["scheduledTask"])
            running = next(row for row in first_plan["frontier"] if row["state"] == "running")
            connection = connect_orchestration(root)
            try:
                complete_profile_experiment_frontier(
                    connection,
                    frontier_id=running["frontierId"],
                    normalized_outcome={
                        "outcome": "inconclusive",
                        "reason": "authentication-expiry-or-state",
                        "cleanupComplete": True,
                    },
                    broker_evidence_verified=False,
                )
                connection.commit()
            finally:
                connection.close()
            second_plan = plan(root, input_path, None)
            self.assertTrue(second_plan["unchanged"])
            self.assertIsNotNone(second_plan["scheduledTask"])
            self.assertNotEqual(first_plan["scheduledTask"], second_plan["scheduledTask"])
            self.assertEqual(
                sum(row["state"] == "inconclusive" for row in second_plan["frontier"]),
                1,
            )
            self.assertEqual(
                sum(row["state"] == "running" for row in second_plan["frontier"]),
                1,
            )

    def test_scoped_preservation_matches_only_same_prerequisite_version(self) -> None:
        scope = {
            "mechanism": "owner-resource-binding",
            "relevantInputs": ["actor", "resource"],
            "configuration": ["owned staging"],
            "state": ["resource belongs to actor-b"],
            "prerequisiteVersion": "web-prereq-v1-same",
        }
        experiment = {"consumer": "WM-1", "experimentalScope": scope}
        negative = {
            "consumer": "WM-1",
            "experimentalScope": dict(scope),
            "reopeningConditions": ["version or state changes"],
        }
        self.assertTrue(scoped_negative_matches_experiment(experiment, negative))
        negative["experimentalScope"] = {
            **scope,
            "prerequisiteVersion": "web-prereq-v1-different",
        }
        self.assertFalse(scoped_negative_matches_experiment(experiment, negative))


if __name__ == "__main__":
    unittest.main()
