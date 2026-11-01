from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.web_composition_search import search
from scripts.web_contract import WebContractError
from scripts.web_sequence_evidence import digest, verify_replay
from scripts.web_sequence_executor import evaluate_async_wait
from scripts.web_sequence_planner import validate_operation
from tests.test_web_business_logic import operation
from tests.test_web_composition_search import fixture_graph, goal


class WebSequenceEvidenceTests(unittest.TestCase):
    def specification(self) -> dict:
        return search(fixture_graph(), goal())["plans"][0]["sequenceSpecification"]

    def execution_result(
        self, specification: dict, *, run_id: str, evidence_hash: str
    ) -> dict:
        steps = {value["operationId"]: value for value in specification["steps"]}
        timeline = []
        for index, operation_id in enumerate(specification["histories"]["disputed"]):
            step = steps[operation_id]
            timeline.append(
                {
                    "operationId": operation_id,
                    "beforeStateSha256": f"before-{index}",
                    "afterStateSha256": f"after-{index}",
                    "observationIds": [value["id"] for value in step["observations"]],
                    "referenceExpectation": step["referenceExpectation"],
                    "implementationObservation": "predicate-satisfied",
                }
            )
        return {
            "schemaVersion": 1,
            "kind": "krineon-web-sequence-execution",
            "history": "disputed",
            "runId": run_id,
            "executedOperationIds": specification["histories"]["disputed"],
            "transitionTimeline": timeline,
            "oracleResult": {"outcome": "confirmed-disagreement"},
            "cleanupComplete": True,
            "runnerEvidenceHashes": [evidence_hash],
            "sequenceSpecificationSha256": digest(specification),
        }

    def test_sequence_specification_retains_required_causal_evidence(self) -> None:
        specification = self.specification()
        self.assertEqual(specification["kind"], "krineon-web-sequence-specification")
        self.assertTrue(specification["histories"]["legitimate"])
        self.assertTrue(specification["histories"]["disputed"])
        self.assertTrue(specification["histories"]["controls"])
        self.assertGreaterEqual(len(specification["competingExplanations"]), 2)
        self.assertTrue(specification["independentReplayRequirements"]["freshCredentialBindings"])
        self.assertIn("sessionRefreshVersion", specification["verifiedContext"]["actors"][0])
        self.assertIn("permissionVersion", specification["verifiedContext"]["actors"][0])

    def test_reauthentication_cannot_restore_application_permission(self) -> None:
        value = operation("reauth", "actor-b", "record-b", "actor-b", "reauth-state", [])
        value["identityTransition"] = {
            "kind": "reauthenticate",
            "fromSessionRefreshVersion": "session-refresh-v1",
            "toSessionRefreshVersion": "session-refresh-v2",
            "permissionVersionBefore": "application-permissions-v1",
            "permissionVersionAfter": "application-permissions-v2",
            "startingConditionsReestablished": True,
            "evidence": ["owned reauthentication flow"],
        }
        with self.assertRaisesRegex(WebContractError, "cannot restore or alter"):
            validate_operation(value)
        value["identityTransition"]["permissionVersionAfter"] = "application-permissions-v1"
        normalized = validate_operation(value)
        self.assertEqual(
            normalized["identityTransition"]["toSessionRefreshVersion"],
            "session-refresh-v2",
        )

    def test_async_boundary_requires_observed_predicate_and_is_inconclusive_when_unfinished(self) -> None:
        value = operation("job-read", "actor-b", "record-b", "actor-b", "job-state", [])
        value["ordering"]["asyncBoundary"] = True
        value["cost"]["maxPolling"] = 2
        value["produces"] = [
            {
                "id": "owned-job-1",
                "kind": "job",
                "provenance": "broker-observation:job-state",
                "actorBinding": "actor-b",
                "resourceBinding": "record-b",
                "version": "job-v1",
                "transferPolicy": "same-actor",
                "transferEvidence": [],
                "issuer": "owned-job-service",
                "intendedConsumer": "actor-b",
                "expiryPolicy": "operation-bounded",
                "expiryValue": None,
                "singleUse": True,
            }
        ]
        value["observations"][0]["stateSelectors"].update(
            {"jobState": "response.json.state", "pollAttempts": "response.json.attempts"}
        )
        with self.assertRaisesRegex(WebContractError, "asyncWait"):
            validate_operation(value)
        value["asyncWait"] = {
            "mode": "bounded-poll",
            "observationId": "job-state",
            "stateField": "jobState",
            "attemptsField": "pollAttempts",
            "operator": "equals",
            "expected": "complete",
            "maxPolls": 2,
            "retryPolicy": "fixed-bounded",
            "evidence": ["owner-supported asynchronous completion policy"],
        }
        normalized = validate_operation(value)
        complete, reason = evaluate_async_wait(
            normalized,
            [
                {
                    "id": "job-state",
                    "state": {"jobState": "pending", "pollAttempts": 2},
                }
            ],
        )
        self.assertFalse(complete)
        self.assertEqual(reason, "inaccessible-business-state")

    def test_independent_replay_requires_fresh_fixture_credentials_and_evidence(self) -> None:
        original_spec = self.specification()
        replay_spec = copy.deepcopy(original_spec)
        replay_spec["sequenceId"] = original_spec["sequenceId"] + "-replay"
        for actor in replay_spec["verifiedContext"]["actors"]:
            actor["sessionRefreshVersion"] += "-fresh"
        replay_actor_versions = {
            value["id"]: value["sessionRefreshVersion"]
            for value in replay_spec["verifiedContext"]["actors"]
        }
        replay_spec["verifiedContext"]["initialAuthority"][
            "sessionRefreshVersions"
        ] = dict(replay_actor_versions)
        for step in replay_spec["steps"]:
            step["actor"]["sessionRefreshVersion"] = replay_actor_versions[
                step["actor"]["id"]
            ]
        for fixture in replay_spec["verifiedContext"]["fixtures"]:
            fixture["generation"] += "-fresh"
        replay_fixture_generations = {
            value["id"]: value["generation"]
            for value in replay_spec["verifiedContext"]["fixtures"]
        }
        for step in replay_spec["steps"]:
            for resource in step["resources"]:
                resource["generation"] = replay_fixture_generations[resource["id"]]
        original_result = self.execution_result(
            original_spec, run_id="original-run", evidence_hash="a" * 64
        )
        replay_result = self.execution_result(
            replay_spec, run_id="replay-run", evidence_hash="b" * 64
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture.json"
            credential = root / "credential.json"
            fixture.write_text("fresh fixture generation", encoding="utf-8")
            credential.write_text("fresh credential binding", encoding="utf-8")
            attestation = {
                "schemaVersion": 1,
                "originatorIdentity": "worker-origin",
                "reviewerIdentity": "worker-reviewer",
                "copiedTerminalResponse": False,
                "prepopulatedServerState": False,
                "staleApprovalUsed": False,
                "privateEvaluatorResourceUsed": False,
                "legitimateOtherActorActions": ["actor-a owns record-a"],
                "victimInteraction": "owned actor-a performs the normal read",
                "fixtureRebuildEvidence": [
                    {
                        "path": "fixture.json",
                        "sha256": hashlib.sha256(fixture.read_bytes()).hexdigest(),
                    }
                ],
                "freshCredentialBindingEvidence": [
                    {
                        "path": "credential.json",
                        "sha256": hashlib.sha256(credential.read_bytes()).hexdigest(),
                    }
                ],
            }
            accepted = verify_replay(
                original_spec,
                original_result,
                replay_spec,
                replay_result,
                attestation,
                evidence_root=root,
            )
            self.assertTrue(accepted["accepted"])
            stale = copy.deepcopy(replay_spec)
            stale["verifiedContext"]["actors"][0]["sessionRefreshVersion"] = (
                original_spec["verifiedContext"]["actors"][0]["sessionRefreshVersion"]
            )
            stale_actor_id = stale["verifiedContext"]["actors"][0]["id"]
            stale["verifiedContext"]["initialAuthority"]["sessionRefreshVersions"][
                stale_actor_id
            ] = stale["verifiedContext"]["actors"][0]["sessionRefreshVersion"]
            for step in stale["steps"]:
                if step["actor"]["id"] == stale_actor_id:
                    step["actor"]["sessionRefreshVersion"] = stale[
                        "verifiedContext"
                    ]["actors"][0]["sessionRefreshVersion"]
            stale_result = copy.deepcopy(replay_result)
            stale_result["sequenceSpecificationSha256"] = digest(stale)
            with self.assertRaisesRegex(WebContractError, "reused a credential"):
                verify_replay(
                    original_spec,
                    original_result,
                    stale,
                    stale_result,
                    attestation,
                    evidence_root=root,
                )

            incomplete = copy.deepcopy(replay_result)
            incomplete["transitionTimeline"].pop()
            with self.assertRaisesRegex(WebContractError, "complete transition timeline"):
                verify_replay(
                    original_spec,
                    original_result,
                    replay_spec,
                    incomplete,
                    attestation,
                    evidence_root=root,
                )


if __name__ == "__main__":
    unittest.main()
