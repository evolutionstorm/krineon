import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.campaign_intelligence import IntelligenceError, IntelligenceStore


class CampaignIntelligenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "campaign.json").write_text(
            json.dumps({"schemaVersion": 1, "target": "owned-fixture"}),
            encoding="utf-8",
        )
        self.source = self.root / "source"
        (self.source / "src").mkdir(parents=True)
        (self.source / "tests").mkdir()
        self.program = self.source / "src" / "dispatch.py"
        self.program.write_text(
            "def authorize(path):\n"
            "    return path.startswith('/public')\n\n"
            "def dispatch(path):\n"
            "    return open(path).read()\n",
            encoding="utf-8",
        )
        (self.source / "tests" / "test_dispatch.py").write_text(
            "def test_placeholder(): pass\n", encoding="utf-8"
        )
        (self.root / "evidence").mkdir()
        self.evidence = self.root / "evidence" / "observation.json"
        self.evidence.write_text('{"observed":true}\n', encoding="utf-8")
        self.artifact = self.root / "evidence" / "stage.json"
        self.artifact.write_text('{"stage":"complete"}\n', encoding="utf-8")
        self.store = IntelligenceStore(self.root)
        self.inventory = self.store.inventory_source(self.source)
        self.architecture = self.store.ingest_architecture(
            {
                "objects": [
                    {
                        "id": "public-entry",
                        "kind": "entrypoint",
                        "name": "HTTP request",
                        "confidence": "source-supported",
                        "attributes": {"protocol": "HTTP"},
                        "evidence": ["src/dispatch.py:1"],
                    },
                    {
                        "id": "file-consumer",
                        "kind": "consumer",
                        "name": "dispatch",
                        "confidence": "source-supported",
                        "attributes": {"authority": "filesystem-read"},
                        "evidence": ["src/dispatch.py:4"],
                    },
                ],
                "relations": [
                    {
                        "source": "public-entry",
                        "relation": "reaches",
                        "target": "file-consumer",
                        "conditions": ["authorize returns true"],
                        "evidence": ["src/dispatch.py"],
                    }
                ],
            }
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temporary.cleanup()

    def admit_location(self) -> str:
        location = self.store.admit_source_location(
            source_root=self.source,
            repository_revision="fixture-revision",
            path="src/dispatch.py",
            start_line=1,
            end_line=5,
            symbol="authorize-to-dispatch",
            admitted_by="coordinator-a",
        )
        return location["location_id"]

    def observation(self, kind: str, location_id: str, suffix: str, payload=None):
        evidence = self.root / "evidence" / f"{suffix}.json"
        evidence.write_text(json.dumps({"kind": kind, "suffix": suffix}), encoding="utf-8")
        return self.store.admit_observation(
            {
                "kind": kind,
                "mechanism": "path-check-consumer-disagreement",
                "confidence": {
                    "source": "source-supported",
                    "runtime-differential": "runtime-observed",
                    "coordinator-replay": "coordinator-replayed",
                    "independent-replay": "independently-replayed",
                }[kind],
                "producerRole": "researcher" if kind != "independent-replay" else "replayer",
                "producerIdentity": f"agent-{suffix}",
                "target": "dispatch",
                "sourceLocations": [location_id],
                "evidence": [evidence.relative_to(self.root).as_posix()],
                "payload": payload or {"observation": suffix},
            }
        )

    def test_architecture_source_coverage_and_pipeline_gates(self) -> None:
        self.assertEqual(self.inventory["files"], 2)
        self.assertEqual(self.inventory["productionFiles"], 1)
        self.assertEqual(self.architecture["objects"], 2)
        report = self.store.source_coverage_report()
        self.assertEqual(report["productionFiles"], 1)
        self.assertEqual(report["counts"]["unassigned"], 1)

        stage = self.store.start_stage("architecture", actor_role="architect")
        self.assertEqual(stage["state"], "running")
        self.store.complete_stage(
            "architecture", actor_role="architect", outcome="complete",
            reason="", artifacts=[],
        )
        self.store.start_stage("threat-model", actor_role="architect")
        self.store.complete_stage(
            "threat-model", actor_role="architect", outcome="complete",
            reason="", artifacts=["evidence/stage.json"],
        )
        self.store.start_stage("research-plan", actor_role="coordinator")
        with self.assertRaisesRegex(IntelligenceError, "not assigned"):
            self.store.complete_stage(
                "research-plan", actor_role="coordinator", outcome="complete",
                reason="", artifacts=["evidence/stage.json"],
            )
        self.store.mark_source_coverage(
            "src/dispatch.py",
            state="assigned",
            assignee="researcher-a",
            mechanisms=["path-check-consumer-disagreement"],
            boundaries=["authorization-to-filesystem"],
        )
        completed = self.store.complete_stage(
            "research-plan", actor_role="coordinator", outcome="complete",
            reason="", artifacts=["evidence/stage.json"],
        )
        self.assertEqual(completed["state"], "complete")
        self.assertEqual(self.store.pipeline_status()["current"], "research")

    def test_evidence_reconciliation_promotion_and_production_critic(self) -> None:
        location_id = self.admit_location()
        source = self.observation("source", location_id, "source")
        runtime = self.observation(
            "runtime-differential",
            location_id,
            "runtime",
            payload={
                "cases": {
                    "baseline": {"status": 403},
                    "negative": {"status": 403},
                    "positive": {"status": 200},
                }
            },
        )
        coordinator = self.observation("coordinator-replay", location_id, "coordinator")
        independent = self.observation("independent-replay", location_id, "independent")
        reconciled = self.store.reconcile(
            "path-check-consumer-disagreement", actor_identity="originator-a"
        )
        retained_source = self.store.observation(source["observation_id"])["evidence"][0]
        retained_path = self.root / retained_source["path"]
        retained_hash = retained_source["sha256"]
        (self.root / retained_source["sourcePath"]).write_text("changed after admission\n", encoding="utf-8")
        self.assertEqual(hashlib.sha256(retained_path.read_bytes()).hexdigest(), retained_hash)
        self.assertEqual(
            set(reconciled["evidence_classes"]),
            {"source", "runtime-differential", "coordinator-replay", "independent-replay"},
        )
        hypothesis_id = reconciled["candidate_hypothesis_id"]
        self.store.promote_hypothesis(
            hypothesis_id, "source-supported-mechanism",
            actor_identity="originator-a", reason="source path admitted",
        )
        self.store.promote_hypothesis(
            hypothesis_id, "runtime-differential",
            actor_identity="originator-a", reason="three-case differential retained",
        )
        self.store.promote_hypothesis(
            hypothesis_id, "verified-primitive",
            actor_identity="coordinator-a", reason="coordinator re-executed it",
        )
        capability = {
            "inputType": "normalized-path",
            "outputAuthority": "filesystem-read",
            "principal": "anonymous",
            "process": "owned-fixture",
            "runtime": "production",
            "acquisitionProof": coordinator["observation_id"],
            "deployment": "supported-release",
        }
        self.store.promote_hypothesis(
            hypothesis_id, "compatible-chain-edge",
            actor_identity="coordinator-a", reason="typed edge is compatible",
            capabilities=[capability],
        )
        terminal = self.store.promote_hypothesis(
            hypothesis_id, "complete-terminal",
            actor_identity="agent-independent", reason="fresh independent replay",
        )
        self.assertEqual(terminal["level"], "complete-terminal")
        self.assertIn(independent["observation_id"], terminal["observation_ids"])
        self.assertIn(runtime["observation_id"], terminal["observation_ids"])
        self.assertIn(source["observation_id"], terminal["observation_ids"])
        report_manifest = self.store.validate_report_manifest(
            {
                "hypothesisIds": [hypothesis_id],
                "sourceLocationIds": [location_id],
            },
            source_root=self.source,
        )
        self.assertTrue(report_manifest["valid"])
        self.assertIn("src/dispatch.py:1-5", report_manifest["sourceLocations"][0]["citation"])

        facts = {
            name: {"value": True, "evidence": ["evidence/observation.json"]}
            for name in (
                "supportedRelease", "shippedArtifact", "externalIngress",
                "productionEntrypoint", "optimizedBuild", "noDevOnlyDependency",
                "noArtificialSink", "remoteAcquisition", "simultaneousPreconditions",
            )
        }
        review = self.store.production_review(
            hypothesis_id,
            {
                "facts": facts,
                "conditions": ["owned production-equivalent fixture"],
                "evidence": ["evidence/observation.json"],
            },
            reviewer_identity="critic-b",
        )
        self.assertEqual(review["status"], "passed")
        adversarial = self.store.adversarial_review(
            hypothesis_id,
            {
                "status": "accepted",
                "hypothesisFailureMode": "the 200 response may be an error-page artifact",
                "observerFailureMode": "the observer may have read a stale marker",
                "challengedConditions": ["the positive response reaches dispatch"],
                "evidence": ["evidence/observation.json"],
            },
            reviewer_identity="reviewer-c",
        )
        self.assertEqual(adversarial["status"], "accepted")
        with self.assertRaisesRegex(IntelligenceError, "different identity"):
            self.store.production_review(
                hypothesis_id,
                {"facts": facts, "conditions": [], "evidence": ["evidence/observation.json"]},
                reviewer_identity="originator-a",
            )
        with self.assertRaisesRegex(IntelligenceError, "different identity"):
            self.store.adversarial_review(
                hypothesis_id,
                {
                    "status": "inconclusive",
                    "hypothesisFailureMode": "unknown",
                    "observerFailureMode": "unknown",
                    "challengedConditions": ["dispatch reachability"],
                    "evidence": ["evidence/observation.json"],
                },
                reviewer_identity="originator-a",
            )

    def test_source_citation_detects_drift(self) -> None:
        location_id = self.admit_location()
        citation = self.store.source_location(location_id, source_root=self.source)
        self.assertIn("src/dispatch.py:1-5", citation["citation"])
        self.program.write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(IntelligenceError, "stale"):
            self.store.source_location(location_id, source_root=self.source)

    def test_role_views_remove_hidden_context_and_secret_values(self) -> None:
        context = {
            "target": {
                "name": "fixture",
                "apiKey": "must-not-appear",
            },
            "claim": "check path disagreement",
            "sourceLocations": ["loc-a"],
            "evidenceIndex": [],
            "originatorConclusion": "definitely vulnerable",
            "expectedVerdict": "confirmed",
            "credentials": {"cookie": "secret"},
        }
        view = self.store.create_role_view(
            role="reviewer", task_id="review-task", agent_identity="reviewer-a",
            context=context,
        )
        rendered = json.dumps(view)
        self.assertIn("[REDACTED]", rendered)
        self.assertNotIn("must-not-appear", rendered)
        self.assertNotIn("definitely vulnerable", rendered)
        self.assertNotIn("confirmed", rendered)
        self.assertFalse(view["isolation"]["campaignRootAccess"])

    def test_hypothesis_blocking_requires_scoped_reopening_criteria(self) -> None:
        location_id = self.admit_location()
        source = self.observation("source", location_id, "blocked-source")
        hypothesis = self.store.create_hypothesis(
            {
                "title": "blocked route",
                "mechanism": "blocked-mechanism",
                "competingExplanations": ["guard holds", "different representation bypasses it"],
                "experiment": {},
                "capabilities": [],
                "observationIds": [source["observation_id"]],
                "sourceLocations": [location_id],
                "originatorIdentity": "researcher-blocked",
            }
        )
        with self.assertRaisesRegex(IntelligenceError, "reopening criteria"):
            self.store.dispose_hypothesis(
                hypothesis["hypothesis_id"], "blocked",
                actor_identity="researcher-blocked", reason="guard rejects it",
                blocker="exact guard remains enforced", reopening=[],
            )
        disposed = self.store.dispose_hypothesis(
            hypothesis["hypothesis_id"], "blocked",
            actor_identity="researcher-blocked", reason="guard rejects it",
            blocker="exact guard remains enforced",
            reopening=["new source evidence identifies a different consumer"],
        )
        self.assertEqual(disposed["disposition"], "blocked")

    def test_scheduler_observation_without_controls_cannot_claim_differential(self) -> None:
        result_path = self.root / "evidence" / "task-result.json"
        result = {
            "taskResult": {
                "observations": [
                    {
                        "kind": "runtime-differential",
                        "mechanism": "legacy-runtime-label",
                        "summary": "worker used a strong label without three cases",
                        "confidence": "runtime-observed",
                        "evidence": ["evidence/observation.json"],
                        "assetRefs": [{"type": "consumer", "name": "dispatch"}],
                    }
                ]
            }
        }
        result_path.write_text(json.dumps(result), encoding="utf-8")
        update = self.store.ingest_task_result(
            result,
            task_id="task-legacy",
            worker_identity="worker-legacy",
            result_path="evidence/task-result.json",
        )
        observation = self.store.observation(update["observations"][0])
        self.assertEqual(observation["kind"], "runtime")
        self.assertIn("not structurally present", observation["payload"]["downgradeReason"])
        location_id = self.admit_location()
        hypothesis = self.store.create_hypothesis(
            {
                "title": "legacy runtime label",
                "mechanism": "legacy-runtime-label-isolated",
                "competingExplanations": ["real differential", "label without controls"],
                "experiment": {},
                "capabilities": [],
                "observationIds": [observation["observation_id"]],
                "sourceLocations": [location_id],
                "originatorIdentity": "worker-legacy",
            }
        )
        self.store.promote_hypothesis(
            hypothesis["hypothesis_id"], "source-supported-mechanism",
            actor_identity="worker-legacy", reason="source path exists",
        )
        with self.assertRaisesRegex(IntelligenceError, "three-case"):
            self.store.promote_hypothesis(
                hypothesis["hypothesis_id"], "runtime-differential",
                actor_identity="worker-legacy", reason="worker label alone is insufficient",
            )

    def test_sessions_bind_actor_tenant_and_permission_generation(self) -> None:
        session = self.store.bind_web_session(
            {
                "sessionId": "session-victim",
                "actorId": "actor-victim",
                "role": "administrator",
                "tenantId": "tenant-owned-a",
                "permissionVersion": "permissions-v1",
                "credentialRef": "broker:actor-victim",
                "credentialFingerprint": hashlib.sha256(b"credential").hexdigest(),
                "cookieArtifactSha256": hashlib.sha256(b"cookie-jar").hexdigest(),
                "clientKind": "chrome-cdp",
                "authenticatedAt": "2026-11-02T00:00:00Z",
                "expiresAt": "2099-11-03T00:00:00Z",
            }
        )
        self.assertEqual(session["state"], "active")
        self.store.validate_web_session(
            "session-victim", actor_id="actor-victim", role="administrator",
            tenant_id="tenant-owned-a", permission_version="permissions-v1",
        )
        with self.assertRaisesRegex(IntelligenceError, "authority mismatch"):
            self.store.validate_web_session(
                "session-victim", actor_id="actor-attacker", role="administrator",
                tenant_id="tenant-owned-a", permission_version="permissions-v1",
            )
        changed = self.store.authority_changed(
            actor_id="actor-victim", permission_version="permissions-v2",
            evidence=["evidence/observation.json"], reason="role was revoked",
        )
        self.assertEqual(changed["invalidatedSessions"], ["session-victim"])
        with self.assertRaisesRegex(IntelligenceError, "not active"):
            self.store.validate_web_session(
                "session-victim", actor_id="actor-victim", role="administrator",
                tenant_id="tenant-owned-a", permission_version="permissions-v2",
            )


if __name__ == "__main__":
    unittest.main()
