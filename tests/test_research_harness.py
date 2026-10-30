from __future__ import annotations

import concurrent.futures
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.path_proof_fixture import install_machine_path_evidence
from scripts.research_harness import (
    connect_orchestration,
    rebuild_campaign_capability_graph,
    schedule_experiment_frontier,
    validate_research_lead,
)


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "research_harness.py"
PROBE = PROJECT / "scripts" / "tool_probe.py"
PATH_PROOF = PROJECT / "scripts" / "path_proof.py"
REALITY_RUNNER = PROJECT / "scripts" / "reality_runner.py"


class HarnessTests(unittest.TestCase):
    def test_experiment_frontier_advances_past_terminal_top_rank(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            connection = connect_orchestration(campaign)

            def experiment(identifier: str, score: int) -> dict[str, object]:
                return {
                    "id": identifier,
                    "producer": "producer-" + identifier,
                    "consumer": "boundary:exec",
                    "missingCapability": {
                        "type": "capability-" + identifier,
                        "properties": [],
                        "limitations": [],
                        "forbiddenLimitations": [],
                    },
                    "question": "Does this exact mechanism connect?",
                    "setupSequence": [],
                    "oracle": "consumer reached",
                    "falsifier": "guard blocks consumer",
                    "uncertainty": [],
                    "ranking": {"score": score},
                    "sourceEvidence": ["src/fixture.js:1"],
                }

            analysis = {
                "focusEligible": True,
                "missingLinkExperiments": [
                    experiment("first", 100),
                    experiment("second", 90),
                    experiment("third", 80),
                ],
                "scopedNegativeKnowledge": [],
            }
            first_task = schedule_experiment_frontier(
                campaign,
                connection,
                analysis,
                version=1,
                graph_path="evidence/chain-graphs/campaign-v1.json",
            )
            self.assertIsNotNone(first_task)
            connection.execute(
                "UPDATE tasks SET state='completed' WHERE task_id=?", (first_task,)
            )
            connection.execute(
                "UPDATE experiment_frontier SET state='confirmed' WHERE task_id=?",
                (first_task,),
            )
            analysis["scopedNegativeKnowledge"] = [
                {
                    "primitive": "producer-second",
                    "mechanism": "capability-second",
                    "consumer": "boundary:exec",
                    "reopeningConditions": ["different producer or guard state"],
                }
            ]
            second_task = schedule_experiment_frontier(
                campaign,
                connection,
                analysis,
                version=1,
                graph_path="evidence/chain-graphs/campaign-v1.json",
            )
            self.assertIsNotNone(second_task)
            self.assertNotEqual(first_task, second_task)
            states = connection.execute(
                "SELECT experiment_id,state FROM experiment_frontier ORDER BY score DESC"
            ).fetchall()
            self.assertEqual(
                [(row["experiment_id"], row["state"]) for row in states],
                [
                    ("first", "confirmed"),
                    ("second", "refuted"),
                    ("third", "running"),
                ],
            )
            connection.close()

    def run_cli(self, *args: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [sys.executable, str(HARNESS), *args],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            completed.returncode,
            expected,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        return completed

    def create_campaign(self, parent: Path) -> Path:
        campaign = parent / "campaign"
        self.run_cli(
            "init",
            str(campaign),
            "--target",
            "example-target",
            "--repo",
            "https://example.invalid/repository",
            "--commit",
            "0123456789abcdef",
        )
        gate = campaign / "evidence" / "coordinator-gate.json"
        gate.write_text(
            json.dumps(
                {
                    "producer": "krineon-coordinator-gate",
                    "status": "passed",
                    "lyingWorkerRejected": True,
                    "testFixture": True,
                }
            )
            + "\n"
        )
        return campaign

    def install_valid_path_proof(
        self, campaign: Path, finding_id: str, originator: str, reviewer: str
    ) -> None:
        completed = subprocess.run(
            [sys.executable, str(PATH_PROOF), "init", str(campaign), finding_id],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        proof = install_machine_path_evidence(
            campaign, finding_id, originator, reviewer
        )
        proof_path = campaign / "evidence" / "path-proofs" / f"{finding_id}.json"
        proof_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
        completed = subprocess.run(
            [
                sys.executable,
                str(PATH_PROOF),
                "audit",
                str(campaign),
                finding_id,
                "--update-gate",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def install_controlled_path_experiment(
        self, campaign: Path, finding_id: str
    ) -> None:
        from scripts.research_harness import coordinator_reexecute_result

        target = campaign / "evidence" / "bin" / "reality_target.py"
        target_name = target.relative_to(campaign).as_posix()
        campaign_record = json.loads((campaign / "campaign.json").read_text())
        frozen = [
            value
            for value in campaign_record.get("frozenTargetArtifacts", [])
            if isinstance(value, dict) and value.get("path") != target_name
        ]
        frozen.append(
            {
                "path": target_name,
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                "producer": "path-proof-controlled-fixture",
            }
        )
        campaign_record["frozenTargetArtifacts"] = frozen
        (campaign / "campaign.json").write_text(
            json.dumps(campaign_record, indent=2) + "\n"
        )
        recipe = (
            campaign
            / "evidence"
            / "recipes"
            / f"controlled-{finding_id}.json"
        )
        recipe.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "findingId": finding_id,
                    "targetArtifacts": [target_name],
                    "subjectArtifact": target_name,
                    "subjectArgvIndex": 1,
                    "cases": [
                        {
                            "name": "baseline",
                            "command": [sys.executable, target_name],
                            "assertions": [
                                {"id": "b", "kind": "stdout-not-contains-challenge"}
                            ],
                        },
                        {
                            "name": "negative",
                            "command": [sys.executable, target_name],
                            "assertions": [
                                {"id": "n", "kind": "stdout-not-contains-challenge"}
                            ],
                        },
                        {
                            "name": "positive",
                            "command": [sys.executable, target_name],
                            "assertions": [
                                {"id": "p", "kind": "stdout-contains-challenge"}
                            ],
                        },
                    ],
                },
                indent=2,
            )
            + "\n"
        )
        controlled = coordinator_reexecute_result(
            campaign,
            {
                "taskResult": {
                    "coordinatorReplay": {
                        "recipe": recipe.relative_to(campaign).as_posix()
                    }
                }
            },
            finding_id,
            [],
        )
        finding_path = campaign / "findings" / f"{finding_id}.json"
        finding = json.loads(finding_path.read_text())
        finding["controlledExperiments"] = [controlled]
        finding["gates"]["controlled_experiment_verified"] = True
        finding_path.write_text(json.dumps(finding, indent=2) + "\n")

    @staticmethod
    def valid_task_result(task_id: str) -> dict[str, object]:
        return {
            "taskResult": {
                "taskId": task_id,
                "summary": "Completed the assigned first-principles analysis.",
                "conclusion": "The retained evidence supports the recorded conclusion.",
                "searchedSurface": ["pinned/source/example.cc:1"],
                "sourceReferences": ["pinned/source/example.cc:1"],
                "evidence": ["evidence/example.json"],
                "hypotheses": [],
                "nextTasks": [],
                "analysisProvenance": {
                    "firstPrinciplesOnly": True,
                    "changelogUsed": False,
                    "gitHistoryUsed": False,
                    "advisoryMiningUsed": False,
                    "patchedVersionDiffUsed": False,
                    "internetPatchDiffUsed": False,
                },
            }
        }

    @staticmethod
    def chain_contract(identifier: str) -> dict[str, object]:
        progress = {
            "milestones": ["invariant-violation-reproduced"],
            "resolvedPreconditions": ["attacker input reaches the producer"],
            "falsifiedPreconditions": [],
            "connectedPrimitives": [],
            "uncertaintiesResolved": ["the producer and consumer disagree"],
        }
        context = {
            "principal": "attacker",
            "process": "target",
            "namespace": "application",
            "runtime": "production",
        }
        constraints = {
            "lifetime": [],
            "ordering": [],
            "deployment": ["production artifact"],
            "acquisition": ["public input"],
            "requiredState": [],
            "providedState": ["producer-reached"],
        }
        capability = {
            "type": "controlled-value-domain-disagreement",
            "properties": ["attacker-shaped"],
            "limitations": [],
            "forbiddenLimitations": [],
        }
        return {
            "criticalBoundary": {
                "id": f"boundary-{identifier}",
                "operation": "data-to-executable-behavior",
                "eventualImpact": "attacker-controlled code execution in the target process",
                "intermediateCapability": "deliver an attacker-shaped value to a code-selection consumer",
                "requiredCapabilities": [capability],
                "context": context,
                "constraints": constraints,
                "sourceEvidence": ["src/consumer.cc:1"],
            },
            "capabilityModel": {
                "id": f"primitive-{identifier}",
                "attackerControlledInputs": ["request bytes"],
                "produces": [capability],
                "requires": [],
                "context": context,
                "constraints": constraints,
                "stateSequence": {
                    "initialState": "fresh",
                    "transitions": [],
                    "reductionMustPreserve": [],
                },
                "sourceEvidence": ["src/consumer.cc:1"],
                "runtimeEvidence": [],
                "progress": progress,
                "negativeKnowledge": [],
            },
            "chainProgress": progress,
            "negativeKnowledge": [],
        }

    @classmethod
    def valid_replay_result(
        cls,
        campaign: Path,
        task_id: str,
        finding_id: str,
        originator: str,
        reviewer: str,
    ) -> dict[str, object]:
        recipe = f"evidence/recipes/{finding_id}.json"
        completed = subprocess.run(
            [
                sys.executable,
                str(REALITY_RUNNER),
                str(campaign),
                finding_id,
                "--recipe",
                recipe,
                "--worker-id",
                reviewer,
                "--role",
                "reviewer",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode:
            raise AssertionError(completed.stderr or completed.stdout)
        attestation = json.loads(completed.stdout)
        result = cls.valid_task_result(task_id)
        result["independentReplay"] = {
            "findingId": finding_id,
            "originator": originator,
            "reviewer": reviewer,
            "passed": True,
            "attestation": {
                "path": attestation["attestation"],
                "sha256": attestation["sha256"],
            },
            "observerChallenge": {
                "challengedAssumption": "the positive marker alone identifies the claimed mechanism",
                "hypothesisFailureMode": "a generic process artifact could mimic the positive observation",
                "observerFailureMode": "the observer could ignore execution in the negative control",
                "alternateOracle": {
                    "case": "negative",
                    "assertionId": "negative-no-terminal",
                },
                "outcome": "survived",
                "interpretation": "the negative control independently excludes the terminal while the positive case reaches it",
            },
        }
        return result

    @staticmethod
    def valid_blocker_result(blocked_link: str) -> dict[str, object]:
        return {
            "blocker": {
                "category": "technical-chain-blocker",
                "reason": "The current route cannot cross the observed guard.",
                "blockedLink": blocked_link,
                "guardOrFailure": "the consumer rejects the current representation",
                "mechanismFingerprint": "representation-consumer-guard-v1",
                "whyBlocked": "the input does not satisfy the consumer's alternate state",
                "cheapestDiscriminator": "exercise the sibling representation in the same build",
                "evidence": ["evidence/blocker.json"],
                "attempts": ["baseline", "boundary input"],
                "nextExperiments": ["derive a sibling representation from source constraints"],
                "bypassHypotheses": ["the sibling decoder reaches the same sink without the guard"],
                "alternativeRoutes": ["enter through the sibling producer"],
                "canSelfResolve": True,
                "authorityRequired": "none",
                "analysisProvenance": {
                    "firstPrinciplesOnly": True,
                    "changelogUsed": False,
                    "gitHistoryUsed": False,
                    "advisoryMiningUsed": False,
                    "patchedVersionDiffUsed": False,
                    "internetPatchDiffUsed": False,
                },
            }
        }

    def test_init_and_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.assertTrue((campaign / "third_party").is_dir())
            self.assertTrue((campaign / "third_party" / "manifest.json").is_file())
            self.run_cli("plan", str(campaign))
            launch = json.loads((campaign / "launch-plan.json").read_text())
            self.assertEqual(len(launch["tasks"]), 18)
            self.assertTrue((campaign / "tasks" / "wave-1-public-ingress-map.md").is_file())
            self.assertTrue((campaign / "AUTHORIZATION.md").is_file())

    @unittest.skipUnless(shutil.which("git"), "Git is required for dependency pinning")
    def test_dependency_add_pins_and_provisions_isolated_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dependency = root / "dependency-source"
            dependency.mkdir()
            subprocess.run(["git", "init", "-q", str(dependency)], check=True)
            subprocess.run(
                ["git", "-C", str(dependency), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(dependency), "config", "user.name", "Krineon Test"],
                check=True,
            )
            (dependency / "dep.txt").write_text("pinned dependency\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(dependency), "add", "dep.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(dependency), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            revision = subprocess.run(
                ["git", "-C", str(dependency), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            campaign = self.create_campaign(root)
            self.run_cli(
                "dependency-add",
                str(campaign),
                "example-lib",
                "--repo",
                str(dependency),
                "--commit",
                revision,
                "--relationship",
                "runtime",
                "--scope-status",
                "supporting-context",
                "--lock-evidence",
                "package-lock.json:42",
                "--reason",
                "Audit the parser reached by the target's public request path.",
            )
            status = json.loads(
                self.run_cli("dependency-status", str(campaign), "--json").stdout
            )
            self.assertEqual(status["dependencies"][0]["resolvedCommit"], revision)
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "dependency-worker",
                "--agent",
                "codex:dependency-worker",
            )
            claim = json.loads(
                self.run_cli("claim", str(campaign), "dependency-worker", "--json").stdout
            )
            workspace = Path(claim["workspace"])
            self.assertEqual(
                (workspace / "KRINEON_THIRD_PARTY" / "example-lib" / "dep.txt").read_text(),
                "pinned dependency\n",
            )
            assignment = json.loads((workspace / "KRINEON_ASSIGNMENT.json").read_text())
            self.assertEqual(
                assignment["dependencyWorktrees"][0]["resolvedCommit"], revision
            )
            self.run_cli("hash", str(campaign))
            self.assertIn(
                "third_party/manifest.json",
                (campaign / "SHA256SUMS").read_text(encoding="utf-8"),
            )

    def test_chrome_v8_profile_generates_specialized_dependency_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp) / "chrome-v8-campaign"
            self.run_cli(
                "init",
                str(campaign),
                "--target",
                "v8",
                "--repo",
                "https://chromium.googlesource.com/v8/v8",
                "--commit",
                "0123456789abcdef",
                "--profile",
                "chrome-v8",
            )
            self.run_cli("plan", str(campaign))
            launch = json.loads((campaign / "launch-plan.json").read_text())
            self.assertEqual(launch["profile"], "chrome-v8")
            self.assertEqual(len(launch["tasks"]), 17)
            tasks = {item["taskId"]: item for item in launch["tasks"]}
            self.assertEqual(
                tasks["structured-js-fuzzing"]["dependsOn"],
                ["jit-compiler-invariants", "gc-object-lifetime"],
            )
            self.assertEqual(
                tasks["v8-primitive-escalation"]["dependsOn"],
                ["v8-crash-triage", "v8-execution-sink-backtrace", "v8-sandbox-boundaries"],
            )
            self.assertEqual(
                tasks["chromium-integration"]["dependsOn"],
                ["v8-primitive-escalation"],
            )
            self.assertEqual(
                tasks["v8-finding-scoped-replay-scheduler"]["dependsOn"],
                ["chromium-integration"],
            )
            self.assertTrue((campaign / "chrome-v8" / "builds.json").is_file())
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "mac-worker",
                "--agent",
                "codex:mac-worker",
            )
            claim = json.loads(
                self.run_cli("claim", str(campaign), "mac-worker", "--json").stdout
            )
            self.assertTrue(
                (
                    Path(claim["workspace"])
                    / "KRINEON_REFERENCES"
                    / "macos-arm64.md"
                ).is_file()
            )

    def test_candidate_gate_verifies_linked_owned_page_browser_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli(
                "register",
                str(campaign),
                "FBR1",
                "--title",
                "Browser replay gate fixture",
                "--lane",
                "browser-integration",
            )
            replay_id = "20261029T010203123456Z-0123456789"
            finding_path = campaign / "findings" / "FBR1.json"
            finding = json.loads(finding_path.read_text())
            finding["browserReplay"] = {
                "required": True,
                "replayIds": [replay_id],
                "reviewed": True,
                "reviewedBy": "reviewer-browser",
                "reviewNotes": "The retained positive and control establish owned-page reachability.",
            }
            finding_path.write_text(json.dumps(finding, indent=2) + "\n")
            replay_path = (
                campaign
                / "chrome-v8"
                / "browser-replays"
                / replay_id
                / "replay.json"
            )
            replay_path.parent.mkdir(parents=True)
            case = {
                "status": "completed",
                "freshProcess": True,
                "profileDisposable": True,
                "finalUrlOwned": True,
                "expressionMatched": True,
                "sandbox": {"verified": True},
                "blockedExternalRequests": [],
                "targetCrashed": False,
            }
            replay = {
                "replayId": replay_id,
                "driver": "direct-cdp",
                "status": "completed",
                "ownedLocalOrigin": True,
                "build": {"kind": "chrome", "role": "sandboxed-chrome"},
                "site": {"files": [{"path": "index.html", "sha256": "a", "size": 1}]},
                "cases": {"positive": case, "control": dict(case)},
                "summary": {
                    "promotionReady": True,
                    "sandboxVerified": True,
                    "positiveMatched": True,
                    "controlMatched": True,
                },
            }
            replay_path.write_text(json.dumps(replay, indent=2) + "\n")
            result = json.loads(
                self.run_cli(
                    "gate",
                    str(campaign),
                    "FBR1",
                    "--level",
                    "candidate",
                    "--json",
                    expected=1,
                ).stdout
            )
            self.assertFalse(
                any(
                    field.startswith("browserReplay.")
                    for field in result["missingFields"]
                ),
                result,
            )
            self.assertTrue(result["browserReplay"]["required"])
            replay["summary"]["promotionReady"] = False
            replay_path.write_text(json.dumps(replay, indent=2) + "\n")
            failed = json.loads(
                self.run_cli(
                    "gate",
                    str(campaign),
                    "FBR1",
                    "--level",
                    "candidate",
                    "--json",
                    expected=1,
                ).stdout
            )
            self.assertIn(
                f"browserReplay.notPromotionReady:{replay_id}", failed["missingFields"]
            )

    def test_gate_failure_then_reportable_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli(
                "register",
                str(campaign),
                "F001",
                "--title",
                "Example candidate",
                "--lane",
                "protocol-differential",
                "--originator",
                "worker-origin",
            )
            self.run_cli("gate", str(campaign), "F001", "--level", "candidate", expected=1)

            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-origin",
                "--agent",
                "codex:gate-origin",
                "--role",
                "originator",
            )
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-review",
                "--agent",
                "codex:gate-review",
                "--role",
                "reviewer",
            )
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-review-2",
                "--agent",
                "codex:gate-review-2",
                "--role",
                "reviewer",
            )
            self.install_valid_path_proof(
                campaign, "F001", "worker-origin", "worker-review"
            )
            self.install_controlled_path_experiment(campaign, "F001")
            self.run_cli(
                "schedule-replay",
                str(campaign),
                "F001",
                "--task-id",
                "replay-F001-gate",
            )
            replay_claim = json.loads(
                self.run_cli("claim", str(campaign), "worker-review", "--json").stdout
            )
            replay_result = campaign / "gate-replay.json"
            replay_result.write_text(
                json.dumps(
                    self.valid_replay_result(
                        campaign,
                        "replay-F001-gate", "F001", "worker-origin", "worker-review"
                    )
                )
                + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "worker-review",
                replay_claim["taskId"],
                "--lease-token",
                replay_claim["leaseToken"],
                "--result",
                str(replay_result),
                "--idempotency-key",
                "gate-replay-F001-1",
                "--replay-of",
                "F001",
            )
            self.run_cli(
                "schedule-replay",
                str(campaign),
                "F001",
                "--task-id",
                "replay-F001-gate-2",
            )
            replay_claim_2 = json.loads(
                self.run_cli(
                    "claim", str(campaign), "worker-review-2", "--json"
                ).stdout
            )
            replay_result_2 = campaign / "gate-replay-2.json"
            replay_result_2.write_text(
                json.dumps(
                    self.valid_replay_result(
                        campaign,
                        "replay-F001-gate-2",
                        "F001",
                        "worker-origin",
                        "worker-review-2",
                    )
                )
                + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "worker-review-2",
                replay_claim_2["taskId"],
                "--lease-token",
                replay_claim_2["leaseToken"],
                "--result",
                str(replay_result_2),
                "--idempotency-key",
                "gate-replay-F001-2",
                "--replay-of",
                "F001",
            )

            path = campaign / "findings" / "F001.json"
            finding = json.loads(path.read_text())
            finding["rootCause"] = "Producer and consumer disagree about the encoded length domain."
            finding["impactClass"] = "rce"
            finding["impact"] = "Attacker-controlled code executes in the owned target process."
            finding["preconditions"] = ["supported configuration"]
            finding["evidence"] = ["evidence/verification-results.json"]
            finding["chain"] = {
                "attacker": "unauthenticated remote client",
                "ingress": "supported public request handler",
                "attackerControl": "request body and public coordinates",
                "transformations": ["decode", "object construction"],
                "brokenInvariant": "producer and consumer disagree about the length domain",
                "primitive": "attacker-directed callable selection",
                "executionOrCriticalSink": "stock runtime function invocation",
                "terminal": "bounded identity command",
                "remoteAcquisition": "public protocol output",
                "deployment": "unmodified supported build",
                "applicationAuthoredSink": False,
            }
            finding["terminalEvidence"] = {
                "type": "bounded-command-execution",
                "commandOrEffect": "id output from the owned target process",
                "synthetic": False,
            }
            finding["executionEnvironment"] = {
                "environmentClass": "production-equivalent",
                "developmentServer": False,
                "developmentBuild": False,
                "supportedConfiguration": True,
                "primaryTerminalObserved": True,
                "commandOrEntrypoint": "production server entrypoint",
                "evidence": ["evidence/production-environment.json"],
            }
            finding["analysisProvenance"] = {
                "firstPrinciplesOnly": True,
                "changelogUsed": False,
                "gitHistoryUsed": False,
                "advisoryMiningUsed": False,
                "patchedVersionDiffUsed": False,
                "internetPatchDiffUsed": False,
            }
            finding["controls"] = {
                "baseline": "ordinary request succeeds",
                "negative": "enforcing guard rejects the payload",
                "positive": "only the disputed representation crosses the guard",
                "invariantRestored": "sanitized same-revision carrier is rejected",
            }
            for key in finding["gates"]:
                finding["gates"][key] = True
            path.write_text(json.dumps(finding, indent=2) + "\n")
            self.run_cli("gate", str(campaign), "F001", "--level", "reportable")
            finding["dynamicTriage"] = {
                "required": True,
                "crashIds": ["a" * 64],
                "index": "dynamic/triage/index.json",
                "acceptedClusterIds": ["SC-missing"],
                "machineVerdicts": {"a" * 64: "potential-write-primitive"},
                "reviewed": True,
                "reviewedBy": "worker-review",
                "reviewNotes": "Reviewed the machine classification.",
                "overrideReason": "",
            }
            path.write_text(json.dumps(finding, indent=2) + "\n")
            triage_gate = self.run_cli(
                "gate", str(campaign), "F001", "--level", "reportable", "--json", expected=1
            )
            self.assertIn("dynamicTriage.index:missing", triage_gate.stdout)
            self.assertIn("dynamicTriage.missing:", triage_gate.stdout)
            finding["dynamicTriage"] = {
                "required": False,
                "crashIds": [],
                "index": "",
                "acceptedClusterIds": [],
                "machineVerdicts": {},
                "reviewed": False,
                "reviewedBy": "",
                "reviewNotes": "",
                "overrideReason": "",
            }
            path.write_text(json.dumps(finding, indent=2) + "\n")
            self.run_cli("gate", str(campaign), "F001", "--level", "reportable")
            finding["independentReplays"][0]["sha256"] = "0" * 64
            path.write_text(json.dumps(finding, indent=2) + "\n")
            self.run_cli(
                "gate", str(campaign), "F001", "--level", "reportable", expected=1
            )

    def test_durable_scheduler_dependencies_and_idempotent_submission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli(
                "plan",
                str(campaign),
                "--max-concurrency",
                "2",
                "--lease-seconds",
                "30",
            )
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-a",
                "--agent",
                "codex:test-a",
                "--role",
                "originator",
            )
            claim = self.run_cli("claim", str(campaign), "worker-a", "--json")
            assignment = json.loads(claim.stdout)
            self.assertEqual(assignment["taskId"], "coordinator-setup")
            self.assertTrue(Path(assignment["workspace"]).is_dir())
            self.assertTrue((Path(assignment["workspace"]) / "KRINEON_ASSIGNMENT.json").is_file())
            self.assertTrue((Path(assignment["workspace"]) / "KRINEON_CAMPAIGN.json").is_file())
            self.assertTrue((Path(assignment["workspace"]) / "AUTHORIZATION.md").is_file())
            self.assertTrue(
                (Path(assignment["workspace"]) / "KRINEON_TASK_RESULT.template.json").is_file()
            )
            self.assertTrue(
                (
                    Path(assignment["workspace"])
                    / "KRINEON_REFERENCES"
                    / "critical-rce.md"
                ).is_file()
            )

            no_second = self.run_cli(
                "claim", str(campaign), "worker-a", "--json", expected=3
            )
            self.assertFalse(json.loads(no_second.stdout)["claimed"])

            result = campaign / "coordinator-result.json"
            result.write_text(
                json.dumps(self.valid_task_result("coordinator-setup")) + "\n"
            )
            submit_args = (
                "submit",
                str(campaign),
                "worker-a",
                "coordinator-setup",
                "--lease-token",
                assignment["leaseToken"],
                "--result",
                str(result),
                "--idempotency-key",
                "setup-attempt-1",
            )
            self.run_cli(*submit_args)
            self.run_cli(*submit_args)

            wave_one = self.run_cli("claim", str(campaign), "worker-a", "--json")
            self.assertEqual(
                json.loads(wave_one.stdout)["lane"], "public-ingress-map"
            )

    def test_partial_invariant_lead_is_ranked_deduplicated_and_advances_queue(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            checkout = Path(tmp) / "lead-source"
            checkout.mkdir()
            source_file = checkout / "src" / "consumer.cc"
            source_file.parent.mkdir()
            source_file.write_text(
                "auto produced = make_wide();\nauto consumed = narrow(produced);\n"
            )
            campaign_record = json.loads((campaign / "campaign.json").read_text())
            campaign_record["localCheckout"] = str(checkout.resolve())
            campaign_record["authorization"]["confirmed"] = True
            campaign_record["authorization"]["basis"] = "owned coordinator replay fixture"
            replay_target = campaign / "evidence" / "bin" / "reality_target.py"
            replay_target.parent.mkdir(parents=True, exist_ok=True)
            replay_target.write_bytes(
                (PROJECT / "tests" / "fixtures" / "reality_target.py").read_bytes()
            )
            campaign_record["frozenTargetArtifacts"] = [
                {
                    "path": replay_target.relative_to(campaign).as_posix(),
                    "sha256": hashlib.sha256(replay_target.read_bytes()).hexdigest(),
                    "producer": "test-coordinator",
                }
            ]
            (campaign / "campaign.json").write_text(
                json.dumps(campaign_record, indent=2) + "\n"
            )
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "lead-worker",
                "--agent",
                "codex:lead-worker",
            )
            assignment = json.loads(
                self.run_cli("claim", str(campaign), "lead-worker", "--json").stdout
            )
            evidence = campaign / "evidence" / "invariant-observation.json"
            evidence.write_text('{"producer":"wide","consumer":"narrow"}\n')
            lead = {
                **self.chain_contract("invariant"),
                "kind": "invariant-break",
                "title": "Producer and consumer disagree on the value domain",
                "status": "active",
                "sourceReferences": ["src/producer.cc:10", "src/consumer.cc:20"],
                "sourceArtifacts": [
                    {
                        "targetPath": "src/consumer.cc",
                        "sha256": hashlib.sha256(source_file.read_bytes()).hexdigest(),
                        "lineStart": 1,
                        "lineEnd": 2,
                    }
                ],
                "evidence": ["evidence/invariant-observation.json"],
                "approachFamilies": ["representation-parser"],
                "nextExperiment": "Run the same value through the release consumer and restoring control.",
                "invariantBreak": {
                    "boundary": "producer-to-consumer",
                    "invariant": "both sides accept the same numeric domain",
                    "expected": "the consumer preserves the produced value",
                    "observed": "the consumer truncates it",
                    "restoredControl": "a value inside the shared domain is preserved",
                    "runtimeReproduced": False,
                },
            }
            crash_id = "a" * 64
            crash_dir = campaign / "dynamic" / "crashes" / crash_id
            crash_dir.mkdir(parents=True)
            minimized = crash_dir / "minimized.bin"
            minimized.write_bytes(b"minimal-trigger")
            triage = {
                "crashId": crash_id,
                "firstFault": {"class": "out-of-bounds-write"},
                "stack": {"clusterId": "SC-unique-stack"},
            }
            triage_path = crash_dir / "triage.json"
            triage_path.write_text(json.dumps(triage) + "\n")
            stack_lead = {
                **self.chain_contract("stack"),
                "kind": "minimized-stack",
                "title": "Unique minimized first-fault stack",
                "status": "active",
                "sourceReferences": ["src/consumer.cc:20"],
                "evidence": [
                    f"dynamic/crashes/{crash_id}/triage.json",
                    f"dynamic/crashes/{crash_id}/minimized.bin",
                ],
                "approachFamilies": ["memory-lifetime"],
                "nextExperiment": "Restore the disputed bound and replay the minimized input.",
                "minimizedStack": {
                    "crashId": crash_id,
                    "clusterId": "SC-unique-stack",
                    "minimizedSha256": hashlib.sha256(
                        minimized.read_bytes()
                    ).hexdigest(),
                },
            }
            result = self.valid_task_result(assignment["taskId"])
            result["taskResult"]["researchLeads"] = [
                lead,
                dict(lead),
                stack_lead,
                dict(stack_lead),
            ]
            replay_recipe = campaign / "evidence" / "recipes" / "lead-replay.json"
            replay_recipe.parent.mkdir(parents=True, exist_ok=True)
            replay_recipe.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "findingId": assignment["taskId"],
                        "targetArtifacts": ["evidence/bin/reality_target.py"],
                        "subjectArtifact": "evidence/bin/reality_target.py",
                        "subjectArgvIndex": 1,
                        "cases": [
                            {
                                "name": "baseline",
                                "command": [sys.executable, "evidence/bin/reality_target.py"],
                                "assertions": [
                                    {
                                        "id": "baseline-no-challenge",
                                        "kind": "stdout-not-contains-challenge",
                                    }
                                ],
                            },
                            {
                                "name": "negative",
                                "command": [sys.executable, "evidence/bin/reality_target.py"],
                                "assertions": [
                                    {
                                        "id": "negative-no-challenge",
                                        "kind": "stdout-not-contains-challenge",
                                    }
                                ],
                            },
                            {
                                "name": "positive",
                                "command": [sys.executable, "evidence/bin/reality_target.py"],
                                "assertions": [
                                    {
                                        "id": "positive-challenge",
                                        "kind": "stdout-contains-challenge",
                                    }
                                ],
                            },
                        ],
                    },
                    indent=2,
                )
                + "\n"
            )
            result["taskResult"]["coordinatorReplay"] = {
                "recipe": replay_recipe.relative_to(campaign).as_posix(),
                "repetitions": 1,
            }
            result_path = campaign / "lead-result.json"
            result_path.write_text(json.dumps(result) + "\n")
            self.run_cli(
                "submit",
                str(campaign),
                "lead-worker",
                assignment["taskId"],
                "--lease-token",
                assignment["leaseToken"],
                "--result",
                str(result_path),
                "--idempotency-key",
                "partial-lead",
            )
            status = json.loads(
                self.run_cli("lead-status", str(campaign), "--json").stdout
            )
            self.assertFalse(status["impactClaimed"])
            self.assertEqual(len(status["leads"]), 2)
            self.assertEqual(status["leads"][0]["evidenceGrade"], "minimized-stack")
            self.assertEqual(status["leads"][1]["evidenceGrade"], "source-invariant")
            connection = sqlite3.connect(campaign / "orchestration.db")
            try:
                rows = connection.execute(
                    "SELECT task_id,packet FROM tasks WHERE lane='research-lead-validation'"
                ).fetchall()
            finally:
                connection.close()
            self.assertEqual(len(rows), 2)
            for _, packet_path in rows:
                packet = (campaign / packet_path).read_text()
                self.assertIn("RCE chain is **not** required", packet)

    def test_observation_can_enter_queue_without_invented_chain_narrative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp) / "campaign"
            (campaign / "evidence").mkdir(parents=True)
            (campaign / "campaign.json").write_text(
                json.dumps({"authorization": {"confirmed": False}}) + "\n"
            )
            (campaign / "evidence" / "observation.json").write_text(
                '{"expected":"same identity","observed":"different identity"}\n'
            )
            lead = validate_research_lead(
                campaign,
                {
                    "kind": "observation",
                    "chainMaturity": "observation",
                    "title": "Two consumers resolve one token differently",
                    "status": "active",
                    "sourceReferences": ["src/consumer-a.cc:10", "src/consumer-b.cc:20"],
                    "evidence": ["evidence/observation.json"],
                    "approachFamilies": ["representation-parser"],
                    "nextExperiment": "Replay one token through both consumers with an identity oracle.",
                    "negativeKnowledge": [],
                    "observation": {
                        "invariant": "both consumers resolve the same identity",
                        "expected": "identical identity",
                        "observed": "different identities",
                        "reproducible": False,
                    },
                },
            )
            self.assertEqual(lead["chainMaturity"], "observation")
            self.assertNotIn("criticalBoundary", lead)
            self.assertNotIn("capabilityModel", lead)
            self.assertEqual(lead["chainProgressScore"], 0)

    def test_campaign_graph_versions_and_composes_primitives_across_leads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            bridge = {
                "type": "attacker-shaped-bridge",
                "properties": ["controlled"],
                "limitations": [],
                "forbiddenLimitations": [],
            }
            terminal = {
                "type": "manifest-valid-module-selection",
                "properties": ["attacker-selected"],
                "limitations": [],
                "forbiddenLimitations": [],
            }
            first = self.chain_contract("cross-a")
            second = self.chain_contract("cross-b")
            first["capabilityModel"]["produces"] = [bridge]
            first["criticalBoundary"]["requiredCapabilities"] = [terminal]
            second["capabilityModel"]["attackerControlledInputs"] = []
            second["capabilityModel"]["requires"] = [bridge]
            second["capabilityModel"]["produces"] = [terminal]
            second["criticalBoundary"]["requiredCapabilities"] = [terminal]
            connection = connect_orchestration(campaign)
            try:
                now = "2026-01-01T00:00:00+00:00"
                for index, contract in enumerate((first, second), start=1):
                    payload = {
                        **contract,
                        "kind": "invariant-break",
                        "chainMaturity": "chain-hypothesis",
                        "chainProgressScore": 5,
                    }
                    connection.execute(
                        "INSERT INTO research_leads(lead_id,semantic_identity,kind,evidence_grade,state,title,payload_json,first_task_id,first_worker_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            f"L{index}",
                            f"cross-route-{index}",
                            "invariant-break",
                            "source-invariant",
                            "active",
                            f"Cross-route primitive {index}",
                            json.dumps(payload),
                            "inventory-map",
                            "worker-a",
                            now,
                            now,
                        ),
                    )
                update = rebuild_campaign_capability_graph(campaign, connection)
                self.assertIsNotNone(update)
                self.assertEqual(update["analysis"]["graphVersion"], 1)
                path = update["analysis"]["completeBoundaryPaths"][0]
                self.assertIn("primitive-cross-a", path)
                self.assertIn("primitive-cross-b", path)

                second_payload = json.loads(
                    connection.execute(
                        "SELECT payload_json FROM research_leads WHERE lead_id='L2'"
                    ).fetchone()["payload_json"]
                )
                second_payload["capabilityModel"]["measuredCost"] = {
                    "wallSeconds": 3.0,
                    "executions": 1,
                    "evidence": ["evidence/cost.json"],
                }
                connection.execute(
                    "UPDATE research_leads SET payload_json=? WHERE lead_id='L2'",
                    (json.dumps(second_payload),),
                )
                update = rebuild_campaign_capability_graph(campaign, connection)
                self.assertEqual(update["analysis"]["graphVersion"], 2)
                connection.commit()
            finally:
                connection.close()

    def test_coordinator_reexecution_rejects_a_worker_lie(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            campaign_record = json.loads((campaign / "campaign.json").read_text())
            campaign_record["authorization"]["confirmed"] = True
            campaign_record["authorization"]["basis"] = "owned liar-gate fixture"
            target = campaign / "evidence" / "bin" / "always_negative.py"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                "#!/usr/bin/env python3\nprint('no-positive-observation')\n",
                encoding="utf-8",
            )
            campaign_record["frozenTargetArtifacts"] = [
                {
                    "path": target.relative_to(campaign).as_posix(),
                    "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                    "producer": "test-coordinator",
                }
            ]
            (campaign / "campaign.json").write_text(
                json.dumps(campaign_record, indent=2) + "\n"
            )
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "lying-worker",
                "--agent",
                "codex:lying-worker",
            )
            assignment = json.loads(
                self.run_cli("claim", str(campaign), "lying-worker", "--json").stdout
            )
            recipe = campaign / "evidence" / "recipes" / "liar.json"
            recipe.parent.mkdir(parents=True, exist_ok=True)
            recipe.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "findingId": assignment["taskId"],
                        "targetArtifacts": ["evidence/bin/always_negative.py"],
                        "subjectArtifact": "evidence/bin/always_negative.py",
                        "subjectArgvIndex": 1,
                        "cases": [
                            {
                                "name": "baseline",
                                "command": [sys.executable, "evidence/bin/always_negative.py"],
                                "assertions": [
                                    {"id": "b", "kind": "stdout-not-contains-challenge"}
                                ],
                            },
                            {
                                "name": "negative",
                                "command": [sys.executable, "evidence/bin/always_negative.py"],
                                "assertions": [
                                    {"id": "n", "kind": "stdout-not-contains-challenge"}
                                ],
                            },
                            {
                                "name": "positive",
                                "command": [sys.executable, "evidence/bin/always_negative.py"],
                                "assertions": [
                                    {"id": "p", "kind": "stdout-contains-challenge"}
                                ],
                            },
                        ],
                    }
                )
                + "\n"
            )
            result = self.valid_task_result(assignment["taskId"])
            result["taskResult"]["coordinatorReplay"] = {
                "recipe": recipe.relative_to(campaign).as_posix()
            }
            result_path = campaign / "lying-result.json"
            result_path.write_text(json.dumps(result) + "\n")
            rejected = self.run_cli(
                "submit",
                str(campaign),
                "lying-worker",
                assignment["taskId"],
                "--lease-token",
                assignment["leaseToken"],
                "--result",
                str(result_path),
                "--idempotency-key",
                "lying-worker-claim",
                expected=1,
            )
            self.assertIn("coordinator re-execution rejected", rejected.stderr)
            with sqlite3.connect(campaign / "orchestration.db") as connection:
                state = connection.execute(
                    "SELECT state FROM tasks WHERE task_id=?", (assignment["taskId"],)
                ).fetchone()[0]
            self.assertEqual(state, "running")

    def test_scale_out_waits_for_coordinator_gate_self_test(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp) / "campaign"
            self.run_cli(
                "init",
                str(campaign),
                "--target",
                "fixture",
                "--repo",
                "https://example.invalid/fixture",
                "--commit",
                "a" * 40,
            )
            record = json.loads((campaign / "campaign.json").read_text())
            record["authorization"]["confirmed"] = True
            record["authorization"]["basis"] = "owned gate fixture"
            (campaign / "campaign.json").write_text(json.dumps(record) + "\n")
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-one",
                "--agent",
                "codex:one",
            )
            refused = self.run_cli(
                "worker-register",
                str(campaign),
                "worker-two",
                "--agent",
                "codex:two",
                expected=1,
            )
            self.assertIn("additional workers are disabled", refused.stderr)
            self.run_cli("gate-self-test", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-two",
                "--agent",
                "codex:two",
            )

    @unittest.skipUnless(shutil.which("git"), "Git is required for worktree provisioning")
    def test_claim_provisions_detached_git_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp)
            checkout = parent / "source"
            checkout.mkdir()
            subprocess.run(["git", "init", "-q", str(checkout)], check=True)
            subprocess.run(
                ["git", "-C", str(checkout), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(checkout), "config", "user.name", "Krineon Test"],
                check=True,
            )
            (checkout / "target.txt").write_text("pinned source\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(checkout), "add", "target.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(checkout), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            revision = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            campaign = parent / "campaign"
            self.run_cli(
                "init",
                str(campaign),
                "--target",
                "local-fixture",
                "--repo",
                str(checkout),
                "--checkout",
                str(checkout),
                "--commit",
                revision,
            )
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-git",
                "--agent",
                "codex:git-test",
            )
            assignment = json.loads(
                self.run_cli("claim", str(campaign), "worker-git", "--json").stdout
            )
            workspace = Path(assignment["workspace"])
            metadata = json.loads((workspace / "KRINEON_ASSIGNMENT.json").read_text())
            self.assertEqual(metadata["workspaceMode"], "git-worktree")
            self.assertEqual((workspace / "target.txt").read_text(), "pinned source\n")
            actual_revision = subprocess.run(
                ["git", "-C", str(workspace), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(actual_revision, revision)

    def test_lease_recovery_cancel_and_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign), "--max-attempts", "2")
            self.run_cli("queue", str(campaign))
            for worker in ("worker-a", "worker-b"):
                self.run_cli(
                    "worker-register",
                    str(campaign),
                    worker,
                    "--agent",
                    f"codex:{worker}",
                )
            first = json.loads(
                self.run_cli("claim", str(campaign), "worker-a", "--json").stdout
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            database.execute(
                "UPDATE tasks SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE task_id=?",
                (first["taskId"],),
            )
            database.commit()
            database.close()
            self.run_cli("recover", str(campaign))
            second = json.loads(
                self.run_cli("claim", str(campaign), "worker-b", "--json").stdout
            )
            self.assertEqual(second["taskId"], first["taskId"])
            self.assertEqual(second["attempt"], 2)
            self.run_cli(
                "cancel",
                str(campaign),
                second["taskId"],
                "--reason",
                "superseded by safer experiment",
            )
            self.run_cli(
                "retry",
                str(campaign),
                second["taskId"],
                "--reason",
                "corrected task packet",
                "--extend-attempts",
            )

    def test_timeout_is_enforced_at_result_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign), "--task-timeout-seconds", "1")
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-timeout",
                "--agent",
                "codex:timeout-test",
            )
            assignment = json.loads(
                self.run_cli("claim", str(campaign), "worker-timeout", "--json").stdout
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            database.execute(
                "UPDATE tasks SET started_at='2000-01-01T00:00:00+00:00' WHERE task_id=?",
                (assignment["taskId"],),
            )
            database.commit()
            database.close()
            result = campaign / "late-result.json"
            result.write_text(json.dumps({"summary": "too late"}) + "\n")
            self.run_cli(
                "submit",
                str(campaign),
                "worker-timeout",
                assignment["taskId"],
                "--lease-token",
                assignment["leaseToken"],
                "--result",
                str(result),
                "--idempotency-key",
                "late-result-1",
                expected=1,
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            state = database.execute(
                "SELECT state FROM tasks WHERE task_id=?", (assignment["taskId"],)
            ).fetchone()[0]
            database.close()
            self.assertEqual(state, "timed-out")

    def test_campaign_budget_stops_queued_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign), "--budget-seconds", "60")
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "worker-budget",
                "--agent",
                "codex:budget-test",
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            database.execute(
                "UPDATE metadata SET value=? WHERE key='deadlineAt'",
                (json.dumps("2000-01-01T00:00:00+00:00"),),
            )
            database.commit()
            database.close()
            self.run_cli("recover", str(campaign))
            self.run_cli(
                "claim", str(campaign), "worker-budget", "--json", expected=4
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            runnable = database.execute(
                "SELECT COUNT(*) FROM tasks WHERE state IN ('queued','running')"
            ).fetchone()[0]
            database.close()
            self.assertEqual(runnable, 0)

    def test_independent_replay_enforces_distinct_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            for worker, role in (
                ("origin", "originator"),
                ("review", "reviewer"),
                ("review-2", "reviewer"),
            ):
                self.run_cli(
                    "worker-register",
                    str(campaign),
                    worker,
                    "--agent",
                    f"codex:{worker}",
                    "--role",
                    role,
                )
            self.run_cli(
                "register",
                str(campaign),
                "F001",
                "--title",
                "Replay candidate",
                "--lane",
                "protocol-differential",
                "--originator",
                "origin",
            )
            self.install_valid_path_proof(campaign, "F001", "origin", "review")
            self.run_cli(
                "schedule-replay",
                str(campaign),
                "F001",
                "--task-id",
                "replay-F001",
            )

            # The originator is excluded from the high-priority replay task and
            # therefore claims the normal coordinator task instead.
            origin_claim = json.loads(
                self.run_cli("claim", str(campaign), "origin", "--json").stdout
            )
            self.assertNotEqual(origin_claim["taskId"], "replay-F001")
            review_claim = json.loads(
                self.run_cli("claim", str(campaign), "review", "--json").stdout
            )
            self.assertEqual(review_claim["taskId"], "replay-F001")
            prose_only = self.valid_task_result("replay-F001")
            prose_only["independentReplay"] = {
                "findingId": "F001",
                "originator": "origin",
                "reviewer": "review",
                "passed": True,
            }
            prose_result = campaign / "prose-replay.json"
            prose_result.write_text(json.dumps(prose_only) + "\n")
            rejected = self.run_cli(
                "submit",
                str(campaign),
                "review",
                "replay-F001",
                "--lease-token",
                review_claim["leaseToken"],
                "--result",
                str(prose_result),
                "--idempotency-key",
                "replay-F001-prose-only",
                "--replay-of",
                "F001",
                expected=1,
            )
            self.assertIn("machine attestation", rejected.stderr)
            no_challenge = self.valid_replay_result(
                campaign, "replay-F001", "F001", "origin", "review"
            )
            no_challenge["independentReplay"].pop("observerChallenge")
            no_challenge_path = campaign / "replay-without-observer-challenge.json"
            no_challenge_path.write_text(json.dumps(no_challenge) + "\n")
            rejected = self.run_cli(
                "submit",
                str(campaign),
                "review",
                "replay-F001",
                "--lease-token",
                review_claim["leaseToken"],
                "--result",
                str(no_challenge_path),
                "--idempotency-key",
                "replay-F001-no-observer-challenge",
                "--replay-of",
                "F001",
                expected=1,
            )
            self.assertIn("challenge the hypothesis and observer", rejected.stderr)
            replay_result = campaign / "replay.json"
            replay_result.write_text(
                json.dumps(
                    self.valid_replay_result(
                        campaign, "replay-F001", "F001", "origin", "review"
                    )
                )
                + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "review",
                "replay-F001",
                "--lease-token",
                review_claim["leaseToken"],
                "--result",
                str(replay_result),
                "--idempotency-key",
                "replay-F001-review-1",
                "--replay-of",
                "F001",
            )
            finding = json.loads((campaign / "findings" / "F001.json").read_text())
            self.assertFalse(finding["gates"]["independent_replay"])
            self.assertEqual(finding["independentReplays"][0]["reviewer"], "review")
            self.assertEqual(
                finding["independentReplays"][0]["originatorAgent"], "codex:origin"
            )
            self.assertEqual(
                finding["independentReplays"][0]["reviewerAgent"], "codex:review"
            )
            self.run_cli(
                "schedule-replay",
                str(campaign),
                "F001",
                "--task-id",
                "replay-F001-2",
            )
            second_claim = json.loads(
                self.run_cli("claim", str(campaign), "review-2", "--json").stdout
            )
            self.assertEqual(second_claim["taskId"], "replay-F001-2")
            second_result = campaign / "replay-2.json"
            second_result.write_text(
                json.dumps(
                    self.valid_replay_result(
                        campaign, "replay-F001-2", "F001", "origin", "review-2"
                    )
                )
                + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "review-2",
                "replay-F001-2",
                "--lease-token",
                second_claim["leaseToken"],
                "--result",
                str(second_result),
                "--idempotency-key",
                "replay-F001-review-2",
                "--replay-of",
                "F001",
            )
            finding = json.loads((campaign / "findings" / "F001.json").read_text())
            self.assertTrue(finding["gates"]["independent_replay"])
            self.assertEqual(
                {item["reviewerAgent"] for item in finding["independentReplays"]},
                {"codex:review", "codex:review-2"},
            )

    def test_controlled_experiment_gate_recomputes_signed_raw_evidence(self) -> None:
        from scripts.research_harness import (
            controlled_experiment_is_machine_verified,
            coordinator_reexecute_result,
        )

        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            campaign_record = json.loads((campaign / "campaign.json").read_text())
            campaign_record["authorization"]["confirmed"] = True
            campaign_record["authorization"]["basis"] = "owned controlled fixture"
            target = campaign / "evidence" / "bin" / "reality_target.py"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(
                (PROJECT / "tests" / "fixtures" / "reality_target.py").read_bytes()
            )
            target_name = target.relative_to(campaign).as_posix()
            campaign_record["frozenTargetArtifacts"] = [
                {
                    "path": target_name,
                    "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                    "producer": "test-controlled-runner",
                }
            ]
            (campaign / "campaign.json").write_text(
                json.dumps(campaign_record, indent=2) + "\n"
            )
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            recipe = campaign / "evidence" / "recipes" / "controlled-task.json"
            recipe.parent.mkdir(parents=True, exist_ok=True)
            recipe.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "findingId": "controlled-task",
                        "targetArtifacts": [target_name],
                        "subjectArtifact": target_name,
                        "subjectArgvIndex": 1,
                        "cases": [
                            {
                                "name": "baseline",
                                "command": [sys.executable, target_name],
                                "assertions": [
                                    {
                                        "id": "baseline",
                                        "kind": "stdout-not-contains-challenge",
                                    }
                                ],
                            },
                            {
                                "name": "negative",
                                "command": [sys.executable, target_name],
                                "assertions": [
                                    {
                                        "id": "negative",
                                        "kind": "stdout-not-contains-challenge",
                                    }
                                ],
                            },
                            {
                                "name": "positive",
                                "command": [sys.executable, target_name],
                                "assertions": [
                                    {
                                        "id": "positive",
                                        "kind": "stdout-contains-challenge",
                                    }
                                ],
                            },
                        ],
                    },
                    indent=2,
                )
                + "\n"
            )
            controlled = coordinator_reexecute_result(
                campaign,
                {
                    "taskResult": {
                        "coordinatorReplay": {
                            "recipe": recipe.relative_to(campaign).as_posix(),
                            "repetitions": 1,
                        }
                    }
                },
                "controlled-task",
                [],
            )
            self.assertIsNotNone(controlled)
            finding = {"controlledExperiments": [controlled]}
            self.assertTrue(
                controlled_experiment_is_machine_verified(campaign, finding)
            )
            observation = json.loads(
                (campaign / controlled["controlledObservation"]).read_text()
            )
            raw = campaign / observation["rawArtifacts"][0]["path"]
            raw.write_bytes(raw.read_bytes() + b"tampered")
            self.assertFalse(
                controlled_experiment_is_machine_verified(campaign, finding)
            )

    def test_replay_excludes_agent_aliases_and_worker_identity_is_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register", str(campaign), "origin", "--agent", "codex:same"
            )
            self.run_cli(
                "worker-register", str(campaign), "review", "--agent", "codex:other"
            )
            self.run_cli(
                "worker-register", str(campaign), "review-2", "--agent", "codex:third"
            )
            self.run_cli(
                "worker-register",
                str(campaign),
                "origin",
                "--agent",
                "codex:changed",
                expected=1,
            )
            self.run_cli(
                "register",
                str(campaign),
                "FALIAS",
                "--title",
                "Alias replay candidate",
                "--lane",
                "cross-lane-chain-composition",
                "--originator",
                "origin",
            )
            self.install_valid_path_proof(campaign, "FALIAS", "origin", "review")
            self.run_cli(
                "schedule-replay",
                str(campaign),
                "FALIAS",
                "--task-id",
                "replay-FALIAS",
            )
            self.run_cli(
                "worker-register",
                str(campaign),
                "late-origin-alias",
                "--agent",
                "codex:same",
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            row = database.execute(
                "SELECT excluded_workers_json,excluded_agents_json FROM tasks WHERE task_id=?",
                ("replay-FALIAS",),
            ).fetchone()
            database.close()
            self.assertEqual(json.loads(row[0]), ["origin"])
            self.assertEqual(json.loads(row[1]), ["codex:same"])
            alias_claim = json.loads(
                self.run_cli("claim", str(campaign), "late-origin-alias", "--json").stdout
            )
            self.assertNotEqual(alias_claim["taskId"], "replay-FALIAS")
            review_claim = json.loads(
                self.run_cli("claim", str(campaign), "review", "--json").stdout
            )
            self.assertEqual(review_claim["taskId"], "replay-FALIAS")
            replay_result = campaign / "alias-replay.json"
            replay_result.write_text(
                json.dumps(
                    self.valid_replay_result(
                        campaign, "replay-FALIAS", "FALIAS", "origin", "review"
                    )
                )
                + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "review",
                "replay-FALIAS",
                "--lease-token",
                review_claim["leaseToken"],
                "--result",
                str(replay_result),
                "--idempotency-key",
                "alias-replay-1",
                "--replay-of",
                "FALIAS",
            )
            finding = json.loads((campaign / "findings" / "FALIAS.json").read_text())
            from scripts.research_harness import replay_is_machine_verified

            self.assertFalse(replay_is_machine_verified(campaign, finding))
            self.run_cli(
                "schedule-replay",
                str(campaign),
                "FALIAS",
                "--task-id",
                "replay-FALIAS-2",
            )
            second_claim = json.loads(
                self.run_cli("claim", str(campaign), "review-2", "--json").stdout
            )
            self.assertEqual(second_claim["taskId"], "replay-FALIAS-2")
            second_result = campaign / "alias-replay-2.json"
            second_result.write_text(
                json.dumps(
                    self.valid_replay_result(
                        campaign, "replay-FALIAS-2", "FALIAS", "origin", "review-2"
                    )
                )
                + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "review-2",
                "replay-FALIAS-2",
                "--lease-token",
                second_claim["leaseToken"],
                "--result",
                str(second_result),
                "--idempotency-key",
                "alias-replay-2",
                "--replay-of",
                "FALIAS",
            )
            finding = json.loads((campaign / "findings" / "FALIAS.json").read_text())
            self.assertTrue(replay_is_machine_verified(campaign, finding))

    def test_dynamic_task_blocker_unblock_and_automatic_resume(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            for worker in ("explorer", "unblocker"):
                self.run_cli(
                    "worker-register",
                    str(campaign),
                    worker,
                    "--agent",
                    f"codex:{worker}",
                )
            self.run_cli(
                "task-add",
                str(campaign),
                "adjacent-jit-path",
                "--title",
                "Explore adjacent JIT state transition",
                "--lane",
                "open-ended-expansion",
                "--approach-family",
                "blocker-alternative-route",
                "--objective",
                "Follow the producer and consumer disagreement beyond the initial reducer.",
                "--success-criterion",
                "Confirm or disprove the adjacent lowering path with runtime evidence.",
                "--priority",
                "1500",
            )
            claimed = json.loads(
                self.run_cli("claim", str(campaign), "explorer", "--json").stdout
            )
            self.assertEqual(claimed["taskId"], "adjacent-jit-path")
            blocked_result = campaign / "blocked.json"
            blocked_result.write_text(
                json.dumps(
                    {
                        "blocker": {
                            "category": "missing-build-observability",
                            "reason": "The release build lacks the required trace evidence.",
                            "blockedLink": "primitive-to-execution state transition",
                            "guardOrFailure": "release build omits the diagnostic state signal",
                            "mechanismFingerprint": "release-observability-v1",
                            "whyBlocked": "the transition cannot be distinguished from the control",
                            "cheapestDiscriminator": "derive one release-visible output from a diagnostic build",
                            "evidence": ["logs/release-no-trace.txt"],
                            "attempts": ["release replay", "debug replay"],
                            "nextExperiments": [
                                "Build an instrumentation-only diagnostic binary",
                                "Derive an observable state discriminator",
                            ],
                            "bypassHypotheses": [
                                "A sibling output path exposes the same state without instrumentation"
                            ],
                            "alternativeRoutes": [
                                "Reach the execution boundary through the sibling consumer"
                            ],
                            "canSelfResolve": True,
                            "authorityRequired": "none",
                            "analysisProvenance": {
                                "firstPrinciplesOnly": True,
                                "changelogUsed": False,
                                "gitHistoryUsed": False,
                                "advisoryMiningUsed": False,
                                "patchedVersionDiffUsed": False,
                                "internetPatchDiffUsed": False,
                            },
                        }
                    }
                )
                + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "explorer",
                "adjacent-jit-path",
                "--lease-token",
                claimed["leaseToken"],
                "--result",
                str(blocked_result),
                "--idempotency-key",
                "adjacent-jit-path-blocked-1",
                "--outcome",
                "blocked",
            )
            self.run_cli(
                "retry",
                str(campaign),
                "adjacent-jit-path",
                "--reason",
                "same blocked mechanism with new wording",
                expected=1,
            )
            unblock_claim = json.loads(
                self.run_cli("claim", str(campaign), "unblocker", "--json").stdout
            )
            self.assertTrue(unblock_claim["taskId"].startswith("unblock-adjacent-jit-path"))
            self.assertEqual(unblock_claim["lane"], "automatic-blocker-breakout")
            unblock_result = campaign / "unblocked.json"
            unblock_payload = self.valid_task_result(unblock_claim["taskId"])
            unblock_payload["unblock"] = {
                "blockedTaskId": "adjacent-jit-path",
                "blockerAddressed": True,
                "evidence": ["evidence/state-discriminator.json"],
                "resumeStrategy": "Replay the original release build using the discriminator.",
                "newMechanism": {
                    "fingerprint": "release-visible-discriminator-v2",
                    "differsFrom": "release-observability-v1",
                    "mechanism": "derive a discriminator from stock release output",
                    "difference": "uses production output instead of the unavailable trace signal",
                    "evidence": ["evidence/state-discriminator.json"],
                },
            }
            same_mechanism = json.loads(json.dumps(unblock_payload))
            same_mechanism["unblock"]["newMechanism"]["fingerprint"] = (
                "release-observability-v1"
            )
            same_mechanism_result = campaign / "same-mechanism.json"
            same_mechanism_result.write_text(json.dumps(same_mechanism) + "\n")
            self.run_cli(
                "submit",
                str(campaign),
                "unblocker",
                unblock_claim["taskId"],
                "--lease-token",
                unblock_claim["leaseToken"],
                "--result",
                str(same_mechanism_result),
                "--idempotency-key",
                "same-mechanism-rejected",
                expected=1,
            )
            unblock_result.write_text(json.dumps(unblock_payload) + "\n")
            self.run_cli(
                "submit",
                str(campaign),
                "unblocker",
                unblock_claim["taskId"],
                "--lease-token",
                unblock_claim["leaseToken"],
                "--result",
                str(unblock_result),
                "--idempotency-key",
                "unblock-adjacent-jit-path-1",
            )
            resumed = json.loads(
                self.run_cli("claim", str(campaign), "explorer", "--json").stdout
            )
            self.assertEqual(resumed["taskId"], "adjacent-jit-path")
            self.assertEqual(resumed["attempt"], 2)

    def test_one_active_task_per_agent_and_priority_ordering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign), "--max-concurrency", "3")
            self.run_cli("queue", str(campaign))
            for worker, agent in (
                ("worker-a", "codex:a"),
                ("worker-a-alias", "codex:a"),
                ("worker-b", "codex:b"),
                ("worker-c", "codex:c"),
                ("worker-d", "codex:d"),
            ):
                self.run_cli("worker-register", str(campaign), worker, "--agent", agent)
            setup = json.loads(
                self.run_cli("claim", str(campaign), "worker-a", "--json").stdout
            )
            result = campaign / "setup.json"
            result.write_text(
                json.dumps(self.valid_task_result("coordinator-setup")) + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "worker-a",
                setup["taskId"],
                "--lease-token",
                setup["leaseToken"],
                "--result",
                str(result),
                "--idempotency-key",
                "setup-priority-test",
            )
            first = json.loads(
                self.run_cli("claim", str(campaign), "worker-a", "--json").stdout
            )
            self.assertEqual(first["taskId"], "public-ingress-map")
            refused = json.loads(
                self.run_cli(
                    "claim", str(campaign), "worker-a-alias", "--json", expected=3
                ).stdout
            )
            self.assertFalse(refused["claimed"])
            self.assertEqual(refused["reason"], "agent-already-holds-running-task")
            self.assertEqual(refused["taskId"], "public-ingress-map")
            second = json.loads(
                self.run_cli("claim", str(campaign), "worker-b", "--json").stdout
            )
            self.assertEqual(second["taskId"], "execution-sink-backtrace")
            third = json.loads(
                self.run_cli("claim", str(campaign), "worker-c", "--json").stdout
            )
            self.assertEqual(third["taskId"], "capability-code-loading-invariants")
            self.run_cli("claim", str(campaign), "worker-d", "--json", expected=3)
            capped = json.loads(
                self.run_cli("orchestration-status", str(campaign), "--json").stdout
            )["schedulerDemand"]
            self.assertTrue(capped["hardCapReached"])
            self.assertFalse(capped["scaleOutOpportunity"])

    def test_auto_capacity_runs_five_distinct_agents_without_lane_quotas(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "setup-agent",
                "--agent",
                "codex:setup",
                "--role",
                "coordinator",
            )
            setup = json.loads(
                self.run_cli("claim", str(campaign), "setup-agent", "--json").stdout
            )
            result = campaign / "auto-setup.json"
            result.write_text(
                json.dumps(self.valid_task_result("coordinator-setup")) + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "setup-agent",
                setup["taskId"],
                "--lease-token",
                setup["leaseToken"],
                "--result",
                str(result),
                "--idempotency-key",
                "auto-setup-1",
            )
            workers = []
            for index in range(5):
                worker = f"parallel-{index}"
                workers.append(worker)
                self.run_cli(
                    "worker-register",
                    str(campaign),
                    worker,
                    "--agent",
                    f"codex:parallel-{index}",
                )
            self.run_cli(
                "worker-register",
                str(campaign),
                "parallel-0-alias",
                "--agent",
                "codex:parallel-0",
            )
            def concurrent_claim(worker: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        sys.executable,
                        str(HARNESS),
                        "claim",
                        str(campaign),
                        worker,
                        "--json",
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                completed = list(executor.map(concurrent_claim, workers))
            for item in completed:
                self.assertEqual(item.returncode, 0, msg=item.stderr)
            claimed = [json.loads(item.stdout) for item in completed]
            self.assertEqual(
                {item["taskId"] for item in claimed},
                {
                    "public-ingress-map",
                    "execution-sink-backtrace",
                    "capability-code-loading-invariants",
                    "parser-representation-invariants",
                    "dependency-boundary-audit",
                },
            )
            self.assertEqual(len({item["taskId"] for item in claimed}), 5)
            status = json.loads(
                self.run_cli("orchestration-status", str(campaign), "--json").stdout
            )
            demand = status["schedulerDemand"]
            self.assertEqual(demand["configuredConcurrency"], "auto")
            self.assertEqual(demand["activeAgentIdentities"], 6)
            self.assertEqual(demand["running"], 5)

    def test_scheduler_prevents_priority_driven_approach_family_dominance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            for worker in ("setup", "agent-a", "agent-b", "agent-c"):
                self.run_cli(
                    "worker-register",
                    str(campaign),
                    worker,
                    "--agent",
                    f"codex:{worker}",
                )
            setup = json.loads(
                self.run_cli("claim", str(campaign), "setup", "--json").stdout
            )
            setup_result = campaign / "approach-setup.json"
            setup_result.write_text(
                json.dumps(self.valid_task_result("coordinator-setup")) + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "setup",
                setup["taskId"],
                "--lease-token",
                setup["leaseToken"],
                "--result",
                str(setup_result),
                "--idempotency-key",
                "approach-setup-1",
            )
            for suffix in ("one", "two", "three"):
                self.run_cli(
                    "task-add",
                    str(campaign),
                    f"same-family-{suffix}",
                    "--title",
                    f"Representation experiment {suffix}",
                    "--lane",
                    "representation-experiment",
                    "--approach-family",
                    "representation-parser",
                    "--objective",
                    "Test the same producer-consumer invariant family.",
                    "--success-criterion",
                    "Retain a source-derived result.",
                    "--priority",
                    "4000",
                )
            first = json.loads(
                self.run_cli("claim", str(campaign), "agent-a", "--json").stdout
            )
            redirected = json.loads(
                self.run_cli("claim", str(campaign), "agent-b", "--json").stdout
            )
            self.assertEqual(first["approachFamilies"], ["representation-parser"])
            self.assertNotIn("representation-parser", redirected["approachFamilies"])
            self.assertIsNotNone(redirected["approachRedirect"])
            self.assertIn(
                "representation-parser",
                redirected["approachRedirect"]["dominatedFamilies"],
            )
            self.assertIn("raw task priority", redirected["approachRedirect"]["reason"])
            third = json.loads(
                self.run_cli("claim", str(campaign), "agent-c", "--json").stdout
            )
            self.assertNotIn("representation-parser", third["approachFamilies"])
            status = json.loads(
                self.run_cli("approach-status", str(campaign), "--json").stdout
            )
            family = next(
                item for item in status["families"] if item["id"] == "representation-parser"
            )
            self.assertEqual(family["activeAgents"], 1)
            self.assertIn("producer", family["boundary"])
            self.assertIn("domain", family["invariant"])

    def test_rounds_keep_incompatible_routes_independent_and_adversarial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "root",
                "--agent",
                "codex:root",
                "--role",
                "coordinator",
            )
            for worker in (
                "dev-a",
                "dev-b",
                "dev-c",
                "review-a",
                "review-b",
                "review-c",
                "chain-worker",
            ):
                self.run_cli(
                    "worker-register",
                    str(campaign),
                    worker,
                    "--agent",
                    f"codex:{worker}",
                )

            def round_plan(number: int, *, cross: bool = False) -> Path:
                payload: dict[str, object] = {
                    "round": number,
                    "routes": [
                        {
                            "criticalBoundary": self.chain_contract("route-ingress")["criticalBoundary"],
                            "id": "route-ingress",
                            "family": "ingress-authority",
                            "title": "Ingress authority route",
                            "objective": "Test a missing authority transition.",
                            "successCriteria": ["Retain exact reachability evidence."],
                            "incompatibleWith": ["route-parser", "route-memory"],
                        },
                        {
                            "criticalBoundary": self.chain_contract("route-parser")["criticalBoundary"],
                            "id": "route-parser",
                            "family": "representation-parser",
                            "title": "Representation route",
                            "objective": "Test a producer-consumer disagreement.",
                            "successCriteria": ["Retain a differential result."],
                            "incompatibleWith": ["route-ingress", "route-memory"],
                        },
                        {
                            "criticalBoundary": self.chain_contract("route-memory")["criticalBoundary"],
                            "id": "route-memory",
                            "family": "memory-lifetime",
                            "title": "Lifetime route",
                            "objective": "Test an ownership invariant.",
                            "successCriteria": ["Retain lifetime evidence."],
                            "incompatibleWith": ["route-ingress", "route-parser"],
                        },
                    ],
                    "crossPollinations": [],
                }
                if cross:
                    payload["crossPollinations"] = [
                        {
                            "id": "early-composition",
                            "leftRoute": "route-ingress",
                            "rightRoute": "route-parser",
                            "title": "Premature composition",
                            "objective": "Combine the routes.",
                            "successCriteria": ["Reach a composed primitive."],
                        }
                    ]
                path = campaign / f"round-{number}{'-cross' if cross else ''}.json"
                path.write_text(json.dumps(payload) + "\n")
                return path

            self.run_cli(
                "round-plan",
                str(campaign),
                "root",
                "--plan",
                str(round_plan(1)),
            )
            development_claims = []
            for worker in ("dev-a", "dev-b", "dev-c"):
                claim = json.loads(
                    self.run_cli("claim", str(campaign), worker, "--json").stdout
                )
                self.assertEqual(claim["taskKind"], "route-development")
                development_claims.append((worker, claim))
            self.assertEqual(
                len({claim["routeId"] for _, claim in development_claims}), 3
            )
            for worker, claim in development_claims:
                payload = self.valid_task_result(claim["taskId"])
                has_intermediate = claim["routeId"] == "route-ingress"
                payload["routeDevelopment"] = {
                    "criticalBoundary": self.chain_contract(claim["routeId"])["criticalBoundary"],
                    "routeId": claim["routeId"],
                    "round": 1,
                    "strengths": ["One source-derived invariant is testable."],
                    "gaps": ["The terminal is not yet established."],
                    "evidence": [f"evidence/{claim['routeId']}.json"],
                    "nextExperiment": "Exercise the cheapest runtime discriminator.",
                    "freshIdeas": ["Trace a sibling consumer with a different guard."],
                    "intermediateBugs": (
                        [
                            {
                                **self.chain_contract("ingress-intermediate"),
                                "id": "IB-INGRESS-1",
                                "rootCause": "An authority check observes a different representation.",
                                "primitive": "attacker-controlled privileged state transition",
                                "evidence": ["evidence/ingress-intermediate.json"],
                            }
                        ]
                        if has_intermediate
                        else []
                    ),
                    "chainHypotheses": (
                        ["Compose the authority transition with a retained execution sink."]
                        if has_intermediate
                        else []
                    ),
                }
                result_path = campaign / f"{claim['taskId']}.json"
                result_path.write_text(json.dumps(payload) + "\n")
                self.run_cli(
                    "submit",
                    str(campaign),
                    worker,
                    claim["taskId"],
                    "--lease-token",
                    claim["leaseToken"],
                    "--result",
                    str(result_path),
                    "--idempotency-key",
                    f"{claim['taskId']}-1",
                )

            review_claims = []
            for worker in ("review-a", "review-b", "review-c"):
                claim = json.loads(
                    self.run_cli("claim", str(campaign), worker, "--json").stdout
                )
                self.assertEqual(claim["taskKind"], "adversarial-route-review")
                review_claims.append((worker, claim))
            for worker, claim in review_claims:
                payload = self.valid_task_result(claim["taskId"])
                payload["adversarialReview"] = {
                    "reviewedTaskId": claim["reviewsTaskId"],
                    "routeId": claim["routeId"],
                    "round": 1,
                    "sanityPassed": True,
                    "strongestCounterargument": "The observed effect may stop before impact.",
                    "evidence": [f"evidence/{claim['routeId']}-review.json"],
                    "unresolvedGaps": ["Prove the terminal independently."],
                }
                result_path = campaign / f"{claim['taskId']}.json"
                result_path.write_text(json.dumps(payload) + "\n")
                self.run_cli(
                    "submit",
                    str(campaign),
                    worker,
                    claim["taskId"],
                    "--lease-token",
                    claim["leaseToken"],
                    "--result",
                    str(result_path),
                    "--idempotency-key",
                    f"{claim['taskId']}-1",
                )

            campaign_graph = campaign / "evidence" / "chain-graphs" / "campaign-latest.json"
            self.assertTrue(campaign_graph.is_file())
            graph_record = json.loads(campaign_graph.read_text())
            self.assertEqual(graph_record["graphVersion"], 1)
            self.assertIn("origins", graph_record)

            chain_claim = json.loads(
                self.run_cli("claim", str(campaign), "chain-worker", "--json").stdout
            )
            self.assertEqual(chain_claim["taskKind"], "intermediate-chain-composition")
            chain_payload = self.valid_task_result(chain_claim["taskId"])
            chain_payload["chainComposition"] = {
                "sourceIntermediateBugs": ["IB-INGRESS-1"],
                "attemptedChains": ["authority transition -> stock execution sink"],
                "outcome": "The first composition remains blocked at argument adaptation.",
                "freshIdeas": ["Try the sibling sink with compatible argument shape."],
                "evidence": ["evidence/intermediate-chain.json"],
            }
            chain_result = campaign / "intermediate-chain.json"
            chain_result.write_text(json.dumps(chain_payload) + "\n")
            self.run_cli(
                "submit",
                str(campaign),
                "chain-worker",
                chain_claim["taskId"],
                "--lease-token",
                chain_claim["leaseToken"],
                "--result",
                str(chain_result),
                "--idempotency-key",
                "intermediate-chain-1",
            )

            synthesis = json.loads(
                self.run_cli("claim", str(campaign), "root", "--json").stdout
            )
            self.assertEqual(synthesis["taskKind"], "root-round-synthesis")
            synthesis_payload = self.valid_task_result(synthesis["taskId"])
            synthesis_payload["roundSynthesis"] = {
                "round": 1,
                "routes": [
                    {
                        "routeId": route_id,
                        "strengths": ["The route has independent evidence."],
                        "gaps": ["The terminal remains open."],
                        "decision": "continue",
                        "nextExperiment": "Run the next bounded discriminator.",
                    }
                    for route_id in ("route-ingress", "route-parser", "route-memory")
                ],
                "challenges": ["Challenge reachability and attacker control again."],
                "redirects": [],
                "freshIdeas": [
                    "Test a sibling parser.",
                    "Backtrace an alternate sink.",
                    "Measure another acquisition path.",
                ],
                "intermediateChains": [
                    {
                        "sourceIntermediateBugs": ["IB-INGRESS-1"],
                        "outcome": "Argument adaptation still blocks the stock sink.",
                        "nextExperiment": "Try the sibling sink with compatible arguments.",
                    }
                ],
                "launchNextRound": True,
                "nextRoundDirections": [
                    "Retain all routes and test their cheapest missing links."
                ],
            }
            synthesis_result = campaign / "round-1-synthesis.json"
            synthesis_result.write_text(json.dumps(synthesis_payload) + "\n")
            self.run_cli(
                "submit",
                str(campaign),
                "root",
                synthesis["taskId"],
                "--lease-token",
                synthesis["leaseToken"],
                "--result",
                str(synthesis_result),
                "--idempotency-key",
                "round-1-synthesis-1",
            )

            next_round_planning = json.loads(
                self.run_cli("claim", str(campaign), "root", "--json").stdout
            )
            self.assertEqual(next_round_planning["taskKind"], "next-round-planning")

            self.run_cli(
                "round-plan",
                str(campaign),
                "root",
                "--plan",
                str(round_plan(2, cross=True)),
                expected=1,
            )
            self.run_cli(
                "round-plan",
                str(campaign),
                "root",
                "--plan",
                str(round_plan(2)),
            )
            planning_payload = self.valid_task_result(next_round_planning["taskId"])
            planning_payload["nextRoundPlanning"] = {
                "fromRound": 1,
                "launchedRound": 2,
                "planPath": "round-2.json",
                "launchedTaskIds": [
                    "round-2-route-ingress-develop",
                    "round-2-route-parser-develop",
                    "round-2-route-memory-develop",
                    "round-2-root-synthesis",
                ],
            }
            planning_result = campaign / "round-2-planning-result.json"
            planning_result.write_text(json.dumps(planning_payload) + "\n")
            self.run_cli(
                "submit",
                str(campaign),
                "root",
                next_round_planning["taskId"],
                "--lease-token",
                next_round_planning["leaseToken"],
                "--result",
                str(planning_result),
                "--idempotency-key",
                "round-2-planning-1",
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            rounds = database.execute(
                "SELECT COUNT(DISTINCT research_round) FROM tasks "
                "WHERE task_kind='route-development'"
            ).fetchone()[0]
            review_count = database.execute(
                "SELECT COUNT(*) FROM tasks WHERE task_kind='adversarial-route-review'"
            ).fetchone()[0]
            database.close()
            self.assertEqual(rounds, 2)
            self.assertEqual(review_count, 6)

    def test_no_findings_is_not_a_valid_round_stop(self) -> None:
        from scripts.research_harness import validate_round_synthesis_result

        result = {
            "roundSynthesis": {
                "round": 1,
                "routes": [
                    {
                        "routeId": route_id,
                        "strengths": ["The route was examined."],
                        "gaps": ["No terminal was found."],
                        "decision": "no finding",
                        "nextExperiment": "Search an adjacent mechanism.",
                    }
                    for route_id in ("a", "b", "c")
                ],
                "challenges": ["Challenge the current search boundary."],
                "redirects": [],
                "freshIdeas": ["idea-a", "idea-b", "idea-c"],
                "intermediateChains": [],
                "launchNextRound": False,
            }
        }
        with self.assertRaises(SystemExit):
            validate_round_synthesis_result(result, 1)

    def test_scheduler_demand_requests_new_agent_for_excluded_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register", str(campaign), "origin", "--agent", "codex:origin"
            )
            self.run_cli(
                "register",
                str(campaign),
                "FDEMAND",
                "--title",
                "Replay demand",
                "--lane",
                "cross-lane-chain-composition",
                "--originator",
                "origin",
            )
            self.run_cli(
                "schedule-replay",
                str(campaign),
                "FDEMAND",
                "--task-id",
                "replay-FDEMAND",
            )
            demand = json.loads(
                self.run_cli("orchestration-status", str(campaign), "--json").stdout
            )["schedulerDemand"]
            self.assertEqual(demand["resolvedConcurrency"], 1)
            self.assertEqual(demand["runnableTasks"], 2)
            self.assertEqual(demand["claimableByActiveAgents"], 1)
            self.assertEqual(demand["recommendedClaims"], 1)
            self.assertTrue(demand["scaleOutOpportunity"])

    def test_transitive_dependency_block_requires_root_unblock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register", str(campaign), "worker", "--agent", "codex:worker"
            )
            self.run_cli(
                "task-add",
                str(campaign),
                "root-failure",
                "--title",
                "Root blocker",
                "--lane",
                "blocker-test",
                "--approach-family",
                "blocker-alternative-route",
                "--objective",
                "Prove the root blocker.",
                "--success-criterion",
                "Retain root evidence.",
                "--priority",
                "3000",
            )
            self.run_cli(
                "task-add",
                str(campaign),
                "dependent-task",
                "--title",
                "Dependent",
                "--lane",
                "blocker-test",
                "--approach-family",
                "blocker-alternative-route",
                "--objective",
                "Consume the root result.",
                "--success-criterion",
                "Reach the dependent path.",
                "--depends-on",
                "root-failure",
                "--priority",
                "2900",
            )
            claimed = json.loads(
                self.run_cli("claim", str(campaign), "worker", "--json").stdout
            )
            failure = campaign / "failure.json"
            failure.write_text(
                json.dumps(
                    {
                        "failure": {
                            "category": "source-level-falsification",
                            "reason": "The root hypothesis was disproved.",
                            "evidence": ["evidence/root-failure.json"],
                            "analysisProvenance": {
                                "firstPrinciplesOnly": True,
                                "changelogUsed": False,
                                "gitHistoryUsed": False,
                                "advisoryMiningUsed": False,
                                "patchedVersionDiffUsed": False,
                                "internetPatchDiffUsed": False,
                            },
                        }
                    }
                )
                + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "worker",
                claimed["taskId"],
                "--lease-token",
                claimed["leaseToken"],
                "--result",
                str(failure),
                "--idempotency-key",
                "root-failure-1",
                "--outcome",
                "failed",
            )
            self.run_cli("recover", str(campaign))
            rejected = self.run_cli(
                "schedule-unblock",
                str(campaign),
                "dependent-task",
                "--title",
                "Wrong level",
                "--strategy",
                "Resolve the propagated block.",
                "--success-criterion",
                "Dependent becomes runnable.",
                expected=1,
            )
            self.assertIn("root-failure", rejected.stderr)
            self.run_cli(
                "schedule-unblock",
                str(campaign),
                "root-failure",
                "--title",
                "Resolve root",
                "--strategy",
                "Resolve the real blocker.",
                "--success-criterion",
                "Root can resume.",
                "--priority",
                "4000",
            )
            unblock = json.loads(
                self.run_cli("claim", str(campaign), "worker", "--json").stdout
            )
            self.assertTrue(unblock["taskId"].startswith("unblock-root-failure"))
            unblock_payload = self.valid_task_result(unblock["taskId"])
            unblock_payload["unblock"] = {
                "blockedTaskId": "root-failure",
                "blockerAddressed": True,
                "evidence": ["evidence/root-unblocked.json"],
                "resumeStrategy": "Resume the root task with the recovered prerequisite.",
                "newMechanism": {
                    "fingerprint": "root-alternate-proof-v2",
                    "differsFrom": "failure:source-level-falsification",
                    "mechanism": "test an alternate source-derived proof route",
                    "difference": "does not reuse the falsified root hypothesis",
                    "evidence": ["evidence/root-alternate-proof.json"],
                },
            }
            unblock_result = campaign / "root-unblock.json"
            unblock_result.write_text(json.dumps(unblock_payload) + "\n")
            self.run_cli(
                "submit",
                str(campaign),
                "worker",
                unblock["taskId"],
                "--lease-token",
                unblock["leaseToken"],
                "--result",
                str(unblock_result),
                "--idempotency-key",
                "root-unblock-1",
            )
            resumed_root = json.loads(
                self.run_cli("claim", str(campaign), "worker", "--json").stdout
            )
            self.assertEqual(resumed_root["taskId"], "root-failure")
            root_result = campaign / "root-completed.json"
            root_result.write_text(
                json.dumps(self.valid_task_result("root-failure")) + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "worker",
                "root-failure",
                "--lease-token",
                resumed_root["leaseToken"],
                "--result",
                str(root_result),
                "--idempotency-key",
                "root-resumed-2",
            )
            dependent = json.loads(
                self.run_cli("claim", str(campaign), "worker", "--json").stdout
            )
            self.assertEqual(dependent["taskId"], "dependent-task")

    def test_automatic_blocker_breakout_recurses_on_new_technical_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            for worker in ("origin", "fresh-one", "fresh-two"):
                self.run_cli(
                    "worker-register",
                    str(campaign),
                    worker,
                    "--agent",
                    f"codex:{worker}",
                )
            self.run_cli(
                "task-add",
                str(campaign),
                "blocked-chain",
                "--title",
                "Blocked chain",
                "--lane",
                "blocker-loop-test",
                "--approach-family",
                "blocker-alternative-route",
                "--objective",
                "Reach the execution boundary.",
                "--success-criterion",
                "Resolve or precisely classify the guard.",
                "--priority",
                "3000",
            )
            original = json.loads(
                self.run_cli("claim", str(campaign), "origin", "--json").stdout
            )
            first_blocker = campaign / "first-blocker.json"
            first_blocker.write_text(
                json.dumps(self.valid_blocker_result("ingress-to-primitive")) + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "origin",
                original["taskId"],
                "--lease-token",
                original["leaseToken"],
                "--result",
                str(first_blocker),
                "--idempotency-key",
                "first-blocker-1",
                "--outcome",
                "blocked",
            )
            first_breakout = json.loads(
                self.run_cli("claim", str(campaign), "fresh-one", "--json").stdout
            )
            self.assertEqual(first_breakout["lane"], "automatic-blocker-breakout")
            second_blocker = campaign / "second-blocker.json"
            second_blocker.write_text(
                json.dumps(self.valid_blocker_result("primitive-to-execution")) + "\n"
            )
            self.run_cli(
                "submit",
                str(campaign),
                "fresh-one",
                first_breakout["taskId"],
                "--lease-token",
                first_breakout["leaseToken"],
                "--result",
                str(second_blocker),
                "--idempotency-key",
                "second-blocker-1",
                "--outcome",
                "blocked",
            )
            second_breakout = json.loads(
                self.run_cli("claim", str(campaign), "fresh-two", "--json").stdout
            )
            self.assertEqual(second_breakout["lane"], "automatic-blocker-breakout")
            self.assertNotEqual(first_breakout["taskId"], second_breakout["taskId"])

    def test_automatic_blocker_breakout_does_not_bypass_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register", str(campaign), "origin", "--agent", "codex:origin"
            )
            self.run_cli(
                "task-add",
                str(campaign),
                "authority-blocked-chain",
                "--title",
                "Authority-blocked chain",
                "--lane",
                "blocker-loop-test",
                "--approach-family",
                "blocker-alternative-route",
                "--objective",
                "Exercise only the authorized boundary.",
                "--success-criterion",
                "Identify whether additional authority is required.",
                "--priority",
                "3000",
            )
            claimed = json.loads(
                self.run_cli("claim", str(campaign), "origin", "--json").stdout
            )
            result = self.valid_blocker_result("owned-lab-to-shared-testnet")
            result["blocker"]["canSelfResolve"] = False
            result["blocker"]["authorityRequired"] = "explicit testnet permission"
            blocker_path = campaign / "authority-blocker.json"
            blocker_path.write_text(json.dumps(result) + "\n")
            self.run_cli(
                "submit",
                str(campaign),
                "origin",
                claimed["taskId"],
                "--lease-token",
                claimed["leaseToken"],
                "--result",
                str(blocker_path),
                "--idempotency-key",
                "authority-blocker-1",
                "--outcome",
                "blocked",
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            child_count = database.execute(
                "SELECT COUNT(*) FROM tasks WHERE unblocks_task_id=?",
                ("authority-blocked-chain",),
            ).fetchone()[0]
            database.close()
            self.assertEqual(child_count, 0)

    def test_replay_scheduler_cannot_complete_before_machine_verified_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            self.run_cli(
                "worker-register",
                str(campaign),
                "scheduler",
                "--agent",
                "codex:scheduler",
            )
            self.run_cli(
                "worker-register",
                str(campaign),
                "origin",
                "--agent",
                "codex:origin",
            )
            self.run_cli(
                "register",
                str(campaign),
                "FNOREPLAY",
                "--title",
                "Unverified chain",
                "--lane",
                "cross-lane-chain-composition",
                "--originator",
                "origin",
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            database.execute(
                "UPDATE tasks SET state='completed' WHERE task_id='critical-controls-reliability'"
            )
            database.execute(
                "UPDATE tasks SET priority=5000 WHERE task_id='finding-scoped-replay-scheduler'"
            )
            database.commit()
            database.close()
            claimed = json.loads(
                self.run_cli("claim", str(campaign), "scheduler", "--json").stdout
            )
            self.assertEqual(claimed["taskId"], "finding-scoped-replay-scheduler")
            payload = self.valid_task_result("finding-scoped-replay-scheduler")
            payload["taskResult"]["replayFindings"] = ["FNOREPLAY"]
            result = campaign / "unverified-scheduler.json"
            result.write_text(json.dumps(payload) + "\n")
            self.run_cli(
                "submit",
                str(campaign),
                "scheduler",
                claimed["taskId"],
                "--lease-token",
                claimed["leaseToken"],
                "--result",
                str(result),
                "--idempotency-key",
                "unverified-scheduler-1",
                expected=1,
            )
            database = sqlite3.connect(campaign / "orchestration.db")
            state = database.execute(
                "SELECT state FROM tasks WHERE task_id='finding-scoped-replay-scheduler'"
            ).fetchone()[0]
            database.close()
            self.assertEqual(state, "running")

    def test_hash_and_lint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            (campaign / "reports" / "REPORT.md").write_text("# Exact pinned report\n", encoding="utf-8")
            self.run_cli("hash", str(campaign))
            manifest = (campaign / "SHA256SUMS").read_text()
            self.assertIn("reports/REPORT.md", manifest)
            self.assertIn("campaign.json", manifest)
            self.run_cli("lint", str(campaign), "--strict")

    def test_tool_probe_is_json(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(PROBE), "--json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, msg=completed.stderr)
        payload = json.loads(completed.stdout)
        self.assertIn("commands", payload)
        self.assertIn("trailmark", payload["commands"])
        self.assertIn("joern", payload["commands"])
        self.assertIn("tree-sitter", payload["commands"])
        self.assertIn("z3", payload["commands"])
        self.assertIn("gn", payload["commands"])
        self.assertIn("autoninja", payload["commands"])
        self.assertIn("llvm-symbolizer", payload["commands"])
        self.assertIn("swift", payload["commands"])
        self.assertIn("xcrun", payload["commands"])
        self.assertIn(payload["platform"]["architecture"], {"arm64", "x86_64"})
        self.assertIn("z3", payload["pythonModules"])


if __name__ == "__main__":
    unittest.main()
