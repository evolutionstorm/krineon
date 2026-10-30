from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.path_proof_fixture import install_machine_path_evidence


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "research_harness.py"
PATH_PROOF = PROJECT / "scripts" / "path_proof.py"

PROHIBITED_DISCOVERY_INPUTS = {
    "changelogs",
    "git-history",
    "advisories",
    "patched-version-comparisons",
    "internet-patch-diffing",
}

CRITICAL_CHAIN_GATES = {
    "critical_chain_complete",
    "stock_or_supported_reachability",
    "rce_or_critical_impact",
    "no_app_authored_sink",
    "harmless_real_terminal",
    "deployment_feasible",
    "production_equivalent_environment",
}

PROVENANCE_FLAGS = (
    "changelogUsed",
    "gitHistoryUsed",
    "advisoryMiningUsed",
    "patchedVersionDiffUsed",
    "internetPatchDiffUsed",
)


class CriticalRceContractTests(unittest.TestCase):
    def run_cli(
        self, *args: str, expected: int = 0
    ) -> subprocess.CompletedProcess[str]:
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

    def create_campaign(self, root: Path) -> Path:
        campaign = root / "campaign"
        self.run_cli(
            "init",
            str(campaign),
            "--target",
            "source-target",
            "--repo",
            "https://example.invalid/source-target",
            "--commit",
            "0123456789abcdef",
        )
        (campaign / "evidence" / "coordinator-gate.json").write_text(
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
        self, campaign: Path, finding_id: str, originator: str = "origin-worker"
    ) -> None:
        self.run_cli("plan", str(campaign))
        self.run_cli("queue", str(campaign))
        self.run_cli(
            "worker-register",
            str(campaign),
            originator,
            "--agent",
            f"codex:{originator}",
            "--role",
            "originator",
        )
        self.run_cli(
            "worker-register",
            str(campaign),
            "review-worker",
            "--agent",
            "codex:review-worker",
            "--role",
            "reviewer",
        )
        completed = subprocess.run(
            [sys.executable, str(PATH_PROOF), "init", str(campaign), finding_id],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        proof = install_machine_path_evidence(
            campaign, finding_id, originator, "review-worker"
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
        self.install_controlled_experiment(campaign, finding_id)

    def install_controlled_experiment(
        self, campaign: Path, finding_id: str
    ) -> None:
        from scripts.research_harness import coordinator_reexecute_result

        campaign_record = json.loads((campaign / "campaign.json").read_text())
        if "experimentAuthority" not in campaign_record:
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            campaign_record = json.loads((campaign / "campaign.json").read_text())
        target = campaign / "evidence" / "bin" / "controlled_target.py"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            (PROJECT / "tests" / "fixtures" / "reality_target.py").read_bytes()
        )
        target_name = target.relative_to(campaign).as_posix()
        frozen = [
            value
            for value in campaign_record.get("frozenTargetArtifacts", [])
            if isinstance(value, dict) and value.get("path") != target_name
        ]
        frozen.append(
            {
                "path": target_name,
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                "producer": "critical-contract-fixture",
            }
        )
        campaign_record["frozenTargetArtifacts"] = frozen
        (campaign / "campaign.json").write_text(
            json.dumps(campaign_record, indent=2) + "\n"
        )
        recipe = campaign / "evidence" / "recipes" / f"controlled-{finding_id}.json"
        recipe.parent.mkdir(parents=True, exist_ok=True)
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
    def complete_chain(self, finding: dict[str, object], *, impact_class: str = "rce") -> None:
        gates = finding["gates"]
        assert isinstance(gates, dict)
        for gate in gates:
            gates[gate] = True
        finding.update(
            {
                "impactClass": impact_class,
                "rootCause": (
                    "A producer and consumer disagree about an attacker-controlled object."
                ),
                "ingress": "Unauthenticated request in the supported server path.",
                "carrier": "Framework-created object reaching the vulnerable consumer.",
                "terminal": (
                    "Bounded execution of a harmless identity command in an owned lab."
                ),
                "impact": "Attacker-controlled code executes in the server process.",
                "preconditions": ["stock production build", "supported configuration"],
                "attackerAcquisition": ["all coordinates recovered from public output"],
                "evidence": ["evidence/three-case-matrix.json"],
                "chain": {
                    "attacker": "unauthenticated remote client",
                    "ingress": "supported HTTP request handler",
                    "attackerControl": "request body bytes and public identifiers",
                    "transformations": ["decode", "unsafe object construction"],
                    "brokenInvariant": "validated representation differs from consumed state",
                    "primitive": "attacker-directed function selection and arguments",
                    "executionOrCriticalSink": "stock runtime function invocation",
                    "terminal": "bounded identity command executes in the target process",
                    "remoteAcquisition": "all coordinates come from public protocol output",
                    "deployment": "unmodified supported production build",
                    "applicationAuthoredSink": False,
                },
                "terminalEvidence": {
                    "type": "bounded-command-execution",
                    "commandOrEffect": "id output from the target process",
                    "synthetic": False,
                },
                "executionEnvironment": {
                    "environmentClass": "production-equivalent",
                    "developmentServer": False,
                    "developmentBuild": False,
                    "supportedConfiguration": True,
                    "primaryTerminalObserved": True,
                    "commandOrEntrypoint": "production server entrypoint",
                    "evidence": ["evidence/production-environment.json"],
                },
                "controls": {
                    "baseline": "ordinary request succeeds",
                    "negative": "enforcing control rejects the chain",
                    "positive": "only the disputed condition reaches bounded execution",
                    "invariantRestored": "same revision with a sanitized carrier is blocked",
                },
                "analysisProvenance": {
                    "firstPrinciplesOnly": True,
                    "changelogUsed": False,
                    "gitHistoryUsed": False,
                    "advisoryMiningUsed": False,
                    "patchedVersionDiffUsed": False,
                    "internetPatchDiffUsed": False,
                },
            }
        )

    def test_default_campaign_is_critical_rce_first_principles_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            campaign_json = json.loads((campaign / "campaign.json").read_text())
            self.assertEqual(campaign_json["profile"], "critical-rce")
            self.assertEqual(campaign_json["mission"], "critical-rce-chain")
            policy = campaign_json["discoveryPolicy"]
            self.assertTrue(policy["firstPrinciplesOnly"])
            self.assertEqual(
                set(policy["prohibitedDiscoveryInputs"]),
                PROHIBITED_DISCOVERY_INPUTS,
            )
            self.assertIn("pinned-source", policy["allowedDiscoveryBasis"])
            self.assertIn("runtime-behavior", policy["allowedDiscoveryBasis"])

            self.run_cli("plan", str(campaign))
            launch = json.loads((campaign / "launch-plan.json").read_text())
            self.assertEqual(launch["profile"], "critical-rce")
            self.assertEqual(launch["mission"], "critical-rce-chain")
            self.assertEqual(launch["maxConcurrency"], "auto")
            self.assertFalse(launch["schedulingPolicy"]["fixedWorkersPerLane"])
            self.assertTrue(
                launch["schedulingPolicy"]["preferFourOrMoreWorkersWhenAvailable"]
            )
            self.assertFalse(
                launch["schedulingPolicy"]["allowPromiseBasedDominance"]
            )
            self.assertEqual(
                launch["schedulingPolicy"]["approachFamilyBalancing"],
                "active-load-then-coverage-before-priority",
            )
            self.assertEqual(
                set(launch["discoveryPolicy"]["prohibitedDiscoveryInputs"]),
                PROHIBITED_DISCOVERY_INPUTS,
            )
            self.assertGreaterEqual(len(launch["tasks"]), 10)
            first_wave = [
                task
                for task in launch["tasks"]
                if task["dependsOn"] == ["coordinator-setup"]
            ]
            self.assertGreaterEqual(len(first_wave), 5)

            # The machine policy is also embedded in each independently claimed
            # packet so an external worker cannot miss the coordinator setting.
            for task in launch["tasks"]:
                packet = (campaign / task["task"]).read_text(encoding="utf-8")
                self.assertIn("## Critical/RCE mission", packet)
                self.assertIn("first-principles", packet.lower())
                self.assertIn("internet-based patch diff", packet.lower())
                self.assertIn("pinned source", packet.lower())

    def test_candidate_gate_rejects_a_primitive_without_complete_critical_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli(
                "register",
                str(campaign),
                "F001",
                "--title",
                "Primitive without terminal",
                "--lane",
                "sink-first",
            )
            finding_path = campaign / "findings" / "F001.json"
            finding = json.loads(finding_path.read_text())
            self.assertTrue(CRITICAL_CHAIN_GATES.issubset(finding["gates"]))
            self.run_cli("plan", str(campaign))
            self.run_cli("queue", str(campaign))
            campaign_record = json.loads((campaign / "campaign.json").read_text())
            campaign_record["authorization"]["confirmed"] = True
            campaign_record["authorization"]["basis"] = "owned contract fixture"
            (campaign / "campaign.json").write_text(
                json.dumps(campaign_record, indent=2) + "\n"
            )
            self.install_controlled_experiment(campaign, "F001")
            finding = json.loads(finding_path.read_text())

            # Satisfying the legacy evidence gates must not promote a crash,
            # primitive, or medium/high issue without a complete Critical/RCE
            # chain and a stock/supported execution path.
            for gate in finding["gates"]:
                if gate not in CRITICAL_CHAIN_GATES:
                    finding["gates"][gate] = True
            finding.update(
                {
                    "rootCause": "An untrusted length reaches an unsafe consumer.",
                    "impact": "A process crash is reproducible.",
                    "preconditions": ["stock build"],
                    "evidence": ["evidence/crash.json"],
                    "controls": {
                        "baseline": "valid input succeeds",
                        "negative": "bounded input is rejected",
                        "positive": "oversized input crashes",
                        "invariantRestored": "",
                    },
                }
            )
            finding_path.write_text(json.dumps(finding, indent=2) + "\n")
            result = json.loads(
                self.run_cli(
                    "gate",
                    str(campaign),
                    "F001",
                    "--level",
                    "candidate",
                    "--json",
                    expected=1,
                ).stdout
            )
            self.assertEqual(
                set(result["missingGates"]),
                CRITICAL_CHAIN_GATES,
            )

    def test_chrome_profile_has_no_patch_or_history_discovery_lane(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Path(tmp) / "chrome-campaign"
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
            task_ids = {task["taskId"] for task in launch["tasks"]}
            self.assertNotIn("v8-patch-variants", task_ids)
            self.assertIn("v8-execution-sink-backtrace", task_ids)
            for task in launch["tasks"]:
                packet = (campaign / task["task"]).read_text(encoding="utf-8").lower()
                self.assertIn("do not use changelogs", packet)
                self.assertIn("internet-based patch diff", packet)

    def test_complete_critical_chain_fields_and_gates_can_reach_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli(
                "register",
                str(campaign),
                "F002",
                "--title",
                "Complete bounded RCE chain",
                "--lane",
                "chain-composition",
                "--originator",
                "origin-worker",
            )
            self.install_valid_path_proof(campaign, "F002")
            finding_path = campaign / "findings" / "F002.json"
            finding = json.loads(finding_path.read_text())
            self.complete_chain(finding)
            finding_path.write_text(json.dumps(finding, indent=2) + "\n")
            self.run_cli("gate", str(campaign), "F002", "--level", "candidate")

    def test_low_impact_finding_is_rejected_even_if_booleans_are_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli(
                "register",
                str(campaign),
                "F003",
                "--title",
                "High-only finding",
                "--lane",
                "chain-composition",
            )
            finding_path = campaign / "findings" / "F003.json"
            finding = json.loads(finding_path.read_text())
            self.complete_chain(finding, impact_class="high")
            finding_path.write_text(json.dumps(finding, indent=2) + "\n")
            result = json.loads(
                self.run_cli(
                    "gate",
                    str(campaign),
                    "F003",
                    "--level",
                    "candidate",
                    "--json",
                    expected=1,
                ).stdout
            )
            self.assertFalse(result["passed"])

    def test_development_server_finding_is_rejected_even_if_booleans_are_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli(
                "register",
                str(campaign),
                "FDEV",
                "--title",
                "Development-server-only terminal",
                "--lane",
                "chain-composition",
            )
            finding_path = campaign / "findings" / "FDEV.json"
            finding = json.loads(finding_path.read_text())
            self.complete_chain(finding)
            finding["executionEnvironment"].update(
                {
                    "environmentClass": "development",
                    "developmentServer": True,
                    "developmentBuild": True,
                    "commandOrEntrypoint": "framework dev server",
                    "evidence": ["evidence/dev-only.json"],
                }
            )
            finding_path.write_text(json.dumps(finding, indent=2) + "\n")
            result = json.loads(
                self.run_cli(
                    "gate",
                    str(campaign),
                    "FDEV",
                    "--level",
                    "candidate",
                    "--json",
                    expected=1,
                ).stdout
            )
            self.assertFalse(result["passed"])
            self.assertIn(
                "executionEnvironment.developmentServer:false",
                result["missingFields"],
            )

    def test_any_prohibited_analysis_provenance_rejects_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli(
                "register",
                str(campaign),
                "F004",
                "--title",
                "Provenance enforcement",
                "--lane",
                "chain-composition",
                "--originator",
                "origin-worker",
            )
            self.install_valid_path_proof(campaign, "F004")
            finding_path = campaign / "findings" / "F004.json"
            finding = json.loads(finding_path.read_text())
            self.complete_chain(finding)
            finding_path.write_text(json.dumps(finding, indent=2) + "\n")
            self.run_cli("gate", str(campaign), "F004", "--level", "candidate")

            for flag in PROVENANCE_FLAGS:
                with self.subTest(flag=flag):
                    finding["analysisProvenance"][flag] = True
                    finding_path.write_text(json.dumps(finding, indent=2) + "\n")
                    result = json.loads(
                        self.run_cli(
                            "gate",
                            str(campaign),
                            "F004",
                            "--level",
                            "candidate",
                            "--json",
                            expected=1,
                        ).stdout
                    )
                    self.assertFalse(result["passed"])
                    finding["analysisProvenance"][flag] = False


if __name__ == "__main__":
    unittest.main()
