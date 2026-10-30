from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.path_proof_fixture import complete_path_proof, install_machine_path_evidence


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "research_harness.py"
PATH_PROOF = PROJECT / "scripts" / "path_proof.py"
REALITY_RUNNER = PROJECT / "scripts" / "reality_runner.py"


class PathProofTests(unittest.TestCase):
    def run_cli(
        self, script: Path, *args: str, expected: int = 0
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [sys.executable, str(script), *args],
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

    def campaign_with_finding(self, parent: Path) -> Path:
        campaign = parent / "campaign"
        self.run_cli(
            HARNESS,
            "init",
            str(campaign),
            "--target",
            "parser-target",
            "--repo",
            "https://invalid.test/source",
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
        self.run_cli(
            HARNESS,
            "register",
            str(campaign),
            "FPATH",
            "--title",
            "Length confusion reaches an unsafe copy",
            "--lane",
            "parser-boundaries",
            "--originator",
            "worker-originator",
        )
        self.run_cli(HARNESS, "plan", str(campaign))
        self.run_cli(HARNESS, "queue", str(campaign))
        self.run_cli(
            HARNESS,
            "worker-register",
            str(campaign),
            "worker-originator",
            "--agent",
            "codex:originator",
            "--role",
            "originator",
        )
        self.run_cli(
            HARNESS,
            "worker-register",
            str(campaign),
            "worker-reviewer",
            "--agent",
            "codex:reviewer",
            "--role",
            "reviewer",
        )
        self.run_cli(PATH_PROOF, "init", str(campaign), "FPATH")
        return campaign

    def test_incomplete_proof_cannot_clear_candidate_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            campaign = self.campaign_with_finding(Path(temporary))
            audit = json.loads(
                self.run_cli(
                    PATH_PROOF,
                    "audit",
                    str(campaign),
                    "FPATH",
                    "--json",
                    expected=1,
                ).stdout
            )
            self.assertFalse(audit["passed"])
            self.assertIn("complete:true", audit["errors"])
            gate = json.loads(
                self.run_cli(
                    HARNESS,
                    "gate",
                    str(campaign),
                    "FPATH",
                    "--json",
                    expected=1,
                ).stdout
            )
            self.assertTrue(any(item.startswith("pathProof.") for item in gate["missingFields"]))

    def test_complete_independently_reviewed_proof_clears_path_gate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            campaign = self.campaign_with_finding(Path(temporary))
            proof_path = campaign / "evidence" / "path-proofs" / "FPATH.json"
            proof_path.write_text(
                json.dumps(
                    install_machine_path_evidence(
                        campaign, "FPATH", "worker-originator", "worker-reviewer"
                    ),
                    indent=2,
                )
                + "\n"
            )
            audit = json.loads(
                self.run_cli(
                    PATH_PROOF,
                    "audit",
                    str(campaign),
                    "FPATH",
                    "--update-gate",
                    "--json",
                ).stdout
            )
            self.assertTrue(audit["passed"])
            self.assertEqual(audit["summary"]["assumptions"], 0)
            self.assertTrue(audit["summary"]["independentReviewer"])
            self.assertTrue(audit["summary"]["machineIndependentReview"])
            self.assertGreater(audit["summary"]["machineObservations"], 0)
            gate = json.loads(
                self.run_cli(
                    HARNESS,
                    "gate",
                    str(campaign),
                    "FPATH",
                    "--json",
                    expected=1,
                ).stdout
            )
            self.assertTrue(gate["pathProof"]["passed"])
            self.assertFalse(any(item.startswith("pathProof.") for item in gate["missingFields"]))

    def test_assumptions_or_self_review_fail_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            campaign = self.campaign_with_finding(Path(temporary))
            proof = install_machine_path_evidence(
                campaign, "FPATH", "worker-originator", "worker-reviewer"
            )
            proof["assumptions"] = ["the allocator probably preserves the value"]
            proof["review"]["reviewer"] = "worker-originator"
            proof_path = campaign / "evidence" / "path-proofs" / "FPATH.json"
            proof_path.write_text(json.dumps(proof, indent=2) + "\n")
            audit = json.loads(
                self.run_cli(
                    PATH_PROOF,
                    "audit",
                    str(campaign),
                    "FPATH",
                    "--json",
                    expected=1,
                ).stdout
            )
            self.assertIn("assumptions:must-be-empty", audit["errors"])
            self.assertIn("review.reviewer:must-be-independent", audit["errors"])

    def test_distinct_worker_aliases_do_not_count_as_independent_review(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            campaign = self.campaign_with_finding(Path(temporary))
            self.run_cli(
                HARNESS,
                "worker-register",
                str(campaign),
                "worker-alias",
                "--agent",
                "codex:originator",
                "--role",
                "reviewer",
            )
            proof = install_machine_path_evidence(
                campaign, "FPATH", "worker-originator", "worker-alias"
            )
            proof_path = campaign / "evidence" / "path-proofs" / "FPATH.json"
            proof_path.write_text(json.dumps(proof, indent=2) + "\n")
            audit = json.loads(
                self.run_cli(
                    PATH_PROOF,
                    "audit",
                    str(campaign),
                    "FPATH",
                    "--json",
                    expected=1,
                ).stdout
            )
            self.assertIn("review.agent:must-be-independent", audit["errors"])

    def test_prose_and_existing_files_cannot_replace_machine_observations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            campaign = self.campaign_with_finding(Path(temporary))
            artifact = campaign / "evidence" / "path-proof" / "trace.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text('{"observed": true}\n', encoding="utf-8")
            source = campaign / "evidence" / "source-snapshots" / "path.cc"
            source.parent.mkdir(parents=True)
            source.write_text("int parse_request() { return 1; }\n")
            proof = complete_path_proof(source_sha256="0" * 64)
            proof_path = campaign / "evidence" / "path-proofs" / "FPATH.json"
            proof_path.write_text(json.dumps(proof, indent=2) + "\n")
            audit = json.loads(
                self.run_cli(
                    PATH_PROOF,
                    "audit",
                    str(campaign),
                    "FPATH",
                    "--json",
                    expected=1,
                ).stdout
            )
            self.assertFalse(audit["passed"])
            self.assertTrue(
                any("machineEvidence" in error for error in audit["errors"]),
                audit,
            )

    def test_raw_output_tampering_breaks_recomputed_assertion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            campaign = self.campaign_with_finding(Path(temporary))
            proof = install_machine_path_evidence(
                campaign, "FPATH", "worker-originator", "worker-reviewer"
            )
            reference = proof["steps"][0]["machineEvidence"][0]
            attestation = json.loads((campaign / reference["attestation"]).read_text())
            positive = attestation["cases"]["positive"][0]
            stdout_path = campaign / positive["raw"]["stdoutPath"]
            stdout_path.write_text("tampered\n", encoding="utf-8")
            proof_path = campaign / "evidence" / "path-proofs" / "FPATH.json"
            proof_path.write_text(json.dumps(proof, indent=2) + "\n")
            audit = json.loads(
                self.run_cli(
                    PATH_PROOF,
                    "audit",
                    str(campaign),
                    "FPATH",
                    "--json",
                    expected=1,
                ).stdout
            )
            self.assertTrue(any("stdout-hash" in error for error in audit["errors"]), audit)

    def test_recipe_cannot_run_an_unrelated_echo_instead_of_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            campaign = self.campaign_with_finding(Path(temporary))
            record = json.loads((campaign / "campaign.json").read_text())
            record["authorization"]["confirmed"] = True
            record["authorization"]["basis"] = "owned fixture"
            (campaign / "campaign.json").write_text(json.dumps(record) + "\n")
            target = campaign / "evidence" / "bin" / "unused.py"
            target.parent.mkdir(parents=True)
            target.write_text("print('unused')\n")
            recipe = campaign / "evidence" / "recipes" / "echo.json"
            recipe.parent.mkdir(parents=True)
            recipe.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "findingId": "FPATH",
                        "targetArtifacts": ["evidence/bin/unused.py"],
                        "subjectArtifact": "evidence/bin/unused.py",
                        "subjectArgvIndex": 1,
                        "cases": [
                            {
                                "name": name,
                                "command": [sys.executable, "-c", "print('ok')"],
                                "assertions": [
                                    {"id": f"{name}-ok", "kind": "stdout-contains", "value": "ok"}
                                ],
                            }
                            for name in ("baseline", "negative", "positive")
                        ],
                    }
                )
                + "\n"
            )
            completed = self.run_cli(
                REALITY_RUNNER,
                str(campaign),
                "FPATH",
                "--recipe",
                recipe.relative_to(campaign).as_posix(),
                "--worker-id",
                "worker-originator",
                "--role",
                "originator",
                expected=2,
            )
            self.assertIn("does not invoke subjectArtifact", completed.stderr)


if __name__ == "__main__":
    unittest.main()
