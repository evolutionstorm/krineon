from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tests.path_proof_fixture import complete_path_proof


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "research_harness.py"
PATH_PROOF = PROJECT / "scripts" / "path_proof.py"


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
            artifact = campaign / "evidence" / "path-proof" / "trace.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text('{"observed": true}\n', encoding="utf-8")
            proof_path = campaign / "evidence" / "path-proofs" / "FPATH.json"
            proof_path.write_text(json.dumps(complete_path_proof(), indent=2) + "\n")
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
            artifact = campaign / "evidence" / "path-proof" / "trace.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text('{"observed": true}\n', encoding="utf-8")
            proof = complete_path_proof()
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
            artifact = campaign / "evidence" / "path-proof" / "trace.json"
            artifact.parent.mkdir(parents=True)
            artifact.write_text('{"observed": true}\n', encoding="utf-8")
            proof = complete_path_proof()
            proof["review"]["reviewer"] = "worker-alias"
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


if __name__ == "__main__":
    unittest.main()
