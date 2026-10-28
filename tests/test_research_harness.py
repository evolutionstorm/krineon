from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "research_harness.py"
PROBE = PROJECT / "scripts" / "tool_probe.py"


class HarnessTests(unittest.TestCase):
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
        return campaign

    def test_init_and_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            campaign = self.create_campaign(Path(tmp))
            self.run_cli("plan", str(campaign))
            launch = json.loads((campaign / "launch-plan.json").read_text())
            self.assertEqual(len(launch["tasks"]), 10)
            self.assertTrue((campaign / "tasks" / "wave-1-boundary-map.md").is_file())
            self.assertTrue((campaign / "AUTHORIZATION.md").is_file())

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
            )
            self.run_cli("gate", str(campaign), "F001", "--level", "candidate", expected=1)

            path = campaign / "findings" / "F001.json"
            finding = json.loads(path.read_text())
            finding["rootCause"] = "Producer and consumer disagree about the encoded length domain."
            finding["impact"] = "Owned test identity crosses an authorization boundary."
            finding["preconditions"] = ["supported configuration"]
            finding["evidence"] = ["evidence/verification-results.json"]
            finding["controls"] = {
                "baseline": "ordinary request succeeds",
                "negative": "enforcing guard rejects the payload",
                "positive": "only the disputed representation crosses the guard",
                "patched": "patched version rejects it",
            }
            for key in finding["gates"]:
                finding["gates"][key] = True
            path.write_text(json.dumps(finding, indent=2) + "\n")
            self.run_cli("gate", str(campaign), "F001", "--level", "reportable")

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
        self.assertIn("z3", payload["pythonModules"])


if __name__ == "__main__":
    unittest.main()
