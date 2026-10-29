from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
BOOTSTRAP = PROJECT / "scripts" / "campaign_bootstrap.py"
HARNESS = PROJECT / "scripts" / "research_harness.py"


class CampaignBootstrapTests(unittest.TestCase):
    def run_bootstrap(
        self, *args: str, expected: int = 0
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [sys.executable, str(BOOTSTRAP), *args],
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

    @unittest.skipUnless(shutil.which("git"), "Git is required for revision pinning")
    def test_rules_only_intake_pins_checkout_selects_profile_and_queues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "v8-source"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(
                ["git", "-C", str(source), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "config", "user.name", "Krineon Test"],
                check=True,
            )
            (source / "README.md").write_text("V8 fixture\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(source), "add", "README.md"], check=True)
            subprocess.run(
                ["git", "-C", str(source), "commit", "-q", "-m", "fixture"],
                check=True,
            )
            revision = subprocess.run(
                ["git", "-C", str(source), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            rules = root / "rules.md"
            rules_payload = (
                b"# Program rules\n\n"
                b"Testing is limited to the listed source assets.\n"
            )
            scope_payload = (
                b"## In scope assets\n\n"
                b"- https://chromium.googlesource.com/v8/v8 - Source code - Eligible\n"
                b"- Chrome and Chromium V8 engine\n\n"
                b"## Out of scope vulnerabilities\n\n"
                b"- Denial of service without a security boundary impact\n"
            )
            rules.write_bytes(rules_payload)
            scope_file = root / "scope.md"
            scope_file.write_bytes(scope_payload)
            campaign = root / "campaign"
            completed = self.run_bootstrap(
                str(campaign),
                "--guidelines",
                str(rules),
                "--scope",
                str(scope_file),
                "--checkout",
                str(source),
                "--confirm-authorization",
                "--json",
            )
            output = json.loads(completed.stdout)
            self.assertEqual(output["profile"], "chrome-v8")
            self.assertTrue(output["authorizationConfirmed"])
            self.assertTrue(output["queued"])

            self.assertEqual((campaign / "PROGRAM_GUIDELINES.md").read_bytes(), rules_payload)
            self.assertEqual((campaign / "PROGRAM_SCOPE.md").read_bytes(), scope_payload)
            onboarding = json.loads((campaign / "onboarding.json").read_text())
            self.assertEqual(
                onboarding["guidelines"]["sha256"], hashlib.sha256(rules_payload).hexdigest()
            )
            self.assertEqual(
                onboarding["scopeInput"]["sha256"], hashlib.sha256(scope_payload).hexdigest()
            )
            self.assertEqual(onboarding["resolved"]["commit"], revision)
            self.assertEqual(onboarding["resolved"]["profile"], "chrome-v8")
            self.assertTrue(onboarding["inference"]["scopeCandidates"])
            self.assertTrue(onboarding["inference"]["outOfScopeCandidates"])

            campaign_json = json.loads((campaign / "campaign.json").read_text())
            self.assertEqual(campaign_json["commit"], revision)
            self.assertTrue(campaign_json["authorization"]["confirmed"])
            self.assertEqual(campaign_json["profile"], "chrome-v8")
            launch = json.loads((campaign / "launch-plan.json").read_text())
            self.assertEqual(launch["profile"], "chrome-v8")
            self.assertEqual(len(launch["tasks"]), 17)
            self.assertTrue((campaign / "tools" / "tool-probe.json").is_file())
            self.assertTrue((campaign / "orchestration.db").is_file())
            with sqlite3.connect(campaign / "orchestration.db") as connection:
                count = connection.execute("SELECT COUNT(*) FROM tasks").fetchone()[0]
            self.assertEqual(count, 17)

            hashed = subprocess.run(
                [sys.executable, str(HARNESS), "hash", str(campaign)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(hashed.returncode, 0, msg=hashed.stderr)
            manifest = (campaign / "SHA256SUMS").read_text(encoding="utf-8")
            self.assertIn("PROGRAM_GUIDELINES.md", manifest)
            self.assertIn("PROGRAM_SCOPE.md", manifest)
            self.assertIn("onboarding.json", manifest)

    def test_unconfirmed_intake_prepares_source_work_without_dynamic_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rules = root / "rules.md"
            rules.write_text(
                "## In scope\n\n"
                "- https://github.com/example/security-target - Source code\n\n"
                "## Out of scope\n\n"
                "- Production denial of service\n",
                encoding="utf-8",
            )
            campaign = root / "campaign"
            self.run_bootstrap(
                str(campaign),
                "--guidelines",
                str(rules),
                "--json",
            )
            campaign_json = json.loads((campaign / "campaign.json").read_text())
            onboarding = json.loads((campaign / "onboarding.json").read_text())
            self.assertFalse(campaign_json["authorization"]["confirmed"])
            self.assertEqual(campaign_json["commit"], "pending-pin")
            self.assertIn(
                "Confirm authorization after checking the selected asset against the retained rules.",
                onboarding["unresolved"],
            )
            self.assertTrue((campaign / "orchestration.db").is_file())


if __name__ == "__main__":
    unittest.main()
