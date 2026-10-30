from __future__ import annotations

import json
import socket
import platform
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
RESEARCH = PROJECT / "scripts" / "research_harness.py"
CHROME_V8 = PROJECT / "scripts" / "chrome_v8_harness.py"


class ChromeV8HarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.campaign = self.base / "campaign"
        self.run_command(
            RESEARCH,
            "init",
            str(self.campaign),
            "--target",
            "v8",
            "--repo",
            "https://chromium.googlesource.com/v8/v8",
            "--commit",
            "0123456789abcdef",
            "--profile",
            "chrome-v8",
        )
        campaign_path = self.campaign / "campaign.json"
        campaign = json.loads(campaign_path.read_text())
        campaign["authorization"]["confirmed"] = True
        campaign["authorization"]["basis"] = "owned local fixture"
        campaign["authorization"]["allowedEnvironment"] = "disposable local test directory"
        campaign_path.write_text(json.dumps(campaign, indent=2) + "\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_command(
        self, script: Path, *args: str, expected: int = 0
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [sys.executable, str(script), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(
            completed.returncode,
            expected,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        return completed

    def make_d8_fixture(self, name: str) -> Path:
        path = self.base / name
        path.write_text(
            "#!/usr/bin/env python3\n"
            "from pathlib import Path\n"
            "import sys\n"
            "data = Path(sys.argv[-1]).read_text()\n"
            "if 'CRASH' in data:\n"
            "    sys.stderr.write('ERROR: AddressSanitizer: heap-use-after-free\\n')\n"
            "print('stable-output')\n",
            encoding="utf-8",
        )
        path.chmod(0o755)
        return path

    def register_build(self, name: str, role: str, binary: Path) -> None:
        self.run_command(
            CHROME_V8,
            "register-build",
            str(self.campaign),
            name,
            "--kind",
            "d8",
            "--role",
            role,
            "--binary",
            str(binary),
            "--revision",
            "0123456789abcdef",
        )

    def make_chrome_fixture(self) -> Path:
        source = PROJECT / "tests" / "fixtures" / "fake_chromium_cdp.py"
        path = self.base / "fake-chromium"
        path.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        path.chmod(0o755)
        return path

    def register_chrome(self, binary: Path, *extra: str) -> None:
        self.run_command(
            CHROME_V8,
            "register-build",
            str(self.campaign),
            "sandboxed",
            "--kind",
            "chrome",
            "--role",
            "sandboxed-chrome",
            "--binary",
            str(binary),
            "--revision",
            "0123456789abcdef",
            *extra,
        )

    def test_register_audit_and_matrix(self) -> None:
        for role in ("release", "asan", "debug"):
            self.register_build(role, role, self.make_d8_fixture(f"d8-{role}"))
        audit = self.run_command(CHROME_V8, "audit", str(self.campaign), "--json")
        self.assertTrue(json.loads(audit.stdout)["passed"])

        testcase = self.base / "test.js"
        testcase.write_text("console.log('owned fixture');\n", encoding="utf-8")
        matrix = self.run_command(
            CHROME_V8,
            "matrix",
            str(self.campaign),
            "--testcase",
            str(testcase),
        )
        matrix_id = next(
            line.split(": ", 1)[1]
            for line in matrix.stdout.splitlines()
            if line.startswith("matrix: ")
        )
        record = json.loads(
            (self.campaign / "chrome-v8" / "matrices" / matrix_id / "matrix.json").read_text()
        )
        self.assertEqual(record["status"], "completed")
        self.assertEqual(len(record["results"]), 3)
        self.assertFalse(record["summary"]["requiresTriage"])
        builds = json.loads(
            (self.campaign / "chrome-v8" / "builds.json").read_text()
        )["builds"]
        expected_architecture = "arm64" if platform.machine().lower() in {
            "arm64",
            "arm64e",
            "aarch64",
            "armx64",
        } else "x86_64"
        self.assertTrue(
            all(build["architecture"] == expected_architecture for build in builds)
        )
        self.run_command(RESEARCH, "hash", str(self.campaign))
        manifest = (self.campaign / "SHA256SUMS").read_text()
        self.assertIn("chrome-v8/builds.json", manifest)
        self.assertIn(f"chrome-v8/matrices/{matrix_id}/matrix.json", manifest)

    def test_changed_binary_is_rejected(self) -> None:
        binary = self.make_d8_fixture("d8-release")
        self.register_build("release", "release", binary)
        binary.write_text(binary.read_text() + "# changed\n", encoding="utf-8")
        self.run_command(CHROME_V8, "audit", str(self.campaign), expected=1)

    def test_matrix_preserves_sanitizer_lead_without_claiming_impact(self) -> None:
        for role in ("release", "asan", "debug"):
            self.register_build(role, role, self.make_d8_fixture(f"d8-{role}"))
        testcase = self.base / "crash.js"
        testcase.write_text("// CRASH\n", encoding="utf-8")
        completed = self.run_command(
            CHROME_V8,
            "matrix",
            str(self.campaign),
            "--testcase",
            str(testcase),
        )
        matrix_id = next(
            line.split(": ", 1)[1]
            for line in completed.stdout.splitlines()
            if line.startswith("matrix: ")
        )
        record = json.loads(
            (self.campaign / "chrome-v8" / "matrices" / matrix_id / "matrix.json").read_text()
        )
        self.assertTrue(record["summary"]["requiresTriage"])
        self.assertIn("lead only", record["summary"]["securityConclusion"])

    def test_owned_page_direct_cdp_replay_retains_positive_and_control(self) -> None:
        try:
            probe = socket.socket()
            probe.bind(("127.0.0.1", 0))
        except PermissionError:
            self.skipTest("managed test sandbox forbids loopback listeners")
        else:
            probe.close()
        self.register_chrome(self.make_chrome_fixture())
        site = self.base / "owned-page"
        site.mkdir()
        (site / "index.html").write_text(
            "<script>globalThis.__KRINEON_REPLAY_RESULT__ = true</script>\n",
            encoding="utf-8",
        )
        (site / "control.html").write_text(
            "<script>globalThis.__KRINEON_REPLAY_RESULT__ = false</script>\n",
            encoding="utf-8",
        )
        self.run_command(
            RESEARCH,
            "register",
            str(self.campaign),
            "F900",
            "--title",
            "Owned-page replay fixture",
            "--lane",
            "chromium-integration",
        )
        completed = self.run_command(
            CHROME_V8,
            "browser-replay",
            str(self.campaign),
            "--build",
            "sandboxed",
            "--page-dir",
            str(site),
            "--entry",
            "index.html",
            "--control-entry",
            "control.html",
            "--finding-id",
            "F900",
            "--reviewed-by",
            "reviewer-browser",
            "--review-note",
            "The retained cases establish only owned-page browser reachability.",
        )
        replay_id = next(
            line.split(": ", 1)[1]
            for line in completed.stdout.splitlines()
            if line.startswith("browser replay: ")
        )
        record_path = (
            self.campaign
            / "chrome-v8"
            / "browser-replays"
            / replay_id
            / "replay.json"
        )
        record = json.loads(record_path.read_text())
        self.assertEqual(record["driver"], "direct-cdp")
        self.assertTrue(record["ownedLocalOrigin"])
        self.assertEqual(record["cases"]["positive"]["status"], "completed")
        self.assertEqual(record["cases"]["control"]["status"], "completed")
        self.assertTrue(record["cases"]["positive"]["expressionMatched"])
        self.assertTrue(record["cases"]["control"]["expressionMatched"])
        self.assertTrue(record["summary"]["webReachabilityConfirmed"])
        self.assertEqual(
            record["summary"]["promotionReady"], record["summary"]["sandboxVerified"]
        )
        self.assertTrue((record_path.parent / "positive" / "page.png").is_file())
        self.assertTrue((record_path.parent / "positive" / "v8-coverage.json").is_file())
        self.assertIn("v8Coverage", record["cases"]["positive"])
        self.assertTrue((record_path.parent / "control" / "cdp-events.json").is_file())
        finding = json.loads((self.campaign / "findings" / "F900.json").read_text())
        self.assertEqual(finding["browserReplay"]["replayIds"], [replay_id])
        self.assertEqual(
            finding["browserReplay"]["reviewedBy"], "reviewer-browser"
        )
        self.run_command(RESEARCH, "hash", str(self.campaign))
        manifest = (self.campaign / "SHA256SUMS").read_text()
        self.assertIn(
            f"chrome-v8/browser-replays/{replay_id}/replay.json", manifest
        )

    def test_browser_replay_rejects_sandbox_disabling_flag(self) -> None:
        self.register_chrome(self.make_chrome_fixture(), "--flag=--no-sandbox")
        site = self.base / "owned-page"
        site.mkdir()
        (site / "index.html").write_text("owned", encoding="utf-8")
        completed = self.run_command(
            CHROME_V8,
            "browser-replay",
            str(self.campaign),
            "--build",
            "sandboxed",
            "--page-dir",
            str(site),
            expected=1,
        )
        self.assertIn("refuses sandbox-disabling or internal V8 flag", completed.stderr)


if __name__ == "__main__":
    unittest.main()
