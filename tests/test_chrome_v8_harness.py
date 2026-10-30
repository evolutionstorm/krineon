from __future__ import annotations

import json
import socket
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
RESEARCH = PROJECT / "scripts" / "research_harness.py"
CHROME_V8 = PROJECT / "scripts" / "chrome_v8_harness.py"
BUILD_PROVENANCE = PROJECT / "scripts" / "build_provenance.py"


class ChromeV8HarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.campaign = self.base / "campaign"
        self.checkout = self.base / "source"
        self.checkout.mkdir()
        self.manifests: dict[Path, Path] = {}
        (self.checkout / ".gitignore").write_text("out/\n", encoding="utf-8")
        (self.checkout / "d8_fixture.c").write_text(
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "#include <string.h>\n"
            "int main(int argc, char** argv) {\n"
            "  if (argc > 1) { FILE* f=fopen(argv[argc-1], \"rb\"); char b[4096]={0};\n"
            "    if (f) { size_t n=fread(b,1,sizeof(b)-1,f); b[n]=0; fclose(f);\n"
            "      if (strstr(b, \"CRASH\")) fputs(\"ERROR: AddressSanitizer: heap-use-after-free\\n\", stderr); } }\n"
            "  puts(\"stable-output\"); return 0; }\n",
            encoding="utf-8",
        )
        fake_cdp = self.checkout / "fake_chromium_cdp.py"
        fake_cdp.write_bytes(
            (PROJECT / "tests" / "fixtures" / "fake_chromium_cdp.py").read_bytes()
        )
        (self.checkout / "chrome_launcher.c").write_text(
            "#include <stdlib.h>\n#include <unistd.h>\n"
            "int main(int argc, char** argv) { char** v=calloc((size_t)argc+2,sizeof(char*));\n"
            f"v[0]=\"python3\"; v[1]=\"{fake_cdp}\";\n"
            "for(int i=1;i<argc;i++) v[i+1]=argv[i]; execvp(v[0],v); return 127; }\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q", str(self.checkout)], check=True)
        subprocess.run(["git", "-C", str(self.checkout), "config", "user.email", "fixture@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(self.checkout), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(self.checkout), "add", "."], check=True)
        subprocess.run(["git", "-C", str(self.checkout), "commit", "-q", "-m", "fixture"], check=True)
        self.revision = subprocess.run(
            ["git", "-C", str(self.checkout), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.run_command(
            RESEARCH,
            "init",
            str(self.campaign),
            "--target",
            "v8",
            "--repo",
            "https://chromium.googlesource.com/v8/v8",
            "--commit",
            self.revision,
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

    def make_native_fixture(
        self, name: str, *, kind: str, role: str, extra_flags: tuple[str, ...] = ()
    ) -> Path:
        build = self.checkout / "out" / name
        build.mkdir(parents=True)
        target = "d8" if kind == "d8" else "fake-chromium"
        source = self.checkout / ("d8_fixture.c" if kind == "d8" else "chrome_launcher.c")
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler)
        flags = ["-O1"]
        if role == "asan":
            flags.extend(["-fsanitize=address", "-fno-omit-frame-pointer"])
        if role == "debug":
            flags.extend(["-g", "-O0"])
        (build / "args.gn").write_text(
            "target_cpu = \"{}\"\n"
            "is_debug = {}\n"
            "v8_enable_sandbox = true\n"
            "is_asan = {}\n".format(
                "arm64" if platform.machine().lower() in {"arm64", "aarch64", "arm64e"} else "x64",
                "true" if role == "debug" else "false",
                "true" if role == "asan" else "false",
            ),
            encoding="utf-8",
        )
        (build / "build.ninja").write_text(
            f"rule cc\n  command = {compiler} {' '.join(flags)} $in -o $out\n"
            f"build {target}: cc {source}\n",
            encoding="utf-8",
        )
        subprocess.run(["ninja", "-C", str(build), target], check=True, capture_output=True)
        binary = build / target
        manifest = self.campaign / "chrome-v8" / "provenance" / f"{name}.json"
        command = [
            BUILD_PROVENANCE,
            "capture",
            str(self.campaign),
            name,
            "--kind",
            kind,
            "--role",
            role,
            "--checkout",
            str(self.checkout),
            "--build-dir",
            str(build),
            "--binary",
            str(binary),
            "--target",
            target,
            "--output",
            str(manifest),
        ]
        for value in extra_flags:
            command.append("--flag=" + value)
        self.run_command(*command)
        self.manifests[binary.resolve()] = manifest
        return binary

    def make_d8_fixture(self, name: str) -> Path:
        role = name.removeprefix("d8-")
        return self.make_native_fixture(role, kind="d8", role=role)

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
            self.revision,
            "--provenance-manifest",
            str(self.manifests[binary.resolve()]),
        )

    def make_chrome_fixture(self) -> Path:
        return self.make_native_fixture(
            "sandboxed", kind="chrome", role="sandboxed-chrome"
        )

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
            self.revision,
            "--provenance-manifest",
            str(self.manifests[binary.resolve()]),
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
        self.assertIn("requiresTriage", record["summary"])
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
        binary.write_bytes(binary.read_bytes() + b"changed-after-registration")
        self.run_command(CHROME_V8, "audit", str(self.campaign), expected=1)

    def test_tampered_provenance_is_rejected_even_when_binary_is_unchanged(self) -> None:
        binary = self.make_d8_fixture("d8-release")
        self.register_build("release", "release", binary)
        manifest = self.manifests[binary.resolve()]
        value = json.loads(manifest.read_text())
        value["source"]["revision"] = "0" * 40
        manifest.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        completed = self.run_command(
            CHROME_V8, "audit", str(self.campaign), "--json", expected=1
        )
        result = json.loads(completed.stdout)
        self.assertTrue(
            any(
                "signature" in problem or "provenance manifest changed" in problem
                for problem in result["builds"][0]["problems"]
            )
        )

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
        binary = self.make_native_fixture(
            "sandboxed", kind="chrome", role="sandboxed-chrome", extra_flags=("--no-sandbox",)
        )
        self.register_chrome(binary, "--flag=--no-sandbox")
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
