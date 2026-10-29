from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
RESEARCH = PROJECT / "scripts" / "research_harness.py"
FUZZERS = PROJECT / "scripts" / "fuzzer_orchestrator.py"


class ExternalFuzzerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.campaign = self.base / "campaign"
        self.run_command(
            RESEARCH,
            "init",
            str(self.campaign),
            "--target",
            "fixture",
            "--repo",
            "https://example.invalid/fixture",
            "--commit",
            "0123456789abcdef",
            "--mode",
            "local-lab",
        )
        campaign_path = self.campaign / "campaign.json"
        campaign = json.loads(campaign_path.read_text())
        campaign["authorization"]["confirmed"] = True
        campaign["authorization"]["basis"] = "owned external-fuzzer fixture"
        campaign["authorization"]["allowedEnvironment"] = "temporary local directory"
        campaign_path.write_text(json.dumps(campaign, indent=2) + "\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_command(
        self, script: Path, *args: str, expected: int = 0, timeout: int = 60
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [sys.executable, str(script), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        self.assertEqual(
            completed.returncode,
            expected,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        return completed

    def initialize_profile(self) -> tuple[Path, Path]:
        target = self.base / "fixture-target"
        target.write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8")
        target.chmod(0o755)
        self.run_command(
            FUZZERS,
            "register",
            str(self.campaign),
            "native",
            "--engine",
            "libfuzzer",
            "--target",
            str(target),
            "--revision",
            "fixture-libfuzzer-1",
            "--max-input-bytes",
            "1048576",
        )
        builder = PROJECT / "tests" / "fixtures" / "fake_instrumented_builder.py"
        fuzzer_source = PROJECT / "tests" / "fixtures" / "fake_libfuzzer.py"
        environment = self.base / "injected-environment.json"
        build_command = json.dumps(
            [sys.executable, str(builder), str(target), str(fuzzer_source), str(environment)]
        )
        self.run_command(
            FUZZERS,
            "instrument",
            str(self.campaign),
            "native",
            "--kind",
            "libfuzzer-clang",
            "--build-command-json",
            build_command,
        )
        return target, environment

    def test_instrument_harvest_generate_parallel_launch_forward_and_coverage(self) -> None:
        _, environment = self.initialize_profile()
        injected = json.loads(environment.read_text())
        self.assertIn("fuzzer-no-link", injected["CFLAGS"])
        self.assertIn("-fsanitize=fuzzer,address,undefined", injected["LDFLAGS"])

        seeds = self.base / "source-tests"
        seeds.mkdir()
        (seeds / "one.js").write_text("let x = 1;\n", encoding="utf-8")
        (seeds / "duplicate.js").write_text("let x = 1;\n", encoding="utf-8")
        (seeds / "ignored.txt").write_text("ignore", encoding="utf-8")
        self.run_command(
            FUZZERS,
            "seed-harvest",
            str(self.campaign),
            "native",
            "--source",
            str(seeds),
            "--extension",
            ".js",
        )

        generator = self.base / "generator.py"
        generator.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "from pathlib import Path\n"
            "Path(sys.argv[1]).write_text('structured-' + sys.argv[2])\n",
            encoding="utf-8",
        )
        generator.chmod(0o755)
        self.run_command(
            FUZZERS,
            "structured-generate",
            str(self.campaign),
            "native",
            "--command-json",
            json.dumps([str(generator), "{output}", "{seed}"]),
            "--count",
            "2",
            "--suffix",
            ".js",
        )

        launched = self.run_command(
            FUZZERS,
            "launch",
            str(self.campaign),
            "native",
            "--workers",
            "3",
            "--duration-seconds",
            "1",
            "--sync-interval-seconds",
            "0.05",
            "--forward-crashes",
        )
        launch_id = next(
            line.split(": ", 1)[1]
            for line in launched.stdout.splitlines()
            if line.startswith("fuzzer run: ")
        )
        run = json.loads(
            (
                self.campaign
                / "dynamic"
                / "fuzzers"
                / "native"
                / "runs"
                / launch_id
                / "run.json"
            ).read_text()
        )
        self.assertEqual(run["parallelism"], "native jobs/workers")
        self.assertEqual(run["workersRequested"], 3)
        self.assertGreaterEqual(run["summary"]["newCorpusInputs"], 1)
        self.assertEqual(run["summary"]["replayConfirmedCrashes"], 1)
        self.assertEqual(len(list((self.campaign / "dynamic" / "crashes").iterdir())), 1)
        external = next((self.campaign / "dynamic" / "external-crashes").iterdir())
        external_record = json.loads((external / "external.json").read_text())
        self.assertEqual(external_record["classification"], "replay-confirmed Krineon crash")

        showmap_source = PROJECT / "tests" / "fixtures" / "fake_afl_showmap.py"
        showmap = self.base / "afl-showmap"
        showmap.write_text(showmap_source.read_text(encoding="utf-8"), encoding="utf-8")
        showmap.chmod(0o755)
        coverage = self.run_command(
            FUZZERS,
            "coverage-rebuild",
            str(self.campaign),
            "native",
            "--mode",
            "afl-showmap",
            "--tool",
            str(showmap),
        )
        coverage_id = next(
            line.split(": ", 1)[1]
            for line in coverage.stdout.splitlines()
            if line.startswith("coverage rebuild: ")
        )
        coverage_record = json.loads(
            (
                self.campaign
                / "dynamic"
                / "fuzzers"
                / "native"
                / "coverage"
                / coverage_id
                / "coverage.json"
            ).read_text()
        )
        self.assertEqual(coverage_record["coverage"]["uniqueEdges"], 2)
        status = json.loads(
            self.run_command(
                FUZZERS, "status", str(self.campaign), "native", "--json"
            ).stdout
        )
        self.assertGreaterEqual(status["corpusInputs"], 4)

    def test_afl_and_fuzzilli_adapters_use_native_parallel_topology(self) -> None:
        sys.path.insert(0, str(PROJECT / "scripts"))
        try:
            import fuzzer_orchestrator as module
        finally:
            sys.path.pop(0)
        root = self.base / "adapter"
        profile_root = root / "dynamic" / "fuzzers" / "profile"
        corpus = profile_root / "corpus"
        corpus.mkdir(parents=True)
        (corpus / "seed.js").write_text("seed", encoding="utf-8")
        run = profile_root / "runs" / "run-id"
        run.mkdir(parents=True)
        base = {
            "target": {"path": "/owned/target"},
            "engineBinary": {"path": "/owned/engine"},
            "targetArgs": ["@@"],
            "engineArgs": [],
            "dictionary": None,
        }
        afl = module.command_for_workers(
            {**base, "engine": "aflpp"}, run, workers=3, duration=60
        )
        self.assertEqual(len(afl), 3)
        self.assertIn("-M", afl[0][1])
        self.assertIn("-S", afl[1][1])
        fuzzilli = module.command_for_workers(
            {**base, "engine": "fuzzilli"}, run, workers=4, duration=60
        )
        self.assertEqual(len(fuzzilli), 1)
        self.assertIn("--jobs=4", fuzzilli[0][1])
        self.assertTrue(any(value.startswith("--storagePath=") for value in fuzzilli[0][1]))

    def test_launch_refuses_unverified_instrumentation(self) -> None:
        target = self.base / "plain-target"
        target.write_text("#!/usr/bin/env python3\nraise SystemExit(0)\n", encoding="utf-8")
        target.chmod(0o755)
        self.run_command(
            FUZZERS,
            "register",
            str(self.campaign),
            "plain",
            "--engine",
            "libfuzzer",
            "--target",
            str(target),
            "--revision",
            "plain-1",
        )
        seed = self.base / "seed.bin"
        seed.write_bytes(b"seed")
        self.run_command(
            FUZZERS,
            "seed-harvest",
            str(self.campaign),
            "plain",
            "--source",
            str(seed),
        )
        failed = self.run_command(
            FUZZERS,
            "launch",
            str(self.campaign),
            "plain",
            "--duration-seconds",
            "1",
            expected=1,
        )
        self.assertIn("no verified instrumentation", failed.stderr)


if __name__ == "__main__":
    unittest.main()
