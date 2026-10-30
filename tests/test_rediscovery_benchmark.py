from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "research_harness.py"
BENCHMARK = PROJECT / "scripts" / "rediscovery_benchmark.py"
SEARCH = PROJECT / "tests" / "fixtures" / "benchmark_search.py"


class RediscoveryBenchmarkTests(unittest.TestCase):
    def run_cli(
        self, script: Path, *args: str, expected: int = 0
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(script), *args],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            result.returncode,
            expected,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        return result

    def test_frozen_target_oracle_records_actual_rediscovery_time_and_recall(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout = root / "checkout"
            checkout.mkdir()
            oracle_source = checkout / "tests" / "target_invariant.cc"
            oracle_source.parent.mkdir()
            oracle_source.write_text("assert(decoded_length == encoded_length);\n")
            target = checkout / "release-target"
            target.write_text("pinned target artifact\n")
            corpus = root / "corpus"
            corpus.mkdir()
            (corpus / "seed.bin").write_bytes(b"seed")
            identity = "invariant:target-owned-length-domain"
            sealed = root / "evaluator-only-oracles.json"
            sealed.write_text(
                json.dumps(
                    {
                        "oracles": [
                            {
                                "id": "target-invariant-1",
                                "basis": "target-invariant",
                                "sourcePath": "tests/target_invariant.cc",
                                "sourceSha256": hashlib.sha256(
                                    oracle_source.read_bytes()
                                ).hexdigest(),
                                "identity": identity,
                            }
                        ]
                    }
                )
                + "\n"
            )
            campaign = root / "campaign"
            self.run_cli(
                HARNESS,
                "init",
                str(campaign),
                "--target",
                "fixture",
                "--repo",
                "local fixture",
                "--checkout",
                str(checkout),
                "--commit",
                "0123456789abcdef",
            )
            self.run_cli(
                BENCHMARK,
                "freeze",
                str(campaign),
                "baseline",
                "--corpus",
                str(corpus),
                "--sealed-oracles",
                str(sealed),
                "--target-artifact",
                str(target),
            )
            command = json.dumps([sys.executable, str(SEARCH), identity])
            run = self.run_cli(
                BENCHMARK,
                "run",
                str(campaign),
                "baseline",
                "--sealed-oracles",
                str(sealed),
                "--command-json",
                command,
                "--timeout-seconds",
                "10",
            )
            result = json.loads(run.stdout)
            self.assertEqual(result["matchedOracleCount"], 1)
            self.assertEqual(result["recall"], 1.0)
            self.assertIsNotNone(result["hoursToFirstRediscovery"])
            self.assertGreaterEqual(result["secondsToFirstRediscovery"], 0)
            manifest = json.loads(
                (campaign / "benchmarks" / "baseline" / "manifest.json").read_text()
            )
            self.assertNotIn(identity, json.dumps(manifest))
            self.run_cli(HARNESS, "plan", str(campaign))
            launch = json.loads((campaign / "launch-plan.json").read_text())
            self.assertEqual(launch["rediscoveryMeasurement"]["status"], "measured")
            self.assertIsNotNone(
                launch["rediscoveryMeasurement"]["hoursToFirstRediscovery"]
            )

    def test_frozen_corpus_mutation_invalidates_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checkout = root / "checkout"
            checkout.mkdir()
            source = checkout / "oracle.cc"
            source.write_text("assert(invariant);\n")
            target = checkout / "target"
            target.write_text("target\n")
            corpus = root / "corpus"
            corpus.mkdir()
            (corpus / "seed").write_text("seed\n")
            sealed = root / "sealed.json"
            sealed.write_text(
                json.dumps(
                    {
                        "oracles": [
                            {
                                "id": "one",
                                "basis": "target-test",
                                "sourcePath": "oracle.cc",
                                "sourceSha256": hashlib.sha256(
                                    source.read_bytes()
                                ).hexdigest(),
                                "identity": "stack:one",
                            }
                        ]
                    }
                )
                + "\n"
            )
            campaign = root / "campaign"
            self.run_cli(
                HARNESS,
                "init",
                str(campaign),
                "--target",
                "fixture",
                "--repo",
                "local",
                "--checkout",
                str(checkout),
                "--commit",
                "0123456789abcdef",
            )
            self.run_cli(
                BENCHMARK,
                "freeze",
                str(campaign),
                "mutated",
                "--corpus",
                str(corpus),
                "--sealed-oracles",
                str(sealed),
                "--target-artifact",
                str(target),
            )
            (campaign / "benchmarks" / "mutated" / "corpus" / "seed").write_text(
                "changed\n"
            )
            self.run_cli(
                BENCHMARK,
                "run",
                str(campaign),
                "mutated",
                "--sealed-oracles",
                str(sealed),
                "--command-json",
                json.dumps([sys.executable, str(SEARCH), "stack:one"]),
                expected=1,
            )


if __name__ == "__main__":
    unittest.main()
