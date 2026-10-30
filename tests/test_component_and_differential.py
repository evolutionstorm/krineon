from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
FREEZE = PROJECT / "scripts" / "component_freeze.py"
DIFFERENTIAL = PROJECT / "scripts" / "differential_witness.py"
PIPELINE = PROJECT / "scripts" / "static_analysis_pipeline.py"
COMPONENT = PROJECT / "examples" / "frozen-component" / "component.json"


class FrozenDifferentialTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("clang++"), "clang++ is unavailable")
    def test_frozen_sanitized_component_produces_recorded_disagreement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            frozen = root / "frozen"
            build = subprocess.run(
                [sys.executable, str(FREEZE), str(COMPONENT), str(frozen)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            manifest = json.loads((frozen / "frozen-component.json").read_text())
            self.assertEqual(manifest["sanitizers"], {"address": True, "undefined": True})
            binary = frozen / "row-length-consumers"
            inputs = [
                PROJECT / "examples" / "frozen-component" / "seeds" / name
                for name in ("in-range.hex", "wrap.hex")
            ]
            spec = root / "differential.json"
            artifact = {
                "path": str(binary),
                "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            }
            spec.write_text(
                json.dumps(
                    {
                        "name": "row-length-domain",
                        "consumers": [
                            {
                                "name": "wide",
                                "command": [str(binary), "wide", "{input}"],
                                "cwd": str(root),
                                "artifacts": [artifact],
                                "environment": {"ASAN_OPTIONS": "detect_leaks=0"},
                            },
                            {
                                "name": "narrow",
                                "command": [str(binary), "narrow", "{input}"],
                                "cwd": str(root),
                                "artifacts": [artifact],
                                "environment": {"ASAN_OPTIONS": "detect_leaks=0"},
                            },
                        ],
                        "normalization": {
                            "mode": "json-stdout",
                            "ignoreFields": ["consumer"],
                        },
                        "inputs": [
                            {
                                "path": str(path),
                                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                            }
                            for path in inputs
                        ],
                    }
                )
                + "\n"
            )
            output = root / "witness.json"
            run = subprocess.run(
                [
                    sys.executable,
                    str(DIFFERENTIAL),
                    "--spec",
                    str(spec),
                    "--output",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(run.returncode, 0, run.stderr)
            witness = json.loads(output.read_text())
            self.assertEqual(witness["controlCount"], 1)
            self.assertEqual(witness["disagreementCount"], 1)
            self.assertEqual(witness["status"], "witnessed")

            campaign = root / "campaign"
            campaign.mkdir()
            (campaign / "campaign.json").write_text(
                json.dumps({"localCheckout": str(root), "commit": "a" * 40}) + "\n"
            )
            pipeline = subprocess.run(
                [
                    sys.executable,
                    str(PIPELINE),
                    "run",
                    str(campaign),
                    "--source",
                    str(root),
                    "--tool",
                    "differential",
                    "--differential-spec",
                    str(spec),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(pipeline.returncode, 0, pipeline.stderr)
            run_record = json.loads(Path(pipeline.stdout.strip()).read_text())
            self.assertEqual(run_record["leadCount"], 1)
            self.assertTrue(run_record["leads"][0]["provenance"]["runtimeValidated"])
            self.assertFalse(run_record["leads"][0]["provenance"]["staticOnly"])


if __name__ == "__main__":
    unittest.main()
