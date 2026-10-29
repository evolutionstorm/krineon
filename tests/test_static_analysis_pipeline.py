from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "research_harness.py"
PIPELINE = PROJECT / "scripts" / "static_analysis_pipeline.py"
Z3_SOLVER = PROJECT / "scripts" / "z3_boundary_solver.py"


class StaticAnalysisPipelineTests(unittest.TestCase):
    def run_command(self, *args: str, expected: int = 0) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(args, check=False, capture_output=True, text=True)
        self.assertEqual(
            completed.returncode,
            expected,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        return completed

    @unittest.skipUnless(shutil.which("z3"), "Z3 binary is unavailable")
    def test_z3_solver_emits_concrete_wrap_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "result.json"
            payloads = Path(tmp) / "payloads"
            self.run_command(
                sys.executable,
                str(Z3_SOLVER),
                "--kind",
                "truncate",
                "--bits",
                "32",
                "--target",
                "0",
                "--min-x",
                "1",
                "--max-x",
                "4294967296",
                "--output",
                str(output),
                "--emit-dir",
                str(payloads),
            )
            result = json.loads(output.read_text())
            self.assertEqual(result["model"]["x"]["integer"], 2**32)
            self.assertEqual(result["model"]["x"]["consumerUnsigned"], 0)
            self.assertEqual((payloads / "x.hex.txt").read_text().strip(), "100000000")
            self.assertEqual((payloads / "x.big-endian.bin").read_bytes(), b"\x01\x00\x00\x00\x00")

    def test_ingest_creates_idempotent_provenance_validation_task(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            campaign = root / "campaign"
            self.run_command(
                sys.executable,
                str(HARNESS),
                "init",
                str(campaign),
                "--target",
                "fixture",
                "--repo",
                "https://example.invalid/fixture",
                "--commit",
                "a" * 40,
            )
            self.run_command(sys.executable, str(HARNESS), "plan", str(campaign))
            self.run_command(sys.executable, str(HARNESS), "queue", str(campaign))
            run_dir = campaign / "tools" / "static" / "fixture-run"
            run_dir.mkdir(parents=True)
            run_path = run_dir / "run.json"
            run_path.write_text(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "runId": "fixture-run",
                        "campaignCommit": "a" * 40,
                        "source": "/fixture",
                        "leads": [
                            {
                                "id": "SL-0123456789abcdef",
                                "tool": "tree-sitter",
                                "kind": "execution-sink",
                                "title": "Potential process sink",
                                "location": "src/server.c:42",
                                "approachFamily": "execution-sink-backtrace",
                                "evidence": ["tools/static/fixture-run/tree-sitter-census.json"],
                                "provenance": {
                                    "runId": "fixture-run",
                                    "runRecord": "tools/static/fixture-run/run.json",
                                    "campaignCommit": "a" * 40,
                                    "staticOnly": True,
                                    "runtimeValidated": False,
                                },
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            for _ in range(2):
                self.run_command(
                    sys.executable,
                    str(PIPELINE),
                    "ingest",
                    str(campaign),
                    "--run",
                    str(run_path),
                )
            registry = json.loads((campaign / "tools" / "static-leads.json").read_text())
            self.assertEqual(len(registry["leads"]), 1)
            self.assertEqual(registry["leads"][0]["taskId"], "static-0123456789abcdef")
            self.assertTrue(registry["leads"][0]["provenance"]["staticOnly"])
            self.assertFalse(registry["leads"][0]["provenance"]["runtimeValidated"])
            self.assertEqual(len(registry["leads"][0]["observations"]), 1)
            with sqlite3.connect(campaign / "orchestration.db") as connection:
                rows = connection.execute(
                    "SELECT task_id,lane,state FROM tasks WHERE task_id=?",
                    ("static-0123456789abcdef",),
                ).fetchall()
            self.assertEqual(rows, [("static-0123456789abcdef", "static-lead-validation", "queued")])
            findings = json.loads((campaign / "registry.json").read_text())
            self.assertEqual(findings["findings"], [])


if __name__ == "__main__":
    unittest.main()
