from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
ADAPTER = PROJECT / "scripts" / "language_analysis_adapter.py"
PIPELINE = PROJECT / "scripts" / "static_analysis_pipeline.py"


FAKE_ANALYZER = """#!/usr/bin/env python3
import json, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
if '--help' in sys.argv or '--version' in sys.argv:
    print(name + ' fixture 1.0')
    raise SystemExit(0)
if name == 'wpa':
    print('Points-to set pts{1,2}; callgraph edge main -> consume')
elif name == 'phasar-cli':
    print('taint source reaches sink at fixture.cpp:7')
elif name == 'pyre':
    out = pathlib.Path(sys.argv[sys.argv.index('--save-results-to') + 1])
    out.mkdir(parents=True, exist_ok=True)
    (out / 'taint-output.json').write_text(json.dumps([{'callable':'app.route','rule_code':5001,'trace':[]}]))
elif name == 'infer':
    out = pathlib.Path(sys.argv[sys.argv.index('--results-dir') + 1])
    out.mkdir(parents=True, exist_ok=True)
    (out / 'report.json').write_text(json.dumps([{'bug_type':'USE_AFTER_FREE','file':'fixture.c'}]))
elif name == 'callgraph':
    print('example/main.main\\texample/lib.Consume')
else:
    raise SystemExit(3)
"""


class LanguageAnalysisAdapterTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, Path]:
        source = root / "source"
        source.mkdir()
        (source / "app.py").write_text("def route(value): return value\n", encoding="utf-8")
        (source / ".pyre_configuration").write_text(
            json.dumps({"source_directories": ["."]}) + "\n", encoding="utf-8"
        )
        (source / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")
        (source / "fixture.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
        module = source / "fixture.ll"
        module.write_text("define i32 @main() { ret i32 0 }\n", encoding="utf-8")
        build_spec = root / "infer-build.json"
        build_spec.write_text(json.dumps({"command": ["make", "all"]}) + "\n")
        tools = root / "bin"
        tools.mkdir()
        for name in ("wpa", "phasar-cli", "pyre", "infer", "callgraph"):
            executable = tools / name
            executable.write_text(FAKE_ANALYZER, encoding="utf-8")
            executable.chmod(0o700)
        return source, module, build_spec

    def run_tool(
        self,
        *,
        tool: str,
        executable: Path,
        source: Path,
        output: Path,
        extra: list[str] | None = None,
    ) -> dict:
        completed = subprocess.run(
            [
                sys.executable,
                str(ADAPTER),
                "--tool",
                tool,
                "--source",
                str(source),
                "--executable",
                str(executable),
                "--output-dir",
                str(output),
                "--timeout",
                "10",
                *(extra or []),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        semantic = output / f"{tool}-semantic.json"
        self.assertTrue(semantic.is_file())
        return json.loads(semantic.read_text(encoding="utf-8"))

    def test_each_analyzer_retains_static_evidence_without_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, module, build_spec = self.fixture(root)
            tools = root / "bin"
            cases = {
                "svf": ["--module", str(module)],
                "phasar": ["--module", str(module), "--phasar-analysis", "ifds-uninit"],
                "pysa": [],
                "infer": ["--build-spec", str(build_spec)],
                "go-callgraph": ["--go-algorithm", "cha"],
            }
            results = {}
            for tool, extra in cases.items():
                executable_name = {
                    "svf": "wpa",
                    "phasar": "phasar-cli",
                    "pysa": "pyre",
                    "infer": "infer",
                    "go-callgraph": "callgraph",
                }[tool]
                results[tool] = self.run_tool(
                    tool=tool,
                    executable=tools / executable_name,
                    source=source,
                    output=root / f"out-{tool}",
                    extra=extra,
                )
                self.assertFalse(results[tool]["promotion"]["createsFinding"])
                self.assertFalse(results[tool]["promotion"]["createsQueueLead"])
                run_record = json.loads(
                    (root / f"out-{tool}" / f"{tool}-run.json").read_text(
                        encoding="utf-8"
                    )
                )
                self.assertTrue(run_record["sourceUnchanged"])
            self.assertEqual(results["go-callgraph"]["summary"]["callGraphEdgeCount"], 1)
            self.assertEqual(results["infer"]["summary"]["issueTypes"]["USE_AFTER_FREE"], 1)
            self.assertEqual(results["pysa"]["summary"]["callableCount"], 1)

    def test_pipeline_runs_every_installed_compatible_analyzer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source, module, build_spec = self.fixture(root)
            campaign = root / "campaign"
            campaign.mkdir()
            (campaign / "campaign.json").write_text(
                json.dumps({"schemaVersion": 1, "commit": "b" * 40}) + "\n",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["PATH"] = str(root / "bin") + os.pathsep + "/usr/bin:/bin"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(PIPELINE),
                    "run",
                    str(campaign),
                    "--source",
                    str(source),
                    "--llvm-module",
                    str(module),
                    "--infer-build-spec",
                    str(build_spec),
                    "--timeout",
                    "10",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
                env=environment,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            run_path = Path(completed.stdout.strip().splitlines()[-1])
            run = json.loads(run_path.read_text(encoding="utf-8"))
            records = {item["name"]: item for item in run["tools"]}
            for name in ("svf", "phasar", "pysa", "infer", "go-callgraph"):
                self.assertEqual(records[name]["status"], "completed", records[name])
            self.assertEqual(len(run["languageSemanticArtifacts"]), 5)
            self.assertEqual(run["leads"], [])


if __name__ == "__main__":
    unittest.main()
