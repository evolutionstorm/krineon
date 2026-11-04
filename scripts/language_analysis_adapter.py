#!/usr/bin/env python3
"""Run language-specific analyzers and retain provenance-bound static evidence.

The adapter never promotes an analyzer warning to a vulnerability. It preserves
the exact command, target identity, raw output, coverage gaps, and a compact
semantic summary that a later runtime experiment can test.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

try:
    from aisec_cpg_adapter import executable_identity, sha256_file, source_manifest
except ModuleNotFoundError:  # imported as scripts.language_analysis_adapter
    from scripts.aisec_cpg_adapter import executable_identity, sha256_file, source_manifest


TOOLS = ("svf", "phasar", "pysa", "infer", "go-callgraph")


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def compact(value: str, limit: int = 500) -> str:
    return " ".join(value.strip().split())[:limit]


def capability_command(tool: str, executable: Path) -> list[str]:
    if tool in {"svf", "phasar", "go-callgraph"}:
        return [str(executable), "--help"]
    return [str(executable), "--version"]


def run_capture(
    command: list[str], *, cwd: Path, timeout: int
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"analysis timed out after {timeout}s") from exc


def safe_relative_workdir(source: Path, requested: str | None) -> Path:
    if source.is_file():
        base = source.parent
    else:
        base = source
    if not requested:
        return base
    candidate = (base / requested).resolve()
    try:
        candidate.relative_to(base.resolve())
    except ValueError as exc:
        raise RuntimeError("build workingDirectory must remain inside the source tree") from exc
    if not candidate.is_dir():
        raise RuntimeError(f"build workingDirectory is not a directory: {candidate}")
    return candidate


def require_module(args: argparse.Namespace) -> Path:
    if args.module is None:
        raise RuntimeError(f"{args.tool} requires --module with pinned LLVM IR or bitcode")
    module = args.module.expanduser().resolve()
    if not module.is_file() or module.suffix.lower() not in {".ll", ".bc"}:
        raise RuntimeError(f"LLVM module is not a .ll or .bc file: {module}")
    return module


def command_for_tool(
    args: argparse.Namespace, source: Path, output_dir: Path
) -> tuple[list[str], Path, dict[str, Any]]:
    executable = args.executable.expanduser().resolve()
    details: dict[str, Any] = {}
    if args.tool == "svf":
        module = require_module(args)
        details["llvmModule"] = {
            "path": str(module),
            "sha256": sha256_file(module),
        }
        return (
            [str(executable), f"-{args.svf_analysis}", "-stat=false", str(module)],
            output_dir,
            details,
        )
    if args.tool == "phasar":
        module = require_module(args)
        details["llvmModule"] = {
            "path": str(module),
            "sha256": sha256_file(module),
        }
        command = [str(executable), "-m", str(module)]
        if args.phasar_analysis:
            command.extend(["-D", args.phasar_analysis])
        if args.analysis_config:
            config = args.analysis_config.expanduser().resolve()
            if not config.is_file():
                raise RuntimeError(f"PhASAR analysis config does not exist: {config}")
            command.extend(["--analysis-config", str(config)])
            details["analysisConfig"] = {
                "path": str(config),
                "sha256": sha256_file(config),
            }
        return command, output_dir, details
    if args.tool == "pysa":
        configuration = source / ".pyre_configuration" if source.is_dir() else source.parent / ".pyre_configuration"
        if not configuration.is_file():
            raise RuntimeError("Pysa requires a checked-in or reviewed .pyre_configuration")
        results = output_dir / "pysa-results"
        details["configuration"] = {
            "path": str(configuration),
            "sha256": sha256_file(configuration),
        }
        command = [
            str(executable),
            "analyze",
            "--save-results-to",
            str(results),
        ]
        if args.pysa_no_verify:
            command.append("--no-verify")
            details["modelVerificationDisabled"] = True
        return command, source if source.is_dir() else source.parent, details
    if args.tool == "infer":
        if args.build_spec is None:
            raise RuntimeError("Infer requires --build-spec with a reviewed argv build command")
        spec_path = args.build_spec.expanduser().resolve()
        spec = read_object(spec_path)
        build_command = spec.get("command")
        if (
            not isinstance(build_command, list)
            or not build_command
            or not all(isinstance(item, str) and item for item in build_command)
        ):
            raise RuntimeError("Infer build spec command must be a non-empty argv array")
        working_directory = safe_relative_workdir(source, spec.get("workingDirectory"))
        results = output_dir / "infer-out"
        details["buildSpec"] = {
            "path": str(spec_path),
            "sha256": sha256_file(spec_path),
            "command": build_command,
            "workingDirectory": str(working_directory),
        }
        return (
            [str(executable), "run", "--results-dir", str(results), "--", *build_command],
            working_directory,
            details,
        )
    if args.tool == "go-callgraph":
        details["algorithm"] = args.go_algorithm
        details["pattern"] = args.go_pattern
        command = [
            str(executable),
            f"-algo={args.go_algorithm}",
            "-format={{.Caller}}\t{{.Callee}}",
            args.go_pattern,
        ]
        return command, source if source.is_dir() else source.parent, details
    raise RuntimeError(f"unsupported tool: {args.tool}")


def walk_json(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from walk_json(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from walk_json(nested)


def load_json_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = []
        for line in text.splitlines():
            try:
                value.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(walk_json(value))


def artifact_inventory(output_dir: Path, excluded: set[Path]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for path in sorted(output_dir.rglob("*")):
        resolved = path.resolve()
        if not path.is_file() or resolved in excluded:
            continue
        artifacts.append(
            {
                "path": path.relative_to(output_dir).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    return artifacts


def normalize_output(
    *,
    tool: str,
    stdout: str,
    stderr: str,
    output_dir: Path,
    details: dict[str, Any],
) -> dict[str, Any]:
    combined = "\n".join((stdout, stderr))
    locations = sorted(
        set(re.findall(r"(?:[A-Za-z]:)?[^\s:()]+\.(?:c|cc|cpp|h|java|py|go|ll):(\d+)", combined))
    )
    summary: dict[str, Any] = {
        "lineCount": len(combined.splitlines()),
        "nonEmptyLineCount": sum(1 for line in combined.splitlines() if line.strip()),
        "sourceLineReferences": len(locations),
    }
    coverage_gaps: list[str] = []
    if tool == "go-callgraph":
        edges = []
        for line in stdout.splitlines():
            if "\t" not in line:
                continue
            caller, callee = line.split("\t", 1)
            if caller.strip() and callee.strip():
                edges.append((caller.strip(), callee.strip()))
        summary.update(
            {
                "callGraphEdgeCount": len(set(edges)),
                "callGraphNodeCount": len({node for edge in edges for node in edge}),
            }
        )
        coverage_gaps.append("built-in calls are not represented by golang.org/x/tools call graphs")
    elif tool == "infer":
        report = output_dir / "infer-out" / "report.json"
        issues = load_json_records(report) if report.is_file() else []
        issue_rows = [
            row for row in issues if row.get("bug_type") or row.get("bug_type_hum")
        ]
        summary.update(
            {
                "issueCount": len(issue_rows),
                "issueTypes": dict(
                    sorted(
                        Counter(
                            str(row.get("bug_type") or row.get("bug_type_hum"))
                            for row in issue_rows
                        ).items()
                    )
                ),
            }
        )
        if not report.is_file():
            coverage_gaps.append("Infer completed without infer-out/report.json")
    elif tool == "pysa":
        json_files = sorted((output_dir / "pysa-results").rglob("*.json")) if (output_dir / "pysa-results").is_dir() else []
        records = [row for path in json_files for row in load_json_records(path)]
        issue_rows = [
            row
            for row in records
            if any(key in row for key in ("rule", "rule_code", "trace", "callable"))
        ]
        summary.update(
            {
                "jsonArtifactCount": len(json_files),
                "candidateRecordCount": len(issue_rows),
                "callableCount": len({str(row.get("callable")) for row in issue_rows if row.get("callable")}),
            }
        )
        coverage_gaps.extend(
            [
                "unmodelled dependencies and framework APIs can hide flows",
                "model verification status and search_path coverage must be reviewed",
            ]
        )
        if details.get("modelVerificationDisabled"):
            coverage_gaps.append("Pysa model verification was explicitly disabled")
    elif tool == "svf":
        summary.update(
            {
                "pointsToMentions": len(re.findall(r"points?-to|pts", combined, re.I)),
                "callGraphMentions": len(re.findall(r"call\s*graph|callgraph", combined, re.I)),
            }
        )
        coverage_gaps.append("SVF results overapproximate or underapproximate according to the selected analysis")
    elif tool == "phasar":
        summary.update(
            {
                "taintMentions": len(re.findall(r"taint|leak|sink", combined, re.I)),
                "uninitializedMentions": len(re.findall(r"uninitial", combined, re.I)),
            }
        )
        if not details.get("analysisConfig"):
            coverage_gaps.append("no target-specific source/sink analysis configuration was supplied")
    return {
        "schemaVersion": 1,
        "producer": "krineon-language-analysis-adapter",
        "createdAt": utc_now(),
        "tool": tool,
        "details": details,
        "summary": summary,
        "coverageGaps": coverage_gaps,
        "claimBoundary": "static-source-support-runtime-confirmation-required",
        "promotion": {
            "createsFinding": False,
            "createsQueueLead": False,
            "requiredNextEvidence": [
                "exact source path with every conditional resolved",
                "a target-specific executable security oracle",
                "baseline and enforcing negative controls",
                "coordinator execution and independent replay",
            ],
        },
    }


def run_adapter(args: argparse.Namespace) -> int:
    source = args.source.expanduser().resolve()
    executable = args.executable.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    if not source.exists():
        raise RuntimeError(f"source does not exist: {source}")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError(f"analyzer executable is not executable: {executable}")
    source_before = source_manifest(source)
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / f"{args.tool}.stdout"
    stderr_path = output_dir / f"{args.tool}.stderr"
    capability_stdout = output_dir / f"{args.tool}-capability.stdout"
    capability_stderr = output_dir / f"{args.tool}-capability.stderr"

    capability_argv = capability_command(args.tool, executable)
    capability = run_capture(
        capability_argv, cwd=source if source.is_dir() else source.parent, timeout=min(args.timeout, 30)
    )
    capability_stdout.write_text(capability.stdout, encoding="utf-8")
    capability_stderr.write_text(capability.stderr, encoding="utf-8")

    command, cwd, details = command_for_tool(args, source, output_dir)
    if args.llvm_provenance:
        manifest = args.llvm_provenance.expanduser().resolve()
        details["llvmProvenance"] = {
            "path": str(manifest),
            "sha256": sha256_file(manifest),
            "complete": True,
        }
    elif args.tool in {"svf", "phasar"}:
        details["llvmProvenance"] = {"complete": False}

    started = utc_now()
    completed = run_capture(command, cwd=cwd, timeout=args.timeout)
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(
            f"{args.tool} failed with exit {completed.returncode}: {compact(completed.stderr)}"
        )

    semantic = normalize_output(
        tool=args.tool,
        stdout=completed.stdout,
        stderr=completed.stderr,
        output_dir=output_dir,
        details=details,
    )
    semantic_path = output_dir / f"{args.tool}-semantic.json"
    write_json(semantic_path, semantic)
    excluded = {
        semantic_path.resolve(),
        (output_dir / f"{args.tool}-run.json").resolve(),
    }
    artifacts = artifact_inventory(output_dir, excluded)
    record = {
        "schemaVersion": 1,
        "producer": "krineon-language-analysis-adapter",
        "createdAt": utc_now(),
        "startedAt": started,
        "finishedAt": utc_now(),
        "tool": args.tool,
        "source": str(source),
        "sourceManifest": source_before,
        "sourceManifestAfter": source_manifest(source),
        "executable": executable_identity(executable),
        "capability": {
            "command": capability_argv,
            "exitCode": capability.returncode,
            "stdout": capability_stdout.name,
            "stderr": capability_stderr.name,
            "firstLine": compact(capability.stdout or capability.stderr),
        },
        "command": command,
        "workingDirectory": str(cwd),
        "exitCode": completed.returncode,
        "stdout": stdout_path.name,
        "stderr": stderr_path.name,
        "semanticArtifact": {
            "path": semantic_path.name,
            "sha256": sha256_file(semantic_path),
        },
        "artifacts": artifacts,
        "promotion": semantic["promotion"],
    }
    record["sourceUnchanged"] = record["sourceManifest"] == record["sourceManifestAfter"]
    record_path = output_dir / f"{args.tool}-run.json"
    write_json(record_path, record)
    print(record_path)
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--tool", required=True, choices=TOOLS)
    root.add_argument("--source", required=True, type=Path)
    root.add_argument("--executable", required=True, type=Path)
    root.add_argument("--output-dir", required=True, type=Path)
    root.add_argument("--module", type=Path)
    root.add_argument("--llvm-provenance", type=Path)
    root.add_argument("--analysis-config", type=Path)
    root.add_argument("--build-spec", type=Path)
    root.add_argument("--svf-analysis", choices=("ander", "fspta"), default="ander")
    root.add_argument("--phasar-analysis")
    root.add_argument("--pysa-no-verify", action="store_true")
    root.add_argument(
        "--go-algorithm", choices=("static", "cha", "rta", "vta"), default="cha"
    )
    root.add_argument("--go-pattern", default="./...")
    root.add_argument("--timeout", type=int, default=900)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.timeout < 1:
        raise SystemExit("timeout must be positive")
    try:
        return run_adapter(args)
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
