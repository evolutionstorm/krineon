#!/usr/bin/env python3
"""Inventory local analysis tools without installing or modifying anything."""

from __future__ import annotations

import argparse
import importlib.util
import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


COMMANDS: dict[str, list[list[str]]] = {
    "trailmark": [["trailmark", "--version"]],
    "tree-sitter": [["tree-sitter", "--version"]],
    "joern": [["joern", "--version"]],
    "joern-parse": [["joern-parse", "--help"]],
    "joern-scan": [["joern-scan", "--help"]],
    "z3": [["z3", "-version"], ["z3", "--version"]],
    "ripgrep": [["rg", "--version"]],
    "semgrep": [["semgrep", "--version"]],
    "opengrep": [["opengrep", "--version"]],
    "codeql": [["codeql", "version"]],
    "clang": [["clang", "--version"]],
    "llvm-symbolizer": [["llvm-symbolizer", "--version"]],
    "gn": [["gn", "--version"]],
    "ninja": [["ninja", "--version"]],
    "autoninja": [["autoninja", "--version"]],
    "gclient": [["gclient", "--version"]],
    "swift": [["swift", "--version"]],
    "minidump_stackwalk": [["minidump_stackwalk", "--version"]],
    "cargo": [["cargo", "--version"]],
    "node": [["node", "--version"]],
    "chromium": [["chromium", "--version"]],
    "google-chrome": [["google-chrome", "--version"]],
    "afl-fuzz": [["afl-fuzz", "-V"]],
    "afl-showmap": [["afl-showmap", "-h"]],
    "llvm-profdata": [["llvm-profdata", "--version"]],
    "llvm-cov": [["llvm-cov", "--version"]],
    "FuzzilliCli": [["FuzzilliCli", "--help"]],
}

PYTHON_MODULES = (
    "tree_sitter",
    "tree_sitter_languages",
    "z3",
    "playwright",
)


def compact(value: str) -> str:
    return " ".join(value.strip().split())[:500]


def version_label(name: str, output: str, executable: str) -> str:
    match = re.search(r"\bVersion:\s*`?([^`\s]+)", output)
    if match:
        return f"{name} {match.group(1)}"
    return output.splitlines()[0] if output else executable


def command_probe(name: str, variants: list[list[str]]) -> dict[str, Any]:
    executable = shutil.which(variants[0][0])
    result: dict[str, Any] = {
        "installed": executable is not None,
        "available": False,
        "path": executable,
        "version": None,
    }
    if executable is None:
        return result
    last_error = ""
    for command in variants:
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            last_error = str(exc)
            continue
        output = compact(completed.stdout or completed.stderr)
        if completed.returncode == 0:
            result["available"] = True
            result["version"] = version_label(name, output, executable)
            result["probeExitCode"] = completed.returncode
            return result
        last_error = f"exit {completed.returncode}: {output or 'without output'}"
    result["probeError"] = last_error
    return result


def build_inventory() -> dict[str, Any]:
    return {
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "commands": {name: command_probe(name, variants) for name, variants in COMMANDS.items()},
        "pythonModules": {
            name: {"available": importlib.util.find_spec(name) is not None}
            for name in PYTHON_MODULES
        },
        "guidance": {
            "staticPipeline": "Run scripts/static_analysis_pipeline.py; it retains raw outputs and creates provenance-bound validation tasks.",
            "treeSitter": "Use Tree-sitter only to nominate exact producer/consumer pairs; syntax hits do not enter the queue.",
            "joern": "Use Joern only to nominate exact producer/consumer pairs; CPG hits do not enter the queue.",
            "differential": "scripts/differential_witness.py runs two pinned consumers on one hashed input and requires an equal control before retaining a disagreement.",
            "z3": "scripts/z3_boundary_solver.py distinguishes generic models from hashed source-bound constraints; manual transcription is labelled and a model is not runtime proof.",
            "trailmark": "The static pipeline invokes single-revision structure and entrypoint analysis; diff modes are prohibited.",
            "chromeV8": "For chrome-v8 campaigns, record GN, Ninja, Clang, symbolizer, Swift/Fuzzilli, and minidump availability without installing them.",
            "browserReplay": "scripts/chrome_v8_harness.py browser-replay uses direct CDP and does not require Playwright; register an exact sandboxed-chrome binary first.",
            "externalFuzzing": "scripts/fuzzer_orchestrator.py operates pinned AFL++, libFuzzer, and Fuzzilli targets with verified instrumentation, native parallelism, corpus sync, crash forwarding, and coverage rebuilds.",
            "authority": "Source semantics and controlled runtime evidence decide the security claim.",
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--output", type=Path, help="write the JSON inventory to this path")
    args = parser.parse_args(argv)
    inventory = build_inventory()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
        if not args.json:
            print(f"wrote tool inventory: {args.output}")
            return 0
    if args.json:
        print(json.dumps(inventory, indent=2))
        return 0
    print(f"platform: {inventory['platform']['system']} {inventory['platform']['release']} ({inventory['platform']['machine']})")
    print(f"python:   {inventory['platform']['python']}")
    print()
    print(f"{'TOOL':<18} {'AVAILABLE':<10} VERSION OR PATH")
    print("-" * 78)
    for name, details in inventory["commands"].items():
        available = "yes" if details["available"] else "no"
        value = details.get("version") or details.get("path") or "-"
        print(f"{name:<18} {available:<10} {value}")
    for name, details in inventory["pythonModules"].items():
        available = "yes" if details["available"] else "no"
        print(f"python:{name:<11} {available:<10} module")
    return 0


if __name__ == "__main__":
    sys.exit(main())
