#!/usr/bin/env python3
"""Build and freeze one component with ASan/UBSan and hashed corpus inputs."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact(path: Path) -> dict[str, Any]:
    return {"path": str(path), "sha256": sha256(path), "size": path.stat().st_size}


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def resolve_under(root: Path, value: str, label: str) -> Path:
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise RuntimeError(f"{label} escapes component root") from error
    if not candidate.is_file():
        raise RuntimeError(f"{label} is missing: {candidate}")
    return candidate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", type=Path, help="component.json")
    parser.add_argument("output", type=Path, help="empty output directory")
    parser.add_argument("--compiler", help="override compiler path")
    parser.add_argument("--timeout", type=int, default=120)
    args = parser.parse_args(argv)
    try:
        component_path = args.component.expanduser().resolve()
        component_root = component_path.parent
        spec = json.loads(component_path.read_text(encoding="utf-8"))
        output = args.output.expanduser().resolve()
        if output.exists() and any(output.iterdir()):
            raise RuntimeError("output directory must be empty")
        output.mkdir(parents=True, exist_ok=True)
        source = resolve_under(component_root, str(spec["source"]), "source")
        requested = args.compiler or str(spec.get("compiler") or "clang++")
        compiler_value = shutil.which(requested) if not Path(requested).is_absolute() else requested
        if not compiler_value:
            raise RuntimeError(f"compiler is unavailable: {requested}")
        # Keep the driver name (clang++/g++) intact. Resolving a clang++ symlink
        # to clang changes driver mode and silently drops the C++ runtime.
        compiler = Path(compiler_value).absolute()
        flags = [str(value) for value in spec.get("compilerFlags", [])]
        required = {"-fsanitize=address,undefined", "-fno-omit-frame-pointer"}
        if not required.issubset(set(flags)):
            raise RuntimeError("component must enable ASan, UBSan, and frame pointers")
        binary = output / str(spec["name"])
        command = [str(compiler), *flags, str(source), "-o", str(binary)]
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True, timeout=args.timeout
        )
        (output / "build.stdout").write_text(completed.stdout, encoding="utf-8")
        (output / "build.stderr").write_text(completed.stderr, encoding="utf-8")
        if completed.returncode != 0 or not binary.is_file():
            raise RuntimeError("instrumented component build failed")
        strings = subprocess.run(
            ["strings", str(binary)], check=False, capture_output=True, text=True, timeout=30
        )
        sanitizer_symbols = {
            "address": "__asan_" in strings.stdout,
            "undefined": "__ubsan_" in strings.stdout,
        }
        if not all(sanitizer_symbols.values()):
            raise RuntimeError("built binary does not contain both ASan and UBSan instrumentation")
        version = subprocess.run(
            [str(compiler), "--version"], check=False, capture_output=True, text=True, timeout=30
        )
        corpus = [resolve_under(component_root, str(value), "corpus input") for value in spec.get("corpus", [])]
        if not corpus:
            raise RuntimeError("component corpus is empty")
        manifest = {
            "schemaVersion": 1,
            "producer": "krineon-component-freeze",
            "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "name": spec["name"],
            "spec": artifact(component_path),
            "source": artifact(source),
            "compiler": {**artifact(compiler), "version": version.stdout.splitlines()[0]},
            "command": command,
            "sanitizers": sanitizer_symbols,
            "binary": artifact(binary),
            "corpus": [artifact(path) for path in corpus],
            "buildStdout": artifact(output / "build.stdout"),
            "buildStderr": artifact(output / "build.stderr"),
        }
        write_json(output / "frozen-component.json", manifest)
        for parent in (output, *output.parents):
            campaign_path = parent / "campaign.json"
            if not campaign_path.is_file():
                continue
            campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
            try:
                relative_binary = binary.relative_to(parent).as_posix()
                relative_manifest = (output / "frozen-component.json").relative_to(
                    parent
                ).as_posix()
            except ValueError:
                break
            rows = campaign.get("frozenTargetArtifacts")
            if not isinstance(rows, list):
                rows = []
            rows = [
                row
                for row in rows
                if not isinstance(row, dict) or row.get("path") != relative_binary
            ]
            rows.append(
                {
                    "path": relative_binary,
                    "sha256": manifest["binary"]["sha256"],
                    "manifest": relative_manifest,
                    "producer": "krineon-component-freeze",
                }
            )
            campaign["frozenTargetArtifacts"] = rows
            write_json(campaign_path, campaign)
            break
        print(output / "frozen-component.json")
        return 0
    except (OSError, KeyError, ValueError, json.JSONDecodeError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
