#!/usr/bin/env python3
"""Execute two pinned consumers on identical inputs and retain disagreements."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import uuid
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


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def checked_artifact(raw: Any, label: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise RuntimeError(f"{label} must be an artifact object")
    path = Path(str(raw.get("path") or "")).expanduser().resolve()
    if not path.is_file():
        raise RuntimeError(f"{label} is missing: {path}")
    observed = sha256(path)
    if raw.get("sha256") != observed:
        raise RuntimeError(f"{label} hash changed: {path}")
    return artifact(path)


def normalize(stdout: bytes, stderr: bytes, return_code: int, config: dict[str, Any]) -> Any:
    mode = str(config.get("mode") or "json-stdout")
    if mode == "json-stdout":
        try:
            value = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            diagnostic = stderr.decode("utf-8", "replace")[-2000:]
            raise RuntimeError(
                f"consumer did not emit one JSON value: {error}; stderr={diagnostic!r}"
            ) from error
        if isinstance(value, dict):
            for key in config.get("ignoreFields", []):
                value.pop(str(key), None)
        return {"returnCode": return_code, "value": value}
    if mode == "bytes":
        return {
            "returnCode": return_code,
            "stdoutSha256": hashlib.sha256(stdout).hexdigest(),
            "stderrSha256": hashlib.sha256(stderr).hexdigest(),
        }
    raise RuntimeError(f"unsupported normalization mode: {mode}")


def run_consumer(
    consumer: dict[str, Any], input_path: Path, timeout: int, normalization: dict[str, Any]
) -> dict[str, Any]:
    name = str(consumer.get("name") or "")
    command_raw = consumer.get("command")
    if not name or not isinstance(command_raw, list) or not command_raw:
        raise RuntimeError("each consumer needs a name and command array")
    command = [str(value).replace("{input}", str(input_path)) for value in command_raw]
    if not any(str(input_path) in value for value in command):
        raise RuntimeError(f"consumer {name} command does not consume {{input}}")
    for index, raw in enumerate(consumer.get("artifacts", [])):
        checked_artifact(raw, f"consumer {name} artifact {index}")
    cwd = Path(str(consumer.get("cwd") or ".")).expanduser().resolve()
    if not cwd.is_dir():
        raise RuntimeError(f"consumer {name} cwd is missing")
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        timeout=timeout,
        env={**os.environ, **{str(k): str(v) for k, v in consumer.get("environment", {}).items()}},
    )
    return {
        "name": name,
        "command": command,
        "returnCode": completed.returncode,
        "stdoutSha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderrSha256": hashlib.sha256(completed.stderr).hexdigest(),
        "stdout": completed.stdout.decode("utf-8", "replace")[-16384:],
        "stderr": completed.stderr.decode("utf-8", "replace")[-16384:],
        "observation": normalize(
            completed.stdout, completed.stderr, completed.returncode, normalization
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args(argv)
    try:
        spec_path = args.spec.expanduser().resolve()
        spec = json.loads(spec_path.read_text(encoding="utf-8"))
        consumers = spec.get("consumers")
        if not isinstance(consumers, list) or len(consumers) != 2:
            raise RuntimeError("differential witness requires exactly two consumers")
        inputs = [checked_artifact(value, f"input {index}") for index, value in enumerate(spec.get("inputs", []))]
        if not inputs:
            raise RuntimeError("differential witness input set is empty")
        normalization = spec.get("normalization")
        if not isinstance(normalization, dict):
            normalization = {"mode": "json-stdout"}
        cases = []
        for input_artifact in inputs:
            input_path = Path(input_artifact["path"])
            observations = [
                run_consumer(consumer, input_path, args.timeout, normalization)
                for consumer in consumers
            ]
            disagreement = observations[0]["observation"] != observations[1]["observation"]
            cases.append(
                {
                    "input": input_artifact,
                    "consumers": observations,
                    "disagreement": disagreement,
                    "witnessId": (
                        "DW-"
                        + hashlib.sha256(
                            json.dumps(
                                [input_artifact["sha256"], *(item["observation"] for item in observations)],
                                sort_keys=True,
                                separators=(",", ":"),
                            ).encode()
                        ).hexdigest()[:16]
                        if disagreement
                        else None
                    ),
                }
            )
        controls = [case for case in cases if not case["disagreement"]]
        witnesses = [case for case in cases if case["disagreement"]]
        if not controls:
            raise RuntimeError("no equal-observation control was recorded")
        record = {
            "schemaVersion": 1,
            "producer": "krineon-differential-witness",
            "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
            "name": str(spec.get("name") or spec_path.stem),
            "spec": artifact(spec_path),
            "normalization": normalization,
            "consumerNames": [str(value.get("name")) for value in consumers],
            "caseCount": len(cases),
            "controlCount": len(controls),
            "disagreementCount": len(witnesses),
            "cases": cases,
            "status": "witnessed" if witnesses else "no-disagreement",
        }
        atomic_json(args.output.expanduser().resolve(), record)
        print(args.output.expanduser().resolve())
        return 0 if witnesses else 1
    except (
        OSError,
        RuntimeError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
