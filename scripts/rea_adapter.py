#!/usr/bin/env python3
"""Run an installed REA CLI against a frozen campaign artifact and retain Evidence.

The adapter supports two read-only, first-principles workflows documented by
REA: static JavaScript/application analysis and static native inspection. It
does not install REA, analysis engines, or agent configuration, and it does not
run Frida, attach to a process, or execute the target.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Iterable

try:
    from .swarm_control import ControlError, ControlStore
except ImportError:
    from swarm_control import ControlError, ControlStore


OPERATIONS = {"javascript-application", "native-inspect"}
NATIVE_PROVIDERS = {"ghidra", "hopper", "ida", "kuna"}
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_FILES = 100_000
MAX_TARGET_BYTES = 16 * 1024 * 1024 * 1024
MAX_RESULT_BYTES = 64 * 1024 * 1024


class ReaAdapterError(Exception):
    """The REA request, artifact identity, or Evidence contract is invalid."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ReaAdapterError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ReaAdapterError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReaAdapterError(f"expected a JSON object in {path}")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        temporary.write_bytes(json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def campaign_root(value: Path) -> Path:
    root = value.expanduser().resolve()
    if not (root / "campaign.json").is_file():
        raise ReaAdapterError(f"not a Krineon campaign: {root}")
    return root


def campaign_path(root: Path, value: Any, field: str, *, must_exist: bool = True) -> Path:
    raw = str(value or "").strip()
    relative = Path(raw)
    if not raw or relative.is_absolute():
        raise ReaAdapterError(f"{field} must be campaign-relative")
    if ".." in relative.parts:
        raise ReaAdapterError(f"{field} must not contain parent traversal")
    cursor = root
    for part in relative.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise ReaAdapterError(f"{field} must not traverse symbolic links")
    result = cursor.resolve()
    try:
        result.relative_to(root)
    except ValueError as exc:
        raise ReaAdapterError(f"{field} escapes the campaign root") from exc
    if must_exist and not result.exists():
        raise ReaAdapterError(f"{field} does not exist: {raw}")
    return result


def artifact_identity(path: Path) -> dict[str, Any]:
    """Hash one file or a complete bounded directory without following symlinks."""
    if path.is_symlink():
        raise ReaAdapterError("REA targets must not be symbolic links")
    if path.is_file():
        size = path.stat().st_size
        if size > MAX_TARGET_BYTES:
            raise ReaAdapterError("REA target exceeds the bounded artifact size")
        return {"kind": "file", "files": 1, "bytes": size, "sha256": sha256_file(path)}
    if not path.is_dir():
        raise ReaAdapterError("REA target must be a regular file or directory")
    rows: list[tuple[str, int, str]] = []
    total = 0
    for candidate in sorted(path.rglob("*"), key=lambda item: item.relative_to(path).as_posix()):
        relative = candidate.relative_to(path).as_posix()
        if candidate.is_symlink():
            raise ReaAdapterError(f"REA target contains a symbolic link: {relative}")
        if not candidate.is_file():
            continue
        if len(rows) >= MAX_FILES:
            raise ReaAdapterError("REA target exceeds the bounded file count")
        size = candidate.stat().st_size
        total += size
        if total > MAX_TARGET_BYTES:
            raise ReaAdapterError("REA target exceeds the bounded artifact size")
        rows.append((relative, size, sha256_file(candidate)))
    return {
        "kind": "directory",
        "files": len(rows),
        "bytes": total,
        "sha256": sha256_bytes(canonical(rows)),
    }


def validate_spec(root: Path, raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("schemaVersion") != 1:
        raise ReaAdapterError("REA specification requires schemaVersion 1")
    operation = str(raw.get("operation") or "")
    if operation not in OPERATIONS:
        raise ReaAdapterError(f"unsupported REA operation: {operation or '<missing>'}")
    target = campaign_path(root, raw.get("target"), "target")
    provider = raw.get("provider")
    if operation == "native-inspect":
        provider = str(provider or "")
        if provider not in NATIVE_PROVIDERS:
            raise ReaAdapterError("native-inspect requires an approved native provider")
        if not target.is_file():
            raise ReaAdapterError("native-inspect requires one regular binary file")
    elif provider not in {None, ""}:
        raise ReaAdapterError("javascript-application does not accept a native provider")
    timeout = int(raw.get("timeoutSeconds") or 900)
    if not 30 <= timeout <= 3600:
        raise ReaAdapterError("timeoutSeconds must be between 30 and 3600")
    purpose = str(raw.get("purpose") or "").strip()
    if not purpose:
        raise ReaAdapterError("purpose is required")
    outputs = raw.get("expectedOutputs")
    if not isinstance(outputs, list) or not outputs or not all(isinstance(value, str) and value.strip() for value in outputs):
        raise ReaAdapterError("expectedOutputs must be a non-empty string array")
    build_manifest = None
    if raw.get("buildManifest") not in (None, ""):
        build_manifest = campaign_path(root, raw.get("buildManifest"), "buildManifest")
        if not build_manifest.is_file():
            raise ReaAdapterError("buildManifest must be a regular file")
    return {
        "schemaVersion": 1,
        "operation": operation,
        "target": target,
        "targetRelative": target.relative_to(root).as_posix(),
        "provider": provider or None,
        "timeoutSeconds": timeout,
        "purpose": purpose,
        "expectedOutputs": list(outputs),
        "buildManifest": build_manifest,
        "buildManifestRelative": (
            build_manifest.relative_to(root).as_posix() if build_manifest else None
        ),
    }


def resolve_rea() -> Path:
    executable = shutil.which("rea")
    if not executable:
        raise ReaAdapterError(
            "REA is unavailable; install or register it separately with operator approval"
        )
    path = Path(executable).resolve()
    if not path.is_file():
        raise ReaAdapterError("REA executable does not resolve to a regular file")
    return path


def evidence_record(value: Any) -> dict[str, Any]:
    """Accept REA's complete CLI Evidence record, with only documented wrappers."""
    candidate = value
    if isinstance(candidate, dict) and "evidence_id" not in candidate:
        for key in ("evidence", "result"):
            nested = candidate.get(key)
            if isinstance(nested, dict) and "evidence_id" in nested:
                candidate = nested
                break
    if not isinstance(candidate, dict):
        raise ReaAdapterError("REA JSON did not contain one complete Evidence object")
    evidence_id = candidate.get("evidence_id")
    if not isinstance(evidence_id, str) or not evidence_id.strip():
        raise ReaAdapterError("REA Evidence is missing evidence_id")
    if "normalized_result" not in candidate:
        raise ReaAdapterError("REA Evidence is missing normalized_result")
    if "analysis_profile" not in candidate:
        raise ReaAdapterError("REA Evidence is missing analysis_profile")
    return candidate


def count_collection(value: Any, names: Iterable[str]) -> int:
    if not isinstance(value, dict):
        return 0
    for name in names:
        candidate = value.get(name)
        if isinstance(candidate, list):
            return len(candidate)
    return 0


def summarize_evidence(evidence: dict[str, Any], operation: str) -> dict[str, Any]:
    normalized = evidence.get("normalized_result")
    limitations = evidence.get("limitations")
    if not isinstance(limitations, list):
        limitations = []
    unknowns = evidence.get("residual_unknowns")
    if not isinstance(unknowns, list):
        unknowns = []
    coverage = normalized.get("coverage") if isinstance(normalized, dict) else None
    return {
        "evidenceId": str(evidence["evidence_id"]),
        "operation": str(evidence.get("operation") or operation),
        "provider": str(evidence.get("provider") or "unknown"),
        "analysisProfileSha256": sha256_bytes(canonical(evidence.get("analysis_profile"))),
        "evidenceSha256": sha256_bytes(canonical(evidence)),
        "coveragePresent": coverage is not None,
        "coverageSha256": sha256_bytes(canonical(coverage)) if coverage is not None else None,
        "coverageFieldCount": len(coverage) if isinstance(coverage, dict) else 0,
        "limitationCount": len(limitations),
        "residualUnknownCount": len(unknowns),
        "moduleCount": count_collection(normalized, ("modules", "module_graph")),
        "relationshipCount": count_collection(normalized, ("edges", "imports", "relationships")),
        "untrustedTargetContent": True,
    }


def hypotheses(summary: dict[str, Any], operation: str, evidence_path: str) -> list[dict[str, Any]]:
    common = {
        "tool": "rea",
        "kind": "artifact-source-runtime-differential",
        "location": evidence_path,
        "priorityScore": 82,
        "evidence": [evidence_path],
        "reaEvidenceId": summary["evidenceId"],
        "untrustedTargetContent": True,
        "runtimeValidated": False,
        "claimBoundary": "hypothesis-only",
        "requiredControls": [
            "same pinned artifact",
            "artifact provenance links it to the pinned source revision",
            "source or independent observer comparison",
            "REA limitations and residual unknowns retained",
        ],
    }
    if operation == "javascript-application":
        return [{
            **common,
            "title": "Compare shipped JavaScript module boundaries with source security assumptions",
            "approachFamily": "dependency-integration",
            "question": (
                "Does the shipped module/import or native-handoff graph disagree with the source-level "
                "checker, consumer, authority, or generated-bundle mapping?"
            ),
        }]
    return [{
        **common,
        "title": "Compare native call and reference facts with source boundary assumptions",
        "approachFamily": "execution-sink-backtrace",
        "question": (
            "Does the shipped binary's call/reference evidence show a checker-consumer, ownership, "
            "lifetime, or code-loading path absent from the source hypothesis?"
        ),
    }]


def build_command(executable: Path, spec: dict[str, Any]) -> list[str]:
    if spec["operation"] == "javascript-application":
        return [str(executable), "analyze-javascript-application", str(spec["target"]), "--json"]
    return [
        str(executable),
        "inspect",
        str(spec["target"]),
        "--provider",
        str(spec["provider"]),
        "--json",
    ]


def observe_component(
    root: Path,
    component_id: str,
    operation: str,
    outcome: str,
    latency_ms: float,
    artifact_refs: Iterable[str] = (),
    detail: str = "",
) -> None:
    control = ControlStore(root)
    try:
        control.component_observe(
            {
                "componentId": component_id,
                "operation": operation,
                "outcome": outcome,
                "latencyMs": latency_ms,
                "artifactRefs": list(artifact_refs),
                "detail": detail[:500],
            },
            actor="rea-adapter",
        )
        control.connection.commit()
    finally:
        control.close()


def run_adapter(root: Path, spec_path: Path, output: Path | None = None) -> dict[str, Any]:
    spec = validate_spec(root, read_object(spec_path))
    executable = resolve_rea()
    executable_before = sha256_file(executable)
    target_before = artifact_identity(spec["target"])
    build_manifest_before = (
        sha256_file(spec["buildManifest"]) if spec["buildManifest"] else None
    )
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    run_dir = root / "tools" / "rea" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    retained_spec = run_dir / "spec.json"
    write_json(
        retained_spec,
        {
            **{
                key: value
                for key, value in spec.items()
                if key not in {"target", "buildManifest"}
            },
            "targetIdentityBefore": target_before,
            "buildManifestSha256Before": build_manifest_before,
        },
    )
    control = ControlStore(root)
    try:
        component_id = control.ensure_component(
            kind="tool",
            name="rea",
            version="unprobed",
            capabilities=(spec["operation"], "reverse-engineering-evidence"),
            actor="rea-adapter",
        )
        control.connection.commit()
    finally:
        control.close()
    telemetry_started = time.monotonic()
    version = subprocess.run(
        [str(executable), "--version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if version.returncode != 0:
        observe_component(
            root, component_id, spec["operation"], "failed",
            (time.monotonic() - telemetry_started) * 1000,
            detail="REA version probe failed",
        )
        raise ReaAdapterError("REA version probe failed")
    command = build_command(executable, spec)
    stdout_path = run_dir / "rea-evidence.json"
    stderr_path = run_dir / "rea.stderr"
    started_at = utc_now()
    started = time.monotonic()
    try:
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            completed = subprocess.run(
                command,
                check=False,
                stdout=stdout_handle,
                stderr=stderr_handle,
                timeout=spec["timeoutSeconds"],
            )
    except subprocess.TimeoutExpired:
        observe_component(
            root, component_id, spec["operation"], "failed",
            (time.monotonic() - telemetry_started) * 1000,
            detail="REA analysis timed out",
        )
        raise
    elapsed_ms = (time.monotonic() - started) * 1000
    os.chmod(stdout_path, 0o600)
    os.chmod(stderr_path, 0o600)
    if stdout_path.stat().st_size > MAX_RESULT_BYTES or stderr_path.stat().st_size > MAX_RESULT_BYTES:
        observe_component(
            root, component_id, spec["operation"], "failed", elapsed_ms,
            detail="REA output exceeded the retained-output bound",
        )
        raise ReaAdapterError("REA output exceeds the retained-output bound")
    if completed.returncode != 0:
        observe_component(
            root, component_id, spec["operation"], "failed", elapsed_ms,
            artifact_refs=(stderr_path.relative_to(root).as_posix(),),
            detail=f"REA exited with status {completed.returncode}",
        )
        raise ReaAdapterError(f"REA exited with status {completed.returncode}")
    try:
        evidence_value = json.loads(stdout_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        observe_component(
            root, component_id, spec["operation"], "failed", elapsed_ms,
            artifact_refs=(stdout_path.relative_to(root).as_posix(), stderr_path.relative_to(root).as_posix()),
            detail="REA returned invalid JSON Evidence",
        )
        raise ReaAdapterError("REA did not return one valid JSON Evidence record") from exc
    try:
        evidence = evidence_record(evidence_value)
    except ReaAdapterError as exc:
        observe_component(
            root, component_id, spec["operation"], "failed", elapsed_ms,
            artifact_refs=(stdout_path.relative_to(root).as_posix(), stderr_path.relative_to(root).as_posix()),
            detail=str(exc),
        )
        raise
    target_after = artifact_identity(spec["target"])
    executable_after = sha256_file(executable)
    build_manifest_after = (
        sha256_file(spec["buildManifest"]) if spec["buildManifest"] else None
    )
    if target_after != target_before:
        observe_component(
            root, component_id, spec["operation"], "failed", elapsed_ms,
            artifact_refs=(stdout_path.relative_to(root).as_posix(), stderr_path.relative_to(root).as_posix()),
            detail="REA target changed during analysis",
        )
        raise ReaAdapterError("REA target changed during analysis")
    if executable_after != executable_before:
        observe_component(
            root, component_id, spec["operation"], "failed", elapsed_ms,
            artifact_refs=(stdout_path.relative_to(root).as_posix(), stderr_path.relative_to(root).as_posix()),
            detail="REA executable changed during analysis",
        )
        raise ReaAdapterError("REA executable changed during analysis")
    if build_manifest_after != build_manifest_before:
        observe_component(
            root, component_id, spec["operation"], "failed", elapsed_ms,
            artifact_refs=(stdout_path.relative_to(root).as_posix(), stderr_path.relative_to(root).as_posix()),
            detail="REA build manifest changed during analysis",
        )
        raise ReaAdapterError("REA build manifest changed during analysis")
    evidence_relative = stdout_path.relative_to(root).as_posix()
    summary = summarize_evidence(evidence, spec["operation"])
    result = {
        "schemaVersion": 1,
        "runId": run_id,
        "startedAt": started_at,
        "completedAt": utc_now(),
        "operation": spec["operation"],
        "purpose": spec["purpose"],
        "target": spec["targetRelative"],
        "targetIdentity": target_after,
        "sourceBinding": {
            "campaignCommit": read_object(root / "campaign.json").get("commit"),
            "buildManifest": spec["buildManifestRelative"],
            "buildManifestSha256": build_manifest_after,
            "sourceArtifactEquivalenceEstablished": False,
        },
        "rea": {
            "path": str(executable),
            "sha256": executable_after,
            "version": " ".join((version.stdout or version.stderr).strip().split())[:500],
        },
        "command": command,
        "exitCode": completed.returncode,
        "latencyMs": elapsed_ms,
        "evidencePath": evidence_relative,
        "stderrPath": stderr_path.relative_to(root).as_posix(),
        "stderrSha256": sha256_file(stderr_path),
        "evidenceSummary": summary,
        "hypotheses": hypotheses(summary, spec["operation"], evidence_relative),
        "policy": {
            "targetExecuted": False,
            "runtimeAttached": False,
            "targetContentIsUntrusted": True,
            "findingPromotionAllowed": False,
            "requiresIndependentComparison": True,
            "requiresSourceArtifactBinding": True,
        },
    }
    output_path = output or run_dir / "run.json"
    if not output_path.is_absolute():
        output_path = root / output_path
    output_path = output_path.resolve()
    try:
        output_path.relative_to(root)
    except ValueError as exc:
        raise ReaAdapterError("output must remain inside the campaign") from exc
    write_json(output_path, result)
    try:
        control = ControlStore(root)
        try:
            control.component_upsert(
                {
                    "id": component_id,
                    "kind": "tool",
                    "name": "rea",
                    "version": result["rea"]["version"] or "unknown",
                    "capabilities": [spec["operation"], "reverse-engineering-evidence"],
                    "state": "unknown",
                },
                actor="rea-adapter",
            )
            control.connection.commit()
        finally:
            control.close()
        observe_component(
            root,
            component_id,
            spec["operation"],
            "passed",
            elapsed_ms,
            (
                output_path.relative_to(root).as_posix(),
                evidence_relative,
                stderr_path.relative_to(root).as_posix(),
            ),
        )
    except (ControlError, sqlite3.Error) as exc:
        raise ReaAdapterError(f"REA completed but control-plane telemetry failed: {exc}") from exc
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        root = campaign_root(args.campaign)
        spec_path = args.spec.expanduser().resolve()
        result = run_adapter(root, spec_path, args.output)
        print(json.dumps({
            "runId": result["runId"],
            "evidencePath": result["evidencePath"],
            "hypothesisCount": len(result["hypotheses"]),
        }, sort_keys=True))
        return 0
    except (ReaAdapterError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"REA adapter rejected the analysis: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
