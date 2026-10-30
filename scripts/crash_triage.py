#!/usr/bin/env python3
"""Classify crash first faults and validate concrete primitive evidence."""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import uuid
from pathlib import Path
from typing import Any, Iterable

from reality_evidence import safe_campaign_path, sha256_file, validate_attestation


STACK_RE = re.compile(
    r"^\s*#(?P<index>\d+)\s+(?:(?P<pc>0x[0-9a-fA-F]+)\s+)?(?:in\s+)?(?P<body>.+?)\s*$"
)
ACCESS_RE = re.compile(r"(?im)^\s*(READ|WRITE|EXECUTE) of size (\d+)")
ADDRESS_RE = re.compile(r"(?i)(?:on|at|address)\s+(0x[0-9a-f]+)")
PC_RE = re.compile(r"(?i)\bpc\s+(0x[0-9a-f]+)")

FAULT_PATTERNS: tuple[tuple[str, str], ...] = (
    ("control-flow-corruption", r"(?i)(wild jump|instruction pointer|program counter|pc points to|control[- ]flow|EXECUTE of size)"),
    ("double-free", r"(?i)(attempting double-free|double free|double-free)"),
    ("invalid-free", r"(?i)(attempting free on address|invalid free|bad free|alloc-dealloc-mismatch)"),
    ("heap-use-after-free", r"(?i)heap-use-after-free"),
    ("stack-use-after-return", r"(?i)stack-use-after-return"),
    ("stack-use-after-scope", r"(?i)stack-use-after-scope"),
    ("use-after-free", r"(?i)use-after-free"),
    ("heap-buffer-overflow", r"(?i)heap-buffer-overflow"),
    ("stack-buffer-overflow", r"(?i)(dynamic-)?stack-buffer-overflow"),
    ("global-buffer-overflow", r"(?i)global-buffer-overflow"),
    ("container-overflow", r"(?i)container-overflow"),
    ("out-of-bounds", r"(?i)(out[- ]of[- ]bounds|index .* out of bounds)"),
    ("data-race", r"(?i)(ThreadSanitizer: data race|WARNING: ThreadSanitizer)"),
    ("uninitialized-read", r"(?i)(use-of-uninitialized-value|MemorySanitizer)"),
    ("null-dereference", r"(?i)(null pointer|zero page|unknown address 0x0{4,})"),
    ("undefined-behavior", r"(?i)(runtime error:|signed integer overflow|shift exponent|misaligned address)"),
)

MEMORY_SAFETY_CLASSES = {
    "control-flow-corruption",
    "double-free",
    "invalid-free",
    "heap-use-after-free",
    "stack-use-after-return",
    "stack-use-after-scope",
    "use-after-free",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "container-overflow",
    "out-of-bounds",
    "uninitialized-read",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def normalize_frame(body: str) -> str:
    value = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", body)
    value = re.sub(r"\+0x[0-9a-fA-F]+", "+0xOFF", value)
    value = re.sub(r":\d+(?::\d+)?", ":LINE", value)
    value = re.sub(r"(?:[A-Za-z]:)?(?:/[^\s():]+)+/", "/", value)
    return " ".join(value.split())[:1000]


def parse_frames(text: str, limit: int = 32) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    for line in text.splitlines():
        match = STACK_RE.match(line)
        if not match:
            continue
        body = match.group("body")
        frames.append(
            {
                "index": int(match.group("index")),
                "pc": match.group("pc"),
                "raw": line.strip()[:2000],
                "normalized": normalize_frame(body),
            }
        )
        if len(frames) >= limit:
            break
    return frames


def first_fault(text: str, signal_name: str | None, return_code: int | None) -> dict[str, Any]:
    matches: list[tuple[int, str, re.Match[str]]] = []
    for fault_class, pattern in FAULT_PATTERNS:
        match = re.search(pattern, text)
        if match:
            matches.append((match.start(), fault_class, match))
    if matches:
        _, fault_class, match = min(matches, key=lambda item: item[0])
        matched_text = match.group(0)
    elif signal_name:
        fault_class = "bare-signal"
        matched_text = signal_name
    elif return_code not in (None, 0):
        fault_class = "abnormal-exit"
        matched_text = str(return_code)
    else:
        fault_class = "unknown"
        matched_text = ""

    access_match = ACCESS_RE.search(text)
    access = access_match.group(1).lower() if access_match else "unknown"
    access_size = int(access_match.group(2)) if access_match else None
    if fault_class == "uninitialized-read" and access == "unknown":
        access = "read"
    address_match = ADDRESS_RE.search(text)
    pc_match = PC_RE.search(text)
    if access == "execute" and fault_class != "control-flow-corruption":
        fault_class = "control-flow-corruption"
    if fault_class in {"heap-use-after-free", "stack-use-after-return", "stack-use-after-scope", "use-after-free"}:
        family = "lifetime"
    elif fault_class in MEMORY_SAFETY_CLASSES:
        family = "memory-safety"
    elif fault_class == "data-race":
        family = "concurrency"
    elif fault_class == "undefined-behavior":
        family = "undefined-behavior"
    else:
        family = "crash-only"
    return {
        "class": fault_class,
        "family": family,
        "memorySafety": fault_class in MEMORY_SAFETY_CLASSES,
        "access": access,
        "accessSize": access_size,
        "address": address_match.group(1) if address_match else None,
        "programCounter": pc_match.group(1) if pc_match else None,
        "matchedDiagnostic": matched_text[:1000],
        "signal": signal_name,
        "returnCode": return_code,
    }


def occurrence_stats(path: Path) -> dict[str, Any]:
    occurrences: list[dict[str, Any]] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                occurrences.append(value)
    inputs = sorted({str(item.get("inputSha256")) for item in occurrences if item.get("inputSha256")})
    runs = sorted({str(item.get("runId")) for item in occurrences if item.get("runId")})
    return {
        "occurrences": len(occurrences),
        "distinctInputs": len(inputs),
        "distinctRuns": len(runs),
        "inputSha256s": inputs,
        "runIds": runs,
    }


def primitive_control_evidence(crash_dir: Path, fault: dict[str, Any]) -> dict[str, Any]:
    """Accept control only from a recomputable challenge-response attestation."""

    empty = {
        "status": "unverified",
        "claim": None,
        "chosenBytes": False,
        "allocationIdentity": False,
        "chosenProgramCounter": False,
        "crossProcessStability": False,
        "freshProcesses": 0,
        "positiveSuccesses": 0,
        "distinctChosenValues": 0,
        "errors": [
            "a crash class and access direction do not prove attacker control",
            "run reality_runner.py and primitive_verifier.py with fresh-process controls",
        ],
    }
    manifest_path = crash_dir / "primitive-verification.json"
    if not manifest_path.is_file():
        return empty
    try:
        manifest = read_json(manifest_path)
        root = crash_dir.parents[2]
        attestation = manifest.get("attestation")
        if not isinstance(attestation, dict):
            raise ValueError("primitive attestation is absent")
        attestation_path = safe_campaign_path(root, attestation.get("path"))
        validation = validate_attestation(root, attestation_path)
        errors = list(validation["errors"])
        if attestation.get("sha256") != sha256_file(attestation_path):
            errors.append("primitive attestation hash mismatch")
        if manifest.get("producer") != "krineon-primitive-verifier":
            errors.append("primitive verifier producer mismatch")
        if manifest.get("status") != "verified":
            errors.append("primitive verification is not verified")
        if manifest.get("crashId") != crash_dir.name:
            errors.append("primitive crash identity mismatch")
        claim = str(manifest.get("claim") or "")
        claims = manifest.get("claims") if isinstance(manifest.get("claims"), dict) else {}
        if claim == "uaf-write" and not (
            fault.get("access") == "write" and fault.get("family") == "lifetime"
        ):
            errors.append("uaf-write evidence does not match the first fault")
        if claim == "controlled-write" and fault.get("access") != "write":
            errors.append("controlled-write evidence does not match the first fault")
        if claim == "controlled-pc" and not (
            fault.get("access") == "execute" or fault.get("class") == "control-flow-corruption"
        ):
            errors.append("controlled-pc evidence does not match the first fault")
        chosen_bytes = claims.get("chosenBytes") is True
        allocation_identity = claims.get("allocationIdentity") is True
        chosen_pc = claims.get("chosenProgramCounter") is True
        stable = claims.get("crossProcessStability") is True
        if claim == "uaf-write" and not (chosen_bytes and allocation_identity and stable):
            errors.append("uaf-write lacks chosen bytes, allocation identity, or stability")
        if claim == "controlled-write" and not (chosen_bytes and stable):
            errors.append("controlled-write lacks chosen bytes or stability")
        if claim == "controlled-pc" and not (chosen_pc and stable):
            errors.append("controlled-pc lacks chosen PC or stability")
        return {
            "status": "verified" if not errors else "invalid",
            "claim": claim or None,
            "chosenBytes": chosen_bytes and not errors,
            "allocationIdentity": allocation_identity and not errors,
            "chosenProgramCounter": chosen_pc and not errors,
            "crossProcessStability": stable and not errors,
            "freshProcesses": int(manifest.get("freshProcesses") or 0),
            "positiveSuccesses": int(manifest.get("positiveSuccesses") or 0),
            "distinctChosenValues": int(manifest.get("distinctChosenValues") or 0),
            "attestation": attestation,
            "errors": errors,
        }
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        return {**empty, "status": "invalid", "errors": [str(error)]}


def verdict(fault: dict[str, Any], control: dict[str, Any]) -> dict[str, Any]:
    fault_class = str(fault["class"])
    access = str(fault.get("access"))
    if control.get("status") == "verified" and control.get("chosenProgramCounter") is True:
        name, recommendation = "verified-chosen-program-counter", "retain-verified-primitive"
    elif control.get("status") == "verified" and control.get("allocationIdentity") is True:
        name, recommendation = "verified-chosen-byte-uaf-write", "retain-verified-primitive"
    elif control.get("status") == "verified" and control.get("chosenBytes") is True:
        name, recommendation = "verified-chosen-byte-write", "retain-verified-primitive"
    elif fault_class == "control-flow-corruption" or access == "execute":
        name, recommendation = "unverified-control-flow-corruption-lead", "requires-primitive-verification"
    elif fault_class in {"heap-use-after-free", "stack-use-after-return", "stack-use-after-scope", "use-after-free"} and access == "write":
        name, recommendation = "unverified-lifetime-write-lead", "requires-primitive-verification"
    elif fault.get("memorySafety") and access == "write":
        name, recommendation = "unverified-memory-write-lead", "requires-primitive-verification"
    elif fault_class in {"heap-use-after-free", "stack-use-after-return", "stack-use-after-scope", "use-after-free"}:
        name, recommendation = "potential-lifetime-corruption", "retain-lead"
    elif fault.get("memorySafety") and access == "read":
        name, recommendation = "potential-read-primitive", "retain-lead"
    elif fault.get("memorySafety"):
        name, recommendation = "memory-corruption-direction-unknown", "manual-review"
    elif fault_class in {"data-race", "undefined-behavior", "uninitialized-read"}:
        name, recommendation = "undefined-or-concurrent-behavior-lead", "retain-lead"
    else:
        name, recommendation = "crash-only-or-insufficient-evidence", "reject-crash-only"
    return {
        "verdict": name,
        "gateRecommendation": recommendation,
        "machinePromotionEligible": False,
        "rationale": (
            "The crash label classifies the first fault only. Attacker control is verified only "
            "by repeated harness-generated chosen values, explicit allocation identity where "
            "applicable, fresh processes, and recomputed controls."
        ),
    }


def analyze_crash_directory(crash_dir: Path) -> dict[str, Any]:
    record = read_json(crash_dir / "crash.json")
    stderr = (crash_dir / "stderr.bin").read_bytes() if (crash_dir / "stderr.bin").is_file() else b""
    stdout = (crash_dir / "stdout.bin").read_bytes() if (crash_dir / "stdout.bin").is_file() else b""
    text = (stderr + b"\n" + stdout).decode("utf-8", "replace")
    frames = parse_frames(text)
    fault = first_fault(text, record.get("signal"), record.get("returnCode"))
    stack_material = "|".join(frame["normalized"] for frame in frames[:8])
    if not stack_material:
        stack_material = f"no-stack:{record.get('crashId')}:{fault['class']}"
    stack_hash = sha256_bytes(stack_material.encode("utf-8", "replace"))
    stats = occurrence_stats(crash_dir / "occurrences.jsonl")
    minimized = (crash_dir / "minimized.bin").is_file()
    control = primitive_control_evidence(crash_dir, fault)
    assessment = verdict(fault, control)
    return {
        "schemaVersion": 1,
        "classifierVersion": 2,
        "crashId": record.get("crashId") or crash_dir.name,
        "analyzedAt": utc_now(),
        "rawEvidence": {
            "stderrSha256": sha256_bytes(stderr),
            "stdoutSha256": sha256_bytes(stdout),
            "stderrTruncatedAtCapture": record.get("stderrTruncated"),
            "stdoutTruncatedAtCapture": record.get("stdoutTruncated"),
        },
        "firstFault": {**fault, "topFrame": frames[0] if frames else None},
        "stack": {
            "hash": stack_hash,
            "clusterId": f"SC-{stack_hash[:16]}",
            "hashDepth": min(8, len(frames)),
            "frames": frames,
        },
        "occurrenceStats": stats,
        "minimizedInputPresent": minimized,
        "controlEvidence": control,
        "automatedExploitability": assessment,
    }


def build_index(triages: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = sorted(triages, key=lambda item: str(item["crashId"]))
    clusters: dict[str, dict[str, Any]] = {}
    verdict_counts: dict[str, int] = {}
    for triage in rows:
        stack = triage["stack"]
        cluster_id = str(stack["clusterId"])
        verdict_name = str(triage["automatedExploitability"]["verdict"])
        verdict_counts[verdict_name] = verdict_counts.get(verdict_name, 0) + 1
        cluster = clusters.setdefault(
            cluster_id,
            {
                "clusterId": cluster_id,
                "stackHash": stack["hash"],
                "crashIds": [],
                "faultClasses": [],
                "verdicts": [],
                "verifiedPrimitiveCrashIds": [],
            },
        )
        cluster["crashIds"].append(triage["crashId"])
        cluster["faultClasses"] = sorted(set(cluster["faultClasses"] + [triage["firstFault"]["class"]]))
        cluster["verdicts"] = sorted(set(cluster["verdicts"] + [verdict_name]))
        if triage["controlEvidence"].get("status") == "verified":
            cluster["verifiedPrimitiveCrashIds"].append(triage["crashId"])
    return {
        "schemaVersion": 1,
        "classifierVersion": 2,
        "updatedAt": utc_now(),
        "crashCount": len(rows),
        "clusterCount": len(clusters),
        "verdictCounts": verdict_counts,
        "crashes": [
            {
                "crashId": row["crashId"],
                "clusterId": row["stack"]["clusterId"],
                "faultClass": row["firstFault"]["class"],
                "access": row["firstFault"]["access"],
                "controlEvidenceStatus": row["controlEvidence"]["status"],
                "controlClaim": row["controlEvidence"].get("claim"),
                "verdict": row["automatedExploitability"]["verdict"],
                "gateRecommendation": row["automatedExploitability"]["gateRecommendation"],
                "triagePath": f"dynamic/crashes/{row['crashId']}/triage.json",
            }
            for row in rows
        ],
        "clusters": sorted(clusters.values(), key=lambda item: item["clusterId"]),
    }


def _record_triage(crash_dir: Path, triage: dict[str, Any]) -> None:
    atomic_json(crash_dir / "triage.json", triage)
    record_path = crash_dir / "crash.json"
    record = read_json(record_path)
    record["triage"] = {
        "path": f"dynamic/crashes/{triage['crashId']}/triage.json",
        "faultClass": triage["firstFault"]["class"],
        "stackClusterId": triage["stack"]["clusterId"],
        "controlEvidenceStatus": triage["controlEvidence"]["status"],
        "controlClaim": triage["controlEvidence"].get("claim"),
        "verdict": triage["automatedExploitability"]["verdict"],
        "gateRecommendation": triage["automatedExploitability"]["gateRecommendation"],
    }
    atomic_json(record_path, record)


def triage_campaign(root: Path, selected: set[str] | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    triage_root = root / "dynamic" / "triage"
    triage_root.mkdir(parents=True, exist_ok=True)
    lock_path = triage_root / ".lock"
    with lock_path.open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        base = root / "dynamic" / "crashes"
        directories = sorted(path for path in base.iterdir() if path.is_dir()) if base.is_dir() else []
        triages: list[dict[str, Any]] = []
        for crash_dir in directories:
            if selected is not None and crash_dir.name not in selected:
                existing = crash_dir / "triage.json"
                if existing.is_file():
                    triages.append(read_json(existing))
                continue
            triage = analyze_crash_directory(crash_dir)
            _record_triage(crash_dir, triage)
            triages.append(triage)
        # Preserve already-triaged records outside a selected refresh.
        if selected is not None:
            known = {str(item["crashId"]) for item in triages}
            for crash_dir in directories:
                existing = crash_dir / "triage.json"
                if crash_dir.name not in known and existing.is_file():
                    triages.append(read_json(existing))
        index = build_index(triages)
        atomic_json(triage_root / "index.json", index)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    return triages, index


def triage_one(root: Path, crash_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    triages, index = triage_campaign(root, {crash_id})
    for triage in triages:
        if triage.get("crashId") == crash_id:
            return triage, index
    raise FileNotFoundError(f"crash not found: {crash_id}")
