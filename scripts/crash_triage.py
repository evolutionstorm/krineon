#!/usr/bin/env python3
"""Classify crash first faults, cluster stacks, and score controllability."""

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


def controllability(
    fault: dict[str, Any], frames: list[dict[str, Any]], stats: dict[str, Any], minimized: bool
) -> dict[str, Any]:
    fault_class = str(fault["class"])
    bases = {
        "control-flow-corruption": 85,
        "heap-use-after-free": 70,
        "stack-use-after-return": 65,
        "stack-use-after-scope": 65,
        "use-after-free": 65,
        "double-free": 55,
        "invalid-free": 50,
        "heap-buffer-overflow": 50,
        "stack-buffer-overflow": 50,
        "global-buffer-overflow": 50,
        "container-overflow": 45,
        "out-of-bounds": 40,
        "uninitialized-read": 35,
        "data-race": 25,
        "undefined-behavior": 20,
        "null-dereference": 5,
        "bare-signal": 5,
        "abnormal-exit": 0,
        "unknown": 0,
    }
    score = bases.get(fault_class, 10)
    signals: list[str] = [f"first-fault:{fault_class}"]
    limitations: list[str] = []
    access = fault.get("access")
    if access == "write":
        score += 18
        signals.append("sanitizer-recorded-write")
    elif access == "execute":
        score += 10
        signals.append("sanitizer-recorded-execute")
    elif access == "read":
        score += 5
        signals.append("sanitizer-recorded-read")
    else:
        limitations.append("access direction is unknown")
    if fault.get("programCounter"):
        score += 5
        signals.append("program-counter-recorded")
    if frames:
        score += 3
        signals.append("symbolized-first-fault-stack")
    else:
        limitations.append("no symbolized stack frames")
    if int(stats.get("distinctRuns", 0)) >= 2:
        score += 5
        signals.append("reproduced-across-runs")
    if int(stats.get("distinctInputs", 0)) >= 2:
        score += 3
        signals.append("multiple-triggering-inputs")
    if minimized:
        score += 4
        signals.append("fingerprint-preserving-minimized-input")
    score = max(0, min(score, 99))
    tier = "strong" if score >= 85 else "high" if score >= 65 else "medium" if score >= 40 else "low" if score >= 15 else "none"
    limitations.extend(
        [
            "score measures evidence quality, not exploit reliability",
            "no sanitizer report alone proves attacker-controlled PC, read, write, or RCE",
        ]
    )
    return {"score": score, "tier": tier, "signals": signals, "limitations": limitations}


def verdict(fault: dict[str, Any], control: dict[str, Any]) -> dict[str, Any]:
    fault_class = str(fault["class"])
    access = str(fault.get("access"))
    if fault_class == "control-flow-corruption" or access == "execute":
        name, recommendation = "potential-control-flow-corruption", "prioritize"
    elif fault_class in {"heap-use-after-free", "stack-use-after-return", "stack-use-after-scope", "use-after-free"} and access == "write":
        name, recommendation = "potential-lifetime-write-primitive", "prioritize"
    elif fault.get("memorySafety") and access == "write":
        name, recommendation = "potential-write-primitive", "prioritize"
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
        "controllabilityScore": control["score"],
        "rationale": (
            "Automated triage prioritizes the next experiment. It cannot establish a Critical/RCE "
            "terminal, attacker control, production reachability, or filing eligibility."
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
    control = controllability(fault, frames, stats, minimized)
    assessment = verdict(fault, control)
    return {
        "schemaVersion": 1,
        "classifierVersion": 1,
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
        "controllability": control,
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
                "maxControllabilityScore": 0,
            },
        )
        cluster["crashIds"].append(triage["crashId"])
        cluster["faultClasses"] = sorted(set(cluster["faultClasses"] + [triage["firstFault"]["class"]]))
        cluster["verdicts"] = sorted(set(cluster["verdicts"] + [verdict_name]))
        cluster["maxControllabilityScore"] = max(
            int(cluster["maxControllabilityScore"]),
            int(triage["controllability"]["score"]),
        )
    return {
        "schemaVersion": 1,
        "classifierVersion": 1,
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
                "controllabilityScore": row["controllability"]["score"],
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
        "controllabilityScore": triage["controllability"]["score"],
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
