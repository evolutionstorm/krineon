#!/usr/bin/env python3
"""Turn runtime evidence into one bounded, evidence-driven next action."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "research_harness.py"


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def unique_crashes(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for record in records:
        forwarded = record.get("forwarded")
        candidate = forwarded if isinstance(forwarded, dict) else record
        stack = candidate.get("stack") if isinstance(candidate.get("stack"), dict) else {}
        cluster = str(stack.get("clusterId") or candidate.get("clusterId") or "")
        minimized_record = candidate.get("minimized")
        minimized = (
            minimized_record.get("sha256")
            if isinstance(minimized_record, dict)
            else candidate.get("minimizedInput") or candidate.get("minimizedSha256")
        )
        replayed = (
            candidate.get("confirmed") is True
            or candidate.get("replayConfirmed") is True
            or candidate.get("status") == "verified"
            or bool(candidate.get("replay", {}).get("confirmed"))
        )
        if cluster and minimized and replayed:
            unique.setdefault(cluster, candidate)
    return list(unique.values())


def oracle_violations(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    violations: list[dict[str, Any]] = []
    for record in records:
        for result in record.get("results", []) if isinstance(record.get("results"), list) else []:
            evaluation = result.get("evaluation") if isinstance(result, dict) else None
            if isinstance(evaluation, dict) and evaluation.get("verdict") == "oracle-violated":
                violations.append(result)
        if record.get("verdict") in {"oracle-violated", "confirmed-invariant-disagreement"}:
            violations.append(record)
    return violations


def coverage_state(record: dict[str, Any] | None) -> dict[str, Any]:
    if not record:
        return {"newEdges": 0, "plateau": False, "holes": []}
    coverage = record.get("coverage") if isinstance(record.get("coverage"), dict) else {}
    summary = record.get("summary") if isinstance(record.get("summary"), dict) else {}
    plateau_summary = (
        summary.get("plateau") if isinstance(summary.get("plateau"), dict) else {}
    )
    new_edges = int(
        coverage.get("newEdges")
        or summary.get("newEdges")
        or record.get("newEdges")
        or 0
    )
    plateau = bool(
        coverage.get("plateauReached")
        or summary.get("plateauReached")
        or plateau_summary.get("reached")
        or record.get("plateauReached")
    )
    holes = record.get("coverageHoles") or coverage.get("holes") or []
    return {
        "newEdges": new_edges,
        "plateau": plateau,
        "holes": [row for row in holes if isinstance(row, dict)],
    }


def next_unreached_consumer(ir: dict[str, Any]) -> dict[str, Any] | None:
    paths = [
        row
        for row in ir.get("securityPaths", [])
        if isinstance(row, dict) and row.get("status") != "runtime-verified"
    ]
    if not paths:
        return None
    return max(
        paths,
        key=lambda row: (
            len(row.get("unknowns", [])),
            str(row.get("id") or ""),
        ),
    )


def decide(
    ir: dict[str, Any],
    *,
    coverage: dict[str, Any] | None = None,
    crashes: list[dict[str, Any]] | None = None,
    observations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    crash_rows = unique_crashes(crashes or [])
    violation_rows = oracle_violations(observations or [])
    coverage_row = coverage_state(coverage)
    consumer = next_unreached_consumer(ir)
    if crash_rows:
        cluster = str((crash_rows[0].get("stack") or {}).get("clusterId") or crash_rows[0].get("clusterId"))
        action = {
            "kind": "minimize-and-independent-replay",
            "reason": "a unique replay-confirmed stack outranks new corpus growth",
            "target": cluster,
            "machineEvidence": True,
            "successCriterion": "fresh-process replay preserves the minimized first fault and controlled input influence",
        }
    elif violation_rows:
        action = {
            "kind": "verify-invariant-differential",
            "reason": "a machine observation violated an executable security oracle",
            "target": str(violation_rows[0].get("model", {}).get("id") or "runtime-invariant"),
            "machineEvidence": True,
            "successCriterion": "coordinator replay reproduces the violation while the enforcing negative control restores the invariant",
        }
    elif coverage_row["plateau"] and consumer is not None:
        action = {
            "kind": "change-harness-or-grammar",
            "reason": "coverage plateaued before the highest-uncertainty security consumer",
            "target": str(consumer.get("consumer", {}).get("factId") or consumer.get("id")),
            "machineEvidence": bool(coverage),
            "successCriterion": "a justified harness or structured grammar change reaches the source-mapped consumer and records new edges",
            "unresolvedPath": consumer.get("id"),
        }
    elif coverage_row["newEdges"] > 0:
        action = {
            "kind": "continue-bounded-corpus-growth",
            "reason": "the current harness still gains coverage",
            "target": "current-corpus",
            "machineEvidence": True,
            "successCriterion": "continue only until the next measured plateau or security-relevant differential",
        }
    elif consumer is not None:
        action = {
            "kind": "instrument-unreached-consumer",
            "reason": "the semantic IR has an unresolved consumer but no runtime telemetry",
            "target": str(consumer.get("consumer", {}).get("factId") or consumer.get("id")),
            "machineEvidence": False,
            "successCriterion": "produce an executable oracle and fact-linked runtime identity telemetry before scheduling an attack experiment",
            "unresolvedPath": consumer.get("id"),
        }
    else:
        action = {
            "kind": "no-action",
            "reason": "no unique crash, invariant violation, coverage gain, or unresolved semantic consumer was retained",
            "target": "none",
            "machineEvidence": False,
            "successCriterion": "none",
        }
    return {
        "schemaVersion": 1,
        "producer": "krineon-runtime-feedback",
        "decisionId": "RF-" + digest(action)[:20],
        "action": action,
        "inputs": {
            "uniqueReplayConfirmedCrashes": len(crash_rows),
            "oracleViolations": len(violation_rows),
            "coverage": coverage_row,
            "unreachedConsumer": consumer.get("id") if consumer else None,
        },
        "promotionAuthorized": False,
    }


def schedule(campaign: Path, decision: dict[str, Any]) -> str | None:
    action = decision["action"]
    if action["kind"] in {"no-action", "continue-bounded-corpus-growth"}:
        return None
    task_id = "runtime-feedback-" + decision["decisionId"].split("-", 1)[-1]
    command = [
        sys.executable,
        str(HARNESS),
        "task-add",
        str(campaign),
        task_id,
        "--title",
        f"Runtime feedback: {action['kind']}",
        "--lane",
        "runtime-feedback",
        "--objective",
        f"Resolve {action['target']}: {action['reason']}",
        "--approach-family",
        "chain-composition",
        "--success-criterion",
        action["successCriterion"],
        "--priority",
        "2400" if action["machineEvidence"] else "900",
        "--max-attempts",
        "2",
    ]
    completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=30)
    if completed.returncode != 0 and "already exists" not in completed.stderr.lower():
        raise RuntimeError(f"failed to schedule runtime feedback: {completed.stderr.strip()}")
    return task_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("semantic_ir", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--coverage", type=Path)
    parser.add_argument("--crash", action="append", type=Path, default=[])
    parser.add_argument("--observation", action="append", type=Path, default=[])
    parser.add_argument("--campaign", type=Path)
    parser.add_argument("--ingest", action="store_true")
    args = parser.parse_args(argv)
    try:
        ir = read_object(args.semantic_ir.expanduser().resolve())
        coverage = read_object(args.coverage.expanduser().resolve()) if args.coverage else None
        crashes = [read_object(path.expanduser().resolve()) for path in args.crash]
        observations = [read_object(path.expanduser().resolve()) for path in args.observation]
        decision = decide(ir, coverage=coverage, crashes=crashes, observations=observations)
        task_id = None
        if args.ingest:
            if args.campaign is None:
                raise RuntimeError("--ingest requires --campaign")
            task_id = schedule(args.campaign.expanduser().resolve(), decision)
        decision["scheduledTask"] = task_id
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
        print(args.output)
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
