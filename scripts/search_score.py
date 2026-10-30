#!/usr/bin/env python3
"""Score search evidence and retain ablation decisions for Krineon subsystems."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def campaign(value: str) -> Path:
    root = Path(value).expanduser().resolve()
    if not (root / "campaign.json").is_file():
        raise RuntimeError(f"not a Krineon campaign: {root}")
    return root


def latest_coverage(root: Path, profile_name: str) -> dict[str, Any] | None:
    profile_path = root / "dynamic" / "fuzzers" / profile_name / "profile.json"
    if profile_path.is_file():
        rows = read_json(profile_path).get("coverageRebuilds")
        if isinstance(rows, list) and rows:
            record_path = root / str(rows[-1].get("record") or "")
            if record_path.is_file():
                return read_json(record_path)
    campaign_path = root / "campaign.json"
    if campaign_path.is_file():
        rows = read_json(campaign_path).get("jsCoverageRuns")
        matches = (
            [
                row
                for row in rows
                if isinstance(row, dict) and row.get("profile") == profile_name
            ]
            if isinstance(rows, list)
            else []
        )
        if matches:
            record_path = root / str(matches[-1].get("record") or "")
            if record_path.is_file():
                record = read_json(record_path)
                coverage = record.get("coverage")
                return {"metrics": coverage if isinstance(coverage, dict) else {}}
    return None


def unique_stack_count(root: Path) -> int:
    path = root / "dynamic" / "triage" / "index.json"
    if not path.is_file():
        return 0
    record = read_json(path)
    clusters = record.get("clusters")
    return len(clusters) if isinstance(clusters, list) else int(record.get("clusterCount") or 0)


def rediscovery_hours(root: Path, benchmark: str) -> float | None:
    path = root / "benchmarks" / benchmark / "status.json"
    if not path.is_file():
        return None
    value = read_json(path).get("hoursToFirstRediscovery")
    return float(value) if isinstance(value, (int, float)) else None


def score_vector(root: Path, profile: str, benchmark: str) -> dict[str, Any]:
    coverage = latest_coverage(root, profile)
    metrics = coverage.get("metrics") if isinstance(coverage, dict) else {}
    return {
        "newEdgesPerHour": (
            float(metrics["newEdgesPerHour"])
            if isinstance(metrics, dict)
            and isinstance(metrics.get("newEdgesPerHour"), (int, float))
            else None
        ),
        "uniqueStackClusters": unique_stack_count(root),
        "hoursToFirstRediscovery": rediscovery_hours(root, benchmark),
    }


def cmd_snapshot(args: argparse.Namespace) -> int:
    root = campaign(args.campaign_dir)
    value = {
        "schemaVersion": 1,
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "profile": args.profile,
        "benchmark": args.benchmark,
        "score": score_vector(root, args.profile, args.benchmark),
        "direction": {
            "newEdgesPerHour": "higher-is-better",
            "uniqueStackClusters": "higher-is-better",
            "hoursToFirstRediscovery": "lower-is-better",
        },
    }
    output = (
        Path(args.output).expanduser().resolve()
        if args.output
        else root
        / "metrics"
        / "scores"
        / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ") + ".json")
    )
    atomic_json(output, value)
    print(output)
    return 0


def improved(before: Any, after: Any, *, lower: bool = False) -> bool:
    if after is None:
        return False
    if before is None:
        return True
    return after < before if lower else after > before


def cmd_compare(args: argparse.Namespace) -> int:
    root = campaign(args.campaign_dir)
    before = read_json(Path(args.before).expanduser().resolve()).get("score", {})
    after = read_json(Path(args.after).expanduser().resolve()).get("score", {})
    deltas = {
        "newEdgesPerHour": improved(
            before.get("newEdgesPerHour"), after.get("newEdgesPerHour")
        ),
        "uniqueStackClusters": improved(
            before.get("uniqueStackClusters"), after.get("uniqueStackClusters")
        ),
        "hoursToFirstRediscovery": improved(
            before.get("hoursToFirstRediscovery"),
            after.get("hoursToFirstRediscovery"),
            lower=True,
        ),
    }
    moved = any(deltas.values())
    decision = {
        "schemaVersion": 1,
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "subsystem": args.subsystem,
        "before": before,
        "after": after,
        "improvements": deltas,
        "verdict": "keep" if moved else "delete",
        "reason": (
            "moved at least one evidence-rate metric"
            if moved
            else "moved neither edge velocity, unique stacks, nor rediscovery time"
        ),
    }
    output = root / "metrics" / "ablations" / f"{args.subsystem}.json"
    atomic_json(output, decision)
    print(json.dumps(decision, indent=2))
    return 0 if moved or not args.enforce else 1


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    snapshot = commands.add_parser("snapshot")
    snapshot.add_argument("campaign_dir")
    snapshot.add_argument("--profile", required=True)
    snapshot.add_argument("--benchmark", required=True)
    snapshot.add_argument("--output")
    snapshot.set_defaults(func=cmd_snapshot)
    compare = commands.add_parser("compare")
    compare.add_argument("campaign_dir")
    compare.add_argument("--subsystem", required=True)
    compare.add_argument("--before", required=True)
    compare.add_argument("--after", required=True)
    compare.add_argument("--enforce", action="store_true")
    compare.set_defaults(func=cmd_compare)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.func(args))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
