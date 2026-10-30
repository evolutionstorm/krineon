#!/usr/bin/env python3
"""Bind a crash lead to repeated chosen-byte or chosen-PC observations."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from reality_evidence import safe_campaign_path, sha256_file, validate_attestation


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def verify(args: argparse.Namespace) -> int:
    root = Path(args.campaign_dir).expanduser().resolve()
    if not (root / "campaign.json").is_file():
        raise RuntimeError(f"not a Krineon campaign: {root}")
    if not re.fullmatch(r"[0-9a-f]{64}", args.crash_id):
        raise RuntimeError("crash ID must be a full 64-character fingerprint")
    crash_dir = root / "dynamic" / "crashes" / args.crash_id
    if not (crash_dir / "crash.json").is_file():
        raise RuntimeError("crash record is absent")
    attestation_path = safe_campaign_path(root, args.attestation)
    result = validate_attestation(root, attestation_path)
    if not result["passed"]:
        raise RuntimeError("attestation failed validation: " + ", ".join(result["errors"]))
    record = result["record"]
    cases = record["cases"]
    if any(len(cases[name]) < args.minimum_successes for name in ("baseline", "negative", "positive")):
        raise RuntimeError("each case has fewer runs than --minimum-successes")
    positive_kind = "controlled-pc" if args.claim == "controlled-pc" else "controlled-write"
    positive_assertions = result["assertions"].get("positive", {})
    qualifying = [
        (assertion_id, observations)
        for assertion_id, observations in positive_assertions.items()
        if len(observations) >= args.minimum_successes
        and all(item.get("matched") is True for item in observations)
        and all(
            str(item.get("observed", {}).get("claim") or positive_kind)
            in {args.claim, positive_kind}
            for item in observations
        )
    ]
    recipe = read_object(safe_campaign_path(root, record["recipe"]["path"]))
    positive_recipe = next(item for item in recipe["cases"] if item["name"] == "positive")
    positive_kinds = {
        str(item.get("id")): str(item.get("kind"))
        for item in positive_recipe.get("assertions", [])
        if isinstance(item, dict)
    }
    qualifying = [item for item in qualifying if positive_kinds.get(item[0]) == positive_kind]
    if not qualifying:
        raise RuntimeError(f"positive case has no repeated {positive_kind} assertion")
    for control_name in ("baseline", "negative"):
        recipe_case = next(item for item in recipe["cases"] if item["name"] == control_name)
        no_write_ids = {
            str(item.get("id"))
            for item in recipe_case.get("assertions", [])
            if isinstance(item, dict) and item.get("kind") == "no-memory-write"
        }
        if args.claim != "controlled-pc" and not no_write_ids:
            raise RuntimeError(f"{control_name} lacks a no-memory-write assertion")
        for assertion_id in no_write_ids:
            observations = result["assertions"].get(control_name, {}).get(assertion_id, [])
            if len(observations) < args.minimum_successes or not all(
                item.get("matched") is True for item in observations
            ):
                raise RuntimeError(f"{control_name} memory-write control did not hold")
    challenges = {
        run["challengeHex"]
        for run in cases["positive"]
        if isinstance(run, dict) and run.get("challengeHex")
    }
    pids = {
        run["pid"]
        for runs in cases.values()
        for run in runs
        if isinstance(run, dict) and isinstance(run.get("pid"), int)
    }
    expected_processes = sum(len(runs) for runs in cases.values())
    if len(challenges) < args.minimum_successes:
        raise RuntimeError("positive runs did not use distinct harness-generated challenges")
    if len(pids) != expected_processes:
        raise RuntimeError("primitive observations did not use distinct fresh processes")
    assertion_id, observations = qualifying[0]
    allocation_identity = args.claim == "uaf-write" and all(
        item["observed"].get("allocationIdentityMatched") is True for item in observations
    )
    chosen_bytes = args.claim in {"uaf-write", "controlled-write"} and all(
        item["observed"].get("chosenBytesMatched") is True for item in observations
    )
    chosen_pc = args.claim == "controlled-pc"
    manifest = {
        "schemaVersion": 1,
        "producer": "krineon-primitive-verifier",
        "crashId": args.crash_id,
        "claim": args.claim,
        "status": "verified",
        "attestation": {
            "path": attestation_path.relative_to(root).as_posix(),
            "sha256": sha256_file(attestation_path),
            "runId": record["runId"],
        },
        "assertionId": assertion_id,
        "freshProcesses": expected_processes,
        "positiveSuccesses": len(observations),
        "distinctChosenValues": len(challenges),
        "claims": {
            "chosenBytes": chosen_bytes,
            "allocationIdentity": allocation_identity,
            "chosenProgramCounter": chosen_pc,
            "crossProcessStability": len(observations) >= args.minimum_successes,
        },
    }
    write_json(crash_dir / "primitive-verification.json", manifest)
    print(json.dumps(manifest, indent=2))
    return 0


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("campaign_dir")
    value.add_argument("crash_id")
    value.add_argument("--attestation", required=True)
    value.add_argument(
        "--claim", choices=("uaf-write", "controlled-write", "controlled-pc"), required=True
    )
    value.add_argument("--minimum-successes", type=int, default=3)
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.minimum_successes < 2:
        raise SystemExit("--minimum-successes must be at least 2")
    try:
        return verify(args)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
