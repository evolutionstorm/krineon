#!/usr/bin/env python3
"""Run executable differentials and source-bound models into validation tasks."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, Iterable


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "research_harness.py"
Z3_SOLVER = PROJECT / "scripts" / "z3_boundary_solver.py"
DIFFERENTIAL = PROJECT / "scripts" / "differential_witness.py"
ALLOWED_FAMILIES = {
    "ingress-authority",
    "execution-sink-backtrace",
    "memory-lifetime",
    "representation-parser",
    "capability-code-loading",
    "attacker-acquisition",
    "stock-reachability",
    "jit-optimization",
    "wasm-validation-compiler",
    "sandbox-capability",
    "structured-generation",
    "browser-integration",
    "dependency-integration",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def command_record(
    name: str,
    command: list[str],
    run_dir: Path,
    timeout: int,
) -> dict[str, Any]:
    stdout_path = run_dir / f"{name}.stdout"
    stderr_path = run_dir / f"{name}.stderr"
    started = utc_now()
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=run_dir,
        )
        stdout_path.write_text(completed.stdout, encoding="utf-8")
        stderr_path.write_text(completed.stderr, encoding="utf-8")
        return {
            "name": name,
            "command": command,
            "startedAt": started,
            "finishedAt": utc_now(),
            "exitCode": completed.returncode,
            "status": "completed" if completed.returncode == 0 else "failed",
            "stdout": stdout_path.name,
            "stderr": stderr_path.name,
        }
    except subprocess.TimeoutExpired as exc:
        timed_stdout = exc.stdout or ""
        timed_stderr = exc.stderr or ""
        if isinstance(timed_stdout, bytes):
            timed_stdout = timed_stdout.decode("utf-8", "replace")
        if isinstance(timed_stderr, bytes):
            timed_stderr = timed_stderr.decode("utf-8", "replace")
        stdout_path.write_text(timed_stdout, encoding="utf-8")
        stderr_path.write_text(timed_stderr, encoding="utf-8")
        return {
            "name": name,
            "command": command,
            "startedAt": started,
            "finishedAt": utc_now(),
            "status": "timed-out",
            "timeoutSeconds": timeout,
            "stdout": stdout_path.name,
            "stderr": stderr_path.name,
        }


def stable_lead_id(tool: str, kind: str, location: str, title: str) -> str:
    digest = hashlib.sha256(
        json.dumps([tool, kind, location, title], separators=(",", ":")).encode()
    ).hexdigest()[:16]
    return f"SL-{digest}"


def normalize_lead(
    raw: dict[str, Any],
    *,
    run_id: str,
    run_path: str,
    commit: str,
    default_evidence: Iterable[str],
) -> dict[str, Any]:
    tool = str(raw.get("tool") or "unknown")
    kind = str(raw.get("kind") or "static-lead")
    title = str(raw.get("title") or kind.replace("-", " ").title())
    location = str(raw.get("location") or "unknown")
    family = str(raw.get("approachFamily") or "representation-parser")
    if family not in ALLOWED_FAMILIES:
        family = "representation-parser"
    raw_evidence = raw.get("evidence")
    if not isinstance(raw_evidence, list):
        raw_evidence = []
    evidence = sorted(set(str(item) for item in [*default_evidence, *raw_evidence] if item))
    lead = dict(raw)
    lead.update(
        {
            "id": stable_lead_id(tool, kind, location, title),
            "tool": tool,
            "kind": kind,
            "title": title,
            "location": location,
            "approachFamily": family,
            "priorityScore": int(raw.get("priorityScore") or raw.get("score") or 0),
            "evidence": evidence,
            "provenance": {
                **(raw.get("provenance") if isinstance(raw.get("provenance"), dict) else {}),
                "runId": run_id,
                "runRecord": run_path,
                "campaignCommit": commit,
                "staticOnly": raw.get("runtimeValidated") is not True,
                "runtimeValidated": raw.get("runtimeValidated") is True,
                "firstPrinciplesOnly": True,
                "gitHistoryUsed": False,
                "patchedVersionDiffUsed": False,
                "internetPatchDiffUsed": False,
            },
        }
    )
    return lead


def select_normalized_leads(
    raw_leads: Iterable[tuple[dict[str, Any], list[str]]],
    *,
    run_id: str,
    run_path: str,
    commit: str,
    max_leads: int,
) -> tuple[list[dict[str, Any]], int]:
    """Deduplicate and rank semantic compositions above inventory discovery."""
    normalized_by_id: dict[str, dict[str, Any]] = {}
    for raw, evidence in raw_leads:
        lead = normalize_lead(
            raw,
            run_id=run_id,
            run_path=run_path,
            commit=commit,
            default_evidence=evidence,
        )
        previous = normalized_by_id.get(lead["id"])
        if previous is None or int(lead["priorityScore"]) > int(previous["priorityScore"]):
            normalized_by_id[lead["id"]] = lead
    ranked = sorted(
        normalized_by_id.values(),
        key=lambda item: (
            -int(item.get("priorityScore") or 0),
            str(item.get("tool") or ""),
            str(item["id"]),
        ),
    )
    return ranked[:max_leads], len(ranked)


def differential_leads(path: Path) -> list[dict[str, Any]]:
    record = read_json(path)
    if record.get("producer") != "krineon-differential-witness":
        raise RuntimeError(f"not a Krineon differential witness: {path}")
    leads: list[dict[str, Any]] = []
    for case in record.get("cases", []):
        if not isinstance(case, dict) or case.get("disagreement") is not True:
            continue
        witness_id = str(case.get("witnessId") or "")
        input_record = case.get("input") if isinstance(case.get("input"), dict) else {}
        leads.append(
            {
                "tool": "differential-witness",
                "kind": "consumer-disagreement",
                "title": f"Two consumers disagree in {record.get('name')}",
                "location": str(input_record.get("path") or witness_id),
                "approachFamily": "representation-parser",
                "leadClass": "executed-differential",
                "priorityScore": 96,
                "runtimeValidated": True,
                "witnessId": witness_id,
                "input": input_record,
                "observations": [
                    value.get("observation")
                    for value in case.get("consumers", [])
                    if isinstance(value, dict)
                ],
            }
        )
    return leads


def parse_z3_spec(path: Path, *, allow_unbound: bool) -> dict[str, Any]:
    spec = read_json(path)
    kind = spec.get("kind")
    supported = {
        "truncate", "add-wrap", "sub-wrap", "mul-wrap",
        "narrowing-collision", "custom-smt",
    }
    if kind not in supported:
        raise RuntimeError(f"Z3 spec {path} has unsupported kind: {spec.get('kind')}")
    if kind == "custom-smt":
        required = {"kind", "consumerBits", "variables", "assertions"}
    else:
        required = {"kind", "bits", "target", "maxX"}
        if kind != "truncate":
            required.add("maxY")
    missing = required.difference(spec)
    if missing:
        raise RuntimeError(f"Z3 spec {path} missing: {', '.join(sorted(missing))}")
    binding = spec.get("implementationBinding")
    if not isinstance(binding, dict) and not allow_unbound:
        raise RuntimeError(
            f"Z3 spec {path} is generic mathematics, not target analysis; add "
            "implementationBinding or pass --allow-unbound-z3 for artifact-only output"
        )
    if isinstance(binding, dict):
        binding_required = {
            "sourceFile", "startLine", "endLine", "expression", "constraintExtraction"
        }
        binding_missing = binding_required.difference(binding)
        if binding_missing:
            raise RuntimeError(
                f"Z3 spec {path} binding missing: {', '.join(sorted(binding_missing))}"
            )
    return spec


def z3_command(spec_path: Path, source: Path, output: Path, emit_dir: Path) -> list[str]:
    return [
        sys.executable,
        str(Z3_SOLVER),
        "--spec",
        str(spec_path),
        "--source-root",
        str(source),
        "--output",
        str(output),
        "--emit-dir",
        str(emit_dir),
    ]


def resolve_source(campaign: dict[str, Any], explicit: Path | None) -> Path:
    value = explicit or (Path(campaign["localCheckout"]) if campaign.get("localCheckout") else None)
    if value is None:
        raise RuntimeError("campaign has no local checkout; pass --source")
    source = value.expanduser().resolve()
    if not source.exists():
        raise RuntimeError(f"source does not exist: {source}")
    return source


def source_identity(source: Path) -> dict[str, Any]:
    identity: dict[str, Any] = {"path": str(source), "kind": "file" if source.is_file() else "directory"}
    if source.is_file():
        identity["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    git_root = source.parent if source.is_file() else source
    if shutil.which("git"):
        commit = subprocess.run(
            ["git", "-C", str(git_root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
        )
        if commit.returncode == 0:
            identity["gitCommit"] = commit.stdout.strip()
            dirty = subprocess.run(
                ["git", "-C", str(git_root), "status", "--porcelain", "--untracked-files=no"],
                check=False,
                capture_output=True,
                text=True,
            )
            identity["trackedWorktreeDirty"] = bool(dirty.stdout.strip()) if dirty.returncode == 0 else None
    return identity


def relative_evidence(campaign_root: Path, path: Path) -> str:
    return path.resolve().relative_to(campaign_root.resolve()).as_posix()


def run_pipeline(args: argparse.Namespace) -> int:
    campaign_root = args.campaign_dir.expanduser().resolve()
    campaign_path = campaign_root / "campaign.json"
    if not campaign_path.is_file():
        raise RuntimeError(f"not a Krineon campaign: {campaign_root}")
    campaign = read_json(campaign_path)
    source = resolve_source(campaign, args.source)
    selected = set(args.tool or ("trailmark", "differential", "z3"))
    run_id = (
        dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-")
        + uuid.uuid4().hex[:8]
    )
    run_dir = campaign_root / "tools" / "static" / run_id
    run_dir.mkdir(parents=True)
    run_record_path = run_dir / "run.json"
    run_record_relative = relative_evidence(campaign_root, run_record_path)
    tools: list[dict[str, Any]] = []
    raw_leads: list[tuple[dict[str, Any], list[str]]] = []

    if "trailmark" in selected:
        executable = shutil.which("trailmark")
        if not executable:
            tools.append({"name": "trailmark", "status": "unavailable"})
        elif not args.language:
            tools.append({"name": "trailmark", "status": "skipped", "reason": "--language is required"})
        else:
            summary = command_record(
                "trailmark-analyze",
                [executable, "analyze", str(source), "--language", args.language, "--summary"],
                run_dir,
                args.timeout,
            )
            entries_file = run_dir / "trailmark-entrypoints.json"
            entries = command_record(
                "trailmark-entrypoints",
                [executable, "entrypoints", str(source), "--language", args.language, "--json"],
                run_dir,
                args.timeout,
            )
            if entries["status"] == "completed":
                (run_dir / entries["stdout"]).replace(entries_file)
                entries["stdout"] = entries_file.name
            tools.extend((summary, entries))

    if "differential" in selected:
        if not args.differential_spec:
            tools.append(
                {
                    "name": "differential-witness",
                    "status": "skipped",
                    "reason": "no --differential-spec supplied",
                }
            )
        for index, spec_path in enumerate(args.differential_spec or (), 1):
            retained_spec = run_dir / f"differential-{index}-spec.json"
            shutil.copyfile(spec_path.expanduser().resolve(), retained_spec)
            output = run_dir / f"differential-{index}.json"
            result = command_record(
                f"differential-{index}",
                [
                    sys.executable,
                    str(DIFFERENTIAL),
                    "--spec",
                    str(retained_spec),
                    "--output",
                    str(output),
                    "--timeout",
                    str(args.timeout),
                ],
                run_dir,
                args.timeout * 10,
            )
            tools.append(result)
            if result["status"] == "completed" and output.is_file():
                for lead in differential_leads(output):
                    raw_leads.append(
                        (
                            lead,
                            [
                                relative_evidence(campaign_root, retained_spec),
                                relative_evidence(campaign_root, output),
                            ],
                        )
                    )

    if "z3" in selected:
        if not args.z3_spec:
            tools.append({"name": "z3", "status": "skipped", "reason": "no --z3-spec supplied"})
        for index, spec_path in enumerate(args.z3_spec or (), 1):
            spec = parse_z3_spec(
                spec_path.expanduser().resolve(), allow_unbound=args.allow_unbound_z3
            )
            retained_spec = run_dir / f"z3-{index}-spec.json"
            write_json(retained_spec, spec)
            output = run_dir / f"z3-{index}.json"
            emit_dir = run_dir / f"z3-{index}-payloads"
            result = command_record(
                f"z3-{index}",
                z3_command(retained_spec, source, output, emit_dir),
                run_dir,
                args.timeout,
            )
            tools.append(result)
            if result["status"] == "completed" and output.is_file():
                model = read_json(output)
                binding = model.get("implementationBinding")
                binding = binding if isinstance(binding, dict) else {}
                if binding.get("sourceBound") is True:
                    raw_leads.append(
                        (
                            {
                                "tool": "z3",
                                "kind": "source-bound-constraint-input",
                                "title": f"Source-bound {spec['kind']} constraint model",
                                "location": (
                                    f"{binding.get('sourceFile')}:{binding.get('startLine')}"
                                ),
                                "approachFamily": "representation-parser",
                                "constraint": spec,
                                "model": model.get("model"),
                                "implementationBinding": binding,
                                "leadClass": "source-bound-constraint",
                                "priorityScore": 86,
                                "provenance": {
                                    "sourceBound": True,
                                    "implementationMatched": binding.get(
                                        "implementationMatched", False
                                    ),
                                    "constraintExtraction": binding.get(
                                        "constraintExtraction"
                                    ),
                                },
                            },
                            [
                                relative_evidence(campaign_root, retained_spec),
                                relative_evidence(campaign_root, output),
                                relative_evidence(campaign_root, emit_dir),
                            ],
                        )
                    )

    normalized, untruncated_lead_count = select_normalized_leads(
        raw_leads,
        run_id=run_id,
        run_path=run_record_relative,
        commit=str(campaign.get("commit") or "unknown"),
        max_leads=args.max_leads,
    )
    run_record = {
        "schemaVersion": 1,
        "runId": run_id,
        "createdAt": utc_now(),
        "campaign": str(campaign_root),
        "campaignCommit": campaign.get("commit"),
        "source": str(source),
        "sourceIdentity": source_identity(source),
        "selectedTools": sorted(selected),
        "analysisProvenance": {
            "firstPrinciplesOnly": True,
            "gitHistoryUsed": False,
            "changelogUsed": False,
            "advisoryMiningUsed": False,
            "patchedVersionDiffUsed": False,
            "internetPatchDiffUsed": False,
        },
        "tools": tools,
        "leadCount": len(normalized),
        "untruncatedLeadCount": untruncated_lead_count,
        "leadSelection": "semantic-priority-not-tool-order",
        "leads": normalized,
    }
    write_json(run_record_path, run_record)
    print(run_record_path)
    if args.ingest:
        return ingest_run(campaign_root, run_record_path, args.max_leads)
    return 0


def task_exists(database: Path, task_id: str) -> bool:
    with sqlite3.connect(database) as connection:
        row = connection.execute("SELECT 1 FROM tasks WHERE task_id=?", (task_id,)).fetchone()
    return row is not None


def ingest_run(campaign_root: Path, run_path: Path, max_leads: int) -> int:
    database = campaign_root / "orchestration.db"
    if not database.is_file():
        raise RuntimeError("orchestration.db is absent; run research_harness.py plan and queue first")
    run = read_json(run_path)
    registry_path = campaign_root / "tools" / "static-leads.json"
    registry = read_json(registry_path) if registry_path.is_file() else {
        "schemaVersion": 1,
        "createdAt": utc_now(),
        "updatedAt": utc_now(),
        "leads": [],
    }
    existing = {str(item["id"]): item for item in registry.get("leads", []) if isinstance(item, dict) and item.get("id")}
    created = 0
    for lead in run.get("leads", [])[:max_leads]:
        if not isinstance(lead, dict):
            continue
        lead_id = str(lead["id"])
        task_id = "static-" + lead_id.removeprefix("SL-").lower()
        if not task_exists(database, task_id):
            objective = (
                f"Validate or falsify evidence lead {lead_id} at {lead.get('location')}. "
                f"Inspect the pinned source manually, establish attacker control and guards, then re-execute the recorded differential on a stock build. "
                f"Provenance: {lead['provenance']['runRecord']}; evidence: {', '.join(lead.get('evidence', []))}. "
                "Do not promote the analyzer or differential hit itself as a finding."
            )
            command = [
                sys.executable,
                str(HARNESS),
                "task-add",
                str(campaign_root),
                task_id,
                "--title",
                f"Validate evidence lead: {lead.get('title')}",
                "--lane",
                "evidence-lead-validation",
                "--objective",
                objective,
                "--approach-family",
                str(lead.get("approachFamily") or "representation-parser"),
                "--success-criterion",
                "Retain a manual source slice confirming or falsifying the two consumers and guard ordering.",
                "--success-criterion",
                "Run a bounded positive/negative runtime discriminator on an unmodified supported build, or record the exact blocking mechanism.",
                "--success-criterion",
                "Link every conclusion to the static run, tool output, campaign commit, worker identity, and retained artifact paths.",
                "--priority",
                "650",
                "--max-attempts",
                "2",
            ]
            completed = subprocess.run(command, check=False, capture_output=True, text=True)
            if completed.returncode and not task_exists(database, task_id):
                raise RuntimeError(f"failed to create {task_id}: {completed.stderr.strip()}")
            if completed.returncode == 0:
                created += 1
        previous = existing.get(lead_id, {})
        observations = previous.get("observations", [])
        if not isinstance(observations, list):
            observations = []
        observation = {
            "runId": lead.get("provenance", {}).get("runId"),
            "runRecord": lead.get("provenance", {}).get("runRecord"),
            "campaignCommit": lead.get("provenance", {}).get("campaignCommit"),
            "evidence": lead.get("evidence", []),
            "observedAt": utc_now(),
        }
        if not any(item.get("runId") == observation["runId"] for item in observations if isinstance(item, dict)):
            observations.append(observation)
        saved = dict(lead)
        saved["taskId"] = task_id
        saved["status"] = "queued-validation"
        saved["ingestedAt"] = previous.get("ingestedAt") or utc_now()
        saved["observations"] = observations
        existing[lead_id] = saved
    registry["updatedAt"] = utc_now()
    registry["leads"] = sorted(existing.values(), key=lambda item: str(item["id"]))
    write_json(registry_path, registry)
    print(f"ingested {min(len(run.get('leads', [])), max_leads)} leads; created {created} validation tasks")
    print(registry_path)
    return 0


def ingest_command(args: argparse.Namespace) -> int:
    return ingest_run(
        args.campaign_dir.expanduser().resolve(),
        args.run.expanduser().resolve(),
        args.max_leads,
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="execute selected analyzers and retain normalized leads")
    run.add_argument("campaign_dir", type=Path)
    run.add_argument("--source", type=Path)
    run.add_argument("--language")
    run.add_argument(
        "--tool", action="append", choices=("trailmark", "differential", "z3")
    )
    run.add_argument(
        "--differential-spec",
        action="append",
        type=Path,
        help="two-consumer executable witness specification; repeatable",
    )
    run.add_argument("--z3-spec", action="append", type=Path)
    run.add_argument(
        "--allow-unbound-z3",
        action="store_true",
        help="retain generic solver output but never enqueue it as a target-source lead",
    )
    run.add_argument("--timeout", type=int, default=120)
    run.add_argument("--max-leads", type=int, default=100)
    run.add_argument("--ingest", action="store_true")
    run.set_defaults(func=run_pipeline)
    ingest = sub.add_parser("ingest", help="create idempotent validation tasks from a retained run")
    ingest.add_argument("campaign_dir", type=Path)
    ingest.add_argument("--run", required=True, type=Path)
    ingest.add_argument("--max-leads", type=int, default=100)
    ingest.set_defaults(func=ingest_command)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if getattr(args, "timeout", 1) < 1 or args.max_leads < 1:
        raise SystemExit("timeouts and lead limits must be positive")
    try:
        return args.func(args)
    except (RuntimeError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
