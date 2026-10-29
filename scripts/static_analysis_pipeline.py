#!/usr/bin/env python3
"""Run static analyzers and turn retained leads into durable validation tasks."""

from __future__ import annotations

import argparse
import csv
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
TREE_CENSUS = PROJECT / "scripts" / "tree_sitter_census.py"
Z3_SOLVER = PROJECT / "scripts" / "z3_boundary_solver.py"
JOERN_QUERIES = (
    ("critical-sink-reachability", PROJECT / "queries" / "joern" / "critical-sink-reachability.sc"),
    ("missing-validation", PROJECT / "queries" / "joern" / "missing-validation.sc"),
)
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
            "evidence": evidence,
            "provenance": {
                **(raw.get("provenance") if isinstance(raw.get("provenance"), dict) else {}),
                "runId": run_id,
                "runRecord": run_path,
                "campaignCommit": commit,
                "staticOnly": True,
                "runtimeValidated": False,
                "firstPrinciplesOnly": True,
                "gitHistoryUsed": False,
                "patchedVersionDiffUsed": False,
                "internetPatchDiffUsed": False,
            },
        }
    )
    return lead


def trailmark_leads(path: Path) -> list[dict[str, Any]]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        return []
    leads = []
    for item in value:
        if not isinstance(item, dict):
            continue
        symbol = str(item.get("node_id") or item.get("name") or "entrypoint")
        leads.append(
            {
                "tool": "trailmark",
                "kind": "public-ingress",
                "title": f"Review public entry point {symbol}",
                "location": symbol,
                "approachFamily": "ingress-authority",
                "excerpt": str(item.get("description") or ""),
                "trailmark": item,
            }
        )
    return leads


def parse_joern_tsv(path: Path, query: str) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    leads: list[dict[str, Any]] = []
    with path.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream, delimiter="\t"):
            kind = row.get("kind") or query
            location = f"{row.get('file') or 'unknown'}:{row.get('line') or '?'}"
            family = (
                "execution-sink-backtrace"
                if kind == "sink-reachability"
                else "ingress-authority"
            )
            leads.append(
                {
                    "tool": "joern",
                    "kind": kind,
                    "title": f"Joern {kind}: {row.get('method') or row.get('code') or location}",
                    "location": location,
                    "approachFamily": family,
                    "excerpt": row.get("code") or "",
                    "query": query,
                }
            )
    return leads


def parse_z3_spec(path: Path) -> dict[str, Any]:
    spec = read_json(path)
    required = {"kind", "bits", "target", "maxX"}
    if spec.get("kind") not in {"truncate", "add-wrap", "mul-wrap"}:
        raise RuntimeError(f"Z3 spec {path} has unsupported kind: {spec.get('kind')}")
    if spec.get("kind") != "truncate":
        required.add("maxY")
    missing = required.difference(spec)
    if missing:
        raise RuntimeError(f"Z3 spec {path} missing: {', '.join(sorted(missing))}")
    return spec


def z3_command(spec: dict[str, Any], output: Path, emit_dir: Path) -> list[str]:
    command = [
        sys.executable,
        str(Z3_SOLVER),
        "--kind",
        str(spec["kind"]),
        "--bits",
        str(spec["bits"]),
        "--target",
        str(spec["target"]),
        "--min-x",
        str(spec.get("minX", 0)),
        "--max-x",
        str(spec["maxX"]),
        "--output",
        str(output),
        "--emit-dir",
        str(emit_dir),
    ]
    if spec["kind"] != "truncate":
        command.extend(
            [
                "--min-y",
                str(spec.get("minY", 0)),
                "--max-y",
                str(spec["maxY"]),
            ]
        )
    return command


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
    selected = set(args.tool or ("trailmark", "tree-sitter", "joern", "z3"))
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
                for lead in trailmark_leads(entries_file):
                    raw_leads.append((lead, [relative_evidence(campaign_root, entries_file)]))
            tools.extend((summary, entries))

    if "tree-sitter" in selected:
        tree_output = run_dir / "tree-sitter-census.json"
        command = [sys.executable, str(TREE_CENSUS), str(source), "--max-leads", str(args.max_leads), "--output", str(tree_output)]
        if args.language:
            command.extend(["--language", args.language])
        result = command_record("tree-sitter-census", command, run_dir, args.timeout)
        tools.append(result)
        if result["status"] == "completed" and tree_output.is_file():
            census = read_json(tree_output)
            for lead in census.get("leads", []):
                if isinstance(lead, dict):
                    raw_leads.append((lead, [relative_evidence(campaign_root, tree_output)]))

    if "joern" in selected:
        parser_executable = shutil.which("joern-parse")
        joern_executable = shutil.which("joern")
        if not parser_executable or not joern_executable:
            tools.append({"name": "joern", "status": "unavailable"})
        else:
            cpg = run_dir / "cpg.bin"
            parse_result = command_record(
                "joern-parse",
                [parser_executable, str(source), "-o", str(cpg)],
                run_dir,
                max(args.timeout, 300),
            )
            tools.append(parse_result)
            if parse_result["status"] == "completed":
                for name, query in JOERN_QUERIES:
                    output = run_dir / f"joern-{name}.tsv"
                    result = command_record(
                        f"joern-{name}",
                        [joern_executable, "--script", str(query), "--param", f"cpgFile={cpg}", "--param", f"out={output}"],
                        run_dir,
                        max(args.timeout, 300),
                    )
                    tools.append(result)
                    if result["status"] == "completed":
                        for lead in parse_joern_tsv(output, name):
                            raw_leads.append((lead, [relative_evidence(campaign_root, output)]))

    if "z3" in selected:
        if not args.z3_spec:
            tools.append({"name": "z3", "status": "skipped", "reason": "no --z3-spec supplied"})
        for index, spec_path in enumerate(args.z3_spec or (), 1):
            spec = parse_z3_spec(spec_path.expanduser().resolve())
            retained_spec = run_dir / f"z3-{index}-spec.json"
            write_json(retained_spec, spec)
            output = run_dir / f"z3-{index}.json"
            emit_dir = run_dir / f"z3-{index}-payloads"
            result = command_record(
                f"z3-{index}",
                z3_command(spec, output, emit_dir),
                run_dir,
                args.timeout,
            )
            tools.append(result)
            if result["status"] == "completed" and output.is_file():
                model = read_json(output)
                raw_leads.append(
                    (
                        {
                            "tool": "z3",
                            "kind": "concrete-boundary-input",
                            "title": f"Concrete {spec['kind']} input for {spec['bits']}-bit consumer",
                            "location": spec_path.name,
                            "approachFamily": "representation-parser",
                            "constraint": spec,
                            "model": model.get("model"),
                        },
                        [
                            relative_evidence(campaign_root, retained_spec),
                            relative_evidence(campaign_root, output),
                            relative_evidence(campaign_root, emit_dir),
                        ],
                    )
                )

    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw, evidence in raw_leads:
        lead = normalize_lead(
            raw,
            run_id=run_id,
            run_path=run_record_relative,
            commit=str(campaign.get("commit") or "unknown"),
            default_evidence=evidence,
        )
        if lead["id"] not in seen:
            seen.add(lead["id"])
            normalized.append(lead)
        if len(normalized) >= args.max_leads:
            break
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
                f"Validate or falsify static lead {lead_id} at {lead.get('location')}. "
                f"Inspect the pinned source manually, establish attacker control and guards, then run a bounded stock-build discriminator. "
                f"Provenance: {lead['provenance']['runRecord']}; evidence: {', '.join(lead.get('evidence', []))}. "
                "Do not promote the analyzer hit itself as a finding."
            )
            command = [
                sys.executable,
                str(HARNESS),
                "task-add",
                str(campaign_root),
                task_id,
                "--title",
                f"Validate static lead: {lead.get('title')}",
                "--lane",
                "static-lead-validation",
                "--objective",
                objective,
                "--approach-family",
                str(lead.get("approachFamily") or "representation-parser"),
                "--success-criterion",
                "Retain a manual source slice confirming or falsifying the analyzer's semantics and guard ordering.",
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
    run.add_argument("--tool", action="append", choices=("trailmark", "tree-sitter", "joern", "z3"))
    run.add_argument("--z3-spec", action="append", type=Path)
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
