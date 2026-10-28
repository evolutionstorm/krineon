#!/usr/bin/env python3
"""Create and validate evidence-driven, authorized security campaigns.

This harness deliberately does not send requests, exploit targets, or submit
reports. It creates research task packets, tracks hypotheses, checks evidence
gates, and inventories retained artifacts.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ASSETS = PROJECT_ROOT / "assets"

CAMPAIGN_DIRS = (
    "tasks",
    "findings",
    "evidence",
    "tools",
    "reports",
    "logs",
    "worktrees",
)

STATUS_VALUES = (
    "idea",
    "source-confirmed",
    "primitive",
    "candidate",
    "validated",
    "reportable",
    "blocked",
    "disproved",
    "duplicate-risk",
)

CANDIDATE_GATES = (
    "authorization_confirmed",
    "scope_confirmed",
    "exact_version_pinned",
    "root_cause_identified",
    "attacker_control_proven",
    "baseline_control",
    "negative_control",
    "positive_case",
    "concrete_impact",
)

REPORTABLE_GATES = CANDIDATE_GATES + (
    "reproduction_complete",
    "independent_replay",
    "prior_art_checked",
    "official_docs_checked",
    "upstream_tests_checked",
    "patch_status_checked",
    "source_refs_verified",
    "cleanup_verified",
    "secrets_removed",
)

LANES = (
    {
        "wave": 0,
        "id": "coordinator-setup",
        "title": "Scope, revision, and threat-model coordinator",
        "objective": (
            "Freeze authorization, scope, exact artifacts, documented security "
            "promises, public entry points, privileged sinks, and stop conditions."
        ),
        "deliverables": (
            "completed campaign.json",
            "authorization record",
            "entry-point and sink inventory",
            "tool probe",
        ),
    },
    {
        "wave": 1,
        "id": "boundary-map",
        "title": "Trust-boundary and identity mapper",
        "objective": (
            "Map authentication, provenance, tenant/project/build/route identity, "
            "manifest authority, normalization, and validation boundaries."
        ),
        "deliverables": (
            "boundary map",
            "source references",
            "falsifiable hypotheses",
            "searched-surface inventory",
        ),
    },
    {
        "wave": 1,
        "id": "sink-first",
        "title": "Sink-first reachability tracer",
        "objective": (
            "Work backward from execution, module load, file, network, native "
            "parser, key, cache, and policy sinks to public inputs."
        ),
        "deliverables": (
            "sink inventory",
            "guard and dominance map",
            "candidate paths",
            "blocked paths",
        ),
    },
    {
        "wave": 1,
        "id": "state-lifecycle",
        "title": "State, ownership, and lifecycle auditor",
        "objective": (
            "Audit globals, pooling, async settlement, parser errors, ownership, "
            "recycling, realm boundaries, cleanup, and failure-state invariants."
        ),
        "deliverables": (
            "state-owner table",
            "lifecycle diagrams",
            "error/async differences",
            "hypotheses and blockers",
        ),
    },
    {
        "wave": 2,
        "id": "protocol-differential",
        "title": "Producer/consumer and cross-layer differential",
        "objective": (
            "Compare parsing, lengths, encodings, case, paths, methods, headers, "
            "and type domains across every layer that handles the same value."
        ),
        "deliverables": (
            "differential table",
            "minimal harness",
            "baseline and negative control",
            "candidate registry entries",
        ),
    },
    {
        "wave": 2,
        "id": "patch-variants",
        "title": "Patch, sibling-path, and prior-art auditor",
        "objective": (
            "Inspect recent fixes, sibling functions, generated bundles, platform "
            "variants, upstream tests, advisories, and duplicate root causes."
        ),
        "deliverables": (
            "patch matrix",
            "sibling census",
            "prior-art assessment",
            "incomplete-fix hypotheses",
        ),
    },
    {
        "wave": 2,
        "id": "deployment-matrix",
        "title": "Deployment and attacker-acquisition analyst",
        "objective": (
            "Test defaults, supported configurations, hosts, platforms, public "
            "coordinate acquisition, and realistic application carriers."
        ),
        "deliverables": (
            "configuration matrix",
            "remote-acquisition proof or blocker",
            "resource measurements",
            "exact conditions",
        ),
    },
    {
        "wave": 3,
        "id": "independent-replay",
        "title": "Independent clean replay and controls",
        "objective": (
            "Reproduce a candidate without the originating agent's private state, "
            "run fresh-process controls, and preserve raw evidence and cleanup."
        ),
        "deliverables": (
            "clean reproduction",
            "three-case truth table",
            "N/M reliability where applicable",
            "artifact hashes",
        ),
    },
    {
        "wave": 3,
        "id": "adversarial-review",
        "title": "Scope, documentation, duplicate, and severity adversary",
        "objective": (
            "Try to close the candidate as intended behavior, application misuse, "
            "out of scope, stale, unpatched prior art, duplicate, or overstated."
        ),
        "deliverables": (
            "closure arguments",
            "primary-source checks",
            "CVSS metric review",
            "narrow surviving claim",
        ),
    },
    {
        "wave": 4,
        "id": "root-synthesis",
        "title": "Root synthesis and filing package",
        "objective": (
            "Resolve conflicting evidence, run reportable gates, write the "
            "root-cause-first report, and verify a clean package."
        ),
        "deliverables": (
            "submission report",
            "reviewer README",
            "self-contained PoC",
            "SHA256SUMS",
        ),
    },
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"missing required file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"expected a JSON object in {path}")
    return data


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def template(name: str) -> dict[str, Any]:
    return read_json(ASSETS / name)


def campaign_root(value: str) -> Path:
    return Path(value).expanduser().resolve()


def require_campaign(root: Path) -> dict[str, Any]:
    return read_json(root / "campaign.json")


def registry_path(root: Path) -> Path:
    return root / "registry.json"


def load_registry(root: Path) -> dict[str, Any]:
    return read_json(registry_path(root))


def save_registry(root: Path, registry: dict[str, Any]) -> None:
    registry["updatedAt"] = utc_now()
    write_json(registry_path(root), registry)


def task_markdown(lane: dict[str, Any], campaign: dict[str, Any]) -> str:
    deliverables = "\n".join(f"- {item}" for item in lane["deliverables"])
    return f"""# Task: {lane['title']}

## Campaign

- Target: {campaign['target']}
- Repository: {campaign['repository']}
- Exact revision: {campaign['commit']}
- Mode: {campaign['mode']}
- Wave: {lane['wave']}

Read `AUTHORIZATION.md` and `campaign.json` before taking any dynamic action.
Stay within the recorded environment and stop conditions.

## Primary objective

{lane['objective']}

## Required deliverables

{deliverables}

## Evidence contract

- Pin source references to the tested revision.
- Separate runtime proof, source confirmation, and inference.
- Register blocked and disproved paths as well as candidates.
- State the falsification condition for each hypothesis.
- Do not use a static-tool result as exploit evidence.
- Do not access third-party data, degrade services, or broaden authorization.

## Handoff

Use `assets/agent-handoff.template.md` as the structure. Return exact commands,
artifact paths, controls, blockers, and cleanup state.
"""


def cmd_init(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    if root.exists() and any(root.iterdir()):
        raise SystemExit(f"refusing to initialize non-empty directory: {root}")
    root.mkdir(parents=True, exist_ok=True)
    for name in CAMPAIGN_DIRS:
        (root / name).mkdir(exist_ok=True)

    data = template("campaign.template.json")
    data.update(
        {
            "target": args.target,
            "repository": args.repo,
            "commit": args.commit,
            "mode": args.mode,
            "programUrl": args.program_url or "",
            "createdAt": utc_now(),
            "lanes": [lane["id"] for lane in LANES],
        }
    )
    write_json(root / "campaign.json", data)
    write_json(
        registry_path(root),
        {"schemaVersion": 1, "createdAt": utc_now(), "updatedAt": utc_now(), "findings": []},
    )

    authorization = f"""# Authorization record

- Target: {args.target}
- Repository or asset: {args.repo}
- Exact revision: {args.commit}
- Program URL: {args.program_url or 'not recorded'}
- Authorization confirmed: NO
- Allowed environment: local owned fixture
- Allowed actions: source review and bounded local verification
- Prohibited actions: third-party data access, service degradation, persistence,
  uncontrolled code execution, and activity outside recorded scope
- Stop conditions: complete before dynamic testing

Edit this file and `campaign.json` before any live or shared-system test.
"""
    (root / "AUTHORIZATION.md").write_text(authorization, encoding="utf-8")
    (root / "logs" / ".gitkeep").touch()
    print(f"initialized campaign: {root}")
    print("next: edit AUTHORIZATION.md and campaign.json, then run the plan command")
    return 0


def cmd_plan(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    campaign = require_campaign(root)
    selected = set(args.lane or ())
    unknown = selected.difference(lane["id"] for lane in LANES)
    if unknown:
        raise SystemExit(f"unknown lanes: {', '.join(sorted(unknown))}")

    planned: list[dict[str, Any]] = []
    for lane in LANES:
        if selected and lane["id"] not in selected:
            continue
        path = root / "tasks" / f"wave-{lane['wave']}-{lane['id']}.md"
        path.write_text(task_markdown(lane, campaign), encoding="utf-8")
        planned.append(
            {
                "wave": lane["wave"],
                "lane": lane["id"],
                "title": lane["title"],
                "task": str(path.relative_to(root)),
                "dependsOn": (
                    []
                    if lane["wave"] == 0
                    else [
                        earlier["id"]
                        for earlier in LANES
                        if earlier["wave"] == lane["wave"] - 1
                    ]
                ),
            }
        )
    write_json(
        root / "launch-plan.json",
        {
            "schemaVersion": 1,
            "generatedAt": utc_now(),
            "concurrencyGuidance": "root coordinator plus up to three complementary workers",
            "validationRule": "a candidate must be replayed by an agent that did not originate it",
            "tasks": planned,
        },
    )
    print(f"wrote {len(planned)} task packets and launch-plan.json")
    return 0


def validate_finding_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{1,63}", value):
        raise argparse.ArgumentTypeError("finding ID must start with a letter and use letters, digits, _ or -")
    return value


def cmd_register(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    registry = load_registry(root)
    if any(item.get("id") == args.finding_id for item in registry.get("findings", [])):
        raise SystemExit(f"finding already exists: {args.finding_id}")
    finding = template("finding.template.json")
    finding.update(
        {
            "id": args.finding_id,
            "title": args.title,
            "lane": args.lane,
            "status": args.status,
        }
    )
    path = root / "findings" / f"{args.finding_id}.json"
    write_json(path, finding)
    registry.setdefault("findings", []).append(
        {
            "id": args.finding_id,
            "title": args.title,
            "lane": args.lane,
            "status": args.status,
            "path": str(path.relative_to(root)),
        }
    )
    save_registry(root, registry)
    print(f"registered {args.finding_id}: {path}")
    return 0


def finding_path(root: Path, finding_id: str) -> Path:
    path = root / "findings" / f"{finding_id}.json"
    if not path.is_file():
        raise SystemExit(f"unknown finding: {finding_id}")
    return path


def gate_result(finding: dict[str, Any], level: str) -> dict[str, Any]:
    required_gates = CANDIDATE_GATES if level == "candidate" else REPORTABLE_GATES
    gates = finding.get("gates", {})
    missing_gates = [name for name in required_gates if gates.get(name) is not True]
    missing_fields: list[str] = []
    for field in ("rootCause", "impact"):
        if not str(finding.get(field, "")).strip():
            missing_fields.append(field)
    for field in ("preconditions", "evidence"):
        value = finding.get(field)
        if not isinstance(value, list) or not value:
            missing_fields.append(field)
    controls = finding.get("controls", {})
    for control in ("baseline", "negative", "positive"):
        if not str(controls.get(control, "")).strip():
            missing_fields.append(f"controls.{control}")
    passed = not missing_gates and not missing_fields
    return {
        "finding": finding.get("id"),
        "level": level,
        "passed": passed,
        "missingGates": missing_gates,
        "missingFields": missing_fields,
    }


def cmd_gate(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    finding = read_json(finding_path(root, args.finding_id))
    result = gate_result(finding, args.level)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        label = "PASS" if result["passed"] else "FAIL"
        print(f"{label}: {args.finding_id} {args.level} gate")
        if result["missingGates"]:
            print("missing gates:")
            for item in result["missingGates"]:
                print(f"  - {item}")
        if result["missingFields"]:
            print("missing evidence fields:")
            for item in result["missingFields"]:
                print(f"  - {item}")
    return 0 if result["passed"] else 1


def cmd_status(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    campaign = require_campaign(root)
    registry = load_registry(root)
    rows = registry.get("findings", [])
    summary: dict[str, int] = {}
    for row in rows:
        summary[row.get("status", "unknown")] = summary.get(row.get("status", "unknown"), 0) + 1
    if args.json:
        print(json.dumps({"campaign": campaign, "statusCounts": summary, "findings": rows}, indent=2))
        return 0
    print(f"target:     {campaign['target']}")
    print(f"repository: {campaign['repository']}")
    print(f"revision:   {campaign['commit']}")
    print(f"mode:       {campaign['mode']}")
    print(f"findings:   {len(rows)}")
    if not rows:
        return 0
    print()
    print(f"{'ID':<14} {'STATUS':<18} {'LANE':<24} TITLE")
    print("-" * 90)
    for row in rows:
        print(f"{row['id']:<14} {row['status']:<18} {row['lane']:<24} {row['title']}")
    return 0


def iter_artifacts(root: Path) -> Iterable[Path]:
    for dirname in ("evidence", "findings", "reports"):
        base = root / dirname
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file() and not path.is_symlink() and path.name != "SHA256SUMS":
                yield path
    for filename in ("campaign.json", "registry.json", "launch-plan.json", "AUTHORIZATION.md"):
        path = root / filename
        if path.is_file():
            yield path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cmd_hash(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    artifacts = list(dict.fromkeys(iter_artifacts(root)))
    lines = [f"{sha256(path)}  {path.relative_to(root).as_posix()}" for path in artifacts]
    output = root / "SHA256SUMS"
    output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    print(f"hashed {len(lines)} artifacts: {output}")
    return 0


TEXT_SUFFIXES = {".md", ".txt", ".json", ".js", ".cjs", ".mjs", ".ts", ".py", ".sh", ".yml", ".yaml"}
LOCAL_PATH_RE = re.compile(r"(?<![A-Za-z0-9_])(?:/home/[^\s'\"`]+|[A-Za-z]:\\\\Users\\\\[^\s'\"`]+)")
FLOATING_LINK_RE = re.compile(r"https://github\.com/[^/]+/[^/]+/blob/(?:main|master|canary)/")
SECRET_PATTERNS = (
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("generic secret assignment", re.compile(r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?token)\s*[:=]\s*['\"][^'\"]{12,}['\"]")),
)


def lint_files(root: Path) -> Iterable[Path]:
    excluded = {".git", "node_modules", ".next", "dist", "build", "worktrees"}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in excluded for part in path.relative_to(root).parts):
            continue
        yield path


def cmd_lint(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    require_campaign(root)
    findings: list[dict[str, str]] = []
    hard_fail = False
    for path in lint_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        rel = path.relative_to(root).as_posix()
        for label, regex in SECRET_PATTERNS:
            if regex.search(text):
                findings.append({"severity": "error", "file": rel, "issue": label})
                hard_fail = True
        if LOCAL_PATH_RE.search(text):
            findings.append({"severity": "warning", "file": rel, "issue": "researcher-local absolute path"})
        if FLOATING_LINK_RE.search(text):
            findings.append({"severity": "warning", "file": rel, "issue": "floating GitHub source link"})
        if re.search(r"\b(?:TODO|TBD|FIXME)\b", text):
            findings.append({"severity": "warning", "file": rel, "issue": "unresolved placeholder"})
    if args.json:
        print(json.dumps({"passed": not hard_fail and not (args.strict and findings), "findings": findings}, indent=2))
    elif findings:
        for item in findings:
            print(f"{item['severity'].upper()}: {item['file']}: {item['issue']}")
    else:
        print("PASS: no package-hygiene findings")
    return 1 if hard_fail or (args.strict and findings) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="initialize an empty campaign directory")
    init.add_argument("campaign_dir")
    init.add_argument("--target", required=True)
    init.add_argument("--repo", required=True)
    init.add_argument("--commit", required=True)
    init.add_argument("--mode", choices=("source", "local-lab", "testnet", "authorized-live"), default="source")
    init.add_argument("--program-url")
    init.set_defaults(func=cmd_init)

    plan = sub.add_parser("plan", help="write wave-based agent task packets")
    plan.add_argument("campaign_dir")
    plan.add_argument("--lane", action="append", help="limit to a lane ID; repeatable")
    plan.set_defaults(func=cmd_plan)

    register = sub.add_parser("register", help="register a stable candidate ID")
    register.add_argument("campaign_dir")
    register.add_argument("finding_id", type=validate_finding_id)
    register.add_argument("--title", required=True)
    register.add_argument("--lane", required=True)
    register.add_argument("--status", choices=STATUS_VALUES, default="idea")
    register.set_defaults(func=cmd_register)

    status = sub.add_parser("status", help="show campaign and registry status")
    status.add_argument("campaign_dir")
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    gate = sub.add_parser("gate", help="evaluate candidate or reportable evidence gates")
    gate.add_argument("campaign_dir")
    gate.add_argument("finding_id", type=validate_finding_id)
    gate.add_argument("--level", choices=("candidate", "reportable"), default="candidate")
    gate.add_argument("--json", action="store_true")
    gate.set_defaults(func=cmd_gate)

    hash_cmd = sub.add_parser("hash", help="hash retained findings, evidence, reports, and metadata")
    hash_cmd.add_argument("campaign_dir")
    hash_cmd.set_defaults(func=cmd_hash)

    lint = sub.add_parser("lint", help="scan a campaign for secrets, local paths, floating links, and placeholders")
    lint.add_argument("campaign_dir")
    lint.add_argument("--strict", action="store_true", help="fail on warnings as well as secrets")
    lint.add_argument("--json", action="store_true")
    lint.set_defaults(func=cmd_lint)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
