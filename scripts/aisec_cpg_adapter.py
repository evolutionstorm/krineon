#!/usr/bin/env python3
"""Run Fraunhofer AISEC CPG and normalize its graph as Krineon evidence.

The adapter deliberately does not infer vulnerabilities. It preserves the raw
CPG export and emits a small, stable semantic summary that another Krineon
experiment can bind to a runtime oracle.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


IGNORED_PARTS = {
    ".git", ".next", "build", "dist", "node_modules", "target", "vendor",
    "worktrees", "third_party", ".pyre", ".venv", "venv", "__pycache__",
    "infer-out",
}
SEMANTIC_EDGE_FAMILIES = {
    "dfg": {"DFG", "DATA_FLOW", "DATAFLOW", "REACHES", "REFERS_TO"},
    "eog": {"EOG", "EVALUATION_ORDER", "EXECUTION_ORDER"},
    "cfg": {"CFG", "CONTROL_FLOW", "NEXT"},
    "cdg": {"CDG", "CONTROL_DEPENDENCE", "CONTROL_DEPENDENCY"},
    "call": {"CALL", "CALLS", "INVOKES", "CALLEE", "FUNCTION_POINTER"},
    "ast": {"AST", "LHS", "RHS", "BODY", "ARGUMENTS", "PARAMETERS"},
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_manifest(source: Path) -> dict[str, Any]:
    if source.is_file():
        return {
            "kind": "file",
            "fileCount": 1,
            "sha256": sha256_file(source),
        }
    entries: list[dict[str, str]] = []
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if not path.is_file() or any(part in IGNORED_PARTS for part in relative.parts):
            continue
        entries.append(
            {
                "path": relative.as_posix(),
                "sha256": sha256_file(path),
            }
        )
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(entry["path"].encode("utf-8"))
        digest.update(b"\0")
        digest.update(entry["sha256"].encode("ascii"))
        digest.update(b"\n")
    return {
        "kind": "directory",
        "fileCount": len(entries),
        "manifestSha256": digest.hexdigest(),
    }


def compact(value: Any, limit: int = 500) -> str:
    return " ".join(str(value or "").strip().split())[:limit]


def load_export(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        values = []
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                values.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"AISEC CPG export is neither JSON nor JSONL at line {line_number}: {exc}"
                ) from exc
        return values


def items_for_keys(value: Any, keys: Iterable[str]) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return []
    for key in keys:
        candidate = value.get(key)
        if isinstance(candidate, list):
            return [item for item in candidate if isinstance(item, dict)]
    return []


def classify_record(record: dict[str, Any]) -> str | None:
    marker = str(record.get("type") or record.get("kind") or "").lower()
    if marker in {"node", "vertex"}:
        return "node"
    if marker in {"edge", "relationship", "relation"}:
        return "edge"
    if any(key in record for key in ("@out", "@in", "start", "end", "source", "target")):
        return "edge"
    if any(key in record for key in ("@id", "id", "labels", "properties")):
        return "node"
    return None


def graph_records(value: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    nodes = items_for_keys(value, ("nodes", "vertices", "nodeData"))
    edges = items_for_keys(value, ("edges", "relationships", "relations", "edgeData"))
    if nodes or edges:
        return nodes, edges
    records: list[dict[str, Any]] = []
    if isinstance(value, list):
        records = [item for item in value if isinstance(item, dict)]
    elif isinstance(value, dict):
        for key in ("graph", "data", "elements"):
            nested = value.get(key)
            nested_nodes, nested_edges = graph_records(nested)
            if nested_nodes or nested_edges:
                return nested_nodes, nested_edges
        records = [value]
    for record in records:
        kind = classify_record(record)
        if kind == "node":
            nodes.append(record)
        elif kind == "edge":
            edges.append(record)
    return nodes, edges


def labels(record: dict[str, Any]) -> list[str]:
    raw = record.get("@label", record.get("labels", record.get("label", record.get("type"))))
    if isinstance(raw, list):
        values = raw
    elif raw is None:
        values = []
    else:
        values = [raw]
    return sorted({str(item) for item in values if str(item).strip()})


def properties(record: dict[str, Any]) -> dict[str, Any]:
    raw = record.get("properties")
    if isinstance(raw, dict):
        return raw
    reserved = {
        "@id", "@label", "@out", "@in", "id", "label", "labels", "type",
        "kind", "source", "target", "start", "end",
    }
    return {key: value for key, value in record.items() if key not in reserved}


def edge_family(edge_labels: list[str]) -> str:
    normalized = {value.upper().replace("-", "_") for value in edge_labels}
    for family, candidates in SEMANTIC_EDGE_FAMILIES.items():
        if normalized.intersection(candidates) or any(
            candidate in value for value in normalized for candidate in candidates
        ):
            return family
    return "other"


def deep_graph_facts(value: Any) -> tuple[list[dict[str, Any]], Counter[str]]:
    """Recover nodes and relationship fields from nested OGM JSON exports."""
    nodes: dict[str, dict[str, Any]] = {}
    relationship_labels: Counter[str] = Counter()
    visited: set[int] = set()

    def visit(current: Any) -> None:
        if isinstance(current, (dict, list)):
            identity = id(current)
            if identity in visited:
                return
            visited.add(identity)
        if isinstance(current, list):
            for item in current:
                visit(item)
            return
        if not isinstance(current, dict):
            return
        node_id = current.get("@id", current.get("id"))
        if node_id is not None and classify_record(current) != "edge":
            nodes.setdefault(str(node_id), current)
        for key, nested in current.items():
            family = edge_family([str(key)])
            if family != "other" and nested not in (None, [], {}):
                relationship_labels[str(key)] += len(nested) if isinstance(nested, list) else 1
            visit(nested)

    visit(value)
    return list(nodes.values()), relationship_labels


def normalize_graph(raw: Any, *, language: str, maturity: str) -> dict[str, Any]:
    nodes, edges = graph_records(raw)
    node_labels: Counter[str] = Counter()
    edge_labels: Counter[str] = Counter()
    edge_families: Counter[str] = Counter()
    inferred_nodes = 0
    locations = 0
    unresolved_calls = 0
    nested_relationships: Counter[str] = Counter()
    if not nodes or not edges:
        deep_nodes, nested_relationships = deep_graph_facts(raw)
        if len(deep_nodes) > len(nodes):
            nodes = deep_nodes
    for node in nodes:
        node_labels.update(labels(node))
        props = properties(node)
        if props.get("inferred") is True or props.get("isInferred") is True:
            inferred_nodes += 1
        if any(props.get(key) for key in ("location", "file", "fileName", "codeLocation")):
            locations += 1
        joined = " ".join(labels(node)).lower()
        if "call" in joined and (
            props.get("invokes") is None
            and props.get("callee") is None
            and props.get("resolved") is False
        ):
            unresolved_calls += 1
    for edge in edges:
        current = labels(edge)
        edge_labels.update(current)
        edge_families[edge_family(current)] += 1
    if not edges:
        edge_labels.update(nested_relationships)
        for label, count in nested_relationships.items():
            edge_families[edge_family([label])] += count
    authoritative = maturity == "maintained"
    return {
        "schemaVersion": 1,
        "producer": "krineon-aisec-cpg-adapter",
        "createdAt": utc_now(),
        "frontend": {
            "language": language,
            "maturity": maturity,
            "eligibleAsSourceSupport": authoritative,
            "authoritativeForPromotion": False,
            "claimBoundary": (
                "source-supported-hypothesis-runtime-confirmation-required"
                if authoritative
                else "experimental-or-incubating-hypothesis-only"
            ),
        },
        "inferencePolicy": {
            "unresolvedCallDataFlowMayBeInferredByDefault": True,
            "inferredEdgesAreNotProvedFlows": True,
        },
        "graph": {
            "nodeCount": len(nodes),
            "edgeCount": len(edges) if edges else sum(nested_relationships.values()),
            "nodeLabels": dict(sorted(node_labels.items())),
            "edgeLabels": dict(sorted(edge_labels.items())),
            "semanticEdgeFamilies": dict(sorted(edge_families.items())),
            "nodesWithSourceLocation": locations,
            "inferredNodeCount": inferred_nodes,
            "possiblyUnresolvedCallCount": unresolved_calls,
        },
        "promotion": {
            "createsFinding": False,
            "createsQueueLead": False,
            "requiredNextEvidence": [
                "exact source path with every conditional resolved",
                "bounded runtime discriminator on the shipped or production-equivalent artifact",
                "enforcing negative control",
                "independent coordinator replay",
            ],
        },
    }


def executable_identity(executable: Path) -> dict[str, Any]:
    identity = {"path": str(executable.resolve())}
    if executable.is_file():
        identity["sha256"] = sha256_file(executable)
    return identity


def run_export(args: argparse.Namespace) -> int:
    source = args.source.expanduser().resolve()
    executable = args.executable.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    if not source.exists():
        raise RuntimeError(f"source does not exist: {source}")
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError(f"AISEC CPG executable is not executable: {executable}")
    output_dir.mkdir(parents=True, exist_ok=True)
    raw_path = output_dir / "aisec-cpg-raw.json"
    stdout_path = output_dir / "aisec-cpg.stdout"
    stderr_path = output_dir / "aisec-cpg.stderr"
    capability_stdout_path = output_dir / "aisec-cpg-capability.stdout"
    capability_stderr_path = output_dir / "aisec-cpg-capability.stderr"
    try:
        capability = subprocess.run(
            [str(executable), "--help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=min(args.timeout, 30),
        )
        capability_stdout_path.write_text(capability.stdout, encoding="utf-8")
        capability_stderr_path.write_text(capability.stderr, encoding="utf-8")
        capability_record: dict[str, Any] = {
            "command": [str(executable), "--help"],
            "exitCode": capability.returncode,
            "stdout": capability_stdout_path.name,
            "stderr": capability_stderr_path.name,
            "outputSha256": hashlib.sha256(
                (capability.stdout + capability.stderr).encode("utf-8")
            ).hexdigest(),
            "firstLine": compact(capability.stdout or capability.stderr),
        }
    except subprocess.TimeoutExpired:
        capability_record = {
            "command": [str(executable), "--help"],
            "status": "timed-out",
        }
    command = [
        str(executable), str(source), "--no-neo4j", "--export-json", str(raw_path)
    ]
    started = utc_now()
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=args.timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stdout_path.write_text(
            (exc.stdout or b"").decode("utf-8", "replace")
            if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
            encoding="utf-8",
        )
        stderr_path.write_text(
            (exc.stderr or b"").decode("utf-8", "replace")
            if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
            encoding="utf-8",
        )
        raise RuntimeError(f"AISEC CPG export timed out after {args.timeout}s") from exc
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(
            f"AISEC CPG export failed with exit {completed.returncode}: "
            f"{compact(completed.stderr)}"
        )
    if not raw_path.is_file():
        raise RuntimeError("AISEC CPG completed without creating the requested JSON export")
    raw = load_export(raw_path)
    normalized = normalize_graph(raw, language=args.language, maturity=args.maturity)
    normalized_path = output_dir / "aisec-cpg-semantic.json"
    normalized_path.write_text(json.dumps(normalized, indent=2) + "\n", encoding="utf-8")
    record = {
        "schemaVersion": 1,
        "producer": "krineon-aisec-cpg-adapter",
        "createdAt": utc_now(),
        "startedAt": started,
        "finishedAt": utc_now(),
        "source": str(source),
        "sourceManifest": source_manifest(source),
        "executable": executable_identity(executable),
        "capability": capability_record,
        "command": command,
        "exitCode": completed.returncode,
        "stdout": stdout_path.name,
        "stderr": stderr_path.name,
        "rawExport": {
            "path": raw_path.name,
            "sha256": sha256_file(raw_path),
        },
        "semanticArtifact": {
            "path": normalized_path.name,
            "sha256": sha256_file(normalized_path),
        },
        "frontend": normalized["frontend"],
        "promotion": normalized["promotion"],
    }
    record_path = output_dir / "aisec-cpg-run.json"
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(record_path)
    return 0


def normalize_command(args: argparse.Namespace) -> int:
    raw_path = args.input.expanduser().resolve()
    output = args.output.expanduser().resolve()
    normalized = normalize_graph(
        load_export(raw_path), language=args.language, maturity=args.maturity
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(normalized, indent=2) + "\n", encoding="utf-8")
    print(output)
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="execute cpg-neo4j and retain raw plus normalized evidence")
    run.add_argument("--source", required=True, type=Path)
    run.add_argument("--executable", required=True, type=Path)
    run.add_argument("--output-dir", required=True, type=Path)
    run.add_argument("--language", required=True)
    run.add_argument(
        "--maturity", required=True, choices=("maintained", "incubating", "experimental")
    )
    run.add_argument("--timeout", type=int, default=900)
    run.set_defaults(func=run_export)
    normalize = sub.add_parser("normalize", help="normalize an existing AISEC CPG JSON export")
    normalize.add_argument("--input", required=True, type=Path)
    normalize.add_argument("--output", required=True, type=Path)
    normalize.add_argument("--language", required=True)
    normalize.add_argument(
        "--maturity", required=True, choices=("maintained", "incubating", "experimental")
    )
    normalize.set_defaults(func=normalize_command)
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if getattr(args, "timeout", 1) < 1:
        raise SystemExit("timeout must be positive")
    try:
        return args.func(args)
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
