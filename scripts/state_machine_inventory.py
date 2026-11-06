#!/usr/bin/env python3
"""Validate and merge evidence-bound state-machine inventories."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any


IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$")
MACHINE_KINDS = {
    "explicit",
    "implicit",
    "protocol",
    "lifecycle",
    "retry",
    "concurrency",
    "authorization",
    "cache",
    "parser",
    "ownership",
    "cancellation",
    "job",
    "storage",
    "transport",
    "transaction",
    "cryptographic",
    "compiler",
    "memory-lifetime",
    "capability",
    "workflow",
    "session",
    "resource",
    "upload",
    "scheduler",
    "replication",
    "consensus",
    "database",
    "network",
    "io",
}
EVIDENCE_KINDS = {
    "source",
    "runtime",
    "test",
    "assertion",
    "trace",
    "replay",
    "documentation",
    "specification",
    "protocol-capture",
    "browser",
    "debugger",
    "sanitizer",
    "fuzzer",
    "binary",
}
CONFIDENCE = {"hypothesized", "source-supported", "runtime-observed", "independently-replayed"}
INVALID_STATUS = {"source-reachable", "runtime-reproduced", "independently-replayed", "refuted"}
SOURCE_SUFFIXES = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "c-header",
    ".hh": "cpp-header",
    ".hpp": "cpp-header",
    ".m": "objective-c",
    ".mm": "objective-cpp",
    ".rs": "rust",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".fs": "fsharp",
    ".fsx": "fsharp",
    ".swift": "swift",
    ".lua": "lua",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hrl": "erlang",
    ".dart": "dart",
    ".zig": "zig",
    ".sol": "solidity",
    ".vy": "vyper",
    ".proto": "protobuf",
    ".capnp": "capnproto",
    ".thrift": "thrift",
}
DEFAULT_EXCLUDED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".next",
    ".venv",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "out",
    "target",
    "coverage",
    "__pycache__",
}
STATE_SYMBOL = re.compile(
    r"(?i)(?:^|[^A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*(?:state|status|phase|mode|stage|lifecycle|generation|epoch)[A-Za-z0-9_]*)"
)
ENUM_DECLARATION = re.compile(
    r"(?i)\b(?:enum(?:\s+class)?|sealed\s+class|type)\s+([A-Za-z_][A-Za-z0-9_]*(?:state|status|phase|mode|stage|lifecycle)[A-Za-z0-9_]*)"
)
ASSIGNMENT = re.compile(
    r"(?i)\b([A-Za-z_][A-Za-z0-9_.]*(?:state|status|phase|mode|stage|generation|epoch)[A-Za-z0-9_.]*)\s*(?:=|:=|<-)\s*([A-Za-z_][A-Za-z0-9_.:-]*|['\"][^'\"]{1,80}['\"]|[0-9]{1,12})"
)
COMPARISON = re.compile(
    r"(?i)\b([A-Za-z_][A-Za-z0-9_.]*(?:state|status|phase|mode|stage|generation|epoch)[A-Za-z0-9_.]*)\s*(?:===?|!==?|<=?|>=?)\s*([A-Za-z_][A-Za-z0-9_.:-]*|['\"][^'\"]{1,80}['\"]|[0-9]{1,12})"
)
ASSERTION = re.compile(r"(?i)\b(assert|check|ensure|require|invariant|unreachable|panic|fatal)\b")
TRANSITION_CALL = re.compile(
    r"(?i)\b(setState|setStatus|transitionTo|changeState|mark[A-Z][A-Za-z0-9_]*|enter[A-Z][A-Za-z0-9_]*|leave[A-Z][A-Za-z0-9_]*)\s*\("
)
IMPLICIT_FAMILIES: dict[str, tuple[re.Pattern[str], ...]] = {
    "lifecycle": tuple(
        re.compile(pattern, re.I)
        for pattern in (
            r"\b(init|initialize|start|open|connect|mount|attach)\b",
            r"\b(close|stop|shutdown|dispose|destroy|finalize|unmount|detach)\b",
        )
    ),
    "memory-lifetime": tuple(
        re.compile(pattern, re.I)
        for pattern in (
            r"\b(alloc|allocate|new|retain|borrow|pin|root|trace|visit)\b",
            r"\b(free|release|delete|drop|unroot|detach|resize|move)\b",
        )
    ),
    "retry": tuple(
        re.compile(pattern, re.I)
        for pattern in (r"(retry|reconnect|backoff|attempt)", r"(timeout|deadline|timer)")
    ),
    "concurrency": tuple(
        re.compile(pattern, re.I)
        for pattern in (
            r"(lock|mutex|semaphore|atomic|compare_exchange|cas|synchronized)",
            r"(thread|task|worker|channel|queue|race|concurrent|parallel)",
        )
    ),
    "cache": tuple(
        re.compile(pattern, re.I)
        for pattern in (r"\b(cache|memo|cached)\b", r"\b(invalidate|evict|revalidate|expire|stale)\b")
    ),
    "parser": tuple(
        re.compile(pattern, re.I)
        for pattern in (r"\b(parse|decode|deserialize|tokenize|lexer)\b", r"\b(frame|length|offset|cursor|boundary)\b")
    ),
    "protocol": tuple(
        re.compile(pattern, re.I)
        for pattern in (r"\b(handshake|frame|message|request|response|stream)\b", r"\b(send|receive|read|write|flush)\b")
    ),
    "authorization": tuple(
        re.compile(pattern, re.I)
        for pattern in (r"\b(auth|authorize|permission|privilege|role|principal)\b", r"\b(session|token|credential|identity|tenant)\b")
    ),
    "cancellation": tuple(
        re.compile(pattern, re.I)
        for pattern in (r"\b(cancel|abort|terminate|interrupt)\b", r"\b(signal|cleanup|rollback|compensate)\b")
    ),
    "job": tuple(
        re.compile(pattern, re.I)
        for pattern in (r"\b(job|task|work item|background|scheduler)\b", r"\b(enqueue|dequeue|complete|ack|nack)\b")
    ),
    "transaction": tuple(
        re.compile(pattern, re.I)
        for pattern in (r"\b(transaction|commit|rollback|prepare)\b", r"\b(version|revision|generation|compare.and.swap)\b")
    ),
    "capability": tuple(
        re.compile(pattern, re.I)
        for pattern in (r"\b(capability|handle|descriptor|grant|revoke)\b", r"\b(sandbox|isolate|realm|context|boundary)\b")
    ),
}


class InventoryError(ValueError):
    """The inventory is incomplete, contradictory, or malformed."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def require_dict(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InventoryError(f"{field} must be an object")
    return value


def require_list(value: Any, field: str, *, populated: bool = False) -> list[Any]:
    if not isinstance(value, list) or (populated and not value):
        suffix = " and must not be empty" if populated else ""
        raise InventoryError(f"{field} must be an array{suffix}")
    return value


def require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InventoryError(f"{field} must be a non-empty string")
    return value.strip()


def require_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise InventoryError(f"{field} must be a boolean")
    return value


def require_id(value: Any, field: str) -> str:
    result = require_text(value, field)
    if not IDENTIFIER.fullmatch(result):
        raise InventoryError(f"{field} must be a stable identifier")
    return result


def unique_ids(values: list[Any], field: str) -> None:
    seen: set[str] = set()
    for index, value in enumerate(values):
        identifier = require_id(require_dict(value, f"{field}[{index}]").get("id"), f"{field}[{index}].id")
        if identifier in seen:
            raise InventoryError(f"{field} contains duplicate id {identifier}")
        seen.add(identifier)


def _source_reference(relative: str, line_number: int) -> str:
    return f"{relative}:{line_number}"


def _source_observation(line: str) -> str:
    compact = " ".join(line.strip().split())
    return compact[:400] if compact else "source signal"


def _state_token(value: str) -> str:
    return value.strip().strip("'\"").rstrip(",;)")[:128]


def _candidate_id(relative: str, identity: str) -> str:
    digest = hashlib.sha256(f"{relative}\0{identity}".encode("utf-8")).hexdigest()
    return f"candidate-{digest[:16]}"


def _new_candidate(
    relative: str,
    language: str,
    identity: str,
    kind: str,
    symbol: str | None,
) -> dict[str, Any]:
    return {
        "id": _candidate_id(relative, identity),
        "candidateKind": kind,
        "component": relative,
        "language": language,
        "symbol": symbol,
        "observedStateTokens": [],
        "transitionSignals": [],
        "guardSignals": [],
        "invariantSignals": [],
        "implicitSignals": [],
        "evidence": [],
        "promotionState": "source-signal-only",
        "promotionRequirements": [
            "resolve function-scoped def-use and aliases",
            "identify target-owned invariants and dominating guards",
            "prove concrete from-state, to-state, trigger, and effects",
            "run the cheapest distinguishing experiment for unresolved behavior",
        ],
    }


def _append_unique(rows: list[Any], value: Any, *, limit: int = 64) -> None:
    if value not in rows and len(rows) < limit:
        rows.append(value)


def _iter_source_files(
    source_root: Path,
    excluded: set[str],
    max_files: int,
) -> tuple[list[Path], int]:
    files: list[Path] = []
    skipped = 0
    for directory, directories, names in os.walk(source_root):
        directories[:] = sorted(
            name
            for name in directories
            if name not in excluded and not Path(directory, name).is_symlink()
        )
        for name in sorted(names):
            path = Path(directory, name)
            if path.is_symlink() or path.suffix.lower() not in SOURCE_SUFFIXES:
                continue
            if len(files) >= max_files:
                skipped += 1
                continue
            files.append(path)
    return files, skipped


def discover_state_machines(
    source_root: Path,
    *,
    revision: str,
    excluded_directories: set[str] | None = None,
    max_files: int = 5000,
    max_file_bytes: int = 1024 * 1024,
    max_candidates: int = 1200,
) -> dict[str, Any]:
    """Extract universal source signals without promoting them to vulnerability facts."""
    root = source_root.expanduser().resolve()
    if root.is_symlink() or not root.is_dir():
        raise InventoryError("state-machine source root must be a directory")
    if max_files < 1 or max_file_bytes < 1024 or max_candidates < 1:
        raise InventoryError("state-machine discovery limits must be positive")
    excluded = set(DEFAULT_EXCLUDED_DIRECTORIES)
    excluded.update(excluded_directories or set())
    files, limit_skips = _iter_source_files(root, excluded, max_files)
    candidates: dict[tuple[str, str], dict[str, Any]] = {}
    languages: dict[str, int] = {}
    skipped: list[dict[str, str]] = []
    bytes_scanned = 0

    def candidate_for(
        relative: str,
        language: str,
        identity: str,
        kind: str,
        symbol: str | None,
    ) -> dict[str, Any]:
        key = (relative, identity)
        if key not in candidates:
            candidates[key] = _new_candidate(relative, language, identity, kind, symbol)
        return candidates[key]

    for path in files:
        relative = path.relative_to(root).as_posix()
        try:
            size = path.stat().st_size
        except OSError as exc:
            skipped.append({"path": relative, "reason": f"stat failed: {exc}"})
            continue
        if size > max_file_bytes:
            skipped.append({"path": relative, "reason": "file exceeds byte limit"})
            continue
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            skipped.append({"path": relative, "reason": f"unreadable text: {exc}"})
            continue
        if "\x00" in text:
            skipped.append({"path": relative, "reason": "binary content"})
            continue
        lines = text.splitlines()
        if lines and len(text) / len(lines) > 2000:
            skipped.append({"path": relative, "reason": "likely generated or minified"})
            continue
        language = SOURCE_SUFFIXES[path.suffix.lower()]
        languages[language] = languages.get(language, 0) + 1
        bytes_scanned += len(raw)
        digest = hashlib.sha256(raw).hexdigest()
        family_hits: dict[str, dict[int, list[tuple[int, str]]]] = {
            family: {} for family in IMPLICIT_FAMILIES
        }

        for line_index, line in enumerate(lines, start=1):
            if not line.strip() or len(line) > 4000:
                continue
            reference = _source_reference(relative, line_index)
            observation = _source_observation(line)
            base_evidence = {
                "kind": "source",
                "reference": reference,
                "observation": observation,
                "fileSha256": digest,
            }

            declaration = ENUM_DECLARATION.search(line)
            if declaration:
                symbol = declaration.group(1)
                row = candidate_for(relative, language, f"symbol:{symbol}", "explicit", symbol)
                _append_unique(row["evidence"], base_evidence)
                block = "\n".join(lines[line_index - 1 : min(len(lines), line_index + 30)])
                if "{" in block:
                    block = block.split("{", 1)[1].split("}", 1)[0]
                for token in re.findall(r"['\"]([^'\"]{1,80})['\"]|\b([A-Z][A-Za-z0-9_]{1,80})\b", block):
                    selected = token[0] or token[1]
                    if selected and selected != symbol:
                        _append_unique(row["observedStateTokens"], selected)

            for assignment in ASSIGNMENT.finditer(line):
                symbol, raw_value = assignment.groups()
                value = _state_token(raw_value)
                row = candidate_for(relative, language, f"symbol:{symbol}", "explicit", symbol)
                _append_unique(row["observedStateTokens"], value)
                _append_unique(
                    row["transitionSignals"],
                    {
                        "reference": reference,
                        "operation": "assignment",
                        "toCandidate": value,
                        "observation": observation,
                    },
                )
                _append_unique(row["evidence"], base_evidence)

            for comparison in COMPARISON.finditer(line):
                symbol, raw_value = comparison.groups()
                value = _state_token(raw_value)
                row = candidate_for(relative, language, f"symbol:{symbol}", "explicit", symbol)
                _append_unique(row["observedStateTokens"], value)
                _append_unique(
                    row["guardSignals"],
                    {
                        "reference": reference,
                        "comparedWith": value,
                        "observation": observation,
                    },
                )
                _append_unique(row["evidence"], base_evidence)

            transition_call = TRANSITION_CALL.search(line)
            if transition_call:
                symbol = transition_call.group(1)
                row = candidate_for(
                    relative, language, f"transition-api:{symbol}", "explicit", symbol
                )
                _append_unique(
                    row["transitionSignals"],
                    {
                        "reference": reference,
                        "operation": "transition-call",
                        "toCandidate": "unresolved",
                        "observation": observation,
                    },
                )
                _append_unique(row["evidence"], base_evidence)

            if ASSERTION.search(line) and STATE_SYMBOL.search(line):
                symbol_match = STATE_SYMBOL.search(line)
                assert symbol_match is not None
                symbol = symbol_match.group(1)
                row = candidate_for(relative, language, f"symbol:{symbol}", "explicit", symbol)
                _append_unique(
                    row["invariantSignals"],
                    {"reference": reference, "observation": observation},
                )
                _append_unique(row["evidence"], base_evidence)

            for family, patterns in IMPLICIT_FAMILIES.items():
                for pattern_index, pattern in enumerate(patterns):
                    if pattern.search(line):
                        family_hits[family].setdefault(pattern_index, []).append(
                            (line_index, observation)
                        )

        for family, pattern_hits in family_hits.items():
            if len(pattern_hits) < len(IMPLICIT_FAMILIES[family]):
                continue
            row = candidate_for(relative, language, f"implicit:{family}", family, None)
            for pattern_index in sorted(pattern_hits):
                for line_index, observation in pattern_hits[pattern_index][:4]:
                    signal = {
                        "reference": _source_reference(relative, line_index),
                        "family": family,
                        "observation": observation,
                    }
                    _append_unique(row["implicitSignals"], signal)
                    _append_unique(
                        row["evidence"],
                        {
                            "kind": "source",
                            "reference": signal["reference"],
                            "observation": observation,
                            "fileSha256": digest,
                        },
                    )

    ranked = sorted(
        candidates.values(),
        key=lambda row: (
            -(
                len(row["observedStateTokens"]) * 3
                + len(row["transitionSignals"]) * 3
                + len(row["guardSignals"]) * 2
                + len(row["invariantSignals"]) * 4
                + len(row["implicitSignals"])
            ),
            row["component"],
            row["id"],
        ),
    )
    retained = ranked[:max_candidates]
    return {
        "schemaVersion": 1,
        "extractor": "krineon-universal-state-machine-source-v1",
        "generatedAt": utc_now(),
        "sourceRoot": str(root),
        "revision": revision,
        "mode": "candidate-only",
        "filesScanned": sum(languages.values()),
        "bytesScanned": bytes_scanned,
        "filesSkippedByLimit": limit_skips,
        "languages": dict(sorted(languages.items())),
        "excludedDirectories": sorted(excluded),
        "skippedFiles": skipped[:500],
        "candidateCountBeforeLimit": len(ranked),
        "candidates": retained,
        "limitations": [
            "lexical source signals do not establish function-scoped data flow or reachability",
            "state tokens do not prove a transition between two concrete states",
            "implicit family co-occurrence is a prioritization hint, not an invariant failure",
            "generated, oversized, binary, excluded, and unsupported-language files require separate review",
            "runtime-only state, retries, and interleavings require controlled experiments",
        ],
    }


def empty_discovery(revision: str) -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "extractor": "krineon-universal-state-machine-source-v1",
        "generatedAt": "",
        "sourceRoot": "",
        "revision": revision,
        "mode": "pending",
        "filesScanned": 0,
        "bytesScanned": 0,
        "filesSkippedByLimit": 0,
        "languages": {},
        "excludedDirectories": sorted(DEFAULT_EXCLUDED_DIRECTORIES),
        "skippedFiles": [],
        "candidateCountBeforeLimit": 0,
        "candidates": [],
        "limitations": [],
    }


def validate_discovery(value: Any, revision: str) -> dict[str, Any]:
    if value is None:
        return empty_discovery(revision)
    row = require_dict(value, "inventory.discovery")
    if row.get("schemaVersion") != 1:
        raise InventoryError("inventory.discovery requires schemaVersion 1")
    if row.get("revision") != revision:
        raise InventoryError("inventory.discovery revision does not match inventory revision")
    mode = require_text(row.get("mode"), "inventory.discovery.mode")
    if mode not in {"pending", "candidate-only"}:
        raise InventoryError("inventory.discovery.mode is unsupported")
    candidates = require_list(row.get("candidates", []), "inventory.discovery.candidates")
    seen: set[str] = set()
    for index, candidate_raw in enumerate(candidates):
        candidate = require_dict(candidate_raw, f"inventory.discovery.candidates[{index}]")
        identifier = require_id(candidate.get("id"), f"inventory.discovery.candidates[{index}].id")
        if identifier in seen:
            raise InventoryError("inventory.discovery contains duplicate candidate ids")
        seen.add(identifier)
        if candidate.get("promotionState") != "source-signal-only":
            raise InventoryError("discovery candidates cannot be promoted by the extractor")
        require_text(candidate.get("component"), f"inventory.discovery.candidates[{index}].component")
        require_list(
            candidate.get("promotionRequirements"),
            f"inventory.discovery.candidates[{index}].promotionRequirements",
            populated=True,
        )
    return row


def evidence(values: Any, field: str, *, required: bool = True) -> list[dict[str, Any]]:
    rows = require_list(values, field, populated=required)
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(rows):
        row = require_dict(raw, f"{field}[{index}]")
        kind = require_text(row.get("kind"), f"{field}[{index}].kind")
        if kind not in EVIDENCE_KINDS:
            raise InventoryError(f"{field}[{index}].kind is unsupported")
        reference = require_text(row.get("reference"), f"{field}[{index}].reference")
        observation = require_text(row.get("observation"), f"{field}[{index}].observation")
        normalized.append({"kind": kind, "reference": reference, "observation": observation})
    return normalized


def validate_state(raw: Any, field: str) -> dict[str, Any]:
    row = require_dict(raw, field)
    confidence = require_text(row.get("confidence"), f"{field}.confidence")
    if confidence not in CONFIDENCE:
        raise InventoryError(f"{field}.confidence is unsupported")
    return {
        "id": require_id(row.get("id"), f"{field}.id"),
        "description": require_text(row.get("description"), f"{field}.description"),
        "entryConditions": [require_text(value, f"{field}.entryConditions[]") for value in require_list(row.get("entryConditions"), f"{field}.entryConditions")],
        "exitConditions": [require_text(value, f"{field}.exitConditions[]") for value in require_list(row.get("exitConditions"), f"{field}.exitConditions")],
        "confidence": confidence,
        "evidence": evidence(row.get("evidence"), f"{field}.evidence"),
    }


def validate_invariant(raw: Any, field: str, state_ids: set[str]) -> dict[str, Any]:
    row = require_dict(raw, field)
    states = [require_id(value, f"{field}.appliesInStates[]") for value in require_list(row.get("appliesInStates"), f"{field}.appliesInStates", populated=True)]
    unknown = set(states).difference(state_ids)
    if unknown:
        raise InventoryError(f"{field} references unknown states: {', '.join(sorted(unknown))}")
    return {
        "id": require_id(row.get("id"), f"{field}.id"),
        "statement": require_text(row.get("statement"), f"{field}.statement"),
        "appliesInStates": states,
        "basis": require_text(row.get("basis"), f"{field}.basis"),
        "evidence": evidence(row.get("evidence"), f"{field}.evidence"),
    }


def validate_transition(raw: Any, field: str, state_ids: set[str]) -> dict[str, Any]:
    row = require_dict(raw, field)
    origins = [require_id(value, f"{field}.from[]") for value in require_list(row.get("from"), f"{field}.from", populated=True)]
    destination = require_id(row.get("to"), f"{field}.to")
    unknown = set(origins + [destination]).difference(state_ids)
    if unknown:
        raise InventoryError(f"{field} references unknown states: {', '.join(sorted(unknown))}")
    guards = require_list(row.get("guards"), f"{field}.guards")
    normalized_guards = []
    for index, guard_raw in enumerate(guards):
        guard = require_dict(guard_raw, f"{field}.guards[{index}]")
        normalized_guards.append(
            {
                "condition": require_text(guard.get("condition"), f"{field}.guards[{index}].condition"),
                "requiredOutcome": require_text(guard.get("requiredOutcome"), f"{field}.guards[{index}].requiredOutcome"),
                "attackerInfluence": require_text(guard.get("attackerInfluence"), f"{field}.guards[{index}].attackerInfluence"),
            }
        )
    retry = require_dict(row.get("retry"), f"{field}.retry")
    concurrency = require_dict(row.get("concurrency"), f"{field}.concurrency")
    confidence = require_text(row.get("confidence"), f"{field}.confidence")
    if confidence not in CONFIDENCE:
        raise InventoryError(f"{field}.confidence is unsupported")
    return {
        "id": require_id(row.get("id"), f"{field}.id"),
        "from": origins,
        "to": destination,
        "trigger": require_text(row.get("trigger"), f"{field}.trigger"),
        "actor": require_text(row.get("actor"), f"{field}.actor"),
        "guards": normalized_guards,
        "effects": [require_text(value, f"{field}.effects[]") for value in require_list(row.get("effects"), f"{field}.effects", populated=True)],
        "retry": {
            "possible": require_bool(retry.get("possible"), f"{field}.retry.possible"),
            "policy": require_text(retry.get("policy"), f"{field}.retry.policy"),
            "identityOrIdempotencyBinding": require_text(retry.get("identityOrIdempotencyBinding"), f"{field}.retry.identityOrIdempotencyBinding"),
            "stateAfterFailure": require_text(retry.get("stateAfterFailure"), f"{field}.retry.stateAfterFailure"),
        },
        "concurrency": {
            "possible": require_bool(
                concurrency.get("possible"), f"{field}.concurrency.possible"
            ),
            "interleavings": [require_text(value, f"{field}.concurrency.interleavings[]") for value in require_list(concurrency.get("interleavings"), f"{field}.concurrency.interleavings")],
            "serializationOrLocking": require_text(concurrency.get("serializationOrLocking"), f"{field}.concurrency.serializationOrLocking"),
            "sharedState": [require_text(value, f"{field}.concurrency.sharedState[]") for value in require_list(concurrency.get("sharedState"), f"{field}.concurrency.sharedState")],
        },
        "confidence": confidence,
        "evidence": evidence(row.get("evidence"), f"{field}.evidence"),
    }


def validate_invalid(raw: Any, field: str, state_ids: set[str], transition_ids: set[str], invariant_ids: set[str]) -> dict[str, Any]:
    row = require_dict(raw, field)
    kind = require_text(row.get("kind"), f"{field}.kind")
    if kind not in {"invalid-state", "invalid-transition"}:
        raise InventoryError(f"{field}.kind is unsupported")
    state = str(row.get("state") or "").strip()
    transition = str(row.get("transition") or "").strip()
    if kind == "invalid-state" and state not in state_ids:
        raise InventoryError(f"{field}.state must identify a declared state")
    if kind == "invalid-transition" and transition not in transition_ids:
        raise InventoryError(f"{field}.transition must identify a declared transition")
    violated = [require_id(value, f"{field}.violatedInvariants[]") for value in require_list(row.get("violatedInvariants"), f"{field}.violatedInvariants", populated=True)]
    if set(violated).difference(invariant_ids):
        raise InventoryError(f"{field} references an unknown invariant")
    status = require_text(row.get("status"), f"{field}.status")
    if status not in INVALID_STATUS:
        raise InventoryError(f"{field}.status is unsupported")
    retained_evidence = evidence(row.get("evidence"), f"{field}.evidence")
    controls = evidence(row.get("controls"), f"{field}.controls", required=status != "source-reachable")
    return {
        "id": require_id(row.get("id"), f"{field}.id"),
        "kind": kind,
        "state": state,
        "transition": transition,
        "violatedInvariants": violated,
        "actualPath": [require_text(value, f"{field}.actualPath[]") for value in require_list(row.get("actualPath"), f"{field}.actualPath", populated=True)],
        "attackerControl": require_text(row.get("attackerControl"), f"{field}.attackerControl"),
        "requiredHistory": [require_text(value, f"{field}.requiredHistory[]") for value in require_list(row.get("requiredHistory"), f"{field}.requiredHistory")],
        "retrySchedule": [require_text(value, f"{field}.retrySchedule[]") for value in require_list(row.get("retrySchedule"), f"{field}.retrySchedule")],
        "concurrencySchedule": [require_text(value, f"{field}.concurrencySchedule[]") for value in require_list(row.get("concurrencySchedule"), f"{field}.concurrencySchedule")],
        "status": status,
        "evidence": retained_evidence,
        "controls": controls,
    }


def validate_machine(raw: Any, field: str) -> dict[str, Any]:
    row = require_dict(raw, field)
    kind = require_text(row.get("kind"), f"{field}.kind")
    if not IDENTIFIER.fullmatch(kind):
        raise InventoryError(f"{field}.kind must be a stable machine-kind identifier")
    states_raw = require_list(row.get("states"), f"{field}.states", populated=True)
    unique_ids(states_raw, f"{field}.states")
    states = [validate_state(value, f"{field}.states[{index}]") for index, value in enumerate(states_raw)]
    state_ids = {value["id"] for value in states}
    invariants_raw = require_list(row.get("invariants"), f"{field}.invariants", populated=True)
    unique_ids(invariants_raw, f"{field}.invariants")
    invariants = [validate_invariant(value, f"{field}.invariants[{index}]", state_ids) for index, value in enumerate(invariants_raw)]
    invariant_ids = {value["id"] for value in invariants}
    transitions_raw = require_list(row.get("transitions"), f"{field}.transitions", populated=True)
    unique_ids(transitions_raw, f"{field}.transitions")
    transitions = [validate_transition(value, f"{field}.transitions[{index}]", state_ids) for index, value in enumerate(transitions_raw)]
    transition_ids = {value["id"] for value in transitions}
    invalid_raw = require_list(row.get("reachableInvalid"), f"{field}.reachableInvalid")
    unique_ids(invalid_raw, f"{field}.reachableInvalid")
    invalid = [validate_invalid(value, f"{field}.reachableInvalid[{index}]", state_ids, transition_ids, invariant_ids) for index, value in enumerate(invalid_raw)]
    return {
        "id": require_id(row.get("id"), f"{field}.id"),
        "name": require_text(row.get("name"), f"{field}.name"),
        "kind": kind,
        "scope": require_text(row.get("scope"), f"{field}.scope"),
        "initialStates": [require_id(value, f"{field}.initialStates[]") for value in require_list(row.get("initialStates"), f"{field}.initialStates", populated=True)],
        "states": states,
        "invariants": invariants,
        "transitions": transitions,
        "reachableInvalid": invalid,
        "unknowns": [require_text(value, f"{field}.unknowns[]") for value in require_list(row.get("unknowns"), f"{field}.unknowns")],
        "evidence": evidence(row.get("evidence"), f"{field}.evidence"),
    }


def recalculate(root: dict[str, Any]) -> None:
    machines = root["machines"]
    discovery = root.get("discovery") or empty_discovery(root["revision"])
    root["coverage"] = {
        "explicitMachinesReviewed": sum(machine["kind"] == "explicit" for machine in machines),
        "implicitMachinesReviewed": sum(machine["kind"] != "explicit" for machine in machines),
        "retryTransitionsReviewed": sum(transition["retry"]["possible"] for machine in machines for transition in machine["transitions"]),
        "concurrentTransitionsReviewed": sum(transition["concurrency"]["possible"] for machine in machines for transition in machine["transitions"]),
        "reachableInvalidStates": sum(item["status"] != "refuted" for machine in machines for item in machine["reachableInvalid"]),
        "unresolvedMachines": [machine["id"] for machine in machines if machine["unknowns"]],
        "sourceFilesScanned": int(discovery.get("filesScanned", 0)),
        "sourceLanguagesObserved": sorted((discovery.get("languages") or {}).keys()),
        "unpromotedSourceCandidates": len(discovery.get("candidates") or []),
    }
    root["status"] = "populated" if machines else "uninitialized"


def validate_inventory(raw: Any, *, allow_empty: bool = True) -> dict[str, Any]:
    root = require_dict(raw, "inventory")
    if root.get("schemaVersion") != 1:
        raise InventoryError("inventory requires schemaVersion 1")
    machines_raw = require_list(root.get("machines"), "inventory.machines", populated=not allow_empty)
    unique_ids(machines_raw, "inventory.machines")
    machines = [validate_machine(value, f"inventory.machines[{index}]") for index, value in enumerate(machines_raw)]
    normalized = {
        "schemaVersion": 1,
        "target": require_text(root.get("target"), "inventory.target"),
        "revision": require_text(root.get("revision"), "inventory.revision"),
        "createdAt": require_text(root.get("createdAt"), "inventory.createdAt"),
        "updatedAt": require_text(root.get("updatedAt"), "inventory.updatedAt"),
        "status": str(root.get("status") or "uninitialized"),
        "discovery": validate_discovery(root.get("discovery"), require_text(root.get("revision"), "inventory.revision")),
        "machines": machines,
        "coverage": {},
    }
    for machine in machines:
        unknown_initial = set(machine["initialStates"]).difference(state["id"] for state in machine["states"])
        if unknown_initial:
            raise InventoryError(f"machine {machine['id']} has unknown initial states")
    recalculate(normalized)
    return normalized


def read_json(path: Path) -> dict[str, Any]:
    return require_dict(json.loads(path.read_text(encoding="utf-8")), str(path))


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def merge_rows(current: list[dict[str, Any]], incoming: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    result = list(current)
    by_id = {row["id"]: row for row in result}
    for row in incoming:
        prior = by_id.get(row["id"])
        if prior is not None and prior != row:
            raise InventoryError(f"conflicting {field} id {row['id']}; submit a new versioned id")
        if prior is None:
            result.append(row)
            by_id[row["id"]] = row
    return result


def merge_machine(current: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    for field in ("name", "kind", "scope", "initialStates"):
        if current[field] != incoming[field]:
            raise InventoryError(f"conflicting machine {current['id']} field {field}")
    merged = dict(current)
    for field in ("states", "invariants", "transitions", "reachableInvalid"):
        merged[field] = merge_rows(current[field], incoming[field], f"{current['id']}.{field}")
    merged["unknowns"] = list(dict.fromkeys(current["unknowns"] + incoming["unknowns"]))
    merged["evidence"] = current["evidence"] + [item for item in incoming["evidence"] if item not in current["evidence"]]
    return merged


def merge_inventory(inventory_path: Path, proposal_path: Path) -> dict[str, Any]:
    lock_path = inventory_path.with_suffix(inventory_path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        current = validate_inventory(read_json(inventory_path))
        proposal = validate_inventory(read_json(proposal_path), allow_empty=False)
        if (current["target"], current["revision"]) != (proposal["target"], proposal["revision"]):
            raise InventoryError("proposal target or revision does not match the campaign inventory")
        by_id = {machine["id"]: machine for machine in current["machines"]}
        for machine in proposal["machines"]:
            if machine["id"] in by_id:
                merged = merge_machine(by_id[machine["id"]], machine)
                current["machines"][current["machines"].index(by_id[machine["id"]])] = merged
                by_id[machine["id"]] = merged
            else:
                current["machines"].append(machine)
                by_id[machine["id"]] = machine
        current["updatedAt"] = utc_now()
        recalculate(current)
        atomic_json(inventory_path, current)
        return current


def extract_inventory(
    inventory_path: Path,
    source_root: Path,
    *,
    excluded_directories: set[str] | None = None,
    max_files: int = 5000,
    max_file_bytes: int = 1024 * 1024,
    max_candidates: int = 1200,
) -> dict[str, Any]:
    lock_path = inventory_path.with_suffix(inventory_path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        current = validate_inventory(read_json(inventory_path))
        current["discovery"] = discover_state_machines(
            source_root,
            revision=current["revision"],
            excluded_directories=excluded_directories,
            max_files=max_files,
            max_file_bytes=max_file_bytes,
            max_candidates=max_candidates,
        )
        current["updatedAt"] = utc_now()
        recalculate(current)
        atomic_json(inventory_path, current)
        return current


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    initialize = sub.add_parser("init")
    initialize.add_argument("inventory", type=Path)
    initialize.add_argument("--target", required=True)
    initialize.add_argument("--revision", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("inventory", type=Path)
    validate.add_argument("--require-populated", action="store_true")
    merge = sub.add_parser("merge")
    merge.add_argument("inventory", type=Path)
    merge.add_argument("proposal", type=Path)
    extract = sub.add_parser(
        "extract",
        help="seed the inventory with universal, unpromoted source candidates",
    )
    extract.add_argument("inventory", type=Path)
    extract.add_argument("source_root", type=Path)
    extract.add_argument("--exclude-directory", action="append", default=[])
    extract.add_argument("--max-files", type=int, default=5000)
    extract.add_argument("--max-file-bytes", type=int, default=1024 * 1024)
    extract.add_argument("--max-candidates", type=int, default=1200)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "init":
            if args.inventory.exists():
                raise InventoryError("refusing to replace an existing inventory")
            now = utc_now()
            result = {
                "schemaVersion": 1,
                "target": args.target,
                "revision": args.revision,
                "createdAt": now,
                "updatedAt": now,
                "status": "uninitialized",
                "discovery": empty_discovery(args.revision),
                "machines": [],
                "coverage": {
                    "explicitMachinesReviewed": 0,
                    "implicitMachinesReviewed": 0,
                    "retryTransitionsReviewed": 0,
                    "concurrentTransitionsReviewed": 0,
                    "reachableInvalidStates": 0,
                    "unresolvedMachines": [],
                    "sourceFilesScanned": 0,
                    "sourceLanguagesObserved": [],
                    "unpromotedSourceCandidates": 0,
                },
            }
            atomic_json(args.inventory, result)
        elif args.command == "validate":
            result = validate_inventory(read_json(args.inventory), allow_empty=not args.require_populated)
        elif args.command == "extract":
            result = extract_inventory(
                args.inventory,
                args.source_root,
                excluded_directories=set(args.exclude_directory),
                max_files=args.max_files,
                max_file_bytes=args.max_file_bytes,
                max_candidates=args.max_candidates,
            )
        else:
            result = merge_inventory(args.inventory, args.proposal)
        print(json.dumps(result, indent=2, sort_keys=False))
        return 0
    except (OSError, json.JSONDecodeError, InventoryError) as error:
        print(f"state-machine inventory error: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
