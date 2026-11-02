#!/usr/bin/env python3
"""Canonical architecture, evidence, and decision plane for Krineon.

The intelligence plane connects source inventory, architecture facts, staged
research, immutable observations, production criticism, role-isolated context,
source citations, hypothesis accounting, and authenticated-session semantics.
It does not execute targets or decide that a vulnerability exists. Runtime
claims still require Krineon's coordinator-controlled execution plane.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable


DATABASE_RELATIVE = Path("knowledge") / "campaign-intelligence.db"
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
SOURCE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
    ".m", ".mm", ".rs", ".go", ".java", ".kt", ".kts", ".swift",
    ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts",
    ".py", ".rb", ".php", ".cs", ".fs", ".fsx", ".scala", ".sol",
    ".vy", ".wasm", ".wat", ".proto", ".graphql", ".gql",
}
IGNORED_DIRECTORY_NAMES = {
    ".git", ".hg", ".svn", ".next", ".turbo", ".cache", "coverage",
    "dist", "build", "target", "out", "node_modules", "__pycache__",
}
NON_PRODUCTION_PARTS = {
    "test", "tests", "testing", "spec", "specs", "fixtures", "fixture",
    "examples", "example", "bench", "benchmark", "benchmarks", "docs", "doc",
}
GENERATED_PARTS = {"generated", "gen", "dist", "build", "compiled"}
VENDORED_PARTS = {"vendor", "vendored", "third_party", "third-party", "deps"}

ARCHITECTURE_KINDS = {
    "component", "identity", "resource", "trust-boundary", "dependency",
    "entrypoint", "consumer", "state-store", "generated-artifact",
}
ARCHITECTURE_CONFIDENCE = {
    "hypothesized", "source-supported", "runtime-observed", "owner-specified",
    "coordinator-replayed",
}
COVERAGE_STATES = {
    "unassigned", "assigned", "investigating", "reviewed", "excluded",
    "blocked",
}
PIPELINE_STAGES = (
    "architecture",
    "threat-model",
    "research-plan",
    "research",
    "reconciliation",
    "adversarial-review",
    "production-critic",
    "runtime-confirmation",
    "independent-replay",
    "report",
)
PIPELINE_STATES = {"pending", "running", "complete", "partial", "blocked", "skipped"}
STAGE_ROLES = {
    "architecture": {"architect", "coordinator"},
    "threat-model": {"architect", "coordinator"},
    "research-plan": {"coordinator"},
    "research": {"researcher", "coordinator"},
    "reconciliation": {"coordinator"},
    "adversarial-review": {"reviewer"},
    "production-critic": {"critic"},
    "runtime-confirmation": {"coordinator"},
    "independent-replay": {"replayer"},
    "report": {"reporter"},
}
OBSERVATION_KINDS = {
    "source", "runtime", "runtime-differential", "fuzzing", "browser",
    "coordinator-replay", "independent-replay", "negative", "owner-rule",
}
OBSERVATION_CONFIDENCE = {
    "hypothesized", "source-supported", "runtime-observed",
    "coordinator-replayed", "independently-replayed",
}
HYPOTHESIS_LEVELS = (
    "observation",
    "source-supported-mechanism",
    "runtime-differential",
    "verified-primitive",
    "compatible-chain-edge",
    "complete-terminal",
)
HYPOTHESIS_DISPOSITIONS = {
    "active", "exploited", "refuted", "blocked", "inconclusive", "superseded",
}
CRITIC_FACTS = (
    "supportedRelease",
    "shippedArtifact",
    "externalIngress",
    "productionEntrypoint",
    "optimizedBuild",
    "noDevOnlyDependency",
    "noArtificialSink",
    "remoteAcquisition",
    "simultaneousPreconditions",
)
ROLE_POLICIES: dict[str, dict[str, Any]] = {
    "architect": {
        "allowedSections": ["target", "sourceInventory", "architecture", "ownerRules"],
        "allowedTools": ["read", "search", "static-analysis", "submit-architecture"],
        "deniedSections": ["candidateVerdicts", "expectedTerminal", "credentials", "secrets"],
    },
    "researcher": {
        "allowedSections": ["target", "architecture", "threatModel", "assignment", "evidenceIndex"],
        "allowedTools": ["read", "search", "static-analysis", "propose-experiment", "submit-observation"],
        "deniedSections": ["otherWorkerConclusions", "expectedVerdict", "credentials", "secrets"],
    },
    "reviewer": {
        "allowedSections": ["target", "claim", "sourceLocations", "evidenceIndex", "conditions"],
        "allowedTools": ["read", "search", "challenge-claim", "submit-review"],
        "deniedSections": ["originatorConclusion", "expectedVerdict", "expectedOutput", "credentials", "secrets"],
    },
    "replayer": {
        "allowedSections": ["target", "frozenArtifacts", "recipe", "sourceLocations", "safety"],
        "allowedTools": ["read", "execute-approved-recipe", "submit-replay"],
        "deniedSections": ["originatorConclusion", "reviewerConclusion", "expectedVerdict", "credentials", "secrets"],
    },
    "reporter": {
        "allowedSections": ["target", "verifiedClaim", "sourceLocations", "verifiedEvidence", "conditions", "critic"],
        "allowedTools": ["read", "render-citation", "draft-report"],
        "deniedSections": ["unverifiedObservations", "credentials", "secrets", "rawCookies"],
    },
}
SENSITIVE_KEY = re.compile(
    r"(?:authorization|cookie|password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token)",
    re.IGNORECASE,
)


class IntelligenceError(Exception):
    """The supplied campaign intelligence state is invalid."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_timestamp(value: str, field: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise IntelligenceError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise IntelligenceError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest_value(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_id(prefix: str, *values: Any) -> str:
    return f"{prefix}-{digest_value(values)[:20]}"


def require_id(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not SAFE_ID.fullmatch(result):
        raise IntelligenceError(f"{field} must match {SAFE_ID.pattern}")
    return result


def require_text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise IntelligenceError(f"{field} is required")
    return result


def require_list(value: Any, field: str, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list):
        raise IntelligenceError(f"{field} must be an array")
    if nonempty and not value:
        raise IntelligenceError(f"{field} must be non-empty")
    return value


def read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise IntelligenceError(f"missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise IntelligenceError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise IntelligenceError(f"expected JSON object in {path}")
    return value


def atomic_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    try:
        temporary.write_bytes(json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n")
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def campaign_root(value: str | Path) -> Path:
    root = Path(value).expanduser().resolve()
    if not (root / "campaign.json").is_file():
        raise IntelligenceError(f"not a Krineon campaign: {root}")
    return root


def contained_path(root: Path, value: Any, field: str, *, must_exist: bool = True) -> Path:
    raw = str(value or "").strip()
    if not raw or Path(raw).is_absolute():
        raise IntelligenceError(f"{field} must be relative to {root}")
    path = (root / raw).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise IntelligenceError(f"{field} escapes {root}") from exc
    if must_exist and not path.exists():
        raise IntelligenceError(f"{field} does not exist: {raw}")
    return path


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _load(value: str) -> Any:
    return json.loads(value)


class IntelligenceStore:
    """Campaign-local canonical research and provenance store."""

    def __init__(self, root: Path):
        self.root = root
        self.database_path = root / DATABASE_RELATIVE
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.artifact_root = root / "knowledge" / "artifacts" / "sha256"
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.database_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA busy_timeout=5000")
        self.initialize()

    def close(self) -> None:
        self.connection.close()

    def initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS architecture_objects (
              object_id TEXT PRIMARY KEY,
              kind TEXT NOT NULL,
              name TEXT NOT NULL,
              confidence TEXT NOT NULL,
              attributes_json TEXT NOT NULL,
              evidence_json TEXT NOT NULL,
              content_digest TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE(kind,name)
            );
            CREATE TABLE IF NOT EXISTS architecture_relations (
              relation_id TEXT PRIMARY KEY,
              source_id TEXT NOT NULL,
              relation TEXT NOT NULL,
              target_id TEXT NOT NULL,
              conditions_json TEXT NOT NULL,
              evidence_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              UNIQUE(source_id,relation,target_id),
              FOREIGN KEY(source_id) REFERENCES architecture_objects(object_id),
              FOREIGN KEY(target_id) REFERENCES architecture_objects(object_id)
            );
            CREATE TABLE IF NOT EXISTS source_files (
              path TEXT PRIMARY KEY,
              sha256 TEXT NOT NULL,
              size INTEGER NOT NULL,
              language TEXT NOT NULL,
              production INTEGER NOT NULL,
              generated INTEGER NOT NULL,
              vendored INTEGER NOT NULL,
              source_root TEXT NOT NULL,
              inventoried_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS source_coverage (
              path TEXT PRIMARY KEY,
              state TEXT NOT NULL,
              assignee TEXT NOT NULL,
              mechanisms_json TEXT NOT NULL,
              boundaries_json TEXT NOT NULL,
              evidence_json TEXT NOT NULL,
              reason TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              FOREIGN KEY(path) REFERENCES source_files(path)
            );
            CREATE TABLE IF NOT EXISTS pipeline_stages (
              stage TEXT PRIMARY KEY,
              ordinal INTEGER NOT NULL,
              state TEXT NOT NULL,
              actor_role TEXT NOT NULL,
              outcome TEXT NOT NULL,
              reason TEXT NOT NULL,
              artifacts_json TEXT NOT NULL,
              gate_json TEXT NOT NULL,
              started_at TEXT,
              completed_at TEXT,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS source_locations (
              location_id TEXT PRIMARY KEY,
              repository_revision TEXT NOT NULL,
              path TEXT NOT NULL,
              file_sha256 TEXT NOT NULL,
              start_line INTEGER NOT NULL,
              end_line INTEGER NOT NULL,
              snippet_sha256 TEXT NOT NULL,
              symbol TEXT NOT NULL,
              generated_path TEXT NOT NULL,
              runtime_observation_id TEXT NOT NULL,
              admitted_by TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(path) REFERENCES source_files(path)
            );
            CREATE TABLE IF NOT EXISTS observations (
              observation_id TEXT PRIMARY KEY,
              content_digest TEXT NOT NULL UNIQUE,
              kind TEXT NOT NULL,
              mechanism TEXT NOT NULL,
              confidence TEXT NOT NULL,
              producer_role TEXT NOT NULL,
              producer_identity TEXT NOT NULL,
              target TEXT NOT NULL,
              evidence_json TEXT NOT NULL,
              source_locations_json TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS hypotheses (
              hypothesis_id TEXT PRIMARY KEY,
              title TEXT NOT NULL,
              mechanism TEXT NOT NULL,
              level TEXT NOT NULL,
              disposition TEXT NOT NULL,
              competing_json TEXT NOT NULL,
              experiment_json TEXT NOT NULL,
              capabilities_json TEXT NOT NULL,
              observation_ids_json TEXT NOT NULL,
              source_locations_json TEXT NOT NULL,
              blocker TEXT NOT NULL,
              reopening_json TEXT NOT NULL,
              originator_identity TEXT NOT NULL,
              revision INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS hypothesis_events (
              event_id INTEGER PRIMARY KEY AUTOINCREMENT,
              hypothesis_id TEXT NOT NULL,
              event_type TEXT NOT NULL,
              from_level TEXT NOT NULL,
              to_level TEXT NOT NULL,
              disposition TEXT NOT NULL,
              evidence_json TEXT NOT NULL,
              actor_identity TEXT NOT NULL,
              reason TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(hypothesis_id)
            );
            CREATE TABLE IF NOT EXISTS reconciliations (
              reconciliation_id TEXT PRIMARY KEY,
              mechanism TEXT NOT NULL,
              observation_ids_json TEXT NOT NULL,
              source_locations_json TEXT NOT NULL,
              evidence_classes_json TEXT NOT NULL,
              conflicts_json TEXT NOT NULL,
              candidate_hypothesis_id TEXT NOT NULL,
              input_digest TEXT NOT NULL UNIQUE,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS critic_reviews (
              review_id TEXT PRIMARY KEY,
              hypothesis_id TEXT NOT NULL,
              reviewer_identity TEXT NOT NULL,
              status TEXT NOT NULL,
              facts_json TEXT NOT NULL,
              conditions_json TEXT NOT NULL,
              issues_json TEXT NOT NULL,
              evidence_json TEXT NOT NULL,
              input_digest TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(hypothesis_id)
            );
            CREATE TABLE IF NOT EXISTS adversarial_reviews (
              review_id TEXT PRIMARY KEY,
              hypothesis_id TEXT NOT NULL,
              reviewer_identity TEXT NOT NULL,
              status TEXT NOT NULL,
              hypothesis_failure_mode TEXT NOT NULL,
              observer_failure_mode TEXT NOT NULL,
              challenged_conditions_json TEXT NOT NULL,
              evidence_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(hypothesis_id) REFERENCES hypotheses(hypothesis_id)
            );
            CREATE TABLE IF NOT EXISTS role_views (
              view_id TEXT PRIMARY KEY,
              role TEXT NOT NULL,
              task_id TEXT NOT NULL,
              agent_identity TEXT NOT NULL,
              policy_json TEXT NOT NULL,
              context_digest TEXT NOT NULL,
              relative_path TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS web_sessions (
              session_id TEXT PRIMARY KEY,
              actor_id TEXT NOT NULL,
              role TEXT NOT NULL,
              tenant_id TEXT NOT NULL,
              permission_version TEXT NOT NULL,
              credential_ref TEXT NOT NULL,
              credential_fingerprint TEXT NOT NULL,
              cookie_artifact_sha256 TEXT NOT NULL,
              client_kind TEXT NOT NULL,
              state TEXT NOT NULL,
              authenticated_at TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              invalidation_reason TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS web_session_events (
              event_id INTEGER PRIMARY KEY AUTOINCREMENT,
              session_id TEXT NOT NULL,
              event_type TEXT NOT NULL,
              actor_id TEXT NOT NULL,
              old_permission_version TEXT NOT NULL,
              new_permission_version TEXT NOT NULL,
              evidence_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              FOREIGN KEY(session_id) REFERENCES web_sessions(session_id)
            );
            CREATE INDEX IF NOT EXISTS architecture_kind_idx ON architecture_objects(kind,name);
            CREATE INDEX IF NOT EXISTS source_coverage_state_idx ON source_coverage(state,path);
            CREATE INDEX IF NOT EXISTS observations_mechanism_idx ON observations(mechanism,kind);
            CREATE INDEX IF NOT EXISTS hypotheses_state_idx ON hypotheses(disposition,level,updated_at);
            CREATE INDEX IF NOT EXISTS sessions_actor_idx ON web_sessions(actor_id,tenant_id,state);
            """
        )
        now = utc_now()
        for ordinal, stage in enumerate(PIPELINE_STAGES):
            self.connection.execute(
                "INSERT OR IGNORE INTO pipeline_stages(stage,ordinal,state,actor_role,outcome,reason,artifacts_json,gate_json,updated_at) "
                "VALUES(?,?,'pending','','','', '[]','{}',?)",
                (stage, ordinal, now),
            )
        self.connection.commit()

    # Architecture knowledge and source coverage.

    def ingest_architecture(self, specification: dict[str, Any]) -> dict[str, Any]:
        objects = require_list(specification.get("objects"), "objects", nonempty=True)
        relations = require_list(specification.get("relations", []), "relations")
        admitted: dict[str, str] = {}
        now = utc_now()
        with self.connection:
            for index, item in enumerate(objects):
                if not isinstance(item, dict):
                    raise IntelligenceError(f"objects[{index}] must be an object")
                kind = str(item.get("kind") or "").strip()
                if kind not in ARCHITECTURE_KINDS:
                    raise IntelligenceError(f"unsupported architecture kind: {kind}")
                name = require_text(item.get("name"), f"objects[{index}].name")
                confidence = str(item.get("confidence") or "hypothesized")
                if confidence not in ARCHITECTURE_CONFIDENCE:
                    raise IntelligenceError(f"unsupported architecture confidence: {confidence}")
                attributes = item.get("attributes", {})
                evidence = require_list(item.get("evidence", []), f"objects[{index}].evidence")
                object_id = require_id(
                    item.get("id") or stable_id("arch", kind, name),
                    f"objects[{index}].id",
                )
                content = {
                    "kind": kind, "name": name, "confidence": confidence,
                    "attributes": attributes, "evidence": evidence,
                }
                existing = self.connection.execute(
                    "SELECT object_id FROM architecture_objects WHERE kind=? AND name=?",
                    (kind, name),
                ).fetchone()
                if existing and existing["object_id"] != object_id:
                    raise IntelligenceError(f"architecture identity drift for {kind}:{name}")
                self.connection.execute(
                    "INSERT INTO architecture_objects(object_id,kind,name,confidence,attributes_json,evidence_json,content_digest,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(object_id) DO UPDATE SET confidence=excluded.confidence,attributes_json=excluded.attributes_json,evidence_json=excluded.evidence_json,content_digest=excluded.content_digest,updated_at=excluded.updated_at",
                    (object_id, kind, name, confidence, _json(attributes), _json(evidence), digest_value(content), now, now),
                )
                admitted[str(item.get("id") or name)] = object_id
                admitted[name] = object_id
            for index, item in enumerate(relations):
                if not isinstance(item, dict):
                    raise IntelligenceError(f"relations[{index}] must be an object")
                source = admitted.get(str(item.get("source")), str(item.get("source") or ""))
                target = admitted.get(str(item.get("target")), str(item.get("target") or ""))
                if self.connection.execute("SELECT 1 FROM architecture_objects WHERE object_id=?", (source,)).fetchone() is None:
                    raise IntelligenceError(f"unknown relation source: {source}")
                if self.connection.execute("SELECT 1 FROM architecture_objects WHERE object_id=?", (target,)).fetchone() is None:
                    raise IntelligenceError(f"unknown relation target: {target}")
                relation = require_text(item.get("relation"), f"relations[{index}].relation")
                conditions = require_list(item.get("conditions", []), f"relations[{index}].conditions")
                evidence = require_list(item.get("evidence", []), f"relations[{index}].evidence")
                relation_id = stable_id("rel", source, relation, target)
                self.connection.execute(
                    "INSERT INTO architecture_relations(relation_id,source_id,relation,target_id,conditions_json,evidence_json,created_at) "
                    "VALUES(?,?,?,?,?,?,?) ON CONFLICT(relation_id) DO UPDATE SET conditions_json=excluded.conditions_json,evidence_json=excluded.evidence_json",
                    (relation_id, source, relation, target, _json(conditions), _json(evidence), now),
                )
        return {"objects": len(objects), "relations": len(relations), "objectIds": sorted(set(admitted.values()))}

    @staticmethod
    def _language(path: Path) -> str:
        mapping = {
            ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
            ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript",
            ".c": "c", ".h": "c-cpp", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
            ".hpp": "cpp", ".hxx": "cpp", ".rs": "rust", ".go": "go", ".py": "python",
            ".java": "java", ".kt": "kotlin", ".swift": "swift", ".cs": "csharp",
            ".sol": "solidity", ".vy": "vyper", ".proto": "protobuf",
        }
        return mapping.get(path.suffix.lower(), path.suffix.lower().lstrip(".") or "unknown")

    def inventory_source(self, source_root: Path, *, maximum_file_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
        source_root = source_root.expanduser().resolve()
        if not source_root.is_dir():
            raise IntelligenceError(f"source root is not a directory: {source_root}")
        rows: list[tuple[Any, ...]] = []
        skipped = 0
        now = utc_now()
        for current, directories, files in os.walk(source_root, followlinks=False):
            directories[:] = sorted(name for name in directories if name not in IGNORED_DIRECTORY_NAMES)
            base = Path(current)
            for name in sorted(files):
                path = base / name
                if path.is_symlink() or path.suffix.lower() not in SOURCE_SUFFIXES:
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    skipped += 1
                    continue
                if stat.st_size > maximum_file_bytes:
                    skipped += 1
                    continue
                relative = path.relative_to(source_root).as_posix()
                parts = {part.lower() for part in Path(relative).parts[:-1]}
                production = not bool(parts & NON_PRODUCTION_PARTS)
                generated = bool(parts & GENERATED_PARTS)
                vendored = bool(parts & VENDORED_PARTS)
                rows.append((
                    relative, digest_file(path), stat.st_size, self._language(path),
                    int(production), int(generated), int(vendored), str(source_root), now,
                ))
        with self.connection:
            self.connection.execute("DELETE FROM source_files WHERE source_root=?", (str(source_root),))
            self.connection.executemany(
                "INSERT INTO source_files(path,sha256,size,language,production,generated,vendored,source_root,inventoried_at) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256,size=excluded.size,language=excluded.language,production=excluded.production,generated=excluded.generated,vendored=excluded.vendored,source_root=excluded.source_root,inventoried_at=excluded.inventoried_at",
                rows,
            )
            for row in rows:
                self.connection.execute(
                    "INSERT OR IGNORE INTO source_coverage(path,state,assignee,mechanisms_json,boundaries_json,evidence_json,reason,updated_at) VALUES(?,'unassigned','','[]','[]','[]','',?)",
                    (row[0], now),
                )
        return {
            "sourceRoot": str(source_root), "files": len(rows),
            "productionFiles": sum(row[4] for row in rows), "skipped": skipped,
        }

    def mark_source_coverage(
        self,
        path: str,
        *,
        state: str,
        assignee: str = "",
        mechanisms: list[str] | None = None,
        boundaries: list[str] | None = None,
        evidence: list[str] | None = None,
        reason: str = "",
    ) -> dict[str, Any]:
        if state not in COVERAGE_STATES:
            raise IntelligenceError(f"unsupported coverage state: {state}")
        if self.connection.execute("SELECT 1 FROM source_files WHERE path=?", (path,)).fetchone() is None:
            raise IntelligenceError(f"source file is not inventoried: {path}")
        if state == "excluded" and not reason.strip():
            raise IntelligenceError("excluded source coverage requires a reason")
        self.connection.execute(
            "UPDATE source_coverage SET state=?,assignee=?,mechanisms_json=?,boundaries_json=?,evidence_json=?,reason=?,updated_at=? WHERE path=?",
            (state, assignee.strip(), _json(sorted(set(mechanisms or []))), _json(sorted(set(boundaries or []))), _json(evidence or []), reason.strip(), utc_now(), path),
        )
        self.connection.commit()
        return self.source_coverage_report(path=path)

    def source_coverage_report(self, *, path: str | None = None) -> dict[str, Any]:
        if path:
            row = self.connection.execute(
                "SELECT f.*,c.state,c.assignee,c.mechanisms_json,c.boundaries_json,c.evidence_json,c.reason,c.updated_at FROM source_files f JOIN source_coverage c USING(path) WHERE path=?",
                (path,),
            ).fetchone()
            if row is None:
                raise IntelligenceError(f"unknown source file: {path}")
            value = dict(row)
            for key in ("mechanisms_json", "boundaries_json", "evidence_json"):
                value[key.removesuffix("_json")] = _load(value.pop(key))
            return value
        counts = {
            row["state"]: row["n"]
            for row in self.connection.execute(
                "SELECT c.state,COUNT(*) AS n FROM source_coverage c JOIN source_files f USING(path) WHERE f.production=1 GROUP BY c.state"
            )
        }
        total = int(self.connection.execute("SELECT COUNT(*) FROM source_files WHERE production=1").fetchone()[0])
        accounted = sum(counts.get(state, 0) for state in ("reviewed", "excluded"))
        missing = [
            row["path"] for row in self.connection.execute(
                "SELECT f.path FROM source_files f JOIN source_coverage c USING(path) WHERE f.production=1 AND c.state NOT IN ('reviewed','excluded') ORDER BY f.path"
            )
        ]
        return {"productionFiles": total, "accounted": accounted, "counts": counts, "missing": missing}

    # Source locations and immutable observations.

    def admit_source_location(
        self,
        *,
        source_root: Path,
        repository_revision: str,
        path: str,
        start_line: int,
        end_line: int,
        symbol: str,
        admitted_by: str,
        generated_path: str = "",
        runtime_observation_id: str = "",
    ) -> dict[str, Any]:
        source_root = source_root.expanduser().resolve()
        file_row = self.connection.execute("SELECT * FROM source_files WHERE path=?", (path,)).fetchone()
        if file_row is None:
            raise IntelligenceError(f"source location is not inventoried: {path}")
        candidate = contained_path(source_root, path, "source path")
        if not candidate.is_file() or candidate.is_symlink():
            raise IntelligenceError("source location must be a regular, non-symlink file")
        if digest_file(candidate) != file_row["sha256"]:
            raise IntelligenceError(f"source file changed after inventory: {path}")
        lines = candidate.read_bytes().splitlines(keepends=True)
        if start_line < 1 or end_line < start_line or end_line > len(lines):
            raise IntelligenceError("source location line range is invalid")
        snippet = b"".join(lines[start_line - 1 : end_line])
        location_id = stable_id(
            "loc", repository_revision, path, file_row["sha256"], start_line, end_line, hashlib.sha256(snippet).hexdigest(),
        )
        now = utc_now()
        self.connection.execute(
            "INSERT OR IGNORE INTO source_locations(location_id,repository_revision,path,file_sha256,start_line,end_line,snippet_sha256,symbol,generated_path,runtime_observation_id,admitted_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                location_id, require_text(repository_revision, "repositoryRevision"), path,
                file_row["sha256"], start_line, end_line, hashlib.sha256(snippet).hexdigest(),
                symbol.strip(), generated_path.strip(), runtime_observation_id.strip(),
                require_id(admitted_by, "admittedBy"), now,
            ),
        )
        self.connection.commit()
        return self.source_location(location_id, source_root=source_root)

    def source_location(self, location_id: str, *, source_root: Path | None = None) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM source_locations WHERE location_id=?", (location_id,)).fetchone()
        if row is None:
            raise IntelligenceError(f"unknown source location: {location_id}")
        value = dict(row)
        if source_root is not None:
            candidate = contained_path(source_root.resolve(), value["path"], "source location")
            if digest_file(candidate) != value["file_sha256"]:
                raise IntelligenceError(f"source citation is stale: {value['path']}")
            lines = candidate.read_bytes().splitlines(keepends=True)
            snippet = b"".join(lines[value["start_line"] - 1 : value["end_line"]])
            if hashlib.sha256(snippet).hexdigest() != value["snippet_sha256"]:
                raise IntelligenceError(f"source snippet is stale: {value['path']}")
        value["citation"] = f"{value['path']}:{value['start_line']}-{value['end_line']}@{value['repository_revision']}"
        return value

    def validate_report_manifest(self, value: dict[str, Any], *, source_root: Path) -> dict[str, Any]:
        if any(key in value for key in ("rawSourceCitations", "fileLineClaims", "freeformLocations")):
            raise IntelligenceError("report manifests may cite only admitted source location IDs")
        hypothesis_ids = [require_id(item, "hypothesisIds[]") for item in require_list(value.get("hypothesisIds"), "hypothesisIds", nonempty=True)]
        location_ids = [require_id(item, "sourceLocationIds[]") for item in require_list(value.get("sourceLocationIds"), "sourceLocationIds", nonempty=True)]
        hypotheses = [self.hypothesis(item) for item in hypothesis_ids]
        for hypothesis in hypotheses:
            if hypothesis["level"] != "complete-terminal":
                raise IntelligenceError(f"report hypothesis is not a complete terminal: {hypothesis['hypothesis_id']}")
        locations = [self.source_location(item, source_root=source_root) for item in location_ids]
        allowed_locations = {
            item for hypothesis in hypotheses for item in hypothesis["source_locations"]
        }
        unbound = sorted(set(location_ids) - allowed_locations)
        if unbound:
            raise IntelligenceError("report locations are not bound to the terminal hypothesis: " + ", ".join(unbound))
        return {
            "valid": True,
            "hypothesisIds": hypothesis_ids,
            "sourceLocations": [
                {
                    "locationId": location["location_id"],
                    "citation": location["citation"],
                    "fileSha256": location["file_sha256"],
                    "snippetSha256": location["snippet_sha256"],
                }
                for location in locations
            ],
            "manifestDigest": digest_value(value),
        }

    def _retain_artifact(self, source: Path) -> dict[str, Any]:
        payload = source.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        destination = self.artifact_root / digest[:2] / digest
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            temporary = destination.with_name(f".{digest}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
            try:
                temporary.write_bytes(payload)
                os.chmod(temporary, 0o600)
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
        elif digest_file(destination) != digest:
            raise IntelligenceError(f"content-addressed artifact corruption: {digest}")
        return {
            "path": destination.relative_to(self.root).as_posix(),
            "sha256": digest,
            "size": len(payload),
        }

    def _validate_evidence(self, evidence: list[Any]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for index, raw in enumerate(evidence):
            if isinstance(raw, str):
                relative = raw
                kind = "file"
            elif isinstance(raw, dict):
                relative = str(raw.get("path") or "")
                kind = str(raw.get("kind") or "file")
            else:
                raise IntelligenceError(f"evidence[{index}] must be a path or object")
            path = contained_path(self.root, relative, f"evidence[{index}]")
            if not path.is_file() or path.is_symlink():
                raise IntelligenceError(f"evidence is not a safe regular file: {relative}")
            retained = self._retain_artifact(path)
            normalized.append({
                **retained,
                "kind": kind,
                "sourcePath": path.relative_to(self.root).as_posix(),
            })
        return normalized

    def admit_observation(self, value: dict[str, Any]) -> dict[str, Any]:
        kind = str(value.get("kind") or "")
        if kind not in OBSERVATION_KINDS:
            raise IntelligenceError(f"unsupported observation kind: {kind}")
        confidence = str(value.get("confidence") or "hypothesized")
        if confidence not in OBSERVATION_CONFIDENCE:
            raise IntelligenceError(f"unsupported observation confidence: {confidence}")
        mechanism = require_text(value.get("mechanism"), "mechanism")
        producer_role = require_text(value.get("producerRole"), "producerRole")
        producer_identity = require_id(value.get("producerIdentity"), "producerIdentity")
        target = require_text(value.get("target"), "target")
        location_ids = [require_id(item, "sourceLocations[]") for item in require_list(value.get("sourceLocations", []), "sourceLocations")]
        for location_id in location_ids:
            if self.connection.execute("SELECT 1 FROM source_locations WHERE location_id=?", (location_id,)).fetchone() is None:
                raise IntelligenceError(f"unknown source location: {location_id}")
        evidence = self._validate_evidence(require_list(value.get("evidence", []), "evidence", nonempty=True))
        payload = value.get("payload", {})
        if not isinstance(payload, dict):
            raise IntelligenceError("payload must be an object")
        if kind == "runtime-differential":
            cases = payload.get("cases")
            if not isinstance(cases, dict) or not {"baseline", "negative", "positive"} <= set(cases):
                raise IntelligenceError("runtime-differential observations require baseline, negative, and positive cases")
        canonical = {
            "kind": kind, "mechanism": mechanism, "confidence": confidence,
            "producerRole": producer_role, "producerIdentity": producer_identity,
            "target": target, "evidence": evidence, "sourceLocations": sorted(location_ids),
            "payload": payload,
        }
        content_digest = digest_value(canonical)
        observation_id = str(value.get("observationId") or f"obs-{content_digest[:20]}")
        require_id(observation_id, "observationId")
        existing = self.connection.execute("SELECT * FROM observations WHERE content_digest=?", (content_digest,)).fetchone()
        if existing:
            return self._observation_value(existing)
        self.connection.execute(
            "INSERT INTO observations(observation_id,content_digest,kind,mechanism,confidence,producer_role,producer_identity,target,evidence_json,source_locations_json,payload_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                observation_id, content_digest, kind, mechanism, confidence, producer_role,
                producer_identity, target, _json(evidence), _json(sorted(location_ids)),
                _json(payload), utc_now(),
            ),
        )
        self.connection.commit()
        return self.observation(observation_id)

    @staticmethod
    def _observation_value(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        for key in ("evidence_json", "source_locations_json", "payload_json"):
            value[key.removesuffix("_json")] = _load(value.pop(key))
        return value

    def observation(self, observation_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM observations WHERE observation_id=?", (observation_id,)).fetchone()
        if row is None:
            raise IntelligenceError(f"unknown observation: {observation_id}")
        return self._observation_value(row)

    def reconcile(self, mechanism: str, *, actor_identity: str, create_hypothesis: bool = True) -> dict[str, Any]:
        mechanism = require_text(mechanism, "mechanism")
        rows = list(self.connection.execute("SELECT * FROM observations WHERE mechanism=? ORDER BY created_at,observation_id", (mechanism,)))
        if not rows:
            raise IntelligenceError(f"no observations for mechanism: {mechanism}")
        observations = [self._observation_value(row) for row in rows]
        observation_ids = [row["observation_id"] for row in observations]
        location_ids = sorted({item for row in observations for item in row["source_locations"]})
        classes = sorted({row["kind"] for row in observations})
        conflicts: list[str] = []
        targets = sorted({row["target"] for row in observations})
        if len(targets) > 1:
            conflicts.append("observations name different concrete targets")
        positive_digests = {
            digest_value(row["payload"].get("cases", {}).get("positive"))
            for row in observations if row["kind"] == "runtime-differential"
        }
        if len(positive_digests) > 1:
            conflicts.append("runtime observations disagree on the positive-case representation")
        reconciliation_input = {
            "mechanism": mechanism,
            "observationDigests": [row["content_digest"] for row in observations],
            "sourceLocations": location_ids,
        }
        input_digest = digest_value(reconciliation_input)
        existing = self.connection.execute("SELECT * FROM reconciliations WHERE input_digest=?", (input_digest,)).fetchone()
        if existing:
            return self._reconciliation_value(existing)
        hypothesis_id = ""
        if create_hypothesis:
            existing_hypothesis = self.connection.execute(
                "SELECT * FROM hypotheses WHERE mechanism=? AND disposition='active' ORDER BY created_at LIMIT 1",
                (mechanism,),
            ).fetchone()
            if existing_hypothesis is not None:
                existing_value = self._hypothesis_value(existing_hypothesis)
                merged_observations = list(dict.fromkeys([*existing_value["observation_ids"], *observation_ids]))
                merged_locations = list(dict.fromkeys([*existing_value["source_locations"], *location_ids]))
                self.connection.execute(
                    "UPDATE hypotheses SET observation_ids_json=?,source_locations_json=?,revision=revision+1,updated_at=? WHERE hypothesis_id=?",
                    (_json(merged_observations), _json(merged_locations), utc_now(), existing_value["hypothesis_id"]),
                )
                self.connection.commit()
                hypothesis_id = existing_value["hypothesis_id"]
            else:
                hypothesis = self.create_hypothesis({
                    "title": f"Investigate {mechanism}",
                    "mechanism": mechanism,
                    "competingExplanations": [
                        "the observed behavior is the proposed security-boundary disagreement",
                        "the observed target is intentionally public or equivalent",
                        "the observation is an instrumentation or error-response artifact",
                        "a different upstream component caused the behavior",
                    ],
                    "experiment": {},
                    "capabilities": [],
                    "observationIds": observation_ids,
                    "sourceLocations": location_ids,
                    "originatorIdentity": actor_identity,
                })
                hypothesis_id = hypothesis["hypothesis_id"]
        reconciliation_id = stable_id("reconcile", input_digest)
        self.connection.execute(
            "INSERT INTO reconciliations(reconciliation_id,mechanism,observation_ids_json,source_locations_json,evidence_classes_json,conflicts_json,candidate_hypothesis_id,input_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (reconciliation_id, mechanism, _json(observation_ids), _json(location_ids), _json(classes), _json(conflicts), hypothesis_id, input_digest, utc_now()),
        )
        self.connection.commit()
        return self._reconciliation_value(self.connection.execute("SELECT * FROM reconciliations WHERE reconciliation_id=?", (reconciliation_id,)).fetchone())

    def ingest_task_result(
        self,
        result: dict[str, Any],
        *,
        task_id: str,
        worker_identity: str,
        result_path: str,
    ) -> dict[str, Any]:
        """Admit scheduler observations without inflating their evidence grade.

        Legacy worker observations that call themselves a runtime differential
        but do not contain baseline/negative/positive cases are retained as
        generic runtime observations. They cannot satisfy the differential
        promotion gate merely by using the stronger label.
        """

        task_result = result.get("taskResult")
        if not isinstance(task_result, dict):
            return {"observations": [], "reconciliations": []}
        raw_observations = task_result.get("observations", [])
        if not isinstance(raw_observations, list):
            raise IntelligenceError("taskResult.observations must be an array")
        admitted: list[str] = []
        mechanisms: set[str] = set()
        for index, raw in enumerate(raw_observations):
            if not isinstance(raw, dict):
                raise IntelligenceError(f"taskResult.observations[{index}] must be an object")
            mechanism = require_text(
                raw.get("mechanism") or raw.get("mechanismFingerprint") or raw.get("kind"),
                f"taskResult.observations[{index}].mechanism",
            )
            legacy_kind = str(raw.get("kind") or "source")
            cases = raw.get("cases")
            if cases is None and isinstance(raw.get("payload"), dict):
                cases = raw["payload"].get("cases")
            valid_cases = isinstance(cases, dict) and {"baseline", "negative", "positive"} <= set(cases)
            if legacy_kind == "runtime-differential" and valid_cases:
                kind = "runtime-differential"
                payload = {"cases": cases, "legacyObservation": raw}
            elif str(raw.get("confidence")) in {"runtime-observed", "coordinator-replayed", "independently-replayed"}:
                kind = "runtime"
                payload = {
                    "legacyKind": legacy_kind,
                    "legacyObservation": raw,
                    "downgradeReason": "baseline/negative/positive cases were not structurally present",
                }
            else:
                kind = "source"
                payload = {"legacyKind": legacy_kind, "legacyObservation": raw}
            confidence = str(raw.get("confidence") or "hypothesized")
            confidence = {
                "coordinator-replayed": "runtime-observed",
                "independently-replayed": "runtime-observed",
            }.get(confidence, confidence)
            if confidence not in OBSERVATION_CONFIDENCE:
                confidence = "hypothesized"
            evidence = raw.get("evidence")
            if not isinstance(evidence, list) or not evidence:
                evidence = [result_path]
            asset_refs = raw.get("assetRefs", [])
            target = task_id
            if isinstance(asset_refs, list):
                named = [str(item.get("name")) for item in asset_refs if isinstance(item, dict) and item.get("name")]
                if named:
                    target = named[0]
            observation = self.admit_observation(
                {
                    "kind": kind,
                    "mechanism": mechanism,
                    "confidence": confidence,
                    "producerRole": "researcher",
                    "producerIdentity": worker_identity,
                    "target": target,
                    "sourceLocations": [],
                    "evidence": evidence,
                    "payload": payload,
                }
            )
            admitted.append(observation["observation_id"])
            mechanisms.add(mechanism)
        reconciliations = [
            self.reconcile(mechanism, actor_identity=worker_identity)
            for mechanism in sorted(mechanisms)
        ]
        return {
            "observations": admitted,
            "reconciliations": [item["reconciliation_id"] for item in reconciliations],
            "hypotheses": sorted({item["candidate_hypothesis_id"] for item in reconciliations if item["candidate_hypothesis_id"]}),
        }

    @staticmethod
    def _reconciliation_value(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        for key in ("observation_ids_json", "source_locations_json", "evidence_classes_json", "conflicts_json"):
            value[key.removesuffix("_json")] = _load(value.pop(key))
        return value

    # Hypothesis queue and promotion accounting.

    def create_hypothesis(self, value: dict[str, Any]) -> dict[str, Any]:
        title = require_text(value.get("title"), "title")
        mechanism = require_text(value.get("mechanism"), "mechanism")
        competing = require_list(value.get("competingExplanations"), "competingExplanations", nonempty=True)
        observations = [require_id(item, "observationIds[]") for item in require_list(value.get("observationIds", []), "observationIds")]
        locations = [require_id(item, "sourceLocations[]") for item in require_list(value.get("sourceLocations", []), "sourceLocations")]
        for observation_id in observations:
            self.observation(observation_id)
        for location_id in locations:
            self.source_location(location_id)
        originator = require_id(value.get("originatorIdentity"), "originatorIdentity")
        experiment = value.get("experiment", {})
        capabilities = value.get("capabilities", [])
        if not isinstance(experiment, dict) or not isinstance(capabilities, list):
            raise IntelligenceError("experiment must be an object and capabilities must be an array")
        hypothesis_id = str(value.get("hypothesisId") or stable_id("hyp", mechanism, title, originator))
        require_id(hypothesis_id, "hypothesisId")
        now = utc_now()
        try:
            self.connection.execute(
                "INSERT INTO hypotheses(hypothesis_id,title,mechanism,level,disposition,competing_json,experiment_json,capabilities_json,observation_ids_json,source_locations_json,blocker,reopening_json,originator_identity,revision,created_at,updated_at) VALUES(?,?,?,'observation','active',?,?,?,?,?,'','[]',?,1,?,?)",
                (hypothesis_id, title, mechanism, _json(competing), _json(experiment), _json(capabilities), _json(observations), _json(locations), originator, now, now),
            )
            self.connection.commit()
        except sqlite3.IntegrityError as exc:
            raise IntelligenceError(f"hypothesis already exists: {hypothesis_id}") from exc
        self._hypothesis_event(hypothesis_id, "created", "", "observation", "active", observations, originator, "initial observation retained")
        return self.hypothesis(hypothesis_id)

    @staticmethod
    def _hypothesis_value(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        for key in ("competing_json", "experiment_json", "capabilities_json", "observation_ids_json", "source_locations_json", "reopening_json"):
            value[key.removesuffix("_json")] = _load(value.pop(key))
        return value

    def hypothesis(self, hypothesis_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM hypotheses WHERE hypothesis_id=?", (hypothesis_id,)).fetchone()
        if row is None:
            raise IntelligenceError(f"unknown hypothesis: {hypothesis_id}")
        return self._hypothesis_value(row)

    def _hypothesis_event(self, hypothesis_id: str, event_type: str, old: str, new: str, disposition: str, evidence: list[str], actor: str, reason: str) -> None:
        self.connection.execute(
            "INSERT INTO hypothesis_events(hypothesis_id,event_type,from_level,to_level,disposition,evidence_json,actor_identity,reason,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (hypothesis_id, event_type, old, new, disposition, _json(evidence), actor, reason, utc_now()),
        )
        self.connection.commit()

    def _promotion_gate(self, hypothesis: dict[str, Any], target_level: str) -> list[str]:
        observations = [self.observation(item) for item in hypothesis["observation_ids"]]
        kinds = {item["kind"] for item in observations}
        issues: list[str] = []
        if target_level == "source-supported-mechanism" and not hypothesis["source_locations"]:
            issues.append("source-supported promotion requires an admitted source location")
        elif target_level == "runtime-differential" and "runtime-differential" not in kinds:
            issues.append("runtime-differential promotion requires a three-case runtime observation")
        elif target_level == "verified-primitive" and "coordinator-replay" not in kinds:
            issues.append("verified-primitive promotion requires a coordinator-replay observation")
        elif target_level == "compatible-chain-edge":
            if not hypothesis["capabilities"]:
                issues.append("compatible-chain-edge promotion requires typed capability contracts")
            for capability in hypothesis["capabilities"]:
                if not isinstance(capability, dict) or not {
                    "inputType", "outputAuthority", "principal", "process", "runtime",
                    "acquisitionProof", "deployment",
                } <= set(capability):
                    issues.append("each capability requires typed authority, context, acquisition, and deployment fields")
                    break
        elif target_level == "complete-terminal" and "independent-replay" not in kinds:
            issues.append("complete-terminal promotion requires an independent-replay observation")
        return issues

    def promote_hypothesis(self, hypothesis_id: str, target_level: str, *, actor_identity: str, reason: str, observation_ids: list[str] | None = None, capabilities: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        if target_level not in HYPOTHESIS_LEVELS:
            raise IntelligenceError(f"unsupported hypothesis level: {target_level}")
        value = self.hypothesis(hypothesis_id)
        current_index = HYPOTHESIS_LEVELS.index(value["level"])
        target_index = HYPOTHESIS_LEVELS.index(target_level)
        if target_index != current_index + 1:
            raise IntelligenceError("hypotheses must advance exactly one promotion level")
        merged_observations = list(dict.fromkeys([*value["observation_ids"], *(observation_ids or [])]))
        for observation_id in merged_observations:
            self.observation(observation_id)
        merged_capabilities = capabilities if capabilities is not None else value["capabilities"]
        candidate = dict(value)
        candidate["observation_ids"] = merged_observations
        candidate["capabilities"] = merged_capabilities
        issues = self._promotion_gate(candidate, target_level)
        if issues:
            raise IntelligenceError("; ".join(issues))
        actor = require_id(actor_identity, "actorIdentity")
        now = utc_now()
        self.connection.execute(
            "UPDATE hypotheses SET level=?,observation_ids_json=?,capabilities_json=?,revision=revision+1,updated_at=? WHERE hypothesis_id=?",
            (target_level, _json(merged_observations), _json(merged_capabilities), now, hypothesis_id),
        )
        self.connection.commit()
        self._hypothesis_event(hypothesis_id, "promoted", value["level"], target_level, value["disposition"], merged_observations, actor, require_text(reason, "reason"))
        return self.hypothesis(hypothesis_id)

    def dispose_hypothesis(self, hypothesis_id: str, disposition: str, *, actor_identity: str, reason: str, blocker: str = "", reopening: list[str] | None = None, evidence: list[str] | None = None) -> dict[str, Any]:
        if disposition not in HYPOTHESIS_DISPOSITIONS - {"active"}:
            raise IntelligenceError(f"unsupported terminal disposition: {disposition}")
        if disposition == "blocked" and (not blocker.strip() or not reopening):
            raise IntelligenceError("blocked disposition requires an exact blocker and reopening criteria")
        value = self.hypothesis(hypothesis_id)
        actor = require_id(actor_identity, "actorIdentity")
        self.connection.execute(
            "UPDATE hypotheses SET disposition=?,blocker=?,reopening_json=?,revision=revision+1,updated_at=? WHERE hypothesis_id=?",
            (disposition, blocker.strip(), _json(reopening or []), utc_now(), hypothesis_id),
        )
        self.connection.commit()
        self._hypothesis_event(hypothesis_id, "disposed", value["level"], value["level"], disposition, evidence or [], actor, require_text(reason, "reason"))
        return self.hypothesis(hypothesis_id)

    # Production critic and stage machine.

    def adversarial_review(self, hypothesis_id: str, value: dict[str, Any], *, reviewer_identity: str) -> dict[str, Any]:
        hypothesis = self.hypothesis(hypothesis_id)
        reviewer = require_id(reviewer_identity, "reviewerIdentity")
        if reviewer == hypothesis["originator_identity"]:
            raise IntelligenceError("adversarial review must use a different identity from the originator")
        status = str(value.get("status") or "")
        if status not in {"accepted", "rejected", "inconclusive"}:
            raise IntelligenceError("adversarial review status must be accepted, rejected, or inconclusive")
        hypothesis_failure = require_text(value.get("hypothesisFailureMode"), "hypothesisFailureMode")
        observer_failure = require_text(value.get("observerFailureMode"), "observerFailureMode")
        conditions = require_list(value.get("challengedConditions", []), "challengedConditions", nonempty=True)
        evidence = self._validate_evidence(require_list(value.get("evidence", []), "evidence", nonempty=True))
        review_id = stable_id(
            "adversarial", hypothesis_id, hypothesis["revision"], reviewer, status,
            hypothesis_failure, observer_failure, conditions, evidence,
        )
        self.connection.execute(
            "INSERT OR REPLACE INTO adversarial_reviews(review_id,hypothesis_id,reviewer_identity,status,hypothesis_failure_mode,observer_failure_mode,challenged_conditions_json,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                review_id, hypothesis_id, reviewer, status, hypothesis_failure,
                observer_failure, _json(conditions), _json(evidence), utc_now(),
            ),
        )
        self.connection.commit()
        return {
            "reviewId": review_id,
            "hypothesisId": hypothesis_id,
            "reviewerIdentity": reviewer,
            "status": status,
            "hypothesisFailureMode": hypothesis_failure,
            "observerFailureMode": observer_failure,
            "challengedConditions": conditions,
            "evidence": evidence,
        }

    def production_review(self, hypothesis_id: str, value: dict[str, Any], *, reviewer_identity: str) -> dict[str, Any]:
        hypothesis = self.hypothesis(hypothesis_id)
        reviewer = require_id(reviewer_identity, "reviewerIdentity")
        if reviewer == hypothesis["originator_identity"]:
            raise IntelligenceError("production critic must use a different identity from the originator")
        facts = value.get("facts")
        if not isinstance(facts, dict):
            raise IntelligenceError("critic facts must be an object")
        evidence = self._validate_evidence(require_list(value.get("evidence", []), "evidence", nonempty=True))
        conditions = require_list(value.get("conditions", []), "conditions")
        issues: list[dict[str, str]] = []
        for name in CRITIC_FACTS:
            fact = facts.get(name)
            if not isinstance(fact, dict) or fact.get("value") not in {True, False, None}:
                issues.append({"fact": name, "state": "inconclusive", "reason": "missing explicit true/false/null fact"})
                continue
            if fact["value"] is None:
                issues.append({"fact": name, "state": "inconclusive", "reason": str(fact.get("reason") or "required telemetry is absent")})
            elif fact["value"] is False:
                issues.append({"fact": name, "state": "refuted", "reason": str(fact.get("reason") or "production condition is false")})
            elif not fact.get("evidence"):
                issues.append({"fact": name, "state": "inconclusive", "reason": "true fact lacks an evidence reference"})
        status = "passed"
        if any(item["state"] == "refuted" for item in issues):
            status = "refuted"
        elif issues:
            status = "inconclusive"
        critic_input = {
            "hypothesisId": hypothesis_id, "hypothesisRevision": hypothesis["revision"],
            "facts": facts, "conditions": conditions, "evidence": evidence,
        }
        input_digest = digest_value(critic_input)
        review_id = stable_id("critic", hypothesis_id, input_digest, reviewer)
        self.connection.execute(
            "INSERT OR REPLACE INTO critic_reviews(review_id,hypothesis_id,reviewer_identity,status,facts_json,conditions_json,issues_json,evidence_json,input_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (review_id, hypothesis_id, reviewer, status, _json(facts), _json(conditions), _json(issues), _json(evidence), input_digest, utc_now()),
        )
        self.connection.commit()
        return {
            "reviewId": review_id, "hypothesisId": hypothesis_id, "status": status,
            "issues": issues, "conditions": conditions, "inputDigest": input_digest,
        }

    def pipeline_status(self) -> dict[str, Any]:
        rows = []
        for row in self.connection.execute("SELECT * FROM pipeline_stages ORDER BY ordinal"):
            value = dict(row)
            value["artifacts"] = _load(value.pop("artifacts_json"))
            value["gate"] = _load(value.pop("gate_json"))
            rows.append(value)
        current = next((row["stage"] for row in rows if row["state"] not in {"complete", "partial", "skipped"}), None)
        return {"stages": rows, "current": current}

    def _stage_gate(self, stage: str, outcome: str) -> list[str]:
        issues: list[str] = []
        if stage == "architecture":
            if self.connection.execute("SELECT COUNT(*) FROM architecture_objects").fetchone()[0] == 0:
                issues.append("architecture knowledge base has no objects")
            if self.connection.execute("SELECT COUNT(*) FROM source_files").fetchone()[0] == 0:
                issues.append("source inventory is empty")
        elif stage == "research-plan":
            unassigned = self.connection.execute(
                "SELECT COUNT(*) FROM source_files f JOIN source_coverage c USING(path) WHERE f.production=1 AND c.state='unassigned'"
            ).fetchone()[0]
            if unassigned:
                issues.append(f"{unassigned} production source files are not assigned or explicitly excluded")
        elif stage == "research" and outcome == "complete":
            report = self.source_coverage_report()
            if report["missing"]:
                issues.append(f"{len(report['missing'])} production source files remain unaccounted")
        elif stage == "reconciliation":
            unreconciled = self.connection.execute(
                "SELECT COUNT(DISTINCT mechanism) FROM observations WHERE mechanism NOT IN (SELECT mechanism FROM reconciliations)"
            ).fetchone()[0]
            if unreconciled:
                issues.append(f"{unreconciled} observed mechanisms have not been reconciled")
        elif stage == "adversarial-review":
            missing = self.connection.execute(
                "SELECT COUNT(*) FROM hypotheses h WHERE h.level != 'observation' AND h.disposition='active' AND NOT EXISTS (SELECT 1 FROM adversarial_reviews r WHERE r.hypothesis_id=h.hypothesis_id)"
            ).fetchone()[0]
            if missing:
                issues.append(f"{missing} promoted hypotheses lack an independent adversarial review")
        elif stage == "production-critic":
            missing = self.connection.execute(
                "SELECT COUNT(*) FROM hypotheses h WHERE h.level IN ('verified-primitive','compatible-chain-edge','complete-terminal') AND h.disposition='active' AND NOT EXISTS (SELECT 1 FROM critic_reviews c WHERE c.hypothesis_id=h.hypothesis_id)"
            ).fetchone()[0]
            if missing:
                issues.append(f"{missing} promoted hypotheses lack a production review")
        elif stage == "runtime-confirmation":
            rows = list(self.connection.execute(
                "SELECT * FROM hypotheses WHERE level IN ('verified-primitive','compatible-chain-edge','complete-terminal') AND disposition='active'"
            ))
            missing = 0
            for row in rows:
                observations = [self.observation(item) for item in _load(row["observation_ids_json"])]
                if not any(item["kind"] == "coordinator-replay" for item in observations):
                    missing += 1
            if missing:
                issues.append(f"{missing} primitive hypotheses lack coordinator replay")
        elif stage == "independent-replay":
            terminal_rows = list(self.connection.execute("SELECT * FROM hypotheses WHERE level='complete-terminal' AND disposition='active'"))
            for row in terminal_rows:
                observations = [self.observation(item) for item in _load(row["observation_ids_json"])]
                if not any(item["kind"] == "independent-replay" for item in observations):
                    issues.append(f"terminal hypothesis {row['hypothesis_id']} lacks independent replay")
        elif stage == "report":
            terminal = self.connection.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE level='complete-terminal' AND disposition IN ('active','exploited')"
            ).fetchone()[0]
            if outcome == "complete" and not terminal:
                issues.append("report completion requires a complete terminal")
        return issues

    def start_stage(self, stage: str, *, actor_role: str) -> dict[str, Any]:
        if stage not in PIPELINE_STAGES:
            raise IntelligenceError(f"unknown pipeline stage: {stage}")
        status = self.pipeline_status()
        if status["current"] != stage:
            raise IntelligenceError(f"pipeline stage is not eligible; current stage is {status['current']}")
        if actor_role not in STAGE_ROLES[stage]:
            raise IntelligenceError(
                f"role {actor_role!r} cannot run {stage}; expected one of {sorted(STAGE_ROLES[stage])}"
            )
        now = utc_now()
        self.connection.execute(
            "UPDATE pipeline_stages SET state='running',actor_role=?,started_at=COALESCE(started_at,?),updated_at=? WHERE stage=?",
            (require_text(actor_role, "actorRole"), now, now, stage),
        )
        self.connection.commit()
        return next(item for item in self.pipeline_status()["stages"] if item["stage"] == stage)

    def complete_stage(self, stage: str, *, actor_role: str, outcome: str, reason: str, artifacts: list[str]) -> dict[str, Any]:
        if outcome not in {"complete", "partial", "blocked", "skipped"}:
            raise IntelligenceError("stage outcome must be complete, partial, blocked, or skipped")
        if actor_role not in STAGE_ROLES[stage]:
            raise IntelligenceError(
                f"role {actor_role!r} cannot complete {stage}; expected one of {sorted(STAGE_ROLES[stage])}"
            )
        row = self.connection.execute("SELECT * FROM pipeline_stages WHERE stage=?", (stage,)).fetchone()
        if row is None or row["state"] != "running":
            raise IntelligenceError(f"pipeline stage is not running: {stage}")
        evidence = self._validate_evidence(artifacts) if artifacts else []
        if outcome in {"complete", "partial"} and stage != "architecture" and not evidence:
            raise IntelligenceError("completed stages require at least one retained artifact")
        issues = self._stage_gate(stage, outcome)
        if issues and outcome == "complete":
            raise IntelligenceError("; ".join(issues))
        if outcome in {"partial", "blocked", "skipped"} and not reason.strip():
            raise IntelligenceError(f"{outcome} stage outcome requires a reason")
        now = utc_now()
        self.connection.execute(
            "UPDATE pipeline_stages SET state=?,actor_role=?,outcome=?,reason=?,artifacts_json=?,gate_json=?,completed_at=?,updated_at=? WHERE stage=?",
            (outcome, actor_role, outcome, reason.strip(), _json(evidence), _json({"issues": issues}), now, now, stage),
        )
        self.connection.commit()
        return next(item for item in self.pipeline_status()["stages"] if item["stage"] == stage)

    # Role-isolated context and durable web session semantics.

    @staticmethod
    def _redact(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: ("[REDACTED]" if SENSITIVE_KEY.search(str(key)) else IntelligenceStore._redact(item))
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [IntelligenceStore._redact(item) for item in value]
        return value

    def create_role_view(self, *, role: str, task_id: str, agent_identity: str, context: dict[str, Any]) -> dict[str, Any]:
        if role not in ROLE_POLICIES:
            raise IntelligenceError(f"unsupported role view: {role}")
        task_id = require_id(task_id, "taskId")
        agent_identity = require_id(agent_identity, "agentIdentity")
        policy = ROLE_POLICIES[role]
        allowed = set(policy["allowedSections"])
        selected = {key: value for key, value in context.items() if key in allowed}
        selected = self._redact(selected)
        context_digest = digest_value(selected)
        view_id = stable_id("view", role, task_id, agent_identity, context_digest)
        relative = Path("worktrees") / "role-views" / f"{view_id}.json"
        payload = {
            "schemaVersion": 1,
            "viewId": view_id,
            "role": role,
            "taskId": task_id,
            "agentIdentity": agent_identity,
            "policy": policy,
            "contextDigest": context_digest,
            "context": selected,
            "isolation": {
                "onlyThisContextIsAuthorized": True,
                "campaignRootAccess": False,
                "otherWorkerResultsVisible": False,
                "secretsVisible": False,
            },
        }
        atomic_json(self.root / relative, payload)
        self.connection.execute(
            "INSERT OR REPLACE INTO role_views(view_id,role,task_id,agent_identity,policy_json,context_digest,relative_path,created_at) VALUES(?,?,?,?,?,?,?,?)",
            (view_id, role, task_id, agent_identity, _json(policy), context_digest, relative.as_posix(), utc_now()),
        )
        self.connection.commit()
        return payload

    def bind_web_session(self, value: dict[str, Any]) -> dict[str, Any]:
        session_id = require_id(value.get("sessionId"), "sessionId")
        actor_id = require_id(value.get("actorId"), "actorId")
        role = require_text(value.get("role"), "role")
        tenant_id = require_id(value.get("tenantId"), "tenantId")
        permission_version = require_text(value.get("permissionVersion"), "permissionVersion")
        credential_ref = require_text(value.get("credentialRef"), "credentialRef")
        if SENSITIVE_KEY.search(credential_ref) and any(character in credential_ref for character in (" ", ".", "=")):
            raise IntelligenceError("credentialRef must name a broker reference, not contain a credential")
        fingerprint = str(value.get("credentialFingerprint") or "")
        cookie_digest = str(value.get("cookieArtifactSha256") or "")
        if not HEX_SHA256.fullmatch(fingerprint) or not HEX_SHA256.fullmatch(cookie_digest):
            raise IntelligenceError("credential and cookie artifacts require SHA-256 fingerprints")
        client_kind = str(value.get("clientKind") or "")
        if client_kind not in {"chrome-cdp", "http-replay", "browser-replay"}:
            raise IntelligenceError("unsupported session clientKind")
        authenticated_at = require_text(value.get("authenticatedAt"), "authenticatedAt")
        expires_at = require_text(value.get("expiresAt"), "expiresAt")
        authenticated_time = parse_timestamp(authenticated_at, "authenticatedAt")
        expiry_time = parse_timestamp(expires_at, "expiresAt")
        if expiry_time <= authenticated_time:
            raise IntelligenceError("expiresAt must be later than authenticatedAt")
        now = utc_now()
        self.connection.execute(
            "INSERT INTO web_sessions(session_id,actor_id,role,tenant_id,permission_version,credential_ref,credential_fingerprint,cookie_artifact_sha256,client_kind,state,authenticated_at,expires_at,invalidation_reason,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,'active',?,?, '',?,?)",
            (session_id, actor_id, role, tenant_id, permission_version, credential_ref, fingerprint, cookie_digest, client_kind, authenticated_at, expires_at, now, now),
        )
        self.connection.execute(
            "INSERT INTO web_session_events(session_id,event_type,actor_id,old_permission_version,new_permission_version,evidence_json,created_at) VALUES(?,'bound',?,'',?,'[]',?)",
            (session_id, actor_id, permission_version, now),
        )
        self.connection.commit()
        return self.web_session(session_id)

    def web_session(self, session_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM web_sessions WHERE session_id=?", (session_id,)).fetchone()
        if row is None:
            raise IntelligenceError(f"unknown web session: {session_id}")
        return dict(row)

    def validate_web_session(self, session_id: str, *, actor_id: str, role: str, tenant_id: str, permission_version: str) -> dict[str, Any]:
        value = self.web_session(session_id)
        if value["state"] != "active":
            raise IntelligenceError(f"web session is not active: {value['state']} ({value['invalidation_reason']})")
        if parse_timestamp(value["expires_at"], "expiresAt") <= dt.datetime.now(dt.timezone.utc):
            self.connection.execute(
                "UPDATE web_sessions SET state='expired',invalidation_reason='session expiry reached',updated_at=? WHERE session_id=?",
                (utc_now(), session_id),
            )
            self.connection.commit()
            raise IntelligenceError("web session is expired")
        expected = {
            "actor_id": actor_id, "role": role, "tenant_id": tenant_id,
            "permission_version": permission_version,
        }
        mismatches = [key for key, expected_value in expected.items() if value[key] != expected_value]
        if mismatches:
            raise IntelligenceError("web session authority mismatch: " + ", ".join(mismatches))
        return value

    def authority_changed(self, *, actor_id: str, permission_version: str, evidence: list[Any], reason: str, role: str | None = None, tenant_id: str | None = None) -> dict[str, Any]:
        actor_id = require_id(actor_id, "actorId")
        permission_version = require_text(permission_version, "permissionVersion")
        retained = self._validate_evidence(evidence)
        rows = list(self.connection.execute("SELECT * FROM web_sessions WHERE actor_id=? AND state='active'", (actor_id,)))
        invalidated: list[str] = []
        now = utc_now()
        with self.connection:
            for row in rows:
                authority_matches = (
                    row["permission_version"] == permission_version
                    and (role is None or row["role"] == role)
                    and (tenant_id is None or row["tenant_id"] == tenant_id)
                )
                if authority_matches:
                    continue
                self.connection.execute(
                    "UPDATE web_sessions SET state='stale',invalidation_reason=?,updated_at=? WHERE session_id=?",
                    (require_text(reason, "reason"), now, row["session_id"]),
                )
                self.connection.execute(
                    "INSERT INTO web_session_events(session_id,event_type,actor_id,old_permission_version,new_permission_version,evidence_json,created_at) VALUES(?,'authority-changed',?,?,?,?,?)",
                    (row["session_id"], actor_id, row["permission_version"], permission_version, _json(retained), now),
                )
                invalidated.append(row["session_id"])
        return {
            "actorId": actor_id,
            "role": role,
            "tenantId": tenant_id,
            "permissionVersion": permission_version,
            "invalidatedSessions": invalidated,
        }

    def status(self) -> dict[str, Any]:
        return {
            "architecture": {
                row["kind"]: row["n"]
                for row in self.connection.execute("SELECT kind,COUNT(*) AS n FROM architecture_objects GROUP BY kind")
            },
            "sourceCoverage": self.source_coverage_report(),
            "pipeline": self.pipeline_status(),
            "observations": self.connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0],
            "hypotheses": {
                row["disposition"]: row["n"]
                for row in self.connection.execute("SELECT disposition,COUNT(*) AS n FROM hypotheses GROUP BY disposition")
            },
            "sessions": {
                row["state"]: row["n"]
                for row in self.connection.execute("SELECT state,COUNT(*) AS n FROM web_sessions GROUP BY state")
            },
        }


def _parse_json_argument(value: str) -> Any:
    path = Path(value)
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    return json.loads(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="initialize the campaign intelligence plane")
    init.add_argument("campaign")

    status = subparsers.add_parser("status", help="show canonical intelligence state")
    status.add_argument("campaign")

    architecture = subparsers.add_parser("architecture-ingest", help="ingest canonical architecture objects and relations")
    architecture.add_argument("campaign")
    architecture.add_argument("specification")

    inventory = subparsers.add_parser("source-inventory", help="inventory source files and initialize coverage")
    inventory.add_argument("campaign")
    inventory.add_argument("source_root")

    coverage = subparsers.add_parser("source-cover", help="update one source coverage entry")
    coverage.add_argument("campaign")
    coverage.add_argument("path")
    coverage.add_argument("--state", required=True, choices=sorted(COVERAGE_STATES))
    coverage.add_argument("--assignee", default="")
    coverage.add_argument("--mechanism", action="append", default=[])
    coverage.add_argument("--boundary", action="append", default=[])
    coverage.add_argument("--evidence", action="append", default=[])
    coverage.add_argument("--reason", default="")

    location = subparsers.add_parser("source-admit", help="admit an exact source location")
    location.add_argument("campaign")
    location.add_argument("source_root")
    location.add_argument("path")
    location.add_argument("--revision", required=True)
    location.add_argument("--start", required=True, type=int)
    location.add_argument("--end", required=True, type=int)
    location.add_argument("--symbol", default="")
    location.add_argument("--actor", required=True)

    report_validate = subparsers.add_parser("report-validate", help="validate report citations against admitted, unchanged source")
    report_validate.add_argument("campaign")
    report_validate.add_argument("source_root")
    report_validate.add_argument("manifest")

    observe = subparsers.add_parser("observe", help="admit an immutable source or runtime observation")
    observe.add_argument("campaign")
    observe.add_argument("observation")

    task_ingest = subparsers.add_parser("task-result-ingest", help="admit validated scheduler observations into the intelligence plane")
    task_ingest.add_argument("campaign")
    task_ingest.add_argument("result")
    task_ingest.add_argument("--task", required=True)
    task_ingest.add_argument("--worker", required=True)
    task_ingest.add_argument("--result-path", required=True)

    reconcile = subparsers.add_parser("reconcile", help="reconcile all observations for one mechanism")
    reconcile.add_argument("campaign")
    reconcile.add_argument("mechanism")
    reconcile.add_argument("--actor", required=True)

    hypothesis_create = subparsers.add_parser("hypothesis-create", help="create a retained hypothesis from admitted evidence")
    hypothesis_create.add_argument("campaign")
    hypothesis_create.add_argument("specification")

    hypothesis_promote = subparsers.add_parser("hypothesis-promote", help="advance one machine-gated hypothesis level")
    hypothesis_promote.add_argument("campaign")
    hypothesis_promote.add_argument("hypothesis_id")
    hypothesis_promote.add_argument("target_level", choices=HYPOTHESIS_LEVELS[1:])
    hypothesis_promote.add_argument("--actor", required=True)
    hypothesis_promote.add_argument("--reason", required=True)
    hypothesis_promote.add_argument("--observation", action="append", default=[])
    hypothesis_promote.add_argument("--capabilities")

    hypothesis_dispose = subparsers.add_parser("hypothesis-dispose", help="record a terminal hypothesis disposition")
    hypothesis_dispose.add_argument("campaign")
    hypothesis_dispose.add_argument("hypothesis_id")
    hypothesis_dispose.add_argument("disposition", choices=sorted(HYPOTHESIS_DISPOSITIONS - {"active"}))
    hypothesis_dispose.add_argument("--actor", required=True)
    hypothesis_dispose.add_argument("--reason", required=True)
    hypothesis_dispose.add_argument("--blocker", default="")
    hypothesis_dispose.add_argument("--reopen-when", action="append", default=[])
    hypothesis_dispose.add_argument("--evidence", action="append", default=[])

    stage_start = subparsers.add_parser("stage-start", help="start the current eligible stage")
    stage_start.add_argument("campaign")
    stage_start.add_argument("stage", choices=PIPELINE_STAGES)
    stage_start.add_argument("--role", required=True)

    stage_complete = subparsers.add_parser("stage-complete", help="finish a running stage after its gates pass")
    stage_complete.add_argument("campaign")
    stage_complete.add_argument("stage", choices=PIPELINE_STAGES)
    stage_complete.add_argument("--role", required=True)
    stage_complete.add_argument("--outcome", required=True, choices=("complete", "partial", "blocked", "skipped"))
    stage_complete.add_argument("--reason", default="")
    stage_complete.add_argument("--artifact", action="append", default=[])

    role = subparsers.add_parser("role-view", help="materialize a role-isolated context bundle")
    role.add_argument("campaign")
    role.add_argument("role", choices=sorted(ROLE_POLICIES))
    role.add_argument("task_id")
    role.add_argument("agent_identity")
    role.add_argument("context")

    critic = subparsers.add_parser("critic", help="run the mandatory production viability gate")
    critic.add_argument("campaign")
    critic.add_argument("hypothesis_id")
    critic.add_argument("review")
    critic.add_argument("--reviewer", required=True)

    adversarial = subparsers.add_parser("adversarial-review", help="retain an independent hypothesis and observer challenge")
    adversarial.add_argument("campaign")
    adversarial.add_argument("hypothesis_id")
    adversarial.add_argument("review")
    adversarial.add_argument("--reviewer", required=True)

    bind = subparsers.add_parser("session-bind", help="bind a browser or HTTP session to exact authority")
    bind.add_argument("campaign")
    bind.add_argument("session")

    changed = subparsers.add_parser("session-authority-changed", help="invalidate sessions after a permission change")
    changed.add_argument("campaign")
    changed.add_argument("actor_id")
    changed.add_argument("permission_version")
    changed.add_argument("--reason", required=True)
    changed.add_argument("--evidence", action="append", required=True)
    changed.add_argument("--role")
    changed.add_argument("--tenant")

    validate_session = subparsers.add_parser("session-validate", help="validate an exact actor, tenant, role, and permission binding")
    validate_session.add_argument("campaign")
    validate_session.add_argument("session_id")
    validate_session.add_argument("--actor", required=True)
    validate_session.add_argument("--role", required=True)
    validate_session.add_argument("--tenant", required=True)
    validate_session.add_argument("--permission-version", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        root = campaign_root(args.campaign)
        store = IntelligenceStore(root)
        try:
            if args.command == "init":
                result = {"database": str(store.database_path), "pipeline": store.pipeline_status()}
            elif args.command == "status":
                result = store.status()
            elif args.command == "architecture-ingest":
                result = store.ingest_architecture(read_object(Path(args.specification)))
            elif args.command == "source-inventory":
                result = store.inventory_source(Path(args.source_root))
            elif args.command == "source-cover":
                result = store.mark_source_coverage(
                    args.path, state=args.state, assignee=args.assignee,
                    mechanisms=args.mechanism, boundaries=args.boundary,
                    evidence=args.evidence, reason=args.reason,
                )
            elif args.command == "source-admit":
                result = store.admit_source_location(
                    source_root=Path(args.source_root), repository_revision=args.revision,
                    path=args.path, start_line=args.start, end_line=args.end,
                    symbol=args.symbol, admitted_by=args.actor,
                )
            elif args.command == "report-validate":
                result = store.validate_report_manifest(
                    read_object(Path(args.manifest)), source_root=Path(args.source_root),
                )
            elif args.command == "observe":
                result = store.admit_observation(read_object(Path(args.observation)))
            elif args.command == "task-result-ingest":
                result = store.ingest_task_result(
                    read_object(Path(args.result)), task_id=args.task,
                    worker_identity=args.worker, result_path=args.result_path,
                )
            elif args.command == "reconcile":
                result = store.reconcile(args.mechanism, actor_identity=args.actor)
            elif args.command == "hypothesis-create":
                result = store.create_hypothesis(read_object(Path(args.specification)))
            elif args.command == "hypothesis-promote":
                capabilities = None
                if args.capabilities:
                    capabilities = _parse_json_argument(args.capabilities)
                    if not isinstance(capabilities, list):
                        raise IntelligenceError("capabilities must be a JSON array")
                result = store.promote_hypothesis(
                    args.hypothesis_id, args.target_level, actor_identity=args.actor,
                    reason=args.reason, observation_ids=args.observation,
                    capabilities=capabilities,
                )
            elif args.command == "hypothesis-dispose":
                result = store.dispose_hypothesis(
                    args.hypothesis_id, args.disposition, actor_identity=args.actor,
                    reason=args.reason, blocker=args.blocker,
                    reopening=args.reopen_when, evidence=args.evidence,
                )
            elif args.command == "stage-start":
                result = store.start_stage(args.stage, actor_role=args.role)
            elif args.command == "stage-complete":
                result = store.complete_stage(
                    args.stage, actor_role=args.role, outcome=args.outcome,
                    reason=args.reason, artifacts=args.artifact,
                )
            elif args.command == "role-view":
                result = store.create_role_view(
                    role=args.role, task_id=args.task_id, agent_identity=args.agent_identity,
                    context=read_object(Path(args.context)),
                )
            elif args.command == "critic":
                result = store.production_review(
                    args.hypothesis_id, read_object(Path(args.review)),
                    reviewer_identity=args.reviewer,
                )
            elif args.command == "adversarial-review":
                result = store.adversarial_review(
                    args.hypothesis_id, read_object(Path(args.review)),
                    reviewer_identity=args.reviewer,
                )
            elif args.command == "session-bind":
                result = store.bind_web_session(read_object(Path(args.session)))
            elif args.command == "session-authority-changed":
                result = store.authority_changed(
                    actor_id=args.actor_id, permission_version=args.permission_version,
                    evidence=args.evidence, reason=args.reason,
                    role=args.role, tenant_id=args.tenant,
                )
            elif args.command == "session-validate":
                result = store.validate_web_session(
                    args.session_id, actor_id=args.actor, role=args.role,
                    tenant_id=args.tenant,
                    permission_version=args.permission_version,
                )
            else:
                raise IntelligenceError(f"unsupported command: {args.command}")
        finally:
            store.close()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (IntelligenceError, OSError, sqlite3.Error, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
