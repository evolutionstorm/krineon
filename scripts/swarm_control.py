#!/usr/bin/env python3
"""Durable event-driven coordination and operational safety for Krineon.

The control plane turns retained observations into typed experiment proposals,
but it never authorizes target execution.  It also owns observation trust
ancestry, volatility, independent-verifier and model routing, persistent
cleanup, owned OOB receipts, and provider/tool health telemetry.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
TRUST_TIERS = {
    "untrusted-target": 0,
    "worker-analysis": 1,
    "tool-measurement": 2,
    "coordinator-execution": 3,
    "independent-observer": 4,
    "owner-policy": 5,
}
CONFIDENCE_RANK = {
    "hypothesized": 0,
    "source-supported": 1,
    "observed": 2,
    "runtime-observed": 3,
    "coordinator-replayed": 4,
    "independently-replayed": 5,
}
VOLATILITY_DEFAULT_SECONDS = {
    "immutable": None,
    "source-revision": None,
    "deployment": 86_400,
    "process": 21_600,
    "session": 3_600,
    "token": 900,
    "ephemeral": 300,
}
PROPOSAL_STATES = {"pending", "approved", "rejected", "scheduled", "expired"}
COMPONENT_STATES = {"unknown", "healthy", "degraded", "unhealthy", "disabled"}


class ControlError(Exception):
    """The control-plane contract or state is invalid."""


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def timestamp(value: dt.datetime | None = None) -> str:
    return (value or utc_now()).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_time(value: Any, field: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise ControlError(f"{field} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ControlError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(value: Any) -> str:
    payload = value if isinstance(value, bytes) else canonical(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def stable_id(prefix: str, *values: Any) -> str:
    return f"{prefix}-{digest(values)[:20]}"


def require_id(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not SAFE_ID.fullmatch(result):
        raise ControlError(f"{field} must match {SAFE_ID.pattern}")
    return result


def require_text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise ControlError(f"{field} is required")
    return result


def string_list(value: Any, field: str, *, nonempty: bool = False) -> list[str]:
    if value is None:
        value = []
    if not isinstance(value, list):
        raise ControlError(f"{field} must be an array")
    result = list(dict.fromkeys(str(item).strip() for item in value if str(item).strip()))
    if nonempty and not result:
        raise ControlError(f"{field} must be non-empty")
    return result


def argv_list(value: Any, field: str) -> list[str]:
    """Validate an argv without changing ordering, duplicates, or empty arguments."""
    if not isinstance(value, list) or not value:
        raise ControlError(f"{field} must be a non-empty array")
    if not all(isinstance(item, str) and "\x00" not in item for item in value):
        raise ControlError(f"{field} entries must be strings without NUL bytes")
    if not value[0].strip():
        raise ControlError(f"{field}[0] must name an executable")
    return list(value)


def read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ControlError(f"missing file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ControlError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ControlError(f"expected JSON object in {path}")
    return value


def campaign_root(value: str | Path) -> Path:
    root = Path(value).expanduser().resolve()
    if not (root / "campaign.json").is_file():
        raise ControlError(f"not a Krineon campaign: {root}")
    return root


def contained_path(root: Path, value: Any, field: str, *, exists: bool = True) -> Path:
    raw = str(value or "").strip()
    if not raw or Path(raw).is_absolute():
        raise ControlError(f"{field} must be campaign-relative")
    result = (root / raw).resolve()
    try:
        result.relative_to(root)
    except ValueError as exc:
        raise ControlError(f"{field} escapes the campaign root") from exc
    if exists and not result.exists():
        raise ControlError(f"{field} does not exist: {raw}")
    return result


def ensure_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS swarm_observation_meta (
          observation_id TEXT PRIMARY KEY,
          trust_tier TEXT NOT NULL,
          trust_rank INTEGER NOT NULL,
          content_class TEXT NOT NULL,
          authority_effect TEXT NOT NULL,
          parents_json TEXT NOT NULL,
          ancestry_digest TEXT NOT NULL,
          has_untrusted_ancestor INTEGER NOT NULL,
          policy_eligible INTEGER NOT NULL,
          quarantined INTEGER NOT NULL,
          quarantine_reason TEXT NOT NULL,
          volatility_class TEXT NOT NULL,
          expires_at TEXT,
          stale INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS swarm_subscriptions (
          subscription_id TEXT PRIMARY KEY,
          owner_id TEXT NOT NULL,
          name TEXT NOT NULL,
          kinds_json TEXT NOT NULL,
          mechanisms_json TEXT NOT NULL,
          capabilities_json TEXT NOT NULL,
          min_trust_rank INTEGER NOT NULL,
          min_confidence_rank INTEGER NOT NULL,
          allow_untrusted_ancestry INTEGER NOT NULL,
          include_quarantined INTEGER NOT NULL,
          exclude_owner INTEGER NOT NULL,
          proposal_json TEXT NOT NULL,
          enabled INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS swarm_experiment_proposals (
          proposal_id TEXT PRIMARY KEY,
          subscription_id TEXT NOT NULL,
          observation_id TEXT NOT NULL,
          proposed_by TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('pending','approved','rejected','scheduled','expired')),
          blueprint_json TEXT NOT NULL,
          reason TEXT NOT NULL,
          reviewed_by TEXT,
          reviewed_at TEXT,
          scheduled_task_id TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          UNIQUE(subscription_id, observation_id)
        );
        CREATE TABLE IF NOT EXISTS swarm_verifiers (
          verifier_id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          observer_class TEXT NOT NULL,
          independence_domains_json TEXT NOT NULL,
          capabilities_json TEXT NOT NULL,
          adapter TEXT NOT NULL,
          fixed_cost REAL NOT NULL,
          expected_seconds REAL NOT NULL,
          effect_risk REAL NOT NULL,
          information_gain REAL NOT NULL,
          enabled INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS swarm_verifier_selections (
          selection_id TEXT PRIMARY KEY,
          claim_id TEXT NOT NULL,
          verifier_id TEXT NOT NULL,
          required_capability TEXT NOT NULL,
          origin_classes_json TEXT NOT NULL,
          origin_domains_json TEXT NOT NULL,
          score REAL NOT NULL,
          rationale_json TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS swarm_models (
          model_id TEXT PRIMARY KEY,
          provider TEXT NOT NULL,
          model TEXT NOT NULL,
          family TEXT NOT NULL,
          roles_json TEXT NOT NULL,
          capabilities_json TEXT NOT NULL,
          input_cost REAL NOT NULL,
          output_cost REAL NOT NULL,
          expected_latency REAL NOT NULL,
          quality REAL NOT NULL,
          cache_allowed INTEGER NOT NULL,
          enabled INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS swarm_model_routes (
          route_id TEXT PRIMARY KEY,
          task_id TEXT NOT NULL,
          role TEXT NOT NULL,
          model_id TEXT NOT NULL,
          prior_routes_json TEXT NOT NULL,
          score REAL NOT NULL,
          cache_allowed INTEGER NOT NULL,
          rationale_json TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS swarm_components (
          component_id TEXT PRIMARY KEY,
          kind TEXT NOT NULL,
          name TEXT NOT NULL,
          version TEXT NOT NULL,
          capabilities_json TEXT NOT NULL,
          state TEXT NOT NULL,
          detail TEXT NOT NULL,
          consecutive_failures INTEGER NOT NULL DEFAULT 0,
          last_latency_ms REAL,
          last_checked_at TEXT,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS swarm_invocations (
          invocation_id TEXT PRIMARY KEY,
          component_id TEXT NOT NULL,
          task_id TEXT,
          operation TEXT NOT NULL,
          outcome TEXT NOT NULL,
          latency_ms REAL NOT NULL,
          input_tokens INTEGER NOT NULL,
          output_tokens INTEGER NOT NULL,
          cost REAL NOT NULL,
          artifact_refs_json TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS swarm_cleanup_actions (
          action_id TEXT PRIMARY KEY,
          description TEXT NOT NULL,
          recipe_sha256 TEXT NOT NULL,
          recipe_path TEXT NOT NULL,
          stack_order INTEGER NOT NULL,
          idempotency_key TEXT NOT NULL UNIQUE,
          state TEXT NOT NULL CHECK(state IN ('pending','running','executed','verified','failed','cancelled')),
          approved_by TEXT NOT NULL,
          registered_by TEXT NOT NULL,
          attempt INTEGER NOT NULL DEFAULT 0,
          last_error TEXT NOT NULL,
          registered_at TEXT NOT NULL,
          started_at TEXT,
          completed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS swarm_oob_tokens (
          token_id TEXT PRIMARY KEY,
          experiment_id TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('positive','control')),
          token_sha256 TEXT NOT NULL UNIQUE,
          protocol TEXT NOT NULL,
          max_callbacks INTEGER NOT NULL,
          expires_at TEXT NOT NULL,
          issued_by TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS swarm_oob_receipts (
          receipt_id TEXT PRIMARY KEY,
          token_id TEXT NOT NULL,
          protocol TEXT NOT NULL,
          source TEXT NOT NULL,
          method TEXT NOT NULL,
          metadata_json TEXT NOT NULL,
          received_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS swarm_events (
          event_id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_type TEXT NOT NULL,
          actor_id TEXT NOT NULL,
          object_id TEXT,
          payload_json TEXT NOT NULL,
          created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS swarm_proposals_state_idx
          ON swarm_experiment_proposals(state, created_at);
        CREATE INDEX IF NOT EXISTS swarm_meta_expiry_idx
          ON swarm_observation_meta(stale, expires_at);
        CREATE INDEX IF NOT EXISTS swarm_events_type_idx
          ON swarm_events(event_type, created_at);
        CREATE INDEX IF NOT EXISTS swarm_invocations_component_idx
          ON swarm_invocations(component_id, created_at);
        """
    )


class ControlStore:
    """Campaign-local durable coordination state."""

    def __init__(
        self,
        root: Path,
        connection: sqlite3.Connection | None = None,
        *,
        own_connection: bool | None = None,
    ):
        self.root = campaign_root(root)
        if connection is None:
            connection = sqlite3.connect(self.root / "orchestration.db")
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA busy_timeout=5000")
            self.own_connection = True if own_connection is None else own_connection
        else:
            self.own_connection = False if own_connection is None else own_connection
        self.connection = connection
        ensure_schema(self.connection)

    def close(self) -> None:
        if self.own_connection:
            self.connection.commit()
            self.connection.close()

    def event(self, event_type: str, actor_id: str, object_id: str | None, payload: Any) -> None:
        self.connection.execute(
            "INSERT INTO swarm_events(event_type,actor_id,object_id,payload_json,created_at) VALUES(?,?,?,?,?)",
            (require_text(event_type, "event type"), require_text(actor_id, "actor id"), object_id, canonical(payload), timestamp()),
        )

    def install_defaults(self) -> None:
        defaults = [
            {
                "id": "default-runtime-differential-review",
                "ownerId": "coordinator",
                "name": "Adversarially review runtime differentials",
                "kinds": ["runtime-differential", "fuzzing"],
                "minTrust": "tool-measurement",
                "minConfidence": "runtime-observed",
                "allowUntrustedAncestry": True,
                "proposal": {
                    "title": "Adversarial review of {observationId}",
                    "lane": "adversarial-review",
                    "objective": "Challenge {mechanism} and distinguish false-positive explanations",
                    "approachFamilies": ["validation-replay"],
                    "successCriteria": ["fresh controls either reproduce or refute the observed differential"],
                    "priority": 1800,
                    "maxAttempts": 2,
                },
            },
            {
                "id": "default-verified-primitive-chain",
                "ownerId": "coordinator",
                "name": "Compose verified primitives toward a terminal",
                "minTrust": "coordinator-execution",
                "minConfidence": "coordinator-replayed",
                "proposal": {
                    "title": "Compose verified observation {observationId}",
                    "lane": "chain-composition",
                    "objective": "Connect {mechanism} to one compatible missing authority edge without inventing a capability",
                    "approachFamilies": ["chain-composition"],
                    "successCriteria": ["record a compatible evidenced edge or a scoped refutation"],
                    "priority": 2200,
                    "maxAttempts": 3,
                },
            },
        ]
        for value in defaults:
            self.add_subscription(value, actor="bootstrap", replace=False)

    def add_subscription(self, raw: dict[str, Any], *, actor: str, replace: bool = True) -> str:
        subscription_id = require_id(raw.get("id") or stable_id("SUB", raw), "subscription.id")
        owner = require_id(raw.get("ownerId") or actor, "subscription.ownerId")
        name = require_text(raw.get("name"), "subscription.name")
        min_trust = str(raw.get("minTrust") or "worker-analysis")
        if min_trust not in TRUST_TIERS:
            raise ControlError("subscription.minTrust is unsupported")
        min_confidence = str(raw.get("minConfidence") or "hypothesized")
        if min_confidence not in CONFIDENCE_RANK:
            raise ControlError("subscription.minConfidence is unsupported")
        proposal = raw.get("proposal")
        if not isinstance(proposal, dict):
            raise ControlError("subscription.proposal must be an object")
        for field in ("title", "lane", "objective"):
            require_text(proposal.get(field), f"subscription.proposal.{field}")
        string_list(proposal.get("approachFamilies"), "proposal.approachFamilies", nonempty=True)
        string_list(proposal.get("successCriteria"), "proposal.successCriteria", nonempty=True)
        now = timestamp()
        values = (
            subscription_id, owner, name,
            canonical(string_list(raw.get("kinds"), "subscription.kinds")),
            canonical(string_list(raw.get("mechanisms"), "subscription.mechanisms")),
            canonical(string_list(raw.get("capabilities"), "subscription.capabilities")),
            TRUST_TIERS[min_trust], CONFIDENCE_RANK[min_confidence],
            int(bool(raw.get("allowUntrustedAncestry"))),
            int(bool(raw.get("includeQuarantined"))),
            int(raw.get("excludeOwner", True) is not False), canonical(proposal),
            int(raw.get("enabled", True) is not False), now, now,
        )
        if replace:
            self.connection.execute(
                "INSERT INTO swarm_subscriptions(subscription_id,owner_id,name,kinds_json,mechanisms_json,capabilities_json,"
                "min_trust_rank,min_confidence_rank,allow_untrusted_ancestry,include_quarantined,exclude_owner,proposal_json,enabled,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(subscription_id) DO UPDATE SET owner_id=excluded.owner_id,"
                "name=excluded.name,kinds_json=excluded.kinds_json,mechanisms_json=excluded.mechanisms_json,"
                "capabilities_json=excluded.capabilities_json,min_trust_rank=excluded.min_trust_rank,"
                "min_confidence_rank=excluded.min_confidence_rank,allow_untrusted_ancestry=excluded.allow_untrusted_ancestry,"
                "include_quarantined=excluded.include_quarantined,exclude_owner=excluded.exclude_owner,proposal_json=excluded.proposal_json,"
                "enabled=excluded.enabled,updated_at=excluded.updated_at",
                values,
            )
        else:
            self.connection.execute(
                "INSERT OR IGNORE INTO swarm_subscriptions(subscription_id,owner_id,name,kinds_json,mechanisms_json,capabilities_json,"
                "min_trust_rank,min_confidence_rank,allow_untrusted_ancestry,include_quarantined,exclude_owner,proposal_json,enabled,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                values,
            )
            if not self.connection.execute("SELECT changes() AS n").fetchone()["n"]:
                return subscription_id
        self.event("subscription-upserted", actor, subscription_id, {"owner": owner, "name": name})
        return subscription_id

    def _derive_trust(self, row: sqlite3.Row, payload: dict[str, Any]) -> str:
        requested = str(payload.get("trustTier") or "").strip()
        confidence = str(row["confidence"])
        kind = str(row["kind"])
        maximum = {
            "independently-replayed": "independent-observer",
            "coordinator-replayed": "coordinator-execution",
            "runtime-observed": "tool-measurement",
            "observed": "tool-measurement",
            "source-supported": "worker-analysis",
            "hypothesized": "worker-analysis",
        }.get(confidence, "worker-analysis")
        if (
            kind == "owner-rule"
            and str(row["worker_id"]) == "coordinator"
            and confidence in {"coordinator-replayed", "independently-replayed"}
        ):
            maximum = "owner-policy"
        if kind in {"target-response", "imported-request", "browser-content", "external-content"}:
            maximum = "untrusted-target"
        if requested:
            if requested not in TRUST_TIERS:
                raise ControlError(f"observation {row['observation_id']} requests unsupported trust tier")
            if TRUST_TIERS[requested] > TRUST_TIERS[maximum]:
                raise ControlError(
                    f"observation {row['observation_id']} cannot claim {requested} from {confidence}/{kind}"
                )
            return requested
        return maximum

    def publish_observation(self, observation_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM depth_observations WHERE observation_id=?", (observation_id,)
        ).fetchone()
        if row is None:
            raise ControlError(f"unknown depth observation: {observation_id}")
        payload = json.loads(row["payload_json"])
        if not isinstance(payload, dict):
            payload = {}
        trust = self._derive_trust(row, payload)
        parents = string_list(payload.get("parentObservationIds"), "parentObservationIds")
        if observation_id in parents:
            raise ControlError("an observation cannot be its own parent")
        parent_records = []
        for parent in parents:
            record = self.connection.execute(
                "SELECT * FROM swarm_observation_meta WHERE observation_id=?", (parent,)
            ).fetchone()
            if record is None:
                raise ControlError(f"parent observation has no trust record: {parent}")
            parent_records.append(record)
        has_untrusted = TRUST_TIERS[trust] == 0 or any(
            bool(parent["has_untrusted_ancestor"]) or int(parent["trust_rank"]) == 0
            for parent in parent_records
        )
        content_class = str(payload.get("contentClass") or "research-observation")
        authority_effect = str(payload.get("authorityEffect") or "none")
        forbidden_content = content_class in {"control-instruction", "policy", "authorization"}
        quarantined = forbidden_content and (
            TRUST_TIERS[trust] < TRUST_TIERS["coordinator-execution"] or has_untrusted
        )
        quarantine_reason = (
            "untrusted or insufficiently reviewed content attempted to influence control policy"
            if quarantined else ""
        )
        policy_eligible = (
            not quarantined
            and not has_untrusted
            and TRUST_TIERS[trust] >= TRUST_TIERS["coordinator-execution"]
            and authority_effect in {"none", "scheduling-only"}
        ) or trust == "owner-policy"
        volatility = str(payload.get("volatilityClass") or "immutable")
        if volatility not in VOLATILITY_DEFAULT_SECONDS:
            raise ControlError(f"unsupported volatility class: {volatility}")
        ttl = payload.get("ttlSeconds", VOLATILITY_DEFAULT_SECONDS[volatility])
        expires_at = None
        if ttl is not None:
            if not isinstance(ttl, int) or ttl < 1 or ttl > 31_536_000:
                raise ControlError("ttlSeconds must be between 1 and 31536000")
            expires_at = timestamp(utc_now() + dt.timedelta(seconds=ttl))
        ancestry = digest({
            "observation": observation_id,
            "trust": trust,
            "parents": sorted((parent["observation_id"], parent["ancestry_digest"]) for parent in parent_records),
        })
        now = timestamp()
        self.connection.execute(
            "INSERT INTO swarm_observation_meta(observation_id,trust_tier,trust_rank,content_class,authority_effect,parents_json,"
            "ancestry_digest,has_untrusted_ancestor,policy_eligible,quarantined,quarantine_reason,volatility_class,expires_at,stale,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?) ON CONFLICT(observation_id) DO UPDATE SET trust_tier=excluded.trust_tier,"
            "trust_rank=excluded.trust_rank,content_class=excluded.content_class,authority_effect=excluded.authority_effect,"
            "parents_json=excluded.parents_json,ancestry_digest=excluded.ancestry_digest,has_untrusted_ancestor=excluded.has_untrusted_ancestor,"
            "policy_eligible=excluded.policy_eligible,quarantined=excluded.quarantined,quarantine_reason=excluded.quarantine_reason,"
            "volatility_class=excluded.volatility_class,expires_at=excluded.expires_at,stale=0,updated_at=excluded.updated_at",
            (
                observation_id, trust, TRUST_TIERS[trust], content_class, authority_effect,
                canonical(parents), ancestry, int(has_untrusted), int(policy_eligible), int(quarantined),
                quarantine_reason, volatility, expires_at, now, now,
            ),
        )
        proposals = self.evaluate_subscriptions(observation_id)
        self.event(
            "observation-published", str(row["worker_id"]), observation_id,
            {"trustTier": trust, "quarantined": quarantined, "proposals": proposals},
        )
        return {
            "observationId": observation_id,
            "trustTier": trust,
            "ancestryDigest": ancestry,
            "hasUntrustedAncestor": has_untrusted,
            "policyEligible": policy_eligible,
            "quarantined": quarantined,
            "volatilityClass": volatility,
            "expiresAt": expires_at,
            "proposals": proposals,
        }

    @staticmethod
    def _render(value: str, observation: sqlite3.Row) -> str:
        replacements = {
            "{observationId}": str(observation["observation_id"]),
            "{mechanism}": str(observation["mechanism"]),
            "{summary}": str(observation["summary"]),
            "{taskId}": str(observation["task_id"]),
        }
        for before, after in replacements.items():
            value = value.replace(before, after)
        return value

    def evaluate_subscriptions(self, observation_id: str) -> list[str]:
        observation = self.connection.execute(
            "SELECT d.*,m.trust_rank,m.has_untrusted_ancestor,m.quarantined,m.stale "
            "FROM depth_observations d JOIN swarm_observation_meta m ON m.observation_id=d.observation_id "
            "WHERE d.observation_id=?", (observation_id,)
        ).fetchone()
        if observation is None:
            return []
        produced = set(json.loads(observation["produces_json"]))
        created: list[str] = []
        for subscription in self.connection.execute(
            "SELECT * FROM swarm_subscriptions WHERE enabled=1 ORDER BY created_at,subscription_id"
        ).fetchall():
            kinds = set(json.loads(subscription["kinds_json"]))
            mechanisms = set(json.loads(subscription["mechanisms_json"]))
            capabilities = set(json.loads(subscription["capabilities_json"]))
            if kinds and observation["kind"] not in kinds:
                continue
            if mechanisms and observation["mechanism"] not in mechanisms:
                continue
            if capabilities and not capabilities.issubset(produced):
                continue
            if int(observation["trust_rank"]) < int(subscription["min_trust_rank"]):
                continue
            if CONFIDENCE_RANK.get(str(observation["confidence"]), -1) < int(subscription["min_confidence_rank"]):
                continue
            if observation["has_untrusted_ancestor"] and not subscription["allow_untrusted_ancestry"]:
                continue
            if observation["quarantined"] and not subscription["include_quarantined"]:
                continue
            if observation["stale"]:
                continue
            if subscription["exclude_owner"] and observation["worker_id"] == subscription["owner_id"]:
                continue
            template = json.loads(subscription["proposal_json"])
            blueprint = dict(template)
            for field in ("title", "objective"):
                blueprint[field] = self._render(str(blueprint[field]), observation)
            blueprint["sourceObservationId"] = observation_id
            blueprint["excludedWorkers"] = list(dict.fromkeys(
                string_list(blueprint.get("excludedWorkers"), "proposal.excludedWorkers")
                + [str(observation["worker_id"])]
            ))
            proposal_id = stable_id("PROP", subscription["subscription_id"], observation_id)
            now = timestamp()
            self.connection.execute(
                "INSERT OR IGNORE INTO swarm_experiment_proposals(proposal_id,subscription_id,observation_id,proposed_by,state,"
                "blueprint_json,reason,created_at,updated_at) VALUES(?,?,?,?, 'pending',?,?,?,?)",
                (
                    proposal_id, subscription["subscription_id"], observation_id,
                    subscription["owner_id"], canonical(blueprint),
                    "typed subscription matched retained observation; coordinator review required", now, now,
                ),
            )
            if self.connection.execute(
                "SELECT changes() AS n"
            ).fetchone()["n"]:
                created.append(proposal_id)
                self.event("experiment-proposed", str(subscription["owner_id"]), proposal_id, blueprint)
        return created

    def review_proposal(self, proposal_id: str, *, reviewer: str, decision: str, reason: str) -> None:
        if decision not in {"approved", "rejected"}:
            raise ControlError("proposal decision must be approved or rejected")
        row = self.connection.execute(
            "SELECT p.*,m.quarantined,m.stale FROM swarm_experiment_proposals p "
            "JOIN swarm_observation_meta m ON m.observation_id=p.observation_id WHERE p.proposal_id=?",
            (proposal_id,),
        ).fetchone()
        if row is None or row["state"] != "pending":
            raise ControlError("proposal is not pending")
        if decision == "approved" and (row["quarantined"] or row["stale"]):
            raise ControlError("quarantined or stale evidence cannot authorize a proposal")
        now = timestamp()
        self.connection.execute(
            "UPDATE swarm_experiment_proposals SET state=?,reason=?,reviewed_by=?,reviewed_at=?,updated_at=? WHERE proposal_id=?",
            (decision, require_text(reason, "review reason"), require_id(reviewer, "reviewer"), now, now, proposal_id),
        )
        self.event(f"proposal-{decision}", reviewer, proposal_id, {"reason": reason})

    def proposal_blueprint(self, proposal_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM swarm_experiment_proposals WHERE proposal_id=?", (proposal_id,)
        ).fetchone()
        if row is None:
            raise ControlError("unknown proposal")
        return {"state": row["state"], **json.loads(row["blueprint_json"])}

    def mark_scheduled(self, proposal_id: str, task_id: str, actor: str) -> None:
        update = self.connection.execute(
            "UPDATE swarm_experiment_proposals SET state='scheduled',scheduled_task_id=?,updated_at=? "
            "WHERE proposal_id=? AND state='approved'",
            (require_id(task_id, "task id"), timestamp(), proposal_id),
        )
        if update.rowcount != 1:
            raise ControlError("proposal is not approved")
        self.event("proposal-scheduled", actor, proposal_id, {"taskId": task_id})

    def sweep_volatility(self) -> list[str]:
        now = timestamp()
        rows = self.connection.execute(
            "SELECT observation_id FROM swarm_observation_meta WHERE stale=0 AND expires_at IS NOT NULL AND expires_at<=?",
            (now,),
        ).fetchall()
        expired = [str(row["observation_id"]) for row in rows]
        for observation_id in expired:
            self.connection.execute(
                "UPDATE swarm_observation_meta SET stale=1,updated_at=? WHERE observation_id=?",
                (now, observation_id),
            )
            self.connection.execute(
                "UPDATE depth_observations SET state='superseded',updated_at=? WHERE observation_id=? AND state='active'",
                (now, observation_id),
            )
            self.connection.execute(
                "UPDATE swarm_experiment_proposals SET state='expired',updated_at=? WHERE observation_id=? AND state='pending'",
                (now, observation_id),
            )
            self.event("observation-expired", "volatility-sweeper", observation_id, {})
        return expired

    def register_verifier(self, raw: dict[str, Any], *, actor: str) -> str:
        verifier_id = require_id(raw.get("id") or stable_id("VER", raw), "verifier.id")
        effect_risk = float(raw.get("effectRisk", 0))
        information_gain = float(raw.get("informationGain", 0))
        if not 0 <= effect_risk <= 1 or not 0 < information_gain <= 1:
            raise ControlError("verifier effectRisk/informationGain must be within 0..1")
        now = timestamp()
        self.connection.execute(
            "INSERT INTO swarm_verifiers(verifier_id,name,observer_class,independence_domains_json,capabilities_json,adapter,"
            "fixed_cost,expected_seconds,effect_risk,information_gain,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(verifier_id) DO UPDATE SET name=excluded.name,observer_class=excluded.observer_class,"
            "independence_domains_json=excluded.independence_domains_json,capabilities_json=excluded.capabilities_json,"
            "adapter=excluded.adapter,fixed_cost=excluded.fixed_cost,expected_seconds=excluded.expected_seconds,"
            "effect_risk=excluded.effect_risk,information_gain=excluded.information_gain,enabled=excluded.enabled,updated_at=excluded.updated_at",
            (
                verifier_id, require_text(raw.get("name"), "verifier.name"),
                require_id(raw.get("observerClass"), "verifier.observerClass"),
                canonical(string_list(raw.get("independenceDomains"), "verifier.independenceDomains", nonempty=True)),
                canonical(string_list(raw.get("capabilities"), "verifier.capabilities", nonempty=True)),
                require_text(raw.get("adapter"), "verifier.adapter"),
                max(0.0, float(raw.get("fixedCost", 0))),
                max(0.1, float(raw.get("expectedSeconds", 1))), effect_risk, information_gain,
                int(raw.get("enabled", True) is not False), now, now,
            ),
        )
        self.event("verifier-upserted", actor, verifier_id, {"observerClass": raw.get("observerClass")})
        return verifier_id

    def select_verifier(self, raw: dict[str, Any], *, actor: str) -> dict[str, Any]:
        claim_id = require_id(raw.get("claimId"), "selection.claimId")
        capability = require_text(raw.get("requiredCapability"), "selection.requiredCapability")
        origin_classes = set(string_list(raw.get("originClasses"), "selection.originClasses"))
        origin_domains = set(string_list(raw.get("originDomains"), "selection.originDomains"))
        maximum_effect = float(raw.get("maximumEffectRisk", 1))
        maximum_cost = float(raw.get("maximumCost", 1e12))
        candidates = []
        for row in self.connection.execute("SELECT * FROM swarm_verifiers WHERE enabled=1").fetchall():
            if capability not in set(json.loads(row["capabilities_json"])):
                continue
            domains = set(json.loads(row["independence_domains_json"]))
            if row["observer_class"] in origin_classes or domains & origin_domains:
                continue
            if float(row["effect_risk"]) > maximum_effect or float(row["fixed_cost"]) > maximum_cost:
                continue
            component = self.connection.execute(
                "SELECT state FROM swarm_components WHERE component_id=?", (f"verifier:{row['verifier_id']}",)
            ).fetchone()
            if component is not None and component["state"] in {"unhealthy", "disabled"}:
                continue
            denominator = 1 + float(row["fixed_cost"]) + float(row["expected_seconds"]) / 60 + float(row["effect_risk"]) * 10
            score = float(row["information_gain"]) * 100 / denominator
            candidates.append((score, row, domains))
        if not candidates:
            raise ControlError("no independent verifier satisfies the capability, cost, and effect constraints")
        score, row, domains = sorted(candidates, key=lambda item: (-item[0], item[1]["verifier_id"]))[0]
        rationale = {
            "observerClass": row["observer_class"],
            "independenceDomains": sorted(domains),
            "informationGain": row["information_gain"],
            "fixedCost": row["fixed_cost"],
            "expectedSeconds": row["expected_seconds"],
            "effectRisk": row["effect_risk"],
            "candidateCount": len(candidates),
        }
        selection_id = stable_id("VSEL", claim_id, row["verifier_id"], timestamp())
        self.connection.execute(
            "INSERT INTO swarm_verifier_selections(selection_id,claim_id,verifier_id,required_capability,origin_classes_json,"
            "origin_domains_json,score,rationale_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (selection_id, claim_id, row["verifier_id"], capability, canonical(sorted(origin_classes)), canonical(sorted(origin_domains)), score, canonical(rationale), timestamp()),
        )
        self.event("verifier-selected", actor, selection_id, {"claimId": claim_id, "verifierId": row["verifier_id"], "score": score})
        return {"selectionId": selection_id, "claimId": claim_id, "verifierId": row["verifier_id"], "adapter": row["adapter"], "score": score, "rationale": rationale}

    def register_model(self, raw: dict[str, Any], *, actor: str) -> str:
        model_id = require_id(raw.get("id") or stable_id("MODEL", raw.get("provider"), raw.get("model")), "model.id")
        quality = float(raw.get("quality", 0))
        if not 0 < quality <= 1:
            raise ControlError("model.quality must be within 0..1")
        now = timestamp()
        self.connection.execute(
            "INSERT INTO swarm_models(model_id,provider,model,family,roles_json,capabilities_json,input_cost,output_cost,"
            "expected_latency,quality,cache_allowed,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(model_id) DO UPDATE SET provider=excluded.provider,model=excluded.model,family=excluded.family,"
            "roles_json=excluded.roles_json,capabilities_json=excluded.capabilities_json,input_cost=excluded.input_cost,"
            "output_cost=excluded.output_cost,expected_latency=excluded.expected_latency,quality=excluded.quality,"
            "cache_allowed=excluded.cache_allowed,enabled=excluded.enabled,updated_at=excluded.updated_at",
            (
                model_id, require_id(raw.get("provider"), "model.provider"), require_text(raw.get("model"), "model.model"),
                require_id(raw.get("family"), "model.family"), canonical(string_list(raw.get("roles"), "model.roles", nonempty=True)),
                canonical(string_list(raw.get("capabilities"), "model.capabilities")), max(0.0, float(raw.get("inputCost", 0))),
                max(0.0, float(raw.get("outputCost", 0))), max(0.0, float(raw.get("expectedLatency", 0))), quality,
                int(bool(raw.get("cacheAllowed"))), int(raw.get("enabled", True) is not False), now, now,
            ),
        )
        self.event("model-upserted", actor, model_id, {"provider": raw.get("provider"), "family": raw.get("family")})
        return model_id

    def route_model(self, raw: dict[str, Any], *, actor: str) -> dict[str, Any]:
        task_id = require_id(raw.get("taskId"), "route.taskId")
        role = require_id(raw.get("role"), "route.role")
        required = set(string_list(raw.get("requiredCapabilities"), "route.requiredCapabilities"))
        prior_ids = string_list(raw.get("priorRouteIds"), "route.priorRouteIds")
        prior_families: set[str] = set()
        for route_id in prior_ids:
            prior = self.connection.execute(
                "SELECT m.family FROM swarm_model_routes r JOIN swarm_models m ON m.model_id=r.model_id WHERE r.route_id=?",
                (route_id,),
            ).fetchone()
            if prior is None:
                raise ControlError(f"unknown prior model route: {route_id}")
            prior_families.add(str(prior["family"]))
        independent_role = role in {"reviewer", "replayer", "critic", "adversary"}
        candidates = []
        for row in self.connection.execute("SELECT * FROM swarm_models WHERE enabled=1").fetchall():
            if role not in set(json.loads(row["roles_json"])):
                continue
            if not required.issubset(set(json.loads(row["capabilities_json"]))):
                continue
            if independent_role and prior_families and row["family"] in prior_families:
                continue
            provider = self.connection.execute(
                "SELECT state FROM swarm_components WHERE component_id=?", (f"provider:{row['provider']}",)
            ).fetchone()
            if provider is not None and provider["state"] in {"unhealthy", "disabled"}:
                continue
            average_cost = float(row["input_cost"]) + float(row["output_cost"])
            score = float(row["quality"]) * 100 / (1 + average_cost + float(row["expected_latency"]) / 10)
            if row["family"] not in prior_families:
                score *= 1.15
            candidates.append((score, row))
        if not candidates:
            raise ControlError("no healthy model satisfies the role, capability, and independence constraints")
        score, row = sorted(candidates, key=lambda item: (-item[0], item[1]["model_id"]))[0]
        cache_allowed = bool(row["cache_allowed"]) and role not in {"reviewer", "replayer", "critic", "adversary"}
        rationale = {
            "quality": row["quality"], "inputCost": row["input_cost"], "outputCost": row["output_cost"],
            "latency": row["expected_latency"], "familyDiversity": row["family"] not in prior_families,
            "candidateCount": len(candidates),
        }
        route_id = stable_id("MROUTE", task_id, role, row["model_id"], timestamp())
        self.connection.execute(
            "INSERT INTO swarm_model_routes(route_id,task_id,role,model_id,prior_routes_json,score,cache_allowed,rationale_json,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (route_id, task_id, role, row["model_id"], canonical(prior_ids), score, int(cache_allowed), canonical(rationale), timestamp()),
        )
        self.event("model-routed", actor, route_id, {"taskId": task_id, "modelId": row["model_id"], "role": role})
        return {"routeId": route_id, "taskId": task_id, "role": role, "modelId": row["model_id"], "provider": row["provider"], "model": row["model"], "family": row["family"], "promptCacheAllowed": cache_allowed, "score": score, "rationale": rationale}

    def component_upsert(self, raw: dict[str, Any], *, actor: str) -> str:
        kind = require_id(raw.get("kind"), "component.kind")
        name = require_id(raw.get("name"), "component.name")
        component_id = require_id(raw.get("id") or f"{kind}:{name}", "component.id")
        state = str(raw.get("state") or "unknown")
        if state not in COMPONENT_STATES:
            raise ControlError("unsupported component state")
        now = timestamp()
        self.connection.execute(
            "INSERT INTO swarm_components(component_id,kind,name,version,capabilities_json,state,detail,updated_at) VALUES(?,?,?,?,?,?,?,?) "
            "ON CONFLICT(component_id) DO UPDATE SET kind=excluded.kind,name=excluded.name,version=excluded.version,"
            "capabilities_json=excluded.capabilities_json,state=excluded.state,detail=excluded.detail,updated_at=excluded.updated_at",
            (component_id, kind, name, str(raw.get("version") or "unknown"), canonical(string_list(raw.get("capabilities"), "component.capabilities")), state, str(raw.get("detail") or ""), now),
        )
        self.event("component-upserted", actor, component_id, {"state": state})
        return component_id

    def ensure_component(
        self,
        *,
        kind: str,
        name: str,
        version: str = "unknown",
        capabilities: Iterable[str] = (),
        actor: str,
    ) -> str:
        """Register a runtime component without resetting existing health state."""
        kind = require_id(kind, "component.kind")
        name = require_id(name, "component.name")
        component_id = require_id(f"{kind}:{name}", "component.id")
        now = timestamp()
        self.connection.execute(
            "INSERT OR IGNORE INTO swarm_components(component_id,kind,name,version,capabilities_json,state,detail,updated_at) "
            "VALUES(?,?,?,?,?,'unknown','',?)",
            (component_id, kind, name, str(version or "unknown"), canonical(sorted(set(capabilities))), now),
        )
        if self.connection.execute("SELECT changes() AS n").fetchone()["n"]:
            self.event("component-discovered", actor, component_id, {"version": version})
        return component_id

    def component_observe(self, raw: dict[str, Any], *, actor: str) -> str:
        component_id = require_id(raw.get("componentId"), "observation.componentId")
        component = self.connection.execute(
            "SELECT * FROM swarm_components WHERE component_id=?", (component_id,)
        ).fetchone()
        if component is None:
            raise ControlError("unknown component")
        outcome = require_id(raw.get("outcome"), "observation.outcome")
        latency = max(0.0, float(raw.get("latencyMs", 0)))
        invocation_id = require_id(raw.get("id") or stable_id("INV", component_id, timestamp(), outcome), "invocation.id")
        self.connection.execute(
            "INSERT INTO swarm_invocations(invocation_id,component_id,task_id,operation,outcome,latency_ms,input_tokens,output_tokens,cost,artifact_refs_json,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                invocation_id, component_id, str(raw.get("taskId") or "") or None,
                require_text(raw.get("operation"), "observation.operation"), outcome, latency,
                max(0, int(raw.get("inputTokens", 0))), max(0, int(raw.get("outputTokens", 0))),
                max(0.0, float(raw.get("cost", 0))), canonical(string_list(raw.get("artifactRefs"), "observation.artifactRefs")), timestamp(),
            ),
        )
        success = outcome in {"passed", "success", "healthy"}
        failures = 0 if success else int(component["consecutive_failures"]) + 1
        state = "healthy" if success else "degraded" if failures < 3 else "unhealthy"
        self.connection.execute(
            "UPDATE swarm_components SET state=?,consecutive_failures=?,last_latency_ms=?,last_checked_at=?,detail=?,updated_at=? WHERE component_id=?",
            (state, failures, latency, timestamp(), str(raw.get("detail") or ""), timestamp(), component_id),
        )
        self.event("component-observed", actor, component_id, {"invocationId": invocation_id, "outcome": outcome, "state": state})
        return invocation_id

    def register_cleanup(self, recipe_path: Path, *, registered_by: str) -> dict[str, Any]:
        recipe = read_object(recipe_path)
        if recipe.get("schemaVersion") != 1 or recipe.get("effect") != "cleanup":
            raise ControlError("cleanup recipe requires schemaVersion 1 and effect=cleanup")
        action_id = require_id(recipe.get("actionId"), "cleanup.actionId")
        argv = argv_list(recipe.get("argv"), "cleanup.argv")
        verify = recipe.get("verify")
        if not isinstance(verify, dict):
            raise ControlError("cleanup recipe requires an independent verify command")
        argv_list(verify.get("argv"), "cleanup.verify.argv")
        timeout_seconds = int(recipe.get("timeoutSeconds", 0))
        if not 1 <= timeout_seconds <= 300:
            raise ControlError("cleanup timeoutSeconds must be between 1 and 300")
        verify_timeout = int(verify.get("timeoutSeconds") or timeout_seconds)
        if not 1 <= verify_timeout <= 300:
            raise ControlError("cleanup.verify.timeoutSeconds must be between 1 and 300")
        approval = recipe.get("approval")
        if not isinstance(approval, dict):
            raise ControlError("cleanup recipe requires coordinator approval")
        approved_by = require_id(approval.get("approvedBy"), "cleanup.approval.approvedBy")
        parse_time(approval.get("approvedAt"), "cleanup.approval.approvedAt")
        contained_path(self.root, recipe.get("cwd") or ".", "cleanup.cwd")
        contained_path(self.root, verify.get("cwd") or recipe.get("cwd") or ".", "cleanup.verify.cwd")
        recipe_digest = digest(recipe_path.read_bytes())
        retained = self.root / "evidence" / "control" / "cleanup-recipes" / f"{recipe_digest}.json"
        retained.parent.mkdir(parents=True, exist_ok=True)
        if retained.exists() and digest(retained.read_bytes()) != recipe_digest:
            raise ControlError("cleanup recipe hash collision")
        if not retained.exists():
            shutil.copy2(recipe_path, retained)
            os.chmod(retained, 0o600)
        stack_order = int(self.connection.execute(
            "SELECT COALESCE(MAX(stack_order),0)+1 AS n FROM swarm_cleanup_actions"
        ).fetchone()["n"])
        idempotency_key = require_id(recipe.get("idempotencyKey"), "cleanup.idempotencyKey")
        self.connection.execute(
            "INSERT INTO swarm_cleanup_actions(action_id,description,recipe_sha256,recipe_path,stack_order,idempotency_key,state,"
            "approved_by,registered_by,last_error,registered_at) VALUES(?,?,?,?,?,?, 'pending',?,?, '',?)",
            (action_id, require_text(recipe.get("description"), "cleanup.description"), recipe_digest, retained.relative_to(self.root).as_posix(), stack_order, idempotency_key, approved_by, require_id(registered_by, "registeredBy"), timestamp()),
        )
        self.event("cleanup-registered", registered_by, action_id, {"sha256": recipe_digest, "stackOrder": stack_order, "argvLength": len(argv)})
        return {"actionId": action_id, "sha256": recipe_digest, "stackOrder": stack_order}

    def run_next_cleanup(self, *, coordinator: str, expected_sha256: str) -> dict[str, Any]:
        if not HEX_SHA256.fullmatch(expected_sha256):
            raise ControlError("expected cleanup SHA-256 is invalid")
        row = self.connection.execute(
            "SELECT * FROM swarm_cleanup_actions WHERE state IN ('pending','failed') ORDER BY stack_order DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise ControlError("no pending cleanup action")
        if row["recipe_sha256"] != expected_sha256:
            raise ControlError("reviewed cleanup hash does not match the next LIFO action")
        recipe_path = contained_path(self.root, row["recipe_path"], "cleanup recipe")
        if digest(recipe_path.read_bytes()) != expected_sha256:
            raise ControlError("retained cleanup recipe changed")
        recipe = read_object(recipe_path)
        coordinator = require_id(coordinator, "coordinator")
        self.connection.execute(
            "UPDATE swarm_cleanup_actions SET state='running',attempt=attempt+1,started_at=?,last_error='' WHERE action_id=?",
            (timestamp(), row["action_id"]),
        )
        self.connection.commit()
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}
        try:
            run = subprocess.run(
                argv_list(recipe["argv"], "cleanup.argv"),
                cwd=contained_path(self.root, recipe.get("cwd") or ".", "cleanup.cwd"),
                env=environment, capture_output=True, timeout=int(recipe["timeoutSeconds"]), check=False,
            )
            if run.returncode != 0:
                raise ControlError(f"cleanup command exited {run.returncode}")
            verify = recipe["verify"]
            check = subprocess.run(
                argv_list(verify["argv"], "cleanup.verify.argv"),
                cwd=contained_path(self.root, verify.get("cwd") or recipe.get("cwd") or ".", "cleanup.verify.cwd"),
                env=environment, capture_output=True,
                timeout=int(verify.get("timeoutSeconds") or recipe["timeoutSeconds"]), check=False,
            )
            if check.returncode != 0:
                raise ControlError(f"cleanup verification exited {check.returncode}")
            receipt = {
                "actionId": row["action_id"], "recipeSha256": expected_sha256,
                "commandExit": run.returncode, "verifyExit": check.returncode,
                "stdoutSha256": digest(run.stdout), "stderrSha256": digest(run.stderr),
                "verifyStdoutSha256": digest(check.stdout), "verifyStderrSha256": digest(check.stderr),
                "completedAt": timestamp(), "coordinator": coordinator,
            }
            receipt_path = self.root / "evidence" / "control" / "cleanup-receipts" / f"{row['action_id']}.json"
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            os.chmod(receipt_path, 0o600)
            self.connection.execute(
                "UPDATE swarm_cleanup_actions SET state='verified',completed_at=?,last_error='' WHERE action_id=?",
                (timestamp(), row["action_id"]),
            )
            self.event("cleanup-verified", coordinator, str(row["action_id"]), {"receipt": receipt_path.relative_to(self.root).as_posix()})
            self.connection.commit()
            return receipt
        except (subprocess.TimeoutExpired, OSError, ControlError) as exc:
            self.connection.execute(
                "UPDATE swarm_cleanup_actions SET state='failed',completed_at=?,last_error=? WHERE action_id=?",
                (timestamp(), str(exc), row["action_id"]),
            )
            self.event("cleanup-failed", coordinator, str(row["action_id"]), {"error": str(exc)})
            self.connection.commit()
            raise ControlError(str(exc)) from exc

    def recover_cleanup(self, *, actor: str) -> int:
        update = self.connection.execute(
            "UPDATE swarm_cleanup_actions SET state='pending',last_error='recovered after interrupted coordinator',started_at=NULL "
            "WHERE state='running'"
        )
        self.event("cleanup-recovered", actor, None, {"actions": update.rowcount})
        return update.rowcount

    def issue_oob(self, *, experiment_id: str, protocol: str, issued_by: str, ttl_seconds: int = 900, max_callbacks: int = 1) -> dict[str, Any]:
        experiment_id = require_id(experiment_id, "experimentId")
        issued_by = require_id(issued_by, "issuedBy")
        if protocol != "http":
            raise ControlError("the owned OOB oracle currently supports HTTP only")
        if not 30 <= ttl_seconds <= 86_400 or not 1 <= max_callbacks <= 20:
            raise ControlError("OOB TTL or callback bound is outside the safe range")
        result: dict[str, str] = {"experimentId": experiment_id, "protocol": protocol}
        for role in ("positive", "control"):
            token = secrets.token_urlsafe(24)
            token_id = stable_id("OOB", experiment_id, role, token)
            self.connection.execute(
                "INSERT INTO swarm_oob_tokens(token_id,experiment_id,role,token_sha256,protocol,max_callbacks,expires_at,issued_by,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (token_id, experiment_id, role, digest(token.encode()), protocol, max_callbacks, timestamp(utc_now() + dt.timedelta(seconds=ttl_seconds)), issued_by, timestamp()),
            )
            result[f"{role}Token"] = token
            result[f"{role}TokenId"] = token_id
        self.event("oob-issued", issued_by, experiment_id, {"protocol": protocol, "ttlSeconds": ttl_seconds, "maxCallbacks": max_callbacks})
        return result

    def record_oob(self, *, token: str, protocol: str, source: str, method: str, metadata: dict[str, Any]) -> str:
        token_hash = digest(token.encode())
        row = self.connection.execute(
            "SELECT * FROM swarm_oob_tokens WHERE token_sha256=?", (token_hash,)
        ).fetchone()
        if row is None or row["protocol"] != protocol:
            raise ControlError("unknown OOB token or protocol")
        if parse_time(row["expires_at"], "OOB expiry") <= utc_now():
            raise ControlError("OOB token expired")
        count = int(self.connection.execute(
            "SELECT COUNT(*) AS n FROM swarm_oob_receipts WHERE token_id=?", (row["token_id"],)
        ).fetchone()["n"])
        if count >= int(row["max_callbacks"]):
            raise ControlError("OOB callback bound exhausted")
        receipt_id = stable_id("OOBR", row["token_id"], count, timestamp(), source)
        self.connection.execute(
            "INSERT INTO swarm_oob_receipts(receipt_id,token_id,protocol,source,method,metadata_json,received_at) VALUES(?,?,?,?,?,?,?)",
            (receipt_id, row["token_id"], protocol, source[:255], method[:32], canonical(metadata), timestamp()),
        )
        self.event("oob-received", "owned-oob-listener", receipt_id, {"tokenId": row["token_id"], "protocol": protocol})
        return receipt_id

    def verify_oob(self, experiment_id: str) -> dict[str, Any]:
        experiment_id = require_id(experiment_id, "experimentId")
        rows = self.connection.execute(
            "SELECT t.role,t.token_id,COUNT(r.receipt_id) AS callbacks FROM swarm_oob_tokens t "
            "LEFT JOIN swarm_oob_receipts r ON r.token_id=t.token_id WHERE t.experiment_id=? GROUP BY t.role,t.token_id",
            (experiment_id,),
        ).fetchall()
        counts = {str(row["role"]): int(row["callbacks"]) for row in rows}
        if set(counts) != {"positive", "control"}:
            raise ControlError("experiment does not have a complete positive/control token pair")
        passed = counts["positive"] >= 1 and counts["control"] == 0
        receipts = [
            {
                "receiptId": str(row["receipt_id"]),
                "tokenId": str(row["token_id"]),
                "role": str(row["role"]),
                "protocol": str(row["protocol"]),
                "source": str(row["source"]),
                "method": str(row["method"]),
                "metadataSha256": digest(str(row["metadata_json"]).encode()),
                "receivedAt": str(row["received_at"]),
            }
            for row in self.connection.execute(
                "SELECT r.receipt_id,r.token_id,t.role,r.protocol,r.source,r.method,r.metadata_json,r.received_at "
                "FROM swarm_oob_receipts r JOIN swarm_oob_tokens t ON t.token_id=r.token_id "
                "WHERE t.experiment_id=? ORDER BY r.received_at,r.receipt_id",
                (experiment_id,),
            ).fetchall()
        ]
        retained = {
            "schemaVersion": 1,
            "experimentId": experiment_id,
            "positiveCallbacks": counts["positive"],
            "controlCallbacks": counts["control"],
            "passed": passed,
            "receipts": receipts,
            "verifiedAt": timestamp(),
        }
        receipt_path = self.root / "evidence" / "control" / "oob-receipts" / f"{experiment_id}.json"
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(retained, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(receipt_path, 0o600)
        result = {
            **retained,
            "evidencePath": receipt_path.relative_to(self.root).as_posix(),
            "evidenceSha256": digest(receipt_path.read_bytes()),
        }
        self.event("oob-verified", "oob-oracle", experiment_id, result)
        return result

    def status(self) -> dict[str, Any]:
        def grouped(table: str, column: str) -> dict[str, int]:
            return {str(row["value"]): int(row["n"]) for row in self.connection.execute(
                f"SELECT {column} AS value,COUNT(*) AS n FROM {table} GROUP BY {column}"
            ).fetchall()}
        costs = self.connection.execute(
            "SELECT COALESCE(SUM(cost),0) AS cost,COALESCE(SUM(input_tokens+output_tokens),0) AS tokens,"
            "COALESCE(AVG(latency_ms),0) AS latency FROM swarm_invocations"
        ).fetchone()
        return {
            "subscriptions": int(self.connection.execute("SELECT COUNT(*) AS n FROM swarm_subscriptions WHERE enabled=1").fetchone()["n"]),
            "observationTrust": grouped("swarm_observation_meta", "trust_tier"),
            "proposals": grouped("swarm_experiment_proposals", "state"),
            "components": grouped("swarm_components", "state"),
            "cleanup": grouped("swarm_cleanup_actions", "state"),
            "modelRoutes": int(self.connection.execute("SELECT COUNT(*) AS n FROM swarm_model_routes").fetchone()["n"]),
            "verifierSelections": int(self.connection.execute("SELECT COUNT(*) AS n FROM swarm_verifier_selections").fetchone()["n"]),
            "telemetry": {"cost": float(costs["cost"]), "tokens": int(costs["tokens"]), "averageLatencyMs": float(costs["latency"])},
            "events": int(self.connection.execute("SELECT COUNT(*) AS n FROM swarm_events").fetchone()["n"]),
        }


def ingest_depth_observations(
    root: Path,
    connection: sqlite3.Connection,
    observation_ids: Iterable[str],
) -> dict[str, Any]:
    """Attach trust ancestry and produce decentralized proposals after submit."""
    store = ControlStore(root, connection)
    store.install_defaults()
    expired = store.sweep_volatility()
    published = [store.publish_observation(str(observation_id)) for observation_id in observation_ids]
    return {"published": published, "expired": expired}


def load_spec(path: str) -> dict[str, Any]:
    return read_object(Path(path).expanduser().resolve())


def print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    add_sub = commands.add_parser("subscription-add")
    add_sub.add_argument("--spec", required=True)
    add_sub.add_argument("--actor", required=True)
    commands.add_parser("subscription-list")
    proposals = commands.add_parser("proposal-list")
    proposals.add_argument("--state", choices=sorted(PROPOSAL_STATES))
    review = commands.add_parser("proposal-review")
    review.add_argument("proposal_id")
    review.add_argument("--reviewer", required=True)
    review.add_argument("--decision", choices=("approved", "rejected"), required=True)
    review.add_argument("--reason", required=True)
    materialize = commands.add_parser("proposal-materialize")
    materialize.add_argument("proposal_id")
    materialize.add_argument("--coordinator", required=True)
    sweep = commands.add_parser("volatility-sweep")
    verifier_add = commands.add_parser("verifier-add")
    verifier_add.add_argument("--spec", required=True)
    verifier_add.add_argument("--actor", required=True)
    verifier_select = commands.add_parser("verifier-select")
    verifier_select.add_argument("--spec", required=True)
    verifier_select.add_argument("--actor", required=True)
    model_add = commands.add_parser("model-add")
    model_add.add_argument("--spec", required=True)
    model_add.add_argument("--actor", required=True)
    model_route = commands.add_parser("model-route")
    model_route.add_argument("--spec", required=True)
    model_route.add_argument("--actor", required=True)
    component_add = commands.add_parser("component-add")
    component_add.add_argument("--spec", required=True)
    component_add.add_argument("--actor", required=True)
    component_observe = commands.add_parser("component-observe")
    component_observe.add_argument("--spec", required=True)
    component_observe.add_argument("--actor", required=True)
    cleanup_add = commands.add_parser("cleanup-register")
    cleanup_add.add_argument("--recipe", required=True)
    cleanup_add.add_argument("--registered-by", required=True)
    cleanup_run = commands.add_parser("cleanup-run-next")
    cleanup_run.add_argument("--coordinator", required=True)
    cleanup_run.add_argument("--expected-sha256", required=True)
    cleanup_recover = commands.add_parser("cleanup-recover")
    cleanup_recover.add_argument("--actor", required=True)
    oob_issue = commands.add_parser("oob-issue")
    oob_issue.add_argument("--experiment", required=True)
    oob_issue.add_argument("--protocol", choices=("http",), default="http")
    oob_issue.add_argument("--issued-by", required=True)
    oob_issue.add_argument("--ttl-seconds", type=int, default=900)
    oob_issue.add_argument("--max-callbacks", type=int, default=1)
    oob_verify = commands.add_parser("oob-verify")
    oob_verify.add_argument("--experiment", required=True)
    commands.add_parser("status")
    args = parser.parse_args(argv)
    store = ControlStore(Path(args.campaign))
    try:
        if args.command == "init":
            store.install_defaults()
            result: Any = store.status()
        elif args.command == "subscription-add":
            result = {"subscriptionId": store.add_subscription(load_spec(args.spec), actor=args.actor)}
        elif args.command == "subscription-list":
            result = [dict(row) for row in store.connection.execute("SELECT * FROM swarm_subscriptions ORDER BY subscription_id").fetchall()]
        elif args.command == "proposal-list":
            query = "SELECT * FROM swarm_experiment_proposals"
            values: tuple[Any, ...] = ()
            if args.state:
                query += " WHERE state=?"
                values = (args.state,)
            result = [{**dict(row), "blueprint": json.loads(row["blueprint_json"])} for row in store.connection.execute(query + " ORDER BY created_at", values).fetchall()]
        elif args.command == "proposal-review":
            store.review_proposal(args.proposal_id, reviewer=args.reviewer, decision=args.decision, reason=args.reason)
            result = store.proposal_blueprint(args.proposal_id)
        elif args.command == "proposal-materialize":
            blueprint = store.proposal_blueprint(args.proposal_id)
            if blueprint.pop("state") != "approved":
                raise ControlError("only an approved proposal can become a scheduler task")
            task_id = require_id(
                str(blueprint.get("taskId") or "swarm-" + args.proposal_id.lower().replace(":", "-")[-80:]),
                "proposal task id",
            )
            command = [
                sys.executable,
                str(Path(__file__).with_name("research_harness.py")),
                "task-add",
                str(store.root),
                task_id,
                "--title",
                require_text(blueprint.get("title"), "proposal.title"),
                "--lane",
                require_text(blueprint.get("lane"), "proposal.lane"),
                "--objective",
                require_text(blueprint.get("objective"), "proposal.objective"),
                "--priority",
                str(int(blueprint.get("priority", 1000))),
                "--max-attempts",
                str(int(blueprint.get("maxAttempts", 2))),
                "--task-kind",
                "focused-chain-investigation",
            ]
            for value in string_list(blueprint.get("approachFamilies"), "proposal.approachFamilies", nonempty=True):
                command.extend(["--approach-family", value])
            for value in string_list(blueprint.get("successCriteria"), "proposal.successCriteria", nonempty=True):
                command.extend(["--success-criterion", value])
            for value in string_list(blueprint.get("excludedWorkers"), "proposal.excludedWorkers"):
                command.extend(["--exclude-worker", value])
            completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
            if completed.returncode != 0 and "already exists" not in completed.stderr.lower():
                raise ControlError("scheduler rejected the approved proposal: " + completed.stderr.strip())
            store.mark_scheduled(args.proposal_id, task_id, args.coordinator)
            result = {"proposalId": args.proposal_id, "taskId": task_id, "scheduled": True}
        elif args.command == "volatility-sweep":
            result = {"expired": store.sweep_volatility()}
        elif args.command == "verifier-add":
            result = {"verifierId": store.register_verifier(load_spec(args.spec), actor=args.actor)}
        elif args.command == "verifier-select":
            result = store.select_verifier(load_spec(args.spec), actor=args.actor)
        elif args.command == "model-add":
            result = {"modelId": store.register_model(load_spec(args.spec), actor=args.actor)}
        elif args.command == "model-route":
            result = store.route_model(load_spec(args.spec), actor=args.actor)
        elif args.command == "component-add":
            result = {"componentId": store.component_upsert(load_spec(args.spec), actor=args.actor)}
        elif args.command == "component-observe":
            result = {"invocationId": store.component_observe(load_spec(args.spec), actor=args.actor)}
        elif args.command == "cleanup-register":
            result = store.register_cleanup(Path(args.recipe).expanduser().resolve(), registered_by=args.registered_by)
        elif args.command == "cleanup-run-next":
            result = store.run_next_cleanup(coordinator=args.coordinator, expected_sha256=args.expected_sha256)
        elif args.command == "cleanup-recover":
            result = {"recovered": store.recover_cleanup(actor=args.actor)}
        elif args.command == "oob-issue":
            result = store.issue_oob(experiment_id=args.experiment, protocol=args.protocol, issued_by=args.issued_by, ttl_seconds=args.ttl_seconds, max_callbacks=args.max_callbacks)
        elif args.command == "oob-verify":
            result = store.verify_oob(args.experiment)
        else:
            result = store.status()
        store.connection.commit()
        print_json(result)
        return 0
    except ControlError as exc:
        store.connection.rollback()
        print(f"swarm control rejected the operation: {exc}", file=sys.stderr)
        return 2
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
