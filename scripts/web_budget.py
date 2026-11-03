#!/usr/bin/env python3
"""Process-shared, atomically charged budget for target-facing web adapters.

The budget database is a coordinator-owned capability registry. A reservation
is required before dispatch. Pause, cancellation, expiry, or lease expiry
invalidates all outstanding operations. Adapters must poll cancellation while
running and close their transport before returning.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

try:
    from .web_contract import (
        WebCampaignContract,
        WebContractError,
        require_identifier,
        utc_now,
    )
    from .web_research_governance import (
        AUTHORIZATION_FAMILY,
        NOVEL_ZERO_DAY_FAMILIES,
        WEB_RUNTIME_FAMILIES,
        WebResearchGovernanceError,
        diversity_policy,
        normalize_research_binding,
        record_orchestration_event,
        validate_binding_against_campaign,
    )
except ImportError:
    from web_contract import (
        WebCampaignContract,
        WebContractError,
        require_identifier,
        utc_now,
    )
    from web_research_governance import (
        AUTHORIZATION_FAMILY,
        NOVEL_ZERO_DAY_FAMILIES,
        WEB_RUNTIME_FAMILIES,
        WebResearchGovernanceError,
        diversity_policy,
        normalize_research_binding,
        record_orchestration_event,
        validate_binding_against_campaign,
    )


class SharedWebBudget:
    """Atomic request, byte, storage, action, rate, and capability accounting."""

    def __init__(self, contract: WebCampaignContract, path: Path | str):
        self.contract = contract
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA busy_timeout=15000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS operations (
                    id TEXT PRIMARY KEY,
                    adapter TEXT NOT NULL,
                    origin_id TEXT NOT NULL,
                    cleanup INTEGER NOT NULL,
                    request_bytes INTEGER NOT NULL,
                    reserved_response_bytes INTEGER NOT NULL,
                    actual_response_bytes INTEGER,
                    reserved_storage_bytes INTEGER NOT NULL,
                    actual_storage_bytes INTEGER,
                    action_units INTEGER NOT NULL,
                    browser_events INTEGER NOT NULL,
                    websocket_bytes INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    reserved_at REAL NOT NULL,
                    lease_until REAL NOT NULL,
                    finished_at REAL,
                    reason TEXT
                );
                CREATE INDEX IF NOT EXISTS operations_status
                    ON operations(status, lease_until);
                CREATE TABLE IF NOT EXISTS origin_rate (
                    origin_id TEXT PRIMARY KEY,
                    last_dispatch REAL NOT NULL
                );
                """
            )
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(operations)")
            }
            migrations = {
                "task_id": "TEXT",
                "source_task_id": "TEXT",
                "experiment_id": "TEXT",
                "approach_family": "TEXT",
                "mechanism_fingerprint": "TEXT",
                "target_dispatch": "INTEGER NOT NULL DEFAULT 1",
            }
            for column, declaration in migrations.items():
                if column not in columns:
                    connection.execute(
                        f"ALTER TABLE operations ADD COLUMN {column} {declaration}"
                    )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS operations_family "
                "ON operations(approach_family,status,reserved_at)"
            )
            existing = connection.execute(
                "SELECT value FROM meta WHERE key='contract_sha256'"
            ).fetchone()
            if existing is not None and existing[0] != self.contract.digest:
                raise WebContractError("shared budget belongs to a different contract")
            now = time.time()
            defaults = {
                "contract_sha256": self.contract.digest,
                "started_at": str(now),
                "state": "active",
                "state_reason": "",
                "state_changed_at": str(now),
            }
            for key, value in defaults.items():
                connection.execute(
                    "INSERT OR IGNORE INTO meta(key, value) VALUES(?, ?)",
                    (key, value),
                )

    def _limits(self) -> dict[str, int]:
        raw = self.contract.raw["budget"]
        return {
            "requests": int(raw["totalRequests"]),
            "cleanup": int(raw["cleanupReservedRequests"]),
            "request_bytes": int(raw["totalRequestBytes"]),
            "response_bytes": int(raw["totalResponseBytes"]),
            "storage_bytes": int(raw.get("totalStorageBytes", raw["totalResponseBytes"])),
            "concurrent": int(raw["maxConcurrentRequests"]),
            "actions": int(raw.get("maxActions", raw["totalRequests"])),
            "browser_events": int(raw.get("maxBrowserEvents", 10000)),
            "websocket_bytes": int(raw.get("maxWebsocketFrameBytes", 1048576)),
            "wall_seconds": int(raw["maxWallSeconds"]),
        }

    @staticmethod
    def _meta(connection: sqlite3.Connection) -> dict[str, str]:
        return {row["key"]: row["value"] for row in connection.execute("SELECT * FROM meta")}

    @staticmethod
    def _expire(connection: sqlite3.Connection, now: float) -> None:
        connection.execute(
            """UPDATE operations SET status='expired', finished_at=?,
               reason='dispatch lease expired before reconciliation'
               WHERE status='running' AND lease_until < ?""",
            (now, now),
        )

    def _assert_active(self, connection: sqlite3.Connection, now: float) -> None:
        meta = self._meta(connection)
        state = meta.get("state")
        if state != "active":
            raise WebContractError(
                f"web campaign dispatch is {state}: {meta.get('state_reason', '')}"
            )
        if now - float(meta["started_at"]) > self._limits()["wall_seconds"]:
            self._set_state(connection, "cancelled", "wall-clock budget expired", now)
            raise WebContractError("web campaign wall-clock budget is exhausted")

    @staticmethod
    def _set_state(
        connection: sqlite3.Connection, state: str, reason: str, now: float
    ) -> None:
        for key, value in {
            "state": state,
            "state_reason": reason,
            "state_changed_at": str(now),
        }.items():
            connection.execute("UPDATE meta SET value=? WHERE key=?", (value, key))
        if state in {"paused", "cancelled"}:
            connection.execute(
                """UPDATE operations SET status='revoked', finished_at=?, reason=?
                   WHERE status='running'""",
                (now, f"campaign {state}: {reason}"),
            )

    def reserve(
        self,
        *,
        operation_id: str,
        request_bytes: int,
        estimated_response_bytes: int,
        cleanup: bool,
        adapter: str,
        origin_id: str = "unscoped",
        storage_bytes: int = 0,
        action_units: int = 1,
        browser_events: int = 0,
        websocket_bytes: int = 0,
        lease_seconds: int = 30,
        research_binding: dict[str, Any] | None = None,
        target_dispatch: bool = True,
    ) -> dict[str, Any]:
        require_identifier(operation_id, "operationId")
        values = (
            request_bytes,
            estimated_response_bytes,
            storage_bytes,
            action_units,
            browser_events,
            websocket_bytes,
        )
        if any(isinstance(value, bool) or int(value) < 0 for value in values):
            raise WebContractError("budget reservations cannot be negative")
        if lease_seconds < 1:
            raise WebContractError("dispatch lease must be positive")
        if not isinstance(target_dispatch, bool):
            raise WebContractError("target_dispatch must be Boolean")
        now = time.time()
        limits = self._limits()
        policy = diversity_policy(self.contract.raw)
        binding: dict[str, str] | None = None
        if policy["enforceOperationBinding"] and not cleanup:
            try:
                binding = normalize_research_binding(research_binding)
                binding = validate_binding_against_campaign(
                    self.contract.path.parent, binding
                )
            except WebResearchGovernanceError as exc:
                raise WebContractError(str(exc)) from exc
        elif research_binding is not None:
            try:
                binding = normalize_research_binding(research_binding)
            except WebResearchGovernanceError as exc:
                raise WebContractError(str(exc)) from exc
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._expire(connection, now)
            self._assert_active(connection, now)
            if connection.execute(
                "SELECT 1 FROM operations WHERE id=?", (operation_id,)
            ).fetchone():
                raise WebContractError("budget operation id was already reserved")
            aggregates = connection.execute(
                """SELECT COUNT(*) requests,
                   COALESCE(SUM(cleanup),0) cleanup,
                   COALESCE(SUM(request_bytes),0) request_bytes,
                   COALESCE(SUM(COALESCE(actual_response_bytes,reserved_response_bytes)),0) response_bytes,
                   COALESCE(SUM(COALESCE(actual_storage_bytes,reserved_storage_bytes)),0) storage_bytes,
                   COALESCE(SUM(action_units),0) actions,
                   COALESCE(SUM(browser_events),0) browser_events,
                   COALESCE(SUM(websocket_bytes),0) websocket_bytes
                   FROM operations"""
            ).fetchone()
            running = connection.execute(
                "SELECT COUNT(*) FROM operations WHERE status='running'"
            ).fetchone()[0]
            origin_running = connection.execute(
                "SELECT COUNT(*) FROM operations WHERE status='running' AND origin_id=?",
                (origin_id,),
            ).fetchone()[0]
            total_requests = int(aggregates["requests"]) + 1
            cleanup_requests = int(aggregates["cleanup"]) + int(cleanup)
            normal_requests = total_requests - cleanup_requests
            normal_limit = limits["requests"] - limits["cleanup"]
            if binding is not None and not cleanup:
                previous_normal = int(
                    connection.execute(
                        "SELECT COUNT(*) FROM operations WHERE cleanup=0 AND target_dispatch=1 "
                        "AND status IN ('running','completed')"
                    ).fetchone()[0]
                )
                if (
                    previous_normal >= int(policy["warmupOperations"])
                    and binding["approachFamily"] == AUTHORIZATION_FAMILY
                ):
                    previous_family = int(
                        connection.execute(
                            "SELECT COUNT(*) FROM operations "
                            "WHERE cleanup=0 AND target_dispatch=1 AND approach_family=? "
                            "AND status IN ('running','completed')",
                            (AUTHORIZATION_FAMILY,),
                        ).fetchone()[0]
                    )
                    projected_share = (previous_family + 1) / (previous_normal + 1)
                    maximum_share = float(
                        policy["maximumAuthorizationRequestShare"]
                    )
                    if projected_share > maximum_share:
                        raise WebContractError(
                            "authorization research reached its runtime request-share cap; "
                            "execute a distinct eligible approach family before returning "
                            "to this mechanism"
                        )
            checks = {
                "total request": (total_requests, limits["requests"]),
                "request-byte": (int(aggregates["request_bytes"]) + request_bytes, limits["request_bytes"]),
                "response-byte": (int(aggregates["response_bytes"]) + estimated_response_bytes, limits["response_bytes"]),
                "storage-byte": (int(aggregates["storage_bytes"]) + storage_bytes, limits["storage_bytes"]),
                "action": (int(aggregates["actions"]) + action_units, limits["actions"]),
                "browser-event": (int(aggregates["browser_events"]) + browser_events, limits["browser_events"]),
                "websocket-frame": (int(aggregates["websocket_bytes"]) + websocket_bytes, limits["websocket_bytes"]),
                "concurrent request": (int(running) + 1, limits["concurrent"]),
            }
            for name, (actual, maximum) in checks.items():
                if actual > maximum:
                    raise WebContractError(f"{name} budget is exhausted")
            if origin_id in self.contract.origins and int(origin_running) + 1 > self.contract.origins[origin_id].max_concurrent_requests:
                raise WebContractError("origin concurrent request budget is exhausted")
            if not cleanup and normal_requests > normal_limit:
                raise WebContractError("only the reserved cleanup request budget remains")
            connection.execute(
                """INSERT INTO operations(
                   id,adapter,origin_id,cleanup,request_bytes,reserved_response_bytes,
                   reserved_storage_bytes,action_units,browser_events,websocket_bytes,
                   status,reserved_at,lease_until,task_id,source_task_id,experiment_id,
                   approach_family,mechanism_fingerprint,target_dispatch)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    operation_id,
                    adapter,
                    origin_id,
                    int(cleanup),
                    int(request_bytes),
                    int(estimated_response_bytes),
                    int(storage_bytes),
                    int(action_units),
                    int(browser_events),
                    int(websocket_bytes),
                    "running",
                    now,
                    now + lease_seconds,
                    binding["taskId"] if binding else None,
                    binding["sourceTaskId"] if binding else None,
                    binding["experimentId"] if binding else None,
                    binding["approachFamily"] if binding else None,
                    binding["mechanismFingerprint"] if binding else None,
                    int(target_dispatch),
                ),
            )
            connection.commit()
        if binding is not None:
            try:
                record_orchestration_event(
                    self.contract.path.parent,
                    event_type="web-operation-reserved",
                    binding=binding,
                    operation_id=operation_id,
                    status="running",
                )
            except (OSError, sqlite3.Error) as exc:
                self.abort(operation_id, "orchestration event binding failed")
                raise WebContractError(
                    f"target operation could not enter the durable event stream: {exc}"
                ) from exc
        return self.read()

    def reconcile_response(
        self,
        operation_id: str,
        actual_bytes: int,
        *,
        storage_bytes: int = 0,
        browser_events: int | None = None,
        websocket_bytes: int | None = None,
    ) -> dict[str, Any]:
        if actual_bytes < 0 or storage_bytes < 0 or (
            browser_events is not None and browser_events < 0
        ) or (websocket_bytes is not None and websocket_bytes < 0):
            raise WebContractError("actual byte counts cannot be negative")
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM operations WHERE id=?", (operation_id,)
            ).fetchone()
            if row is None:
                raise WebContractError("budget operation is missing")
            if row["status"] != "running":
                raise WebContractError(f"budget capability is no longer live: {row['status']}")
            limits = self._limits()
            totals = connection.execute(
                """SELECT
                   COALESCE(SUM(CASE WHEN id<>? THEN COALESCE(actual_response_bytes,reserved_response_bytes) ELSE 0 END),0),
                   COALESCE(SUM(CASE WHEN id<>? THEN COALESCE(actual_storage_bytes,reserved_storage_bytes) ELSE 0 END),0)
                   FROM operations""",
                (operation_id, operation_id),
            ).fetchone()
            if int(totals[0]) + actual_bytes > limits["response_bytes"]:
                raise WebContractError("actual response exceeds campaign byte budget")
            if int(totals[1]) + storage_bytes > limits["storage_bytes"]:
                raise WebContractError("actual evidence exceeds campaign storage budget")
            other_usage = connection.execute(
                """SELECT COALESCE(SUM(CASE WHEN id<>? THEN browser_events ELSE 0 END),0),
                   COALESCE(SUM(CASE WHEN id<>? THEN websocket_bytes ELSE 0 END),0)
                   FROM operations""",
                (operation_id, operation_id),
            ).fetchone()
            actual_events = int(row["browser_events"] if browser_events is None else browser_events)
            actual_websocket = int(row["websocket_bytes"] if websocket_bytes is None else websocket_bytes)
            if int(other_usage[0]) + actual_events > limits["browser_events"]:
                raise WebContractError("actual browser events exceed campaign budget")
            if int(other_usage[1]) + actual_websocket > limits["websocket_bytes"]:
                raise WebContractError("actual websocket bytes exceed campaign budget")
            connection.execute(
                """UPDATE operations SET actual_response_bytes=?, actual_storage_bytes=?,
                   browser_events=?, websocket_bytes=?, status='completed', finished_at=?
                   WHERE id=?""",
                (actual_bytes, storage_bytes, actual_events, actual_websocket, now, operation_id),
            )
            connection.commit()
        if row["task_id"]:
            binding = {
                "taskId": row["task_id"],
                "sourceTaskId": row["source_task_id"],
                "experimentId": row["experiment_id"],
                "approachFamily": row["approach_family"],
                "mechanismFingerprint": row["mechanism_fingerprint"],
            }
            try:
                record_orchestration_event(
                    self.contract.path.parent,
                    event_type="web-operation-completed",
                    binding=binding,
                    operation_id=operation_id,
                    status="completed",
                )
            except (OSError, sqlite3.Error) as exc:
                raise WebContractError(
                    f"completed operation could not enter the durable event stream: {exc}"
                ) from exc
        return self.read()

    def abort(self, operation_id: str, reason: str) -> dict[str, Any]:
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """UPDATE operations SET status='aborted', finished_at=?, reason=?
                   WHERE id=? AND status='running'""",
                (now, reason[:1000], operation_id),
            )
            connection.commit()
        return self.read()

    def heartbeat(self, operation_id: str, lease_seconds: int = 30) -> None:
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._assert_active(connection, now)
            changed = connection.execute(
                """UPDATE operations SET lease_until=?
                   WHERE id=? AND status='running'""",
                (now + lease_seconds, operation_id),
            ).rowcount
            if changed != 1:
                raise WebContractError("dispatch capability is missing or revoked")
            connection.commit()

    def wait_rate(self, origin_id: str, max_rate: float) -> None:
        if max_rate <= 0:
            raise WebContractError("rate limit must be positive")
        interval = 1.0 / max_rate
        while True:
            now = time.time()
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._assert_active(connection, now)
                row = connection.execute(
                    "SELECT last_dispatch FROM origin_rate WHERE origin_id=?", (origin_id,)
                ).fetchone()
                remaining = 0.0 if row is None else interval - (now - float(row[0]))
                if remaining <= 0:
                    connection.execute(
                        """INSERT INTO origin_rate(origin_id,last_dispatch) VALUES(?,?)
                           ON CONFLICT(origin_id) DO UPDATE SET last_dispatch=excluded.last_dispatch""",
                        (origin_id, now),
                    )
                    connection.commit()
                    return
                connection.rollback()
            time.sleep(min(remaining, 0.1))

    def pause(self, reason: str) -> dict[str, Any]:
        return self._transition("paused", reason)

    def cancel(self, reason: str) -> dict[str, Any]:
        return self._transition("cancelled", reason)

    def _transition(self, state: str, reason: str) -> dict[str, Any]:
        if not reason.strip():
            raise WebContractError("budget transition requires a reason")
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = self._meta(connection).get("state")
            if current == "cancelled":
                raise WebContractError("cancelled budget cannot transition")
            if current != "active" and state == "paused":
                raise WebContractError("only an active budget can be paused")
            self._set_state(connection, state, reason, now)
            connection.commit()
        return self.read()

    def is_cancelled(self, operation_id: str | None = None) -> bool:
        with self._connect() as connection:
            meta = self._meta(connection)
            if meta.get("state") != "active":
                return True
            if operation_id is None:
                return False
            row = connection.execute(
                "SELECT status, lease_until FROM operations WHERE id=?", (operation_id,)
            ).fetchone()
            return row is None or row["status"] != "running" or float(row["lease_until"]) < time.time()

    def depth_gate(self, *, allow_active_synthesis: bool = False) -> dict[str, Any]:
        """Decide whether a web campaign may claim research completion.

        A user-requested stop, authorization expiry, or safety stop may always
        end traffic, but it must be described as an incomplete campaign when
        this gate fails.
        """

        policy = diversity_policy(self.contract.raw)
        with self._connect() as connection:
            rows = [
                dict(row)
                for row in connection.execute(
                    "SELECT * FROM operations WHERE cleanup=0 AND target_dispatch=1 "
                    "ORDER BY reserved_at,id"
                )
            ]
        completed = [row for row in rows if row["status"] == "completed"]
        families = {
            str(row["approach_family"])
            for row in completed
            if row.get("approach_family") in WEB_RUNTIME_FAMILIES
        }
        non_authorization = families.difference({AUTHORIZATION_FAMILY})
        novel_mechanisms = families.intersection(NOVEL_ZERO_DAY_FAMILIES)
        authorization_count = sum(
            row.get("approach_family") == AUTHORIZATION_FAMILY for row in completed
        )
        authorization_share = (
            authorization_count / len(completed) if completed else 0.0
        )
        unbound = [row["id"] for row in completed if not row.get("task_id")]

        pending_exploration: list[dict[str, str]] = []
        root_synthesis_state = "missing"
        orchestration = self.contract.path.parent / "orchestration.db"
        orchestration_error: str | None = None
        if orchestration.is_file():
            try:
                database = sqlite3.connect(orchestration)
                database.row_factory = sqlite3.Row
                pending_exploration = [
                    dict(row)
                    for row in database.execute(
                        "SELECT DISTINCT tasks.task_id,tasks.state,"
                        "task_approach_families.family_id "
                        "FROM tasks JOIN task_approach_families USING(task_id) "
                        "JOIN approach_families USING(family_id) "
                        "WHERE approach_families.exploration=1 "
                        "AND tasks.state IN ('queued','running','verifying') "
                        "ORDER BY tasks.task_id,task_approach_families.family_id"
                    )
                ]
                root = database.execute(
                    "SELECT state FROM tasks WHERE task_id='web-root-synthesis'"
                ).fetchone()
                if root is not None:
                    root_synthesis_state = str(root["state"])
                database.close()
            except sqlite3.Error as exc:
                orchestration_error = str(exc)
        else:
            orchestration_error = "orchestration.db is missing"

        blockers: list[str] = []
        if policy["enforceOperationBinding"] and unbound:
            blockers.append("target operations are not bound to durable research tasks")
        if len(families) < int(policy["minimumRuntimeFamiliesBeforeClosure"]):
            blockers.append("too few distinct runtime approach families were exercised")
        if len(non_authorization) < int(
            policy["minimumNonAuthorizationFamiliesBeforeClosure"]
        ):
            blockers.append("too few non-authorization runtime families were exercised")
        if len(novel_mechanisms) < int(
            policy["minimumNovelMechanismFamiliesBeforeClosure"]
        ):
            blockers.append(
                "too few novel zero-day mechanism families were exercised"
            )
        if (
            len(completed) > int(policy["warmupOperations"])
            and authorization_share
            > float(policy["maximumAuthorizationRequestShare"])
        ):
            blockers.append("authorization traffic exceeds the campaign family-share limit")
        if pending_exploration:
            blockers.append("eligible exploration tasks remain in the durable frontier")
        acceptable_synthesis = {"completed"}
        if allow_active_synthesis:
            acceptable_synthesis.update({"running", "verifying"})
        if root_synthesis_state not in acceptable_synthesis:
            blockers.append("web-root-synthesis is not complete")
        if orchestration_error:
            blockers.append("orchestration state could not be verified")

        return {
            "schemaVersion": 1,
            "eligibleForCompletedCampaignClaim": not blockers,
            "requiredDispositionWhenBlocked": "coverage-incomplete",
            "policy": policy,
            "completedRuntimeFamilies": sorted(families),
            "completedNonAuthorizationFamilies": sorted(non_authorization),
            "completedNovelMechanismFamilies": sorted(novel_mechanisms),
            "authorizationRequestShare": round(authorization_share, 6),
            "unboundOperationIds": unbound,
            "pendingExplorationTasks": pending_exploration,
            "rootSynthesisState": root_synthesis_state,
            "orchestrationError": orchestration_error,
            "blockers": blockers,
        }

    def read(self) -> dict[str, Any]:
        with self._connect() as connection:
            meta = self._meta(connection)
            rows = [dict(row) for row in connection.execute("SELECT * FROM operations ORDER BY reserved_at,id")]
        family_usage: dict[str, int] = {}
        for row in rows:
            family = row.get("approach_family")
            if family:
                family_usage[str(family)] = family_usage.get(str(family), 0) + 1
        return {
            "schemaVersion": 3,
            "contractSha256": meta.get("contract_sha256"),
            "startedAtUnix": float(meta.get("started_at", "0")),
            "state": meta.get("state"),
            "stateReason": meta.get("state_reason"),
            "operations": rows,
            "requests": len(rows),
            "targetRequests": sum(int(row.get("target_dispatch", 1)) for row in rows),
            "cleanupRequests": sum(int(row["cleanup"]) for row in rows),
            "requestBytes": sum(int(row["request_bytes"]) for row in rows),
            "responseBytes": sum(int(row["actual_response_bytes"] if row["actual_response_bytes"] is not None else row["reserved_response_bytes"]) for row in rows),
            "storageBytes": sum(int(row["actual_storage_bytes"] if row["actual_storage_bytes"] is not None else row["reserved_storage_bytes"]) for row in rows),
            "familyUsage": dict(sorted(family_usage.items())),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract")
    parser.add_argument("ledger")
    parser.add_argument("command", choices=("status", "pause", "cancel", "depth-gate"))
    parser.add_argument("--reason", default="operator request")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        budget = SharedWebBudget(WebCampaignContract.load(args.contract), args.ledger)
        if args.command == "pause":
            result = budget.pause(args.reason)
        elif args.command == "cancel":
            result = budget.cancel(args.reason)
        elif args.command == "depth-gate":
            result = budget.depth_gate()
        else:
            result = budget.read()
        if args.output:
            output = Path(args.output).expanduser().resolve()
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(json.dumps(result, indent=2, sort_keys=True))
        if args.command == "depth-gate":
            return 0 if result["eligibleForCompletedCampaignClaim"] else 3
        return 0
    except (OSError, ValueError, sqlite3.Error, WebContractError) as exc:
        print(f"error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
