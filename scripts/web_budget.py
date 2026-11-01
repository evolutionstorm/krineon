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
except ImportError:
    from web_contract import (
        WebCampaignContract,
        WebContractError,
        require_identifier,
        utc_now,
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
        now = time.time()
        limits = self._limits()
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
                   status,reserved_at,lease_until)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                ),
            )
            connection.commit()
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

    def read(self) -> dict[str, Any]:
        with self._connect() as connection:
            meta = self._meta(connection)
            rows = [dict(row) for row in connection.execute("SELECT * FROM operations ORDER BY reserved_at,id")]
        return {
            "schemaVersion": 2,
            "contractSha256": meta.get("contract_sha256"),
            "startedAtUnix": float(meta.get("started_at", "0")),
            "state": meta.get("state"),
            "stateReason": meta.get("state_reason"),
            "operations": rows,
            "requests": len(rows),
            "cleanupRequests": sum(int(row["cleanup"]) for row in rows),
            "requestBytes": sum(int(row["request_bytes"]) for row in rows),
            "responseBytes": sum(int(row["actual_response_bytes"] if row["actual_response_bytes"] is not None else row["reserved_response_bytes"]) for row in rows),
            "storageBytes": sum(int(row["actual_storage_bytes"] if row["actual_storage_bytes"] is not None else row["reserved_storage_bytes"]) for row in rows),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract")
    parser.add_argument("ledger")
    parser.add_argument("command", choices=("status", "pause", "cancel"))
    parser.add_argument("--reason", default="operator request")
    args = parser.parse_args(argv)
    try:
        budget = SharedWebBudget(WebCampaignContract.load(args.contract), args.ledger)
        if args.command == "pause":
            result = budget.pause(args.reason)
        elif args.command == "cancel":
            result = budget.cancel(args.reason)
        else:
            result = budget.read()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, sqlite3.Error, WebContractError) as exc:
        print(f"error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
