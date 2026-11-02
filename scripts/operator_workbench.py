#!/usr/bin/env python3
"""Serve a loopback-only, read-only Krineon operator workbench."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import sqlite3
import sys
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

try:
    from .runtime_plane import RuntimeStore, RuntimePlaneError, campaign_root
except ImportError:
    from runtime_plane import RuntimeStore, RuntimePlaneError, campaign_root


INDEX = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>Krineon operator workbench</title>
<style>
:root{color-scheme:dark;font:14px system-ui;background:#0b0f14;color:#d9e2ec}body{margin:0}
header{padding:16px 22px;border-bottom:1px solid #27313d;display:flex;gap:18px;align-items:center}
main{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:12px;padding:12px}
section{border:1px solid #27313d;border-radius:8px;background:#111821;min-height:180px;overflow:auto}
h2{font-size:14px;margin:0;padding:10px 12px;border-bottom:1px solid #27313d;color:#89c2ff}
pre{white-space:pre-wrap;word-break:break-word;padding:10px;margin:0;font:12px ui-monospace,monospace}
.ok{color:#66d9a3}.bad{color:#ff7b72}.muted{color:#8b98a5}
</style></head><body><header><strong>Krineon</strong><span class="muted">read-only operator workbench</span>
<span id="state">connecting</span></header><main>
<section><h2>Runtime</h2><pre id="status"></pre></section>
<section><h2>Live trace</h2><pre id="events"></pre></section>
<section><h2>Research graph</h2><pre id="graph"></pre></section>
<section><h2>Traffic metadata</h2><pre id="traffic"></pre></section>
<section><h2>Approvals</h2><pre id="approvals"></pre></section>
<section><h2>Cleanup and leases</h2><pre id="cleanup"></pre></section></main>
<script>
const token=location.hash.slice(1);const headers={'Authorization':'Bearer '+token};
const show=(id,v)=>document.getElementById(id).textContent=JSON.stringify(v,null,2);
async function get(path,id){const r=await fetch(path,{headers});if(!r.ok)throw Error(path+' '+r.status);show(id,await r.json())}
async function refresh(){try{await Promise.all([get('/api/status','status'),get('/api/graph','graph'),get('/api/traffic','traffic'),get('/api/approvals','approvals'),get('/api/cleanup','cleanup')]);document.getElementById('state').textContent='live';document.getElementById('state').className='ok'}catch(e){document.getElementById('state').textContent=String(e);document.getElementById('state').className='bad'}}
let after=0;async function trace(){try{const r=await fetch('/api/events?after='+after,{headers});const v=await r.json();if(v.events.length){after=v.events[v.events.length-1].event_id;show('events',v.events)}}catch(e){}}
refresh();trace();setInterval(refresh,3000);setInterval(trace,1000);
</script></body></html>"""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rows(connection: sqlite3.Connection, query: str, values: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    connection.row_factory = sqlite3.Row
    return [dict(row) for row in connection.execute(query, values)]


def table_exists(connection: sqlite3.Connection, name: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone() is not None


def runtime_snapshot(root: Path) -> dict[str, Any]:
    store = RuntimeStore(root)
    try:
        counts = {
            table: int(store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in ("sessions", "runs", "events", "artifacts", "replays")
        }
        return {
            "counts": counts,
            "sessions": rows(store.connection, "SELECT session_id,task_id,worker_id,agent_identity,provider,model,state,updated_at FROM sessions ORDER BY updated_at DESC LIMIT 50"),
            "runs": rows(store.connection, "SELECT run_id,task_id,worker_id,session_id,state,sandbox_mode,started_at,completed_at,exit_code FROM runs ORDER BY started_at DESC LIMIT 50"),
            "replays": rows(store.connection, "SELECT * FROM replays ORDER BY created_at DESC LIMIT 50"),
        }
    finally:
        store.close()


def runtime_events(root: Path, after: int) -> dict[str, Any]:
    store = RuntimeStore(root)
    try:
        events = rows(
            store.connection,
            "SELECT event_id,run_id,task_id,worker_id,created_at,event_type,tool_call_id,payload_json,artifact_refs_json FROM events WHERE event_id>? ORDER BY event_id LIMIT 250",
            (max(0, after),),
        )
        for event in events:
            event["payload"] = json.loads(event.pop("payload_json"))
            event["artifactRefs"] = json.loads(event.pop("artifact_refs_json"))
        return {"after": after, "events": events}
    finally:
        store.close()


def graph_snapshot(root: Path) -> dict[str, Any]:
    path = root / "orchestration.db"
    if not path.is_file():
        return {"available": False, "reason": "orchestration.db is absent"}
    connection = sqlite3.connect(path)
    try:
        output: dict[str, Any] = {"available": True}
        if table_exists(connection, "depth_observations"):
            output["observations"] = rows(
                connection,
                "SELECT observation_id,task_id,worker_id,kind,mechanism,summary,confidence,state,updated_at FROM depth_observations ORDER BY updated_at DESC LIMIT 100",
            )
        if table_exists(connection, "depth_chain_plans"):
            output["chains"] = rows(
                connection,
                "SELECT chain_id,title,terminal_capability,state,priority,updated_at FROM depth_chain_plans ORDER BY priority DESC,updated_at DESC LIMIT 100",
            )
        if table_exists(connection, "depth_chain_steps"):
            output["steps"] = rows(
                connection,
                "SELECT step_id,chain_id,ordinal,title,state,scheduled_task_id,updated_at FROM depth_chain_steps ORDER BY chain_id,ordinal LIMIT 250",
            )
        if table_exists(connection, "depth_assets"):
            output["assets"] = rows(
                connection,
                "SELECT asset_id,asset_type,name,updated_at FROM depth_assets ORDER BY updated_at DESC LIMIT 100",
            )
        return output
    finally:
        connection.close()


def traffic_snapshot(root: Path) -> dict[str, Any]:
    evidence = root / "evidence" / "web"
    names = {
        "browser-observation.json", "cdp-events.redacted.json", "web-protocol-model.json",
        "client-artifact-graph.json", "budget-ledger.json", "public-evidence.json",
    }
    entries: list[dict[str, Any]] = []
    if evidence.is_dir():
        for path in evidence.rglob("*"):
            if path.is_file() and (path.name in names or path.suffix in {".har", ".jsonl"}):
                stat = path.stat()
                hash_now = stat.st_size <= 16 * 1024 * 1024
                entries.append({
                    "path": path.relative_to(root).as_posix(),
                    "size": stat.st_size,
                    "sha256": sha256_file(path) if hash_now else None,
                    "hashState": "complete" if hash_now else "deferred-large-artifact",
                    "modified": stat.st_mtime,
                })
    return {"rawBodiesExposed": False, "entries": sorted(entries, key=lambda item: item["path"])[:500]}


def approval_snapshot(root: Path) -> dict[str, Any]:
    candidates = [
        *root.glob("web/*authorization*.json"),
        *root.glob("web/*.sig"),
        *root.glob("evidence/web/*authorization*.json"),
    ]
    entries = []
    for path in sorted({candidate.resolve() for candidate in candidates if candidate.is_file()}):
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            continue
        entries.append({"path": relative, "size": path.stat().st_size, "sha256": sha256_file(path)})
    campaign = json.loads((root / "campaign.json").read_text(encoding="utf-8"))
    authorization = campaign.get("authorization") if isinstance(campaign.get("authorization"), dict) else {}
    return {
        "authorization": {
            "confirmed": authorization.get("confirmed") is True,
            "allowedEnvironment": authorization.get("allowedEnvironment"),
        },
        "entries": entries,
    }


def cleanup_snapshot(root: Path) -> dict[str, Any]:
    path = root / "orchestration.db"
    if not path.is_file():
        return {"available": False, "leases": [], "blocks": []}
    connection = sqlite3.connect(path)
    try:
        leases = rows(connection, "SELECT * FROM resource_leases ORDER BY updated_at DESC LIMIT 200") if table_exists(connection, "resource_leases") else []
        blocks = rows(connection, "SELECT * FROM resource_blocks ORDER BY updated_at DESC LIMIT 200") if table_exists(connection, "resource_blocks") else []
        return {"available": True, "leases": leases, "blocks": blocks}
    finally:
        connection.close()


class WorkbenchServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], root: Path, token: str):
        self.root = root
        self.token = token
        super().__init__(address, WorkbenchHandler)


class WorkbenchHandler(BaseHTTPRequestHandler):
    server: WorkbenchServer

    def log_message(self, format: str, *args: Any) -> None:
        return

    def authorized(self) -> bool:
        return secrets.compare_digest(self.headers.get("Authorization", ""), f"Bearer {self.server.token}")

    def write_json(self, value: Any, status: int = 200) -> None:
        payload = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/":
            payload = INDEX.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(payload)
            return
        if not self.authorized():
            self.write_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        try:
            if parsed.path == "/api/status":
                value = runtime_snapshot(self.server.root)
            elif parsed.path == "/api/events":
                query = parse_qs(parsed.query)
                value = runtime_events(self.server.root, int(query.get("after", ["0"])[0]))
            elif parsed.path == "/api/graph":
                value = graph_snapshot(self.server.root)
            elif parsed.path == "/api/traffic":
                value = traffic_snapshot(self.server.root)
            elif parsed.path == "/api/approvals":
                value = approval_snapshot(self.server.root)
            elif parsed.path == "/api/cleanup":
                value = cleanup_snapshot(self.server.root)
            else:
                self.write_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            self.write_json(value)
        except (RuntimePlaneError, ValueError, sqlite3.Error, OSError, json.JSONDecodeError) as exc:
            self.write_json({"error": f"{type(exc).__name__}: {exc}"}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def reject_mutation(self) -> None:
        self.write_json({"error": "operator workbench is read-only"}, HTTPStatus.METHOD_NOT_ALLOWED)

    do_POST = reject_mutation  # type: ignore[assignment]
    do_PUT = reject_mutation  # type: ignore[assignment]
    do_PATCH = reject_mutation  # type: ignore[assignment]
    do_DELETE = reject_mutation  # type: ignore[assignment]


def token_for(root: Path) -> tuple[str, Path]:
    path = root / "private" / "operator-workbench.token"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        token = path.read_text(encoding="utf-8").strip()
        if len(token) < 32:
            raise RuntimePlaneError("operator workbench token is invalid")
    else:
        token = secrets.token_urlsafe(32)
        path.write_text(token + "\n", encoding="utf-8")
        os.chmod(path, 0o600)
    return token, path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign")
    parser.add_argument("--host", default="127.0.0.1", choices=("127.0.0.1", "::1", "localhost"))
    parser.add_argument("--port", type=int, default=8788)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = campaign_root(args.campaign)
        token, token_path = token_for(root)
        server = WorkbenchServer((args.host, args.port), root, token)
        port = int(server.server_address[1])
        print(json.dumps({
            "url": f"http://{args.host}:{port}/#{token}",
            "tokenFile": token_path.relative_to(root).as_posix(),
            "readOnly": True,
        }), flush=True)
        server.serve_forever(poll_interval=0.25)
        return 0
    except (RuntimePlaneError, OSError) as exc:
        print(f"operator-workbench: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
