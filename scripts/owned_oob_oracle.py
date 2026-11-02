#!/usr/bin/env python3
"""Serve a bounded owned HTTP OOB callback oracle for one Krineon campaign."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from .swarm_control import ControlError, ControlStore, campaign_root, parse_time, read_object, utc_now
except ImportError:
    from swarm_control import ControlError, ControlStore, campaign_root, parse_time, read_object, utc_now


MAX_BODY = 16 * 1024
SAFE_HEADERS = {"content-type", "user-agent", "x-request-id"}


def validate_bind(root: Path, bind: str, approval_path: str | None) -> None:
    try:
        address = ipaddress.ip_address(bind)
    except ValueError as exc:
        raise ControlError("OOB bind address must be an IP literal") from exc
    if address.is_loopback:
        return
    if not approval_path:
        raise ControlError("non-loopback OOB binding requires an owner approval record")
    approval = read_object(Path(approval_path).expanduser().resolve())
    if approval.get("schemaVersion") != 1 or approval.get("allowExternalCallbacks") is not True:
        raise ControlError("OOB approval does not allow external callbacks")
    if bind not in approval.get("allowedBindAddresses", []):
        raise ControlError("OOB bind address is not owner-approved")
    if parse_time(approval.get("validUntil"), "OOB approval validUntil") <= utc_now():
        raise ControlError("OOB approval expired")
    campaign_hash = hashlib.sha256((root / "campaign.json").read_bytes()).hexdigest()
    if approval.get("campaignSha256") != campaign_hash:
        raise ControlError("OOB approval belongs to a different campaign contract")
    if not str(approval.get("approvedBy") or "").strip():
        raise ControlError("OOB approval requires approvedBy")


class OracleHandler(BaseHTTPRequestHandler):
    server_version = "KrineonOwnedOOB/1"

    def _record(self) -> None:
        parts = urlsplit(self.path)
        prefix = "/oob/"
        if not parts.path.startswith(prefix):
            self.send_error(404)
            return
        token = parts.path[len(prefix):]
        if not token or "/" in token or len(token) > 256:
            self.send_error(404)
            return
        length = int(self.headers.get("content-length") or 0)
        if length < 0 or length > MAX_BODY:
            self.send_error(413)
            return
        body = self.rfile.read(length) if length else b""
        metadata: dict[str, Any] = {
            "pathSha256": hashlib.sha256(parts.path.encode()).hexdigest(),
            "queryPresent": bool(parts.query),
            "bodyLength": len(body),
            "bodySha256": hashlib.sha256(body).hexdigest(),
            "headers": {
                key.lower(): value[:512]
                for key, value in self.headers.items()
                if key.lower() in SAFE_HEADERS
            },
        }
        store = ControlStore(self.server.campaign_root)  # type: ignore[attr-defined]
        try:
            receipt = store.record_oob(
                token=token,
                protocol="http",
                source=str(self.client_address[0]),
                method=self.command,
                metadata=metadata,
            )
            store.connection.commit()
        except ControlError:
            store.connection.rollback()
            store.close()
            self.send_error(404)
            return
        store.close()
        self.send_response(204)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = _record
    do_POST = _record
    do_HEAD = _record

    def log_message(self, format: str, *args: Any) -> None:
        return


def serve(root: Path, bind: str, port: int, approval: str | None) -> None:
    validate_bind(root, bind, approval)
    server = ThreadingHTTPServer((bind, port), OracleHandler)
    server.campaign_root = root  # type: ignore[attr-defined]
    address, actual_port = server.server_address[:2]
    print(json.dumps({"bind": address, "port": actual_port, "path": "/oob/<issued-token>"}), flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--approval")
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("port must be between 0 and 65535")
    try:
        serve(campaign_root(args.campaign), args.bind, args.port, args.approval)
        return 0
    except (ControlError, OSError) as exc:
        print(f"owned OOB oracle refused to start: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
