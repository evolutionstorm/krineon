#!/usr/bin/env python3
"""Owned loopback fixture for real-Chromium browser acceptance coverage."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return

    def send_value(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/login":
            self.send_value(200, b"<form><input name=csrf value=owned-csrf><input name=user></form>", "text/html")
        elif self.path == "/csrf":
            self.send_value(200, b'{"csrf":"owned-csrf"}', "application/json")
        elif self.path == "/frame":
            self.send_value(200, b"<p id=frame>owned iframe</p>", "text/html")
        elif self.path == "/popup":
            self.send_value(200, b"<p id=popup>owned popup</p>", "text/html")
        elif self.path == "/sw.js":
            self.send_value(200, b"self.addEventListener('fetch',()=>{});", "text/javascript")
        elif self.path == "/app.min.js":
            body = b"""const API='/api';const custom=(p,o)=>fetch(API+p,o);fetch('/csrf').then(r=>r.json()).then(v=>localStorage.setItem('csrf-seen',v.csrf));custom('/projects/owned?view=summary',{headers:{Accept:'application/json'}});fetch('/graphql?query=OwnedProject');navigator.serviceWorker.register('/sw.js');window.open('/popup','owned-popup');new WebSocket('ws://'+location.host+'/ws');import('/lazy.js');const decoy='https://example.invalid/docs/delete-everything';\n//# sourceMappingURL=app.min.js.map\n"""
            self.send_value(200, body, "text/javascript")
        elif self.path == "/lazy.js":
            body = b"""export function redeem(invitationId){return fetch('/api/invitations/'+invitationId+'/redeem',{method:'POST',headers:{'Content-Type':'application/json'}})}fetch('/api/lazy-observed');\n//# sourceMappingURL=lazy.js.map\n"""
            self.send_value(200, body, "text/javascript")
        elif self.path in {"/api/projects/owned?view=summary", "/api/lazy-observed"}:
            self.send_value(200, b'{"id":"owned-project"}', "application/json")
        elif self.path.startswith("/graphql?query=OwnedProject"):
            self.send_value(200, b'{"data":{"project":{"id":"owned-project"}}}', "application/json")
        elif self.path in {"/app.min.js.map", "/lazy.js.map"}:
            body = json.dumps(
                {
                    "version": 3,
                    "file": self.path.removeprefix("/").removesuffix(".map"),
                    "sources": [self.path.removesuffix(".map") + ".source.js"],
                    "sourcesContent": ["// owned source map fixture"],
                    "names": [],
                    "mappings": "AAAA",
                }
            ).encode()
            self.send_value(200, body, "application/json")
        elif self.path == "/ws":
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
        elif self.path == "/fixture":
            body = b"""<!doctype html><title>owned fixture</title>
            <a href='/login'>owned login</a>
            <iframe src='/frame'></iframe>
            <script type='module' src='/app.min.js'></script>"""
            self.send_value(200, body, "text/html")
        else:
            self.send_value(404, json.dumps({"error": "not-found"}).encode(), "application/json")



def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
