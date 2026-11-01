#!/usr/bin/env python3
"""Convert annotated Markdown HTTP captures into a bounded web workflow.

Each request block must be preceded by a metadata comment:

  <!-- krineon: id=read-self origin=app identity=user-a effect=read-only -->

Credentials must use ``Authorization: Bearer ${secret:user-a}``. Literal
credentials are rejected and never copied to the generated workflow.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from .web_contract import WebCampaignContract, WebContractError, atomic_json
except ImportError:
    from web_contract import WebCampaignContract, WebContractError, atomic_json


COMMENT = re.compile(r"<!--\s*krineon:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)
BLOCK = re.compile(r"```(?:http|https|raw-http)\s*\n(.*?)\n```", re.IGNORECASE | re.DOTALL)
TOKEN = re.compile(r"([A-Za-z][A-Za-z0-9_.-]*)=([^\s]+)")
SECRET_PLACEHOLDER = re.compile(r"^\$\{secret:([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\}$")


def metadata_before(text: str, position: int) -> dict[str, str]:
    matches = list(COMMENT.finditer(text, 0, position))
    if not matches:
        raise WebContractError("each HTTP block requires a preceding krineon metadata comment")
    match = matches[-1]
    if text[match.end() : position].strip():
        raise WebContractError("metadata comment must immediately precede its HTTP block")
    return {key: value for key, value in TOKEN.findall(match.group(1))}


def parse_request(raw: str) -> tuple[str, str, list[list[str]], str]:
    normalized = raw.replace("\r\n", "\n")
    head, separator, body = normalized.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        raise WebContractError("HTTP block is empty")
    request_line = lines[0].split()
    if len(request_line) != 3 or not request_line[2].startswith("HTTP/"):
        raise WebContractError("HTTP block must start with METHOD PATH HTTP/VERSION")
    method, path = request_line[:2]
    headers: list[list[str]] = []
    for line in lines[1:]:
        if ":" not in line:
            raise WebContractError("HTTP header is missing a colon")
        name, value = line.split(":", 1)
        if "\r" in name + value or "\n" in name + value:
            raise WebContractError("HTTP header contains a line break")
        headers.append([name.strip(), value.strip()])
    return method.upper(), path, headers, body if separator else ""


def convert(markdown: str, contract: WebCampaignContract, source: str) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    cleanup_steps: list[dict[str, Any]] = []
    for block in BLOCK.finditer(markdown):
        meta = metadata_before(markdown, block.start())
        required = {"id", "origin", "effect"}
        missing = required.difference(meta)
        if missing:
            raise WebContractError(
                "request metadata is missing: " + ", ".join(sorted(missing))
            )
        identity_id = meta.get("identity", "anonymous")
        identity = contract.identity_for_origin(identity_id, meta["origin"])
        method, path, headers, body = parse_request(block.group(1))
        retained_headers: list[list[str]] = []
        authorization_seen = False
        for name, value in headers:
            lowered_name = name.lower()
            if lowered_name in {
                "cookie",
                "proxy-authorization",
                "x-api-key",
                "api-key",
            }:
                raise WebContractError(
                    f"credential header {name} is forbidden; use identityId and secret://"
                )
            if lowered_name != "authorization":
                retained_headers.append([name, value])
                continue
            authorization_seen = True
            if identity is None:
                raise WebContractError("anonymous requests cannot include Authorization")
            scheme, separator, credential = value.partition(" ")
            placeholder = SECRET_PLACEHOLDER.fullmatch(credential)
            if scheme.lower() != "bearer" or not separator or placeholder is None:
                raise WebContractError("literal or unsupported Authorization credentials are forbidden")
            expected = identity.credential_ref.removeprefix("secret://")
            if placeholder.group(1) != expected:
                raise WebContractError("Authorization secret placeholder does not match identity")
        if identity is not None and identity.credential_ref and not authorization_seen:
            # The broker injects this credential. It is intentionally absent
            # from retained request material.
            authorization_seen = True
        contract.admitted_request(
            origin_id=meta["origin"],
            path_or_url=path,
            method=method,
            effect_class=meta["effect"],
            cleanup=meta.get("cleanup", "false").lower() == "true",
            require_live_authorization=False,
        )
        step = {
            "id": meta["id"],
            "type": "http",
            "originId": meta["origin"],
            "identityId": identity_id,
            "method": method,
            "path": path,
            "headers": retained_headers,
            "body": body,
            "effectClass": meta["effect"],
            "operationClass": meta.get("operation", "ordinary-http"),
            "resource": {
                "id": meta.get("resource", "unclassified-resource"),
                "kind": meta.get("kind", "unclassified"),
                "expectedOwner": meta.get("owner", identity_id),
            },
            "cleanup": meta.get("cleanup", "false").lower() == "true",
            "session": meta.get(
                "session", identity.session if identity else "anonymous"
            ),
        }
        if step["cleanup"]:
            cleanup_steps.append(step)
        else:
            steps.append(step)
    if not steps:
        raise WebContractError("Markdown contains no annotated HTTP blocks")
    return {
        "schemaVersion": 1,
        "id": Path(source).stem,
        "title": f"Imported requests from {Path(source).name}",
        "hypothesis": "Imported request sequence. Add a falsifiable invariant before execution.",
        "competingExplanations": [],
        "changedVariable": "unclassified",
        "steps": steps,
        "oracles": [],
        "cleanupSteps": cleanup_steps,
        "coordinatorApproval": {
            "approved": False,
            "approvedBy": "",
            "approvedAt": None,
            "contractSha256": contract.digest,
        },
        "source": {"path": source},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract")
    parser.add_argument("markdown")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        contract = WebCampaignContract.load(args.contract)
        markdown_path = Path(args.markdown).expanduser().resolve()
        workflow = convert(
            markdown_path.read_text(encoding="utf-8"), contract, str(markdown_path)
        )
        atomic_json(Path(args.output).expanduser().resolve(), workflow, mode=0o600)
        print(f"wrote {len(workflow['steps'])} request steps")
        return 0
    except (OSError, ValueError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
