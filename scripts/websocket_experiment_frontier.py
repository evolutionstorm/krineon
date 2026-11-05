#!/usr/bin/env python3
"""Build bounded WebSocket security experiments from browser-observed channels.

This module performs no network traffic. It converts the value-free protocol
model into a prioritized experiment frontier with explicit identities, controls,
frame limits, and terminal invariants.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from web_contract import WebContractError, atomic_json


def stable_id(*values: Any) -> str:
    payload = json.dumps(values, sort_keys=True, separators=(",", ":"))
    return "WS-EXP-" + hashlib.sha256(payload.encode()).hexdigest()[:20]


def build(
    model: dict[str, Any], identities: list[dict[str, Any]]
) -> dict[str, Any]:
    if model.get("kind") != "krineon-websocket-sse-protocol-model":
        raise WebContractError("WebSocket frontier requires a protocol model")
    channels = [
        value
        for value in model.get("channels", [])
        if isinstance(value, dict) and value.get("transport") == "websocket"
    ]
    verified = [
        {
            "id": str(value.get("id") or ""),
            "tenant": str(value.get("tenant") or ""),
            "roles": sorted(map(str, value.get("roles", []))),
        }
        for value in identities
        if isinstance(value, dict)
        and str(value.get("id") or "")
        and value.get("verified") is True
    ]
    experiments: list[dict[str, Any]] = []

    def add(
        channel: dict[str, Any],
        family: str,
        priority: int,
        invariant: str,
        variables: list[str],
        controls: list[str],
        *,
        minimum_identities: int = 1,
        minimum_tenants: int = 1,
    ) -> None:
        distinct_tenants = {
            value["tenant"] for value in verified if value["tenant"]
        }
        ready = (
            len(verified) >= minimum_identities
            and len(distinct_tenants) >= minimum_tenants
        )
        blockers: list[str] = []
        if len(verified) < minimum_identities:
            blockers.append("requires independently verified owned identities")
        if len(distinct_tenants) < minimum_tenants:
            blockers.append("requires verified identities in distinct owned tenants")
        experiments.append(
            {
                "id": stable_id(channel.get("id"), family),
                "channelId": channel.get("id"),
                "url": channel.get("url"),
                "family": family,
                "priority": priority,
                "state": "pending" if ready else "blocked",
                "blocker": "; ".join(blockers),
                "identityIds": [value["id"] for value in verified],
                "tenantBindings": {
                    value["id"]: value["tenant"] for value in verified
                },
                "changedVariables": variables,
                "terminalInvariant": invariant,
                "requiredControls": controls,
                "limits": {
                    "maxConnections": 2,
                    "maxFramesPerConnection": 16,
                    "maxFrameBytes": 65536,
                    "concurrency": 1,
                    "availabilityObjective": False,
                },
                "evidenceRequired": [
                    "browser-observed handshake and message shape",
                    "exact authenticated actor and effective actor",
                    "owned resource and tenant binding",
                    "server-visible terminal readback",
                    "fresh independent replay",
                ],
            }
        )

    operations = [
        value for value in model.get("operations", []) if isinstance(value, dict)
    ]
    for channel in channels:
        channel_operations = [
            value for value in operations if value.get("channelId") == channel.get("id")
        ]
        sent = [value for value in channel_operations if value.get("direction") == "sent"]
        binary = any(
            frame.get("format") == "binary"
            for frame in channel.get("frames", [])
            if isinstance(frame, dict)
        )
        add(
            channel,
            "handshake-identity-and-session-binding",
            100,
            "the upgraded channel belongs only to the authenticated identity and current session that opened it",
            ["credential", "cookie", "session", "anonymous-versus-authenticated"],
            ["same identity valid handshake", "anonymous handshake", "second owned identity"],
            minimum_identities=2,
        )
        add(
            channel,
            "per-message-identity-and-resource-authorization",
            99,
            "each message consumer rechecks the actor and exact owned resource rather than trusting the upgraded channel",
            ["identity", "owned resource reference", "message discriminator"],
            ["actor's own resource", "other owned identity's resource", "invalid resource"],
            minimum_identities=2,
        )
        add(
            channel,
            "cross-tenant-message-authorization",
            98,
            "each message consumer rechecks the actor, tenant, resource, and action rather than trusting the channel",
            ["identity", "tenant", "owned resource reference", "message discriminator"],
            ["actor's own resource", "other owned identity's resource", "invalid resource"],
            minimum_identities=2,
            minimum_tenants=2,
        )
        add(
            channel,
            "origin-and-subprotocol-binding",
            92,
            "the handshake accepts only the intended browser origin and negotiated application subprotocol",
            ["Origin", "Sec-WebSocket-Protocol"],
            ["observed browser origin", "owned alternate origin", "missing subprotocol"],
        )
        add(
            channel,
            "revocation-expiry-and-reconnect",
            96,
            "logout, revocation, permission change, and expiry invalidate both existing and reconnected channels",
            ["session generation", "permission version", "reconnect timing"],
            ["valid connection before change", "existing connection after change", "fresh reconnect after change"],
            minimum_identities=2,
        )
        if sent:
            add(
                channel,
                "message-replay-order-and-alternate-consumer",
                90,
                "one-time or ordered WebSocket operations cannot be replayed, reordered, or consumed through another identity",
                ["message order", "repeat count", "consumer identity"],
                ["legitimate sequence", "single bounded replay", "reordered owned-fixture sequence"],
                minimum_identities=2,
            )
        if binary:
            add(
                channel,
                "binary-frame-parser-differential",
                88,
                "browser and server consumers agree on the structure and boundaries of the same bounded binary frame",
                ["length encoding", "frame fragmentation", "representation"],
                ["observed valid frame", "one-field structural mutation", "clean reconnect"],
            )

    if not channels:
        experiments.append(
            {
                "id": stable_id(model.get("eventsSha256"), "acquire-websocket"),
                "family": "websocket-surface-acquisition",
                "priority": 100,
                "state": "blocked",
                "blocker": "no WebSocket channel was observed in the approved browser journey",
                "nextExperiment": (
                    "exercise observed realtime, notification, collaboration, job-progress, "
                    "or streaming UI features with owned fixtures and rebuild the protocol model"
                ),
            }
        )

    return {
        "schemaVersion": 1,
        "kind": "krineon-websocket-experiment-frontier",
        "protocolModelSha256": hashlib.sha256(
            json.dumps(model, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "policy": {
            "specialFocus": True,
            "browserObservedChannelsOnly": True,
            "ownedIdentitiesAndResourcesOnly": True,
            "rawPayloadValuesRetained": False,
            "availabilityTesting": False,
            "automaticCoordinatorScheduling": True,
        },
        "experiments": sorted(
            experiments, key=lambda value: (-int(value["priority"]), str(value["id"]))
        ),
        "coverage": {
            "observedWebSocketChannels": len(channels),
            "verifiedOwnedIdentities": len(verified),
            "pendingExperiments": sum(
                value.get("state") == "pending" for value in experiments
            ),
            "blockedExperiments": sum(
                value.get("state") == "blocked" for value in experiments
            ),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", type=Path)
    parser.add_argument("--identities", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        model = json.loads(args.model.read_text(encoding="utf-8"))
        identities_value = json.loads(args.identities.read_text(encoding="utf-8"))
        identities = (
            identities_value.get("identities", [])
            if isinstance(identities_value, dict) else identities_value
        )
        if not isinstance(model, dict) or not isinstance(identities, list):
            raise WebContractError("model and identities must be structured JSON")
        result = build(model, identities)
        atomic_json(args.output, result, mode=0o600)
        print(json.dumps(result["coverage"], indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, WebContractError) as exc:
        print(f"WebSocket frontier error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
