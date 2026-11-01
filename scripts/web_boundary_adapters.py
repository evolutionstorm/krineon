#!/usr/bin/env python3
"""Admit narrowly bounded web-boundary research adapters after a measured baseline.

This is a policy compiler, not a generic exploit runner. It performs no target
traffic and produces an admitted contract only when the family-specific safety
and semantic evidence requirements are explicit.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from web_contract import WebContractError, atomic_json


FAMILIES = {
    "parser-normalization",
    "browser-injection",
    "csrf",
    "cors",
    "upload-import-export",
    "ssrf-owned-receiver",
    "session-role-invalidation",
    "graphql-api-authorization",
    "websocket-authorization",
    "browser-persistence-isolation",
    "http-desynchronization",
}
EFFECTS = {"read-only", "owned-canary", "owned-reversible-write"}


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise WebContractError(f"expected JSON object: {path}")
    return value


def text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise WebContractError(f"{field} is required")
    return result


def nonempty_list(value: Any, field: str, *, minimum: int = 1) -> list[Any]:
    if not isinstance(value, list) or len(value) < minimum:
        raise WebContractError(f"{field} requires at least {minimum} entries")
    return value


def require_true(options: dict[str, Any], field: str, message: str) -> None:
    if options.get(field) is not True:
        raise WebContractError(message)


def require_false(options: dict[str, Any], field: str, message: str) -> None:
    if options.get(field) is not False:
        raise WebContractError(message)


def validate_adapter(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("schemaVersion") != 1:
        raise WebContractError("boundary adapter schemaVersion must be 1")
    if raw.get("kind") != "krineon-web-boundary-adapter":
        raise WebContractError("input is not a Krineon boundary adapter")
    for field in ("id", "title", "prerequisiteVersion"):
        text(raw.get(field), field)
    family = str(raw.get("family") or "")
    if family not in FAMILIES:
        raise WebContractError("web boundary adapter family is unsupported")
    if raw.get("baselineMeasured") is not True:
        raise WebContractError("a legitimate baseline must be measured before adapter admission")
    invariant = raw.get("invariant")
    if not isinstance(invariant, dict):
        raise WebContractError("boundary adapter requires an invariant")
    for field in ("statement", "basis", "baselineEvidence"):
        if field == "baselineEvidence":
            nonempty_list(invariant.get(field), f"invariant.{field}")
        else:
            text(invariant.get(field), f"invariant.{field}")
    explanations = nonempty_list(raw.get("competingExplanations"), "competingExplanations", minimum=2)
    for explanation in explanations:
        if not isinstance(explanation, dict):
            raise WebContractError("competing explanations must be objects")
        text(explanation.get("id"), "competingExplanations.id")
        text(explanation.get("statement"), "competingExplanations.statement")
    effects = set(nonempty_list(raw.get("allowedEffects"), "allowedEffects"))
    if not effects.issubset(EFFECTS):
        raise WebContractError("boundary adapter permits an unsupported effect")
    fixtures = nonempty_list(raw.get("fixtures"), "fixtures")
    for fixture in fixtures:
        if not isinstance(fixture, dict) or fixture.get("owned") is not True or fixture.get("disposable") is not True:
            raise WebContractError("boundary adapter fixtures must be owned and disposable")
        for field in ("id", "generation", "factoryRef", "readbackRef", "cleanupRef"):
            text(fixture.get(field), f"fixture.{field}")
    oracle = raw.get("independentOracle")
    if not isinstance(oracle, dict):
        raise WebContractError("boundary adapter requires an independent oracle")
    for field in ("id", "observerIdentity", "authoritativeReadback", "negativeControl"):
        text(oracle.get(field), f"independentOracle.{field}")
    cleanup = raw.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("required") is not True:
        raise WebContractError("boundary adapter requires cleanup")
    if cleanup.get("irreversible") is not False:
        raise WebContractError("boundary adapter cleanup cannot be irreversible")
    text(cleanup.get("verification"), "cleanup.verification")
    options = raw.get("options")
    if not isinstance(options, dict):
        raise WebContractError("boundary adapter requires family-specific options")

    if family == "parser-normalization":
        if len(nonempty_list(options.get("boundaries"), "options.boundaries", minimum=2)) < 2:
            raise WebContractError("parser differential requires at least two real consumers")
        variants = options.get("maxRepresentations")
        if isinstance(variants, bool) or not isinstance(variants, int) or not 1 <= variants <= 16:
            raise WebContractError("parser differential permits at most 16 representations")
    elif family == "browser-injection":
        require_true(options, "ownedBrowserCanary", "browser injection requires an owned browser canary")
        require_true(options, "reflectionInsufficient", "reflection alone cannot prove browser injection")
        require_false(options, "secretExfiltration", "browser injection cannot exfiltrate secrets")
    elif family == "csrf":
        require_true(options, "realBrowserOriginAndSameSite", "CSRF requires real browser Origin and SameSite behavior")
        require_true(options, "ownedReversibleAction", "CSRF requires an owned reversible action")
        require_false(options, "rawHttpOnly", "raw HTTP replay alone cannot prove CSRF")
    elif family == "cors":
        require_true(options, "ownedTestingOrigin", "CORS requires an explicitly owned testing origin")
        require_true(options, "unauthorizedBrowserReadRequired", "CORS requires an actual unauthorized browser read")
        require_true(options, "permissiveHeaderInsufficient", "a permissive header alone cannot prove CORS impact")
    elif family == "upload-import-export":
        require_true(options, "inertFilesOnly", "upload research requires tiny inert files")
        require_true(options, "ownedRecordsOnly", "upload research requires researcher-owned records")
        maximum = options.get("maxFileBytes")
        if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= 65536:
            raise WebContractError("upload research file cap must be between 1 and 65536 bytes")
    elif family == "ssrf-owned-receiver":
        require_true(options, "receiverOwnedAndApproved", "SSRF requires an approved owned receiver")
        for field in ("metadataProbing", "internalPortScanning", "thirdPartyCallbacks"):
            require_false(options, field, "SSRF adapter permits a prohibited destination interaction")
    elif family == "session-role-invalidation":
        if len(nonempty_list(options.get("verifiedOwnedIdentities"), "options.verifiedOwnedIdentities", minimum=2)) < 2:
            raise WebContractError("session invalidation requires at least two verified owned identities")
        require_true(options, "permissionVersionTracked", "session invalidation must track application permission versions")
    elif family == "graphql-api-authorization":
        operations = options.get("maxOperations")
        if isinstance(operations, bool) or not isinstance(operations, int) or not 1 <= operations <= 8:
            raise WebContractError("GraphQL/API adapter permits at most eight operations")
        require_false(options, "batching", "GraphQL batching is disabled")
        require_false(options, "depthOrComplexityExhaustion", "GraphQL exhaustion research is disabled")
    elif family == "websocket-authorization":
        frames = options.get("maxFrames")
        if isinstance(frames, bool) or not isinstance(frames, int) or not 1 <= frames <= 16:
            raise WebContractError("WebSocket adapter permits at most sixteen frames")
        if len(nonempty_list(options.get("identitySeparatedSessions"), "options.identitySeparatedSessions", minimum=2)) < 2:
            raise WebContractError("WebSocket authorization requires identity-separated sessions")
    elif family == "browser-persistence-isolation":
        require_true(options, "applicationExposesUntrustedContent", "persistence research requires an observed untrusted-content surface")
        scopes = set(nonempty_list(options.get("scopes"), "options.scopes"))
        if not scopes.issubset({"origin-storage", "service-worker", "postMessage", "cookies"}):
            raise WebContractError("browser persistence scope is unsupported")
    elif family == "http-desynchronization":
        require_true(options, "explicitExactAuthorization", "HTTP desynchronization is off by default and requires exact authorization")
        require_true(options, "isolatedTopology", "HTTP desynchronization requires an isolated topology")
        require_false(options, "sharedLiveService", "HTTP desynchronization cannot target a shared live service")
        connections = options.get("maxConnections")
        if isinstance(connections, bool) or not isinstance(connections, int) or not 1 <= connections <= 2:
            raise WebContractError("HTTP desynchronization permits at most two isolated connections")
        maximum = options.get("maxBytes")
        if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= 65536:
            raise WebContractError("HTTP desynchronization byte cap exceeds 65536")

    return {
        **raw,
        "admitted": True,
        "genericExploitMode": False,
        "targetExecutionAuthorizedByThisContract": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("experiment", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = validate_adapter(load_object(args.experiment))
        if args.output:
            atomic_json(args.output.expanduser().resolve(), result, mode=0o600)
        print(json.dumps({"admitted": True, "id": result["id"], "family": result["family"]}, indent=2))
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
