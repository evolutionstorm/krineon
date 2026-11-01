#!/usr/bin/env python3
"""Network, destination, path, and operation policy for web adapters.

The policy engine performs no target traffic. It validates the request's raw
and normalized representations, resolves destinations immediately before
dispatch, and verifies the connected peer against the latest authorized DNS
set. DNS rotation is allowed only when every newly selected address remains
inside the reviewed network policy.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import posixpath
import re
import socket
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import unquote, urlsplit

try:
    from .web_contract import (
        WebCampaignContract,
        WebContractError,
        canonical_origin,
        path_matches_prefix,
    )
except ImportError:
    from web_contract import (
        WebCampaignContract,
        WebContractError,
        canonical_origin,
        path_matches_prefix,
    )


FORBIDDEN_INTENTS = {
    "regex-backtracking",
    "deep-recursion",
    "decompression-amplification",
    "deep-nesting",
    "huge-batching",
    "cache-exhaustion",
    "worker-starvation",
    "parser-crash",
    "password-spraying",
    "rate-limit-overrun",
    "availability-impact",
}
UNRESERVED_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
BROWSER_FINGERPRINT_HEADERS = {
    "user-agent",
    "sec-ch-ua",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-mobile",
    "sec-ch-ua-model",
    "sec-ch-ua-platform",
    "sec-ch-ua-platform-version",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "sec-fetch-user",
}
PROVENANCE_REQUIRED_HEADERS = {"origin", "referer"}
SESSION_BOUND_APPLICATION_HEADERS = {
    "x-csrf-token",
    "x-xsrf-token",
    "csrf-token",
    "x-request-signature",
    "x-signature",
    "digest",
}
CHALLENGE_MARKERS = (
    b"cf-chl-",
    b"challenge-platform",
    b"verify you are human",
    b"checking your browser",
    b"enable javascript and cookies to continue",
    b"captcha",
    b"perimeterx",
    b"px-captcha",
    b"datadome",
    b"akamai bot manager",
)
LOGIN_MARKERS = (
    b"type=\"password\"",
    b"type='password'",
    b"name=\"password\"",
    b"name='password'",
    b"/login",
    b"/sign-in",
    b"/signin",
)


def validate_http_replay_headers(
    step: dict[str, Any], headers: list[tuple[str, str]]
) -> dict[str, Any]:
    """Refuse browser-fingerprint impersonation in raw HTTP workflows.

    Origin and Referer may be retained only when the coordinator identifies the
    exact owned browser observation that produced them. This records an HTTP
    replay, never a browser-equivalent request.
    """

    lowered = {name.lower() for name, _ in headers}
    forbidden = sorted(lowered.intersection(BROWSER_FINGERPRINT_HEADERS))
    if forbidden:
        raise WebContractError(
            "raw HTTP replay cannot impersonate browser fingerprint headers: "
            + ", ".join(forbidden)
        )
    contextual = sorted(
        lowered.intersection(
            PROVENANCE_REQUIRED_HEADERS | SESSION_BOUND_APPLICATION_HEADERS
        )
    )
    context = step.get("headerContext")
    if contextual:
        if not isinstance(context, dict):
            raise WebContractError(
                "session-bound or contextual raw HTTP headers require a headerContext provenance record"
            )
        if context.get("mode") != "owned-browser-capture":
            raise WebContractError(
                "contextual raw HTTP headers require mode=owned-browser-capture"
            )
        if not str(context.get("sourceObservation") or "").strip():
            raise WebContractError(
                "contextual raw HTTP headers require the source browser observation"
            )
        preserved = {
            str(value).lower() for value in context.get("preservedHeaders", [])
        }
        if not set(contextual).issubset(preserved):
            raise WebContractError(
                "each contextual header must be listed in headerContext.preservedHeaders"
            )
    changes = [] if not isinstance(context, dict) else context.get("intentionalChanges", [])
    if not isinstance(changes, list) or any(
        not isinstance(item, dict)
        or not str(item.get("name") or "").strip()
        or not str(item.get("reason") or "").strip()
        or not str(item.get("controlStep") or "").strip()
        for item in changes
    ):
        raise WebContractError(
            "headerContext.intentionalChanges must name each change, reason, and control step"
        )
    return {
        "client": "http-client-replay",
        "browserEquivalent": False,
        "contextualHeaders": contextual,
        "sourceObservation": (
            str(context.get("sourceObservation")) if isinstance(context, dict) else ""
        ),
        "intentionalChanges": changes,
    }


def classify_access_response(
    *,
    status: int,
    headers: list[tuple[str, str]],
    body: bytes,
    authenticated: bool,
    location: str = "",
) -> dict[str, Any]:
    """Classify bot challenges and authentication interstitials conservatively."""

    header_map: dict[str, list[str]] = {}
    for name, value in headers:
        header_map.setdefault(name.lower(), []).append(value)
    content_type = " ".join(header_map.get("content-type", [])).lower()
    sample = body[:262144].lower()
    challenge_hits = [
        marker.decode("ascii", "replace")
        for marker in CHALLENGE_MARKERS
        if marker in sample
    ]
    challenge_headers = sorted(
        name
        for name in header_map
        if name.startswith(("cf-chl", "x-datadome", "x-px", "akamai-"))
    )
    if challenge_hits or challenge_headers:
        return {
            "state": "environment-blocked",
            "eligibleForSecurityConclusion": False,
            "reason": "bot-protection challenge or interstitial observed",
            "challengeMarkers": challenge_hits,
            "challengeHeaders": challenge_headers,
            "httpStatus": status,
        }
    login_redirect = bool(
        status in {301, 302, 303, 307, 308}
        and re.search(r"(?i)(?:mfa|login|sign-in|signin|challenge)", location)
    )
    login_html = "html" in content_type and any(marker in sample for marker in LOGIN_MARKERS)
    authenticating = "www-authenticate" in header_map
    if status in {401, 419, 440} or authenticating or login_redirect or (
        authenticated and login_html
    ):
        return {
            "state": "auth-inconclusive",
            "eligibleForSecurityConclusion": False,
            "reason": "authentication challenge, login page, or expired session observed",
            "loginHtmlWith200": status == 200 and login_html,
            "httpStatus": status,
        }
    return {
        "state": "application-response",
        "eligibleForSecurityConclusion": True,
        "reason": "no bot or authentication interstitial was detected",
        "httpStatus": status,
    }


def _decode_unreserved(value: str) -> str:
    def replace(match: re.Match[str]) -> str:
        character = chr(int(match.group(1), 16))
        return character if character.isalnum() or character in "-._~" else match.group(0).upper()

    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        raise WebContractError("request path contains malformed percent encoding")
    return UNRESERVED_ESCAPE.sub(replace, value)


def normalize_scope_path(raw_path: str) -> str:
    if not raw_path.startswith("/"):
        raise WebContractError("request path must use origin-form")
    if "\\" in raw_path or CONTROL.search(raw_path):
        raise WebContractError("request path contains an ambiguous separator or control byte")
    path = _decode_unreserved(raw_path)
    normalized = posixpath.normpath(path)
    if path.endswith("/") and normalized != "/":
        normalized += "/"
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return normalized


def _networks(values: Any, field: str) -> tuple[ipaddress._BaseNetwork, ...]:
    if values is None:
        return ()
    if not isinstance(values, list):
        raise WebContractError(f"networkContainment.{field} must be an array")
    output = []
    for value in values:
        try:
            output.append(ipaddress.ip_network(str(value), strict=True))
        except ValueError as exc:
            raise WebContractError(f"networkContainment.{field} contains an invalid CIDR") from exc
    return tuple(output)


def _inside(address: ipaddress._BaseAddress, networks: tuple[ipaddress._BaseNetwork, ...]) -> bool:
    return any(address.version == network.version and address in network for network in networks)


@dataclass(frozen=True)
class TargetDecision:
    origin_id: str
    origin: str
    hostname: str
    port: int
    raw_path: str
    normalized_path: str
    raw_query: str
    addresses: tuple[str, ...]
    host_header: str
    sni: str | None


class WebPolicyEngine:
    def __init__(
        self,
        contract: WebCampaignContract,
        *,
        resolver: Callable[[str, int], list[tuple[Any, ...]]] | None = None,
    ):
        self.contract = contract
        self.resolver = resolver or (
            lambda host, port: socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        )
        containment = contract.raw["networkContainment"]
        self.owned_internal = _networks(
            containment.get("ownedInternalLabCidrs", []), "ownedInternalLabCidrs"
        )
        self.allowed = _networks(
            containment.get("allowedDestinationCidrs", []), "allowedDestinationCidrs"
        )
        self.denied = _networks(
            containment.get("deniedDestinationCidrs", []), "deniedDestinationCidrs"
        )

    def _address_allowed(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value.split("%", 1)[0])
        except ValueError as exc:
            raise WebContractError("DNS resolver returned an invalid address") from exc
        if _inside(address, self.denied):
            return False
        restricted = (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        )
        if restricted:
            return _inside(address, self.owned_internal)
        return not self.allowed or _inside(address, self.allowed)

    def resolve(self, hostname: str, port: int) -> tuple[str, ...]:
        try:
            records = self.resolver(hostname, port)
        except OSError as exc:
            raise WebContractError(f"DNS resolution failed for {hostname}: {exc}") from exc
        addresses = sorted({str(record[4][0]) for record in records if len(record) >= 5})
        if not addresses:
            raise WebContractError("DNS resolution returned no usable addresses")
        unauthorized = [value for value in addresses if not self._address_allowed(value)]
        if unauthorized:
            raise WebContractError(
                "DNS resolution includes unauthorized destination: " + ", ".join(unauthorized)
            )
        return tuple(addresses)

    def admit(
        self,
        *,
        origin_id: str,
        url: str,
        method: str,
        effect_class: str,
        operation_class: str,
        intent: str,
        operation: str = "http",
    ) -> TargetDecision:
        if intent in FORBIDDEN_INTENTS:
            raise WebContractError(f"prohibited web experiment intent: {intent}")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise WebContractError("dispatch URL must be absolute HTTP(S)")
        origin = canonical_origin(f"{parsed.scheme}://{parsed.netloc}")
        if origin_id not in self.contract.origins or self.contract.origins[origin_id].origin != origin:
            raise WebContractError("dispatch URL does not match its exact contract origin")
        raw_path = parsed.path or "/"
        normalized_path = normalize_scope_path(raw_path)
        policy = self.contract.origins[origin_id]
        for candidate in (raw_path, normalized_path):
            if not any(path_matches_prefix(candidate, prefix) for prefix in policy.allowed_path_prefixes):
                raise WebContractError("raw or normalized path is outside authorized scope")
            if any(path_matches_prefix(candidate, prefix) for prefix in policy.excluded_paths):
                raise WebContractError("raw or normalized path enters an excluded scope")
        # Reuse the contract's method, effect, operation, and action-policy decision.
        self.contract.admitted_request(
            origin_id=origin_id,
            path_or_url=raw_path + ("?" + parsed.query if parsed.query else ""),
            method=method,
            effect_class=effect_class,
            operation_class=operation_class,
            operation=operation,
            require_live_authorization=False,
        )
        canonical = urlsplit(origin)
        assert canonical.hostname is not None
        hostname = canonical.hostname
        port = canonical.port or (443 if parsed.scheme == "https" else 80)
        addresses = self.resolve(hostname, port)
        default = 443 if parsed.scheme == "https" else 80
        host_header = hostname
        if ":" in host_header and not host_header.startswith("["):
            host_header = f"[{host_header}]"
        if port != default:
            host_header += f":{port}"
        return TargetDecision(
            origin_id=origin_id,
            origin=origin,
            hostname=hostname,
            port=port,
            raw_path=raw_path,
            normalized_path=normalized_path,
            raw_query=parsed.query,
            addresses=addresses,
            host_header=host_header,
            sni=hostname if parsed.scheme == "https" else None,
        )

    def verify_connected(self, decision: TargetDecision, peer_address: str) -> None:
        fresh = self.resolve(decision.hostname, decision.port)
        peer = str(ipaddress.ip_address(peer_address.split("%", 1)[0]))
        normalized = {str(ipaddress.ip_address(value.split("%", 1)[0])) for value in fresh}
        if peer not in normalized or not self._address_allowed(peer):
            raise WebContractError("connected address is not in the current authorized DNS set")

    def admit_redirect(
        self,
        *,
        source: TargetDecision,
        location: str,
        method: str,
        effect_class: str,
        operation_class: str,
        intent: str,
        operation: str = "http",
    ) -> TargetDecision:
        if self.contract.raw["authorization"].get("allowRedirects") is not True:
            raise WebContractError("redirect following is not authorized")
        from urllib.parse import urljoin

        target = urljoin(source.origin + source.raw_path, location)
        parsed = urlsplit(target)
        origin = canonical_origin(f"{parsed.scheme}://{parsed.netloc}")
        matches = [item for item in self.contract.origins.values() if item.origin == origin]
        if len(matches) != 1:
            raise WebContractError("redirect destination is only a scope candidate")
        return self.admit(
            origin_id=matches[0].id,
            url=target,
            method=method,
            effect_class=effect_class,
            operation_class=operation_class,
            intent=intent,
            operation=operation,
        )


def validate_step_envelope(step: dict[str, Any], *, cleanup: bool = False) -> dict[str, Any]:
    limits = step.get("limits")
    if not isinstance(limits, dict):
        raise WebContractError("every workflow step requires a limits object")
    required = {
        "maximumEffect",
        "maxActions",
        "maxInputBytes",
        "timeoutSeconds",
        "cleanupPlan",
        "retryPolicy",
        "idempotent",
    }
    missing = required.difference(limits)
    if missing:
        raise WebContractError("step limits are missing: " + ", ".join(sorted(missing)))
    if not str(limits["maximumEffect"]).strip():
        raise WebContractError("step maximumEffect must be concrete")
    for field in ("maxActions", "maxInputBytes", "timeoutSeconds"):
        if isinstance(limits[field], bool) or int(limits[field]) < 1:
            raise WebContractError(f"step limits.{field} must be positive")
    if limits["retryPolicy"] != "never":
        raise WebContractError("automatic request retry is forbidden")
    if not isinstance(limits["idempotent"], bool):
        raise WebContractError("step limits.idempotent must be Boolean")
    if cleanup and str(limits["cleanupPlan"]).strip().lower() in {"", "none"}:
        raise WebContractError("cleanup steps require a concrete cleanup plan")
    intent = str(step.get("intent") or "ordinary-security-observation")
    if intent in FORBIDDEN_INTENTS:
        raise WebContractError(f"prohibited web experiment intent: {intent}")
    return {**limits, "intent": intent}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract")
    parser.add_argument("origin_id")
    parser.add_argument("url")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--effect", default="read-only")
    parser.add_argument("--operation-class", default="ordinary-http")
    parser.add_argument("--intent", default="authorization-invariant")
    args = parser.parse_args(argv)
    try:
        contract = WebCampaignContract.load(args.contract)
        decision = WebPolicyEngine(contract).admit(
            origin_id=args.origin_id,
            url=args.url,
            method=args.method,
            effect_class=args.effect,
            operation_class=args.operation_class,
            intent=args.intent,
        )
        print(json.dumps({
            "passed": True,
            "originId": decision.origin_id,
            "addresses": list(decision.addresses),
            "rawPath": decision.raw_path,
            "normalizedPath": decision.normalized_path,
        }, indent=2))
        return 0
    except (OSError, ValueError, WebContractError) as exc:
        print(f"error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
