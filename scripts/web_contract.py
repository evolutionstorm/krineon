#!/usr/bin/env python3
"""Validate web campaign authority and enforce shared execution budgets.

This module is the policy boundary shared by HTTP, browser, replay, and scanner
adapters. It performs no network traffic.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

try:
    from .experiment_control import (
        ExperimentControlError,
        authority_paths,
        control_public_key,
        ensure_authority,
        sign_file,
        verify_file,
    )
except ImportError:
    from experiment_control import (
        ExperimentControlError,
        authority_paths,
        control_public_key,
        ensure_authority,
        sign_file,
        verify_file,
    )


MANDATORY_DENIED_EFFECTS = {
    "dos",
    "resource-exhaustion",
    "third-party-data",
    "real-fund-movement",
    "persistence",
    "uncontrolled-command-execution",
    "port-scanning",
    "host-discovery",
    "bot-evasion",
}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
EFFECT_CLASSES = {
    "read-only",
    "disposable-write",
    "sensitive",
    "external-side-effect",
    "unknown",
}
OPERATION_CLASSES = {
    "ordinary-http",
    "browser-discovery",
    "browser-action",
    "nuclei-read",
    "cache-experiment",
    "deserialization-experiment",
    "bounded-concurrency",
    "external-callback",
    "upload",
    "terminal-execution",
    "websocket",
    "credential-refresh",
    "oauth-refresh",
    "csrf-handling",
    "request-signing",
    "http-desynchronization",
}
CREDENTIAL_TYPES = {"bearer", "cookie", "api-key", "browser-session"}
CREDENTIAL_TRANSPORTS = {"http", "browser"}
SECRET_REF = re.compile(r"^secret://[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
IDENTIFIER = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
BEARER = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+\-/]+=*")
AUTHORIZATION_REVIEW_CHECKS = (
    "exactOriginsAndPaths",
    "methodsAndActions",
    "ownedAccountsAndTenants",
    "effectClassesAndLimits",
    "budgetsAndCleanup",
    "stopConditions",
    "thirdPartyDataExcluded",
)


class WebContractError(RuntimeError):
    """The web campaign contract does not authorize an operation."""


class ExecutionLease:
    """Conservatively serialize all target-facing adapters for one campaign."""

    def __init__(self, path: Path | str, adapter: str):
        self.path = Path(path).expanduser().resolve()
        self.adapter = adapter
        self.stream: Any | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self.stream.close()
            self.stream = None
            raise WebContractError(
                "another web adapter holds the campaign execution lease"
            ) from exc
        self.stream.seek(0)
        self.stream.truncate()
        self.stream.write(
            json.dumps(
                {
                    "adapter": self.adapter,
                    "pid": os.getpid(),
                    "acquiredAt": utc_now().isoformat(),
                },
                sort_keys=True,
            )
            + "\n"
        )
        self.stream.flush()
        os.fsync(self.stream.fileno())

    def release(self) -> None:
        if self.stream is None:
            return
        fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
        self.stream.close()
        self.stream = None


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.strip():
        raise WebContractError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WebContractError(f"{field} is not a valid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise WebContractError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def atomic_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(mode)
    os.replace(temporary, path)


def load_object(path: Path | str, label: str) -> dict[str, Any]:
    resolved = Path(path).expanduser().resolve()
    try:
        value = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WebContractError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise WebContractError(f"{label} must be a JSON object")
    return value


def safe_campaign_path(campaign: Path, value: Any, field: str) -> Path:
    relative = Path(str(value or ""))
    if not str(relative) or relative.is_absolute() or ".." in relative.parts:
        raise WebContractError(f"{field} must be a campaign-relative path")
    resolved = (campaign / relative).resolve()
    try:
        resolved.relative_to(campaign.resolve())
    except ValueError as exc:
        raise WebContractError(f"{field} escapes the campaign") from exc
    return resolved


def canonical_origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        raise WebContractError("origins must use http or https")
    if not parsed.hostname or parsed.username or parsed.password:
        raise WebContractError("origin must contain only a hostname and optional port")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise WebContractError("origin URL must not contain a path, query, or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise WebContractError("origin contains an invalid port") from exc
    default = 443 if parsed.scheme == "https" else 80
    hostname = parsed.hostname
    if "%" in hostname or "\x00" in hostname:
        raise WebContractError("origin hostname contains an ambiguous escape")
    try:
        ipaddress.ip_address(hostname.split("%", 1)[0])
        authority = hostname.lower()
    except ValueError:
        try:
            authority = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise WebContractError("origin hostname is not valid IDNA") from exc
        if not authority:
            raise WebContractError("origin hostname is empty after canonicalization")
    if ":" in authority and not authority.startswith("["):
        authority = f"[{authority}]"
    if port is not None and port != default:
        authority += f":{port}"
    return f"{parsed.scheme}://{authority}"


def path_matches_prefix(path: str, prefix: str) -> bool:
    if prefix == "/":
        return path.startswith("/")
    normalized = prefix.rstrip("/")
    return path == normalized or path.startswith(normalized + "/")


def require_identifier(value: Any, field: str) -> str:
    text = str(value or "")
    if not IDENTIFIER.fullmatch(text):
        raise WebContractError(f"{field} must be a stable identifier")
    return text


def require_positive_int(value: Any, field: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool):
        raise WebContractError(f"{field} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise WebContractError(f"{field} must be an integer") from exc
    minimum = 0 if allow_zero else 1
    if parsed < minimum:
        raise WebContractError(f"{field} must be at least {minimum}")
    return parsed


@dataclass(frozen=True)
class OriginPolicy:
    id: str
    origin: str
    purpose: str
    allowed_path_prefixes: tuple[str, ...]
    excluded_paths: tuple[str, ...]
    allowed_methods: frozenset[str]
    max_requests_per_second: float
    max_concurrent_requests: int


@dataclass(frozen=True)
class IdentityPolicy:
    id: str
    credential_ref: str
    credential_type: str
    expected_tenant: str
    roles: tuple[str, ...]
    session: str
    allowed_origin_ids: frozenset[str]
    allowed_path_prefixes: tuple[str, ...]
    allowed_transports: frozenset[str]
    expires_at: dt.datetime | None
    verification_status: str
    verification_method: str
    verification_evidence: str
    api_key_header: str
    cookie_name: str
    secret_version: str


@dataclass(frozen=True)
class ActionPolicy:
    id: str
    origin_id: str
    path_prefix: str
    methods: frozenset[str]
    effect_classes: frozenset[str]
    max_request_body_bytes: int
    max_response_body_bytes: int


class WebCampaignContract:
    """Validated versioned authority for one web campaign."""

    def __init__(self, path: Path, raw: dict[str, Any], digest: str):
        self.path = path
        self.raw = raw
        self.digest = digest
        self.origins: dict[str, OriginPolicy] = {}
        self.identities: dict[str, IdentityPolicy] = {}
        self.action_policies: list[ActionPolicy] = []
        self._validate()

    @classmethod
    def load(cls, path: Path | str) -> "WebCampaignContract":
        resolved = Path(path).expanduser().resolve()
        payload = resolved.read_bytes()
        try:
            raw = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise WebContractError(f"invalid web campaign JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise WebContractError("web campaign must be a JSON object")
        return cls(resolved, raw, sha256_bytes(payload))

    def _validate(self) -> None:
        if self.raw.get("schemaVersion") != 2:
            raise WebContractError("web campaign schemaVersion must be 2")
        if self.raw.get("profile") != "web-app":
            raise WebContractError("web campaign profile must be web-app")
        if self.raw.get("targetKind") != "web-application":
            raise WebContractError("targetKind must be web-application")
        if self.raw.get("discoveryTrack") not in {"first-principles", "known-issue-baseline"}:
            raise WebContractError("discoveryTrack must be explicit")
        known = self.raw.get("knownIssueBaseline")
        known = known if isinstance(known, dict) else {}
        if self.raw.get("discoveryTrack") == "first-principles" and known.get("enabled") is True:
            raise WebContractError("first-principles campaigns cannot enable known-issue baselines")
        if self.raw.get("discoveryTrack") == "known-issue-baseline":
            if known.get("enabled") is not True or not isinstance(known.get("sources"), list) or not known.get("sources"):
                raise WebContractError(
                    "known-issue-baseline campaigns require explicit baseline sources"
                )
        if not str(self.raw.get("environmentOwner") or "").strip():
            raise WebContractError("environmentOwner is required")

        origins = self.raw.get("origins")
        if not isinstance(origins, list) or not origins:
            raise WebContractError("at least one exact origin is required")
        for index, item in enumerate(origins):
            if not isinstance(item, dict):
                raise WebContractError(f"origins[{index}] must be an object")
            origin_id = require_identifier(item.get("id"), f"origins[{index}].id")
            if origin_id in self.origins:
                raise WebContractError(f"duplicate origin id: {origin_id}")
            prefixes = item.get("allowedPathPrefixes")
            if not isinstance(prefixes, list) or not prefixes:
                raise WebContractError(f"origin {origin_id} requires allowedPathPrefixes")
            prefix_values = tuple(str(value) for value in prefixes)
            excluded_values = tuple(str(value) for value in item.get("excludedPaths", []))
            if any(not value.startswith("/") for value in (*prefix_values, *excluded_values)):
                raise WebContractError(f"origin {origin_id} paths must start with /")
            methods = item.get("allowedMethods")
            if not isinstance(methods, list) or not methods:
                raise WebContractError(f"origin {origin_id} requires allowedMethods")
            method_values = frozenset(str(value).upper() for value in methods)
            if any(not re.fullmatch(r"[A-Z]+", value) for value in method_values):
                raise WebContractError(f"origin {origin_id} contains an invalid method")
            self.origins[origin_id] = OriginPolicy(
                id=origin_id,
                origin=canonical_origin(str(item.get("url") or "")),
                purpose=str(item.get("purpose") or ""),
                allowed_path_prefixes=prefix_values,
                excluded_paths=excluded_values,
                allowed_methods=method_values,
                max_requests_per_second=float(item.get("maxRequestsPerSecond") or 0),
                max_concurrent_requests=require_positive_int(
                    item.get("maxConcurrentRequests"),
                    f"origins[{index}].maxConcurrentRequests",
                ),
            )
            if self.origins[origin_id].max_requests_per_second <= 0:
                raise WebContractError(f"origin {origin_id} requires a positive rate limit")
            if not self.origins[origin_id].purpose.strip():
                raise WebContractError(f"origin {origin_id} requires a purpose")

        authorization = self.raw.get("authorization")
        if not isinstance(authorization, dict):
            raise WebContractError("authorization object is required")
        denied = set(str(value) for value in authorization.get("denyEffects", []))
        missing_denials = MANDATORY_DENIED_EFFECTS.difference(denied)
        if missing_denials:
            raise WebContractError(
                "authorization.denyEffects is missing mandatory exclusions: "
                + ", ".join(sorted(missing_denials))
            )
        if authorization.get("unknownEffectPolicy") != "block-until-reviewed":
            raise WebContractError("unknown effects must be blocked until reviewed")
        for field in (
            "allowCacheMutation",
            "allowDeserializationExperiments",
            "allowBoundedConcurrency",
            "allowExternalCallbacks",
            "allowRedirects",
            "allowUploads",
            "allowWebSockets",
            "allowBrowserNavigation",
            "allowStateChangingOperations",
            "allowTerminalExecution",
            "allowNuclei",
            "allowCredentialRefresh",
            "allowOAuthRefresh",
            "allowCsrfHandling",
            "allowRequestSigning",
            "allowHttpDesynchronization",
        ):
            if not isinstance(authorization.get(field), bool):
                raise WebContractError(f"authorization.{field} must be Boolean")
        race = authorization.get("boundedRaceApproval")
        if not isinstance(race, dict):
            raise WebContractError("authorization.boundedRaceApproval is required")
        if race.get("availabilityObjective") is not False:
            raise WebContractError("bounded race tests cannot have an availability objective")
        participants = require_positive_int(
            race.get("maxParticipants"),
            "authorization.boundedRaceApproval.maxParticipants",
        )
        if participants > 4:
            raise WebContractError("bounded race tests permit at most four participants")
        if authorization.get("allowBoundedConcurrency") is True:
            if race.get("approved") is not True or not str(
                race.get("disposableFixture") or ""
            ).strip():
                raise WebContractError(
                    "bounded concurrency requires separate approval and a disposable fixture"
                )
        elif race.get("approved") is True:
            raise WebContractError(
                "boundedRaceApproval cannot be approved while bounded concurrency is disabled"
            )
        bot_access = authorization.get("botProtectionApproval")
        if not isinstance(bot_access, dict):
            raise WebContractError("authorization.botProtectionApproval is required")
        if not isinstance(bot_access.get("enabled"), bool):
            raise WebContractError(
                "authorization.botProtectionApproval.enabled must be Boolean"
            )
        if bot_access.get("enabled") is True:
            if bot_access.get("kind") not in {
                "approved-staging",
                "source-ip-allowlist",
                "test-account-policy",
                "researcher-access-path",
            }:
                raise WebContractError(
                    "bot-protection access requires a recognized owner-approved arrangement"
                )
            for field in ("approvedBy", "evidence"):
                if not str(bot_access.get(field) or "").strip():
                    raise WebContractError(
                        f"bot-protection access requires {field}"
                    )
            if bot_access.get("baselineRevalidated") is not True:
                raise WebContractError(
                    "bot-protection access requires a revalidated application baseline"
                )
            differences = bot_access.get("environmentDifferences")
            if not isinstance(differences, list) or any(
                not isinstance(value, str) or not value.strip()
                for value in differences
            ):
                raise WebContractError(
                    "bot-protection environment differences must be an array of descriptions"
                )
        elif any(
            bot_access.get(field)
            for field in (
                "kind",
                "approvedBy",
                "evidence",
                "baselineRevalidated",
                "environmentDifferences",
            )
        ):
            raise WebContractError(
                "disabled bot-protection approval cannot claim an access arrangement"
            )
        callbacks = authorization.get("approvedCallbackOriginIds")
        if not isinstance(callbacks, list) or any(
            not isinstance(value, str) or value not in self.origins for value in callbacks
        ):
            raise WebContractError(
                "authorization.approvedCallbackOriginIds must contain exact contract origin IDs"
            )
        if authorization.get("allowExternalCallbacks") is True and not callbacks:
            raise WebContractError(
                "external callbacks require independently approved callback origins"
            )
        if authorization.get("allowExternalCallbacks") is False and callbacks:
            raise WebContractError(
                "callback origins cannot be approved while callbacks are disabled"
            )
        if authorization.get("confirmed") is True:
            if not str(authorization.get("confirmedBy") or "").strip():
                raise WebContractError("confirmed authorization requires confirmedBy")
            parse_time(authorization.get("confirmedAt"), "authorization.confirmedAt")
            valid_until = parse_time(
                authorization.get("validUntil"), "authorization.validUntil"
            )
            if valid_until <= utc_now():
                raise WebContractError("authorization has expired")
            if not str(authorization.get("ownedFixtureNamespace") or "").strip():
                raise WebContractError("confirmed authorization requires an owned fixture namespace")
            if not str(authorization.get("rulesFile") or "").strip():
                raise WebContractError("confirmed authorization requires a retained rules file")
            program = self.raw.get("program")
            if not isinstance(program, dict):
                raise WebContractError("confirmed authorization requires program metadata")
            rules_date = str(program.get("rulesDate") or "")
            try:
                dt.date.fromisoformat(rules_date)
            except ValueError as exc:
                raise WebContractError(
                    "confirmed authorization requires program.rulesDate in YYYY-MM-DD form"
                ) from exc
            approval_record = authorization.get("approvalRecord")
            approval_signature = authorization.get("approvalSignature")
            if bool(approval_record) != bool(approval_signature):
                raise WebContractError(
                    "authorization approvalRecord and approvalSignature must be supplied together"
                )
            if approval_record:
                safe_campaign_path(
                    self.path.parent,
                    approval_record,
                    "authorization.approvalRecord",
                )
                safe_campaign_path(
                    self.path.parent,
                    approval_signature,
                    "authorization.approvalSignature",
                )

        identities = self.raw.get("identities")
        if not isinstance(identities, list):
            raise WebContractError("identities must be an array")
        for index, item in enumerate(identities):
            if not isinstance(item, dict):
                raise WebContractError(f"identities[{index}] must be an object")
            identity_id = require_identifier(item.get("id"), f"identities[{index}].id")
            if identity_id in self.identities:
                raise WebContractError(f"duplicate identity id: {identity_id}")
            credential_ref = str(item.get("credentialRef") or "")
            if credential_ref and not SECRET_REF.fullmatch(credential_ref):
                raise WebContractError(
                    f"identity {identity_id} credentialRef must use secret://"
                )
            allowed_origin_ids = frozenset(
                str(value) for value in item.get("allowedOriginIds", [])
            )
            if credential_ref and not allowed_origin_ids:
                raise WebContractError(
                    f"identity {identity_id} requires allowedOriginIds for credential use"
                )
            secret_version = str(item.get("secretVersion") or "")
            if credential_ref:
                require_identifier(
                    secret_version, f"identities[{index}].secretVersion"
                )
            unknown_origins = allowed_origin_ids.difference(self.origins)
            if unknown_origins:
                raise WebContractError(
                    f"identity {identity_id} uses unknown credential origins: "
                    + ", ".join(sorted(unknown_origins))
                )
            credential_type = str(item.get("credentialType") or "bearer")
            if credential_type not in CREDENTIAL_TYPES:
                raise WebContractError(
                    f"identity {identity_id} has an unsupported credentialType"
                )
            allowed_paths = item.get("allowedPathPrefixes", ["/"])
            if not isinstance(allowed_paths, list) or not allowed_paths or any(
                not isinstance(value, str) or not value.startswith("/")
                for value in allowed_paths
            ):
                raise WebContractError(
                    f"identity {identity_id} requires allowedPathPrefixes"
                )
            allowed_transports = frozenset(
                str(value) for value in item.get("allowedTransports", ["http"])
            )
            if not allowed_transports or not allowed_transports.issubset(
                CREDENTIAL_TRANSPORTS
            ):
                raise WebContractError(
                    f"identity {identity_id} has invalid allowedTransports"
                )
            expires_value = item.get("expiresAt")
            expires_at = (
                parse_time(expires_value, f"identities[{index}].expiresAt")
                if expires_value is not None
                else None
            )
            verification = item.get("verification", {})
            if not isinstance(verification, dict):
                raise WebContractError(
                    f"identity {identity_id} verification must be an object"
                )
            verification_status = str(verification.get("status") or "unverified")
            if verification_status not in {"verified", "unverified"}:
                raise WebContractError(
                    f"identity {identity_id} has an invalid verification status"
                )
            verification_method = str(verification.get("method") or "")
            verification_evidence = str(verification.get("evidence") or "")
            if verification_status == "verified" and (
                verification_method not in {
                    "owner-assertion",
                    "reviewed-endpoint",
                    "interactive-browser-checkpoint",
                }
                or not verification_evidence.strip()
                or not str(item.get("expectedTenant") or "").strip()
            ):
                raise WebContractError(
                    f"identity {identity_id} verification lacks reviewed tenant evidence"
                )
            api_key_header = str(item.get("apiKeyHeader") or "X-API-Key")
            if credential_type == "api-key" and (
                not re.fullmatch(r"[A-Za-z0-9-]{1,128}", api_key_header)
                or api_key_header.lower()
                in {"host", "content-length", "transfer-encoding", "connection"}
            ):
                raise WebContractError(
                    f"identity {identity_id} has an invalid apiKeyHeader"
                )
            cookie_name = str(item.get("cookieName") or "session")
            if credential_type in {"cookie", "browser-session"} and not re.fullmatch(
                r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}", cookie_name
            ):
                raise WebContractError(
                    f"identity {identity_id} has an invalid cookieName"
                )
            self.identities[identity_id] = IdentityPolicy(
                id=identity_id,
                credential_ref=credential_ref,
                credential_type=credential_type,
                expected_tenant=str(item.get("expectedTenant") or ""),
                roles=tuple(str(value) for value in item.get("roles", [])),
                session=str(item.get("session") or identity_id),
                allowed_origin_ids=allowed_origin_ids,
                allowed_path_prefixes=tuple(str(value) for value in allowed_paths),
                allowed_transports=allowed_transports,
                expires_at=expires_at,
                verification_status=verification_status,
                verification_method=verification_method,
                verification_evidence=verification_evidence,
                api_key_header=api_key_header,
                cookie_name=cookie_name,
                secret_version=secret_version,
            )

        effects = self.raw.get("effectClasses")
        if not isinstance(effects, dict):
            raise WebContractError("effectClasses is required")
        if set(effects).difference(EFFECT_CLASSES):
            raise WebContractError("effectClasses contains an unknown class")
        for required in EFFECT_CLASSES:
            if required not in effects or not isinstance(effects[required], dict):
                raise WebContractError(f"effectClasses.{required} is required")
        if effects["unknown"].get("permitted") is not False:
            raise WebContractError("unknown effects cannot be permitted")

        action_policies = self.raw.get("actionPolicies")
        if not isinstance(action_policies, list) or not action_policies:
            raise WebContractError("actionPolicies must contain bounded action rules")
        action_ids: set[str] = set()
        for index, item in enumerate(action_policies):
            if not isinstance(item, dict):
                raise WebContractError(f"actionPolicies[{index}] must be an object")
            action_id = require_identifier(item.get("id"), f"actionPolicies[{index}].id")
            if action_id in action_ids:
                raise WebContractError(f"duplicate action policy id: {action_id}")
            action_ids.add(action_id)
            origin_id = require_identifier(
                item.get("originId"), f"actionPolicies[{index}].originId"
            )
            if origin_id not in self.origins:
                raise WebContractError(f"action policy {action_id} uses an unknown origin")
            path_prefix = str(item.get("pathPrefix") or "")
            if not path_prefix.startswith("/"):
                raise WebContractError(f"action policy {action_id} requires a path prefix")
            methods = item.get("methods")
            effect_values = item.get("effectClasses")
            if not isinstance(methods, list) or not methods:
                raise WebContractError(f"action policy {action_id} requires methods")
            if not isinstance(effect_values, list) or not effect_values:
                raise WebContractError(f"action policy {action_id} requires effectClasses")
            normalized_methods = frozenset(str(value).upper() for value in methods)
            normalized_effects = frozenset(str(value) for value in effect_values)
            if not normalized_methods.issubset(self.origins[origin_id].allowed_methods):
                raise WebContractError(
                    f"action policy {action_id} exceeds its origin method authority"
                )
            if not normalized_effects.issubset(EFFECT_CLASSES):
                raise WebContractError(f"action policy {action_id} has an unknown effect")
            self.action_policies.append(
                ActionPolicy(
                    id=action_id,
                    origin_id=origin_id,
                    path_prefix=path_prefix,
                    methods=normalized_methods,
                    effect_classes=normalized_effects,
                    max_request_body_bytes=require_positive_int(
                        item.get("maxRequestBodyBytes"),
                        f"actionPolicies[{index}].maxRequestBodyBytes",
                    ),
                    max_response_body_bytes=require_positive_int(
                        item.get("maxResponseBodyBytes"),
                        f"actionPolicies[{index}].maxResponseBodyBytes",
                    ),
                )
            )

        budget = self.raw.get("budget")
        if not isinstance(budget, dict):
            raise WebContractError("budget is required")
        for field in (
            "totalRequests",
            "totalRequestBytes",
            "totalResponseBytes",
            "maxConcurrentRequests",
            "maxRequestBodyBytes",
            "maxResponseBodyBytes",
            "maxDecompressedBytes",
            "maxRedirects",
            "maxWebsocketFrameBytes",
            "maxBrowserEvents",
            "totalStorageBytes",
            "maxActions",
            "maxWallSeconds",
        ):
            require_positive_int(
                budget.get(field),
                f"budget.{field}",
                allow_zero=field == "maxRedirects",
            )
        cleanup = require_positive_int(
            budget.get("cleanupReservedRequests"),
            "budget.cleanupReservedRequests",
            allow_zero=True,
        )
        if cleanup >= int(budget["totalRequests"]):
            raise WebContractError("cleanup reserve must be smaller than totalRequests")
        if int(budget.get("automaticRetries", -1)) != 0:
            raise WebContractError("automaticRetries must be zero")
        if float(budget.get("maxRequestsPerSecond") or 0) <= 0:
            raise WebContractError("budget.maxRequestsPerSecond must be positive")
        if any(
            policy.max_request_body_bytes > int(budget["maxRequestBodyBytes"])
            or policy.max_response_body_bytes > int(budget["maxResponseBodyBytes"])
            for policy in self.action_policies
        ):
            raise WebContractError("action policy byte limits cannot exceed campaign limits")

        program = self.raw.get("program")
        if not isinstance(program, dict):
            raise WebContractError("program metadata is required")
        researcher_headers = program.get("researcherHeaders")
        if not isinstance(researcher_headers, dict):
            raise WebContractError("program.researcherHeaders must be an object")
        for name, value in researcher_headers.items():
            lowered = str(name).lower()
            if lowered in {
                "authorization",
                "proxy-authorization",
                "cookie",
                "set-cookie",
                "x-api-key",
                "api-key",
            }:
                raise WebContractError("researcher headers cannot contain credentials")
            if "\r" in str(name) + str(value) or "\n" in str(name) + str(value):
                raise WebContractError("researcher header contains a line break")

        nuclei = self.raw.get("nuclei")
        if not isinstance(nuclei, dict):
            raise WebContractError("nuclei policy is required")
        enabled = nuclei.get("enabled") is True
        max_templates = require_positive_int(
            nuclei.get("maxTemplates"), "nuclei.maxTemplates", allow_zero=True
        )
        templates = nuclei.get("admittedTemplates")
        if not isinstance(templates, list):
            raise WebContractError("nuclei.admittedTemplates must be an array")
        if not enabled and (max_templates != 0 or templates):
            raise WebContractError("disabled Nuclei must have no admitted templates")
        if enabled:
            if authorization.get("allowNuclei") is not True:
                raise WebContractError("enabled Nuclei requires authorization.allowNuclei")
            if max_templates < 1 or len(templates) > max_templates:
                raise WebContractError("Nuclei template count exceeds its explicit limit")
        template_ids: set[str] = set()
        for index, item in enumerate(templates):
            if not isinstance(item, dict):
                raise WebContractError(f"nuclei.admittedTemplates[{index}] must be an object")
            template_id = require_identifier(
                item.get("id"), f"nuclei.admittedTemplates[{index}].id"
            )
            if template_id in template_ids:
                raise WebContractError(f"duplicate Nuclei template id: {template_id}")
            template_ids.add(template_id)
            path = Path(str(item.get("path") or ""))
            if path.is_absolute() or ".." in path.parts or not str(path):
                raise WebContractError("Nuclei template paths must be campaign-relative")
            if not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256") or "")):
                raise WebContractError("Nuclei templates require a SHA-256 digest")
            require_positive_int(
                item.get("maxRequests"),
                f"nuclei.admittedTemplates[{index}].maxRequests",
            )

        inputs = self.raw.get("requestInputs")
        if not isinstance(inputs, dict):
            raise WebContractError("requestInputs is required")
        for field in (
            "markdownFiles",
            "requestBundles",
            "harFiles",
            "burpExports",
            "apiSpecifications",
            "sourceRoots",
            "deploymentDetails",
        ):
            values = inputs.get(field)
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not value.strip() for value in values
            ):
                raise WebContractError(f"requestInputs.{field} must be an array of paths")
            if field != "sourceRoots" and any(
                Path(value).is_absolute() or ".." in Path(value).parts for value in values
            ):
                raise WebContractError(
                    f"requestInputs.{field} paths must remain campaign-relative"
                )

        containment = self.raw.get("networkContainment")
        if not isinstance(containment, dict):
            raise WebContractError("networkContainment is required")
        if containment.get("runnerNamespaceRequired") is not True:
            raise WebContractError("runner network namespace containment must be required")
        for field in (
            "ownedInternalLabCidrs",
            "allowedDestinationCidrs",
            "deniedDestinationCidrs",
        ):
            values = containment.get(field)
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not value.strip() for value in values
            ):
                raise WebContractError(f"networkContainment.{field} must be an array of CIDRs")
        for field in ("remoteBrowserTraffic", "remoteNucleiTraffic"):
            if containment.get(field) not in {
                "blocked-until-os-egress-enforcement",
                "os-egress-enforced",
            }:
                raise WebContractError(f"networkContainment.{field} is invalid")
        if any(
            containment.get(field) == "os-egress-enforced"
            for field in ("remoteBrowserTraffic", "remoteNucleiTraffic")
        ) and not isinstance(containment.get("evidence"), dict):
            raise WebContractError(
                "claimed OS egress enforcement requires structured containment evidence"
            )
        browser_broker = containment.get("browserBroker")
        if containment.get("remoteBrowserTraffic") == "os-egress-enforced":
            if not isinstance(browser_broker, dict):
                raise WebContractError(
                    "remote browser traffic requires a broker-only containment contract"
                )
            if browser_broker.get("mode") != "os-enforced-broker-only":
                raise WebContractError("browser broker mode must be os-enforced-broker-only")
            proxy_url = str(browser_broker.get("proxyUrl") or "")
            parsed_proxy = urlsplit(proxy_url)
            if parsed_proxy.scheme not in {"http", "https"} or parsed_proxy.hostname not in {
                "127.0.0.1",
                "localhost",
                "::1",
            }:
                raise WebContractError("browser broker proxyUrl must be an explicit loopback proxy")
            if parsed_proxy.port is None or parsed_proxy.username or parsed_proxy.password:
                raise WebContractError("browser broker proxyUrl requires a port and no embedded credentials")
            if browser_broker.get("directEgressBlocked") is not True:
                raise WebContractError("browser broker must prove direct egress is blocked")
            if browser_broker.get("dnsOutsideBrokerBlocked") is not True:
                raise WebContractError("browser broker must prove DNS outside the broker is blocked")
            broker_id = str(browser_broker.get("brokerId") or "")
            broker_version = str(browser_broker.get("brokerVersion") or "")
            if not IDENTIFIER.fullmatch(broker_id) or not broker_version:
                raise WebContractError("browser broker requires stable brokerId and brokerVersion")
            allowed_origins = browser_broker.get("allowedOriginIds")
            if not isinstance(allowed_origins, list) or not allowed_origins:
                raise WebContractError("browser broker requires allowedOriginIds")
            unknown_origins = set(map(str, allowed_origins)).difference(self.origins)
            if unknown_origins:
                raise WebContractError("browser broker references unknown origins")
            evidence = browser_broker.get("evidence")
            if not isinstance(evidence, list) or not evidence or any(
                not isinstance(item, str) or not item.strip() for item in evidence
            ):
                raise WebContractError("browser broker requires OS-enforcement evidence")
        elif browser_broker is not None and browser_broker != {}:
            raise WebContractError(
                "browserBroker is only valid when remote browser traffic is OS-enforced"
            )

    @property
    def authorization_confirmed(self) -> bool:
        authorization = self.raw.get("authorization", {})
        return isinstance(authorization, dict) and authorization.get("confirmed") is True

    def require_live_authorization(self) -> None:
        if not self.authorization_confirmed:
            raise WebContractError(
                "target traffic is blocked because authorization.confirmed is false"
            )
        valid_until = parse_time(
            self.raw["authorization"].get("validUntil"), "authorization.validUntil"
        )
        if valid_until <= utc_now():
            raise WebContractError("target traffic is blocked because authorization expired")
        authorization = self.raw["authorization"]
        approval_record = authorization.get("approvalRecord")
        approval_signature = authorization.get("approvalSignature")
        if approval_record:
            campaign = self.path.parent.resolve()
            record_path = safe_campaign_path(
                campaign, approval_record, "authorization.approvalRecord"
            )
            signature_path = safe_campaign_path(
                campaign, approval_signature, "authorization.approvalSignature"
            )
            try:
                public = control_public_key(campaign)
            except (OSError, ValueError, json.JSONDecodeError, ExperimentControlError) as exc:
                raise WebContractError(
                    f"authorization approval authority is unavailable: {exc}"
                ) from exc
            record = load_object(record_path, "authorization approval")
            if record.get("producer") != "krineon-coordinator":
                raise WebContractError("authorization approval has the wrong producer")
            if record.get("kind") != "krineon-web-authorization-approval":
                raise WebContractError("authorization approval has the wrong kind")
            if record.get("contractSha256After") != self.digest:
                raise WebContractError(
                    "authorization approval is not bound to the current contract"
                )
            if not verify_file(public, record_path, signature_path):
                raise WebContractError("authorization approval signature is invalid")

    def identity(self, identity_id: str | None) -> IdentityPolicy | None:
        if identity_id in {None, "", "anonymous"}:
            return None
        try:
            return self.identities[str(identity_id)]
        except KeyError as exc:
            raise WebContractError(f"unknown identity: {identity_id}") from exc

    def identity_for_origin(
        self, identity_id: str | None, origin_id: str
    ) -> IdentityPolicy | None:
        identity = self.identity(identity_id)
        if (
            identity is not None
            and identity.credential_ref
            and origin_id not in identity.allowed_origin_ids
        ):
            raise WebContractError(
                f"identity {identity.id} credential is not authorized for origin {origin_id}"
            )
        return identity

    def resolve_secret(self, credential_ref: str) -> str:
        if not SECRET_REF.fullmatch(credential_ref):
            raise WebContractError("credential reference must use secret://")
        name = credential_ref.removeprefix("secret://")
        environment_name = "KRINEON_SECRET_" + re.sub(r"[^A-Za-z0-9]", "_", name).upper()
        value = os.environ.get(environment_name)
        if value is None or not value:
            raise WebContractError(
                f"secret reference is unavailable in environment variable {environment_name}"
            )
        return value

    def admitted_request(
        self,
        *,
        origin_id: str,
        path_or_url: str,
        method: str,
        effect_class: str,
        cleanup: bool = False,
        operation: str = "http",
        operation_class: str = "ordinary-http",
        require_live_authorization: bool = True,
    ) -> dict[str, Any]:
        if require_live_authorization:
            self.require_live_authorization()
        try:
            origin = self.origins[origin_id]
        except KeyError as exc:
            raise WebContractError(f"unknown origin: {origin_id}") from exc
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            parsed = urlsplit(path_or_url)
            if parsed.fragment:
                raise WebContractError("request URLs cannot contain fragments")
            request_origin = canonical_origin(
                f"{parsed.scheme}://{parsed.netloc}"
            )
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
        else:
            if not path_or_url.startswith("/"):
                raise WebContractError("request path must start with /")
            request_origin = origin.origin
            path = path_or_url
        if request_origin != origin.origin:
            raise WebContractError("request origin does not match the selected exact origin")
        path_only = urlsplit(path).path or "/"
        if not any(path_matches_prefix(path_only, value) for value in origin.allowed_path_prefixes):
            raise WebContractError(f"path is outside allowed ranges for origin {origin_id}")
        if any(path_matches_prefix(path_only, value) for value in origin.excluded_paths):
            raise WebContractError(f"path is explicitly excluded for origin {origin_id}")
        normalized_method = method.upper()
        if normalized_method not in origin.allowed_methods:
            raise WebContractError(f"method {normalized_method} is not allowed for {origin_id}")
        if effect_class not in EFFECT_CLASSES:
            raise WebContractError(f"unknown effect class: {effect_class}")
        effect_policy = self.raw["effectClasses"][effect_class]
        if effect_policy.get("permitted") is not True:
            raise WebContractError(f"effect class is not permitted: {effect_class}")
        authorization = self.raw["authorization"]
        if operation_class not in OPERATION_CLASSES:
            raise WebContractError(f"unknown operation class: {operation_class}")
        operation_requirements = {
            "cache-experiment": "allowCacheMutation",
            "deserialization-experiment": "allowDeserializationExperiments",
            "bounded-concurrency": "allowBoundedConcurrency",
            "external-callback": "allowExternalCallbacks",
            "upload": "allowUploads",
            "terminal-execution": "allowTerminalExecution",
            "websocket": "allowWebSockets",
            "credential-refresh": "allowCredentialRefresh",
            "oauth-refresh": "allowOAuthRefresh",
            "csrf-handling": "allowCsrfHandling",
            "request-signing": "allowRequestSigning",
            "http-desynchronization": "allowHttpDesynchronization",
        }
        required_flag = operation_requirements.get(operation_class)
        if required_flag and authorization.get(required_flag) is not True:
            raise WebContractError(
                f"operation class {operation_class} requires authorization.{required_flag}"
            )
        if operation_class == "external-callback" and origin_id not in set(
            authorization.get("approvedCallbackOriginIds", [])
        ):
            raise WebContractError("callback destination is not independently approved")
        if operation == "browser" and operation_class not in {
            "browser-discovery",
            "browser-action",
        }:
            raise WebContractError("browser steps must use a browser operation class")
        if operation == "nuclei" and operation_class != "nuclei-read":
            raise WebContractError("Nuclei steps must use nuclei-read")
        if operation == "http" and operation_class in {"browser-discovery", "nuclei-read"}:
            raise WebContractError("HTTP steps cannot impersonate another adapter")
        if effect_class in set(authorization.get("denyEffects", [])):
            raise WebContractError(f"effect is permanently denied: {effect_class}")
        if effect_class == "disposable-write":
            if authorization.get("allowStateChangingOperations") is not True:
                raise WebContractError("state-changing operations are not authorized")
            if effect_policy.get("requiresCleanup") is not True:
                raise WebContractError("disposable writes require cleanup")
        if normalized_method in STATE_CHANGING_METHODS and effect_class == "read-only":
            raise WebContractError("state-changing methods cannot be labelled read-only")
        if operation == "browser" and authorization.get("allowBrowserNavigation") is not True:
            raise WebContractError("browser navigation is not authorized")
        if operation_class == "browser-action" and authorization.get(
            "allowBrowserActions"
        ) is not True:
            raise WebContractError("browser actions are not authorized")
        if operation == "websocket" and authorization.get("allowWebSockets") is not True:
            raise WebContractError("WebSockets are not authorized")
        if operation == "nuclei" and authorization.get("allowNuclei") is not True:
            raise WebContractError("Nuclei is not authorized")
        if cleanup and effect_class != "disposable-write":
            raise WebContractError("cleanup requests must be disposable-write effects")
        policies = sorted(
            (
                policy
                for policy in self.action_policies
                if policy.origin_id == origin_id
                and normalized_method in policy.methods
                and effect_class in policy.effect_classes
                and path_matches_prefix(path_only, policy.path_prefix)
            ),
            key=lambda item: len(item.path_prefix),
            reverse=True,
        )
        if not policies:
            raise WebContractError("no action policy authorizes this request")
        action_policy = policies[0]
        return {
            "originId": origin_id,
            "origin": origin.origin,
            "url": origin.origin + path,
            "path": path,
            "method": normalized_method,
            "effectClass": effect_class,
            "cleanup": cleanup,
            "operation": operation,
            "operationClass": operation_class,
            "actionPolicyId": action_policy.id,
            "maxRequestBodyBytes": action_policy.max_request_body_bytes,
            "maxResponseBodyBytes": action_policy.max_response_body_bytes,
        }

    def offline_plan(self) -> dict[str, Any]:
        return {
            "schemaVersion": 1,
            "contract": str(self.path),
            "contractSha256": self.digest,
            "authorizationConfirmed": self.authorization_confirmed,
            "trafficPermitted": self.authorization_confirmed,
            "origins": [
                {
                    "id": value.id,
                    "origin": value.origin,
                    "purpose": value.purpose,
                    "allowedPathPrefixes": list(value.allowed_path_prefixes),
                    "excludedPaths": list(value.excluded_paths),
                    "allowedMethods": sorted(value.allowed_methods),
                }
                for value in self.origins.values()
            ],
            "identityLabels": sorted(self.identities),
            "actionPolicies": [
                {
                    "id": item.id,
                    "originId": item.origin_id,
                    "pathPrefix": item.path_prefix,
                    "methods": sorted(item.methods),
                    "effectClasses": sorted(item.effect_classes),
                    "maxRequestBodyBytes": item.max_request_body_bytes,
                    "maxResponseBodyBytes": item.max_response_body_bytes,
                }
                for item in self.action_policies
            ],
            "deniedEffects": sorted(self.raw["authorization"]["denyEffects"]),
            "note": (
                "Offline plan only. No target traffic is permitted."
                if not self.authorization_confirmed
                else "Dynamic operations still require coordinator-approved recipes."
            ),
        }


class BudgetLedger:
    """Atomic shared request and byte accounting for all web adapters."""

    def __init__(self, contract: WebCampaignContract, path: Path | str):
        self.contract = contract
        self.path = Path(path).expanduser().resolve()
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def _initial(self) -> dict[str, Any]:
        return {
            "schemaVersion": 1,
            "contractSha256": self.contract.digest,
            "startedAt": utc_now().isoformat(),
            "requests": 0,
            "cleanupRequests": 0,
            "requestBytes": 0,
            "responseBytes": 0,
            "operations": [],
        }

    def read(self) -> dict[str, Any]:
        if not self.path.is_file():
            return self._initial()
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise WebContractError("budget ledger is invalid")
        if value.get("contractSha256") != self.contract.digest:
            raise WebContractError("budget ledger belongs to a different contract")
        return value

    def reserve(
        self,
        *,
        operation_id: str,
        request_bytes: int,
        estimated_response_bytes: int,
        cleanup: bool,
        adapter: str,
    ) -> dict[str, Any]:
        require_identifier(operation_id, "operationId")
        if request_bytes < 0 or estimated_response_bytes < 0:
            raise WebContractError("budget byte reservations cannot be negative")
        budget = self.contract.raw["budget"]
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            ledger = self.read()
            if any(row.get("id") == operation_id for row in ledger["operations"]):
                raise WebContractError("budget operation id was already reserved")
            elapsed = (utc_now() - parse_time(ledger["startedAt"], "ledger.startedAt")).total_seconds()
            if elapsed > int(budget["maxWallSeconds"]):
                raise WebContractError("web campaign wall-clock budget is exhausted")
            total = int(ledger["requests"]) + 1
            cleanup_total = int(ledger["cleanupRequests"]) + (1 if cleanup else 0)
            normal_total = total - cleanup_total
            normal_limit = int(budget["totalRequests"]) - int(
                budget["cleanupReservedRequests"]
            )
            if total > int(budget["totalRequests"]):
                raise WebContractError("total request budget is exhausted")
            if not cleanup and normal_total > normal_limit:
                raise WebContractError("only the reserved cleanup request budget remains")
            if int(ledger["requestBytes"]) + request_bytes > int(
                budget["totalRequestBytes"]
            ):
                raise WebContractError("total request-byte budget is exhausted")
            if int(ledger["responseBytes"]) + estimated_response_bytes > int(
                budget["totalResponseBytes"]
            ):
                raise WebContractError("total response-byte budget is exhausted")
            ledger["requests"] = total
            ledger["cleanupRequests"] = cleanup_total
            ledger["requestBytes"] = int(ledger["requestBytes"]) + request_bytes
            ledger["responseBytes"] = int(ledger["responseBytes"]) + estimated_response_bytes
            ledger["operations"].append(
                {
                    "id": operation_id,
                    "adapter": adapter,
                    "cleanup": cleanup,
                    "requestBytes": request_bytes,
                    "reservedResponseBytes": estimated_response_bytes,
                    "reservedAt": utc_now().isoformat(),
                }
            )
            atomic_json(self.path, ledger)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return ledger

    def reconcile_response(self, operation_id: str, actual_bytes: int) -> dict[str, Any]:
        if actual_bytes < 0:
            raise WebContractError("actual response bytes cannot be negative")
        budget = self.contract.raw["budget"]
        with self.lock_path.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            ledger = self.read()
            matches = [row for row in ledger["operations"] if row.get("id") == operation_id]
            if len(matches) != 1:
                raise WebContractError("budget operation is missing or duplicated")
            row = matches[0]
            if "actualResponseBytes" in row:
                raise WebContractError("budget operation was already reconciled")
            reserved = int(row["reservedResponseBytes"])
            new_total = int(ledger["responseBytes"]) - reserved + actual_bytes
            if new_total > int(budget["totalResponseBytes"]):
                raise WebContractError("actual response exceeds remaining campaign byte budget")
            row["actualResponseBytes"] = actual_bytes
            row["reconciledAt"] = utc_now().isoformat()
            ledger["responseBytes"] = new_total
            atomic_json(self.path, ledger)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        return ledger


def redact(value: Any, secrets: Iterable[str] = ()) -> Any:
    secret_values = sorted((item for item in secrets if item), key=len, reverse=True)

    def redact_text(text: str) -> str:
        result = BEARER.sub(r"\1<redacted>", text)
        for secret in secret_values:
            result = result.replace(secret, "<redacted>")
        return result

    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [redact(item, secret_values) for item in value]
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            lowered = str(key).lower()
            if lowered in {
                "authorization",
                "cookie",
                "set-cookie",
                "proxy-authorization",
                "x-api-key",
                "api-key",
            }:
                output[str(key)] = "<redacted>"
            else:
                output[str(key)] = redact(item, secret_values)
        return output
    return value


def _program_rules_path(contract: WebCampaignContract) -> Path:
    rules_file = contract.raw.get("authorization", {}).get("rulesFile")
    path = safe_campaign_path(contract.path.parent, rules_file, "authorization.rulesFile")
    if not path.is_file() or path.is_symlink():
        raise WebContractError("the retained program-rules file is unavailable")
    return path


def prepare_authorization_review(
    contract_path: Path | str, output_path: Path | str
) -> dict[str, Any]:
    contract = WebCampaignContract.load(contract_path)
    if contract.authorization_confirmed:
        raise WebContractError("authorization is already confirmed")
    rules_path = _program_rules_path(contract)
    review = {
        "schemaVersion": 1,
        "kind": "krineon-web-authorization-review",
        "contractSha256": contract.digest,
        "programRulesSha256": sha256_bytes(rules_path.read_bytes()),
        "approvedBy": "",
        "programRulesDate": "",
        "validUntil": "",
        "environmentOwner": "",
        "ownedFixtureNamespace": "",
        "review": {field: False for field in AUTHORIZATION_REVIEW_CHECKS},
        "note": (
            "Set every review field to true only after checking the exact retained "
            "contract and program rules. This file does not execute target requests."
        ),
    }
    output = Path(output_path).expanduser().resolve()
    atomic_json(output, review)
    return {
        "passed": True,
        "review": str(output),
        "contractSha256": contract.digest,
        "programRulesSha256": review["programRulesSha256"],
        "trafficExecuted": False,
    }


def authorize_contract(
    campaign_path: Path | str,
    contract_path: Path | str,
    review_path: Path | str,
) -> dict[str, Any]:
    campaign = Path(campaign_path).expanduser().resolve()
    contract_file = Path(contract_path).expanduser().resolve()
    try:
        contract_file.relative_to(campaign)
    except ValueError as exc:
        raise WebContractError("web contract must be inside the campaign") from exc
    campaign_record_path = campaign / "campaign.json"
    if not campaign_record_path.is_file():
        raise WebContractError("campaign.json is required for coordinator authorization")
    contract = WebCampaignContract.load(contract_file)
    if contract.authorization_confirmed:
        raise WebContractError("authorization is already confirmed")
    review_file = Path(review_path).expanduser().resolve()
    review = load_object(review_file, "authorization review")
    if review.get("schemaVersion") != 1 or review.get("kind") != (
        "krineon-web-authorization-review"
    ):
        raise WebContractError("authorization review has an unsupported schema or kind")
    if review.get("contractSha256") != contract.digest:
        raise WebContractError("authorization review does not match the current contract")
    rules_path = _program_rules_path(contract)
    rules_digest = sha256_bytes(rules_path.read_bytes())
    if review.get("programRulesSha256") != rules_digest:
        raise WebContractError("authorization review does not match the retained program rules")
    checks = review.get("review")
    if not isinstance(checks, dict):
        raise WebContractError("authorization review checklist is required")
    incomplete = [field for field in AUTHORIZATION_REVIEW_CHECKS if checks.get(field) is not True]
    if incomplete:
        raise WebContractError(
            "authorization review is incomplete: " + ", ".join(incomplete)
        )
    approved_by = str(review.get("approvedBy") or "").strip()
    environment_owner = str(review.get("environmentOwner") or "").strip()
    fixture_namespace = str(review.get("ownedFixtureNamespace") or "").strip()
    if not approved_by or not environment_owner:
        raise WebContractError(
            "authorization review requires approvedBy and environmentOwner"
        )
    require_identifier(fixture_namespace, "ownedFixtureNamespace")
    rules_date = str(review.get("programRulesDate") or "")
    try:
        dt.date.fromisoformat(rules_date)
    except ValueError as exc:
        raise WebContractError("programRulesDate must use YYYY-MM-DD") from exc
    valid_until = parse_time(review.get("validUntil"), "validUntil")
    if valid_until <= utc_now():
        raise WebContractError("authorization review validUntil must be in the future")

    record_relative = Path("web/authorization-approval.json")
    signature_relative = Path("web/authorization-approval.json.sig")
    updated = json.loads(json.dumps(contract.raw))
    updated["environmentOwner"] = environment_owner
    updated["program"]["rulesDate"] = rules_date
    authorization = updated["authorization"]
    authorization.update(
        {
            "confirmed": True,
            "confirmedBy": approved_by,
            "confirmedAt": utc_now().replace(microsecond=0).isoformat(),
            "validUntil": valid_until.isoformat(),
            "ownedFixtureNamespace": fixture_namespace,
            "approvalRecord": record_relative.as_posix(),
            "approvalSignature": signature_relative.as_posix(),
        }
    )
    WebCampaignContract(contract_file, updated, "pending-authorization-record")
    atomic_json(contract_file, updated)
    authorized_contract = WebCampaignContract.load(contract_file)

    authority = ensure_authority(campaign)
    approval_record = {
        "schemaVersion": 1,
        "kind": "krineon-web-authorization-approval",
        "producer": "krineon-coordinator",
        "approvedBy": approved_by,
        "approvedAt": authorization["confirmedAt"],
        "validUntil": authorization["validUntil"],
        "contract": contract_file.relative_to(campaign).as_posix(),
        "contractSha256Before": contract.digest,
        "contractSha256After": authorized_contract.digest,
        "reviewSha256": sha256_bytes(review_file.read_bytes()),
        "programRules": rules_path.relative_to(campaign).as_posix(),
        "programRulesSha256": rules_digest,
        "reviewedChecks": list(AUTHORIZATION_REVIEW_CHECKS),
        "trafficExecuted": False,
    }
    record_path = campaign / record_relative
    signature_path = campaign / signature_relative
    atomic_json(record_path, approval_record)
    private, _ = authority_paths(campaign)
    sign_file(private, record_path, signature_path)

    campaign_record = load_object(campaign_record_path, "campaign")
    campaign_record["experimentAuthority"] = {
        key: value for key, value in authority.items() if key != "privateKey"
    }
    campaign_record["authorization"] = {
        "confirmed": True,
        "basis": (
            "Coordinator review bound to the exact web contract and retained program rules."
        ),
        "approvedBy": approved_by,
        "validUntil": authorization["validUntil"],
        "allowedEnvironment": environment_owner,
        "stopConditions": authorization["stopConditions"],
    }
    atomic_json(campaign_record_path, campaign_record)
    authorized_contract.require_live_authorization()
    return {
        "passed": True,
        "authorizationConfirmed": True,
        "contractSha256": authorized_contract.digest,
        "approvalRecord": record_relative.as_posix(),
        "approvalSignature": signature_relative.as_posix(),
        "trafficExecuted": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", help="validate a web campaign contract")
    validate.add_argument("contract")
    validate.add_argument("--json", action="store_true")
    plan = sub.add_parser("plan", help="produce a zero-traffic offline plan")
    plan.add_argument("contract")
    plan.add_argument("--output")
    review = sub.add_parser(
        "prepare-review",
        help="prepare a contract-hash-bound coordinator authorization checklist",
    )
    review.add_argument("contract")
    review.add_argument("--output", required=True)
    authorize = sub.add_parser(
        "authorize",
        help="confirm web authority from a completed offline coordinator review",
    )
    authorize.add_argument("campaign")
    authorize.add_argument("contract")
    authorize.add_argument("review")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "prepare-review":
            result = prepare_authorization_review(args.contract, args.output)
            print(json.dumps(result, indent=2))
            return 0
        if args.command == "authorize":
            result = authorize_contract(args.campaign, args.contract, args.review)
            print(json.dumps(result, indent=2))
            return 0
        contract = WebCampaignContract.load(args.contract)
        if args.command == "validate":
            result = {
                "passed": True,
                "contractSha256": contract.digest,
                "authorizationConfirmed": contract.authorization_confirmed,
                "originCount": len(contract.origins),
                "identityCount": len(contract.identities),
            }
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print("PASS: web campaign contract is valid")
            return 0
        result = contract.offline_plan()
        if args.output:
            atomic_json(Path(args.output).expanduser().resolve(), result, mode=0o644)
        else:
            print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, ExperimentControlError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
