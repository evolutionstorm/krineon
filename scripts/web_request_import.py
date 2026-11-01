#!/usr/bin/env python3
"""Import URL, Markdown, HAR, or Burp requests as inert campaign evidence.

Markdown prose is never interpreted as authority, a tool directive, or an
executable instruction. Only one strict ``yaml krineon-web`` metadata block
and explicitly named request fences are parsed.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

try:
    from .web_contract import (
        WebCampaignContract,
        WebContractError,
        atomic_json,
        canonical_origin,
    )
    from .web_identity import IdentityBroker
    from .web_request_schema import (
        HEADER_NAME,
        SECRET_PLACEHOLDER,
        load_metadata,
        parse_http_request,
        validate_metadata,
    )
    from .web_secret_store import SecretStore
except ImportError:
    from web_contract import (
        WebCampaignContract,
        WebContractError,
        atomic_json,
        canonical_origin,
    )
    from web_identity import IdentityBroker
    from web_request_schema import (
        HEADER_NAME,
        SECRET_PLACEHOLDER,
        load_metadata,
        parse_http_request,
        validate_metadata,
    )
    from web_secret_store import SecretStore


METADATA_BLOCK = re.compile(
    r"^```yaml[ \t]+krineon-web[ \t]*\r?\n(.*?)\r?\n```[ \t]*$",
    re.MULTILINE | re.DOTALL,
)
REQUEST_HEADING = re.compile(
    r"^##[ \t]+Request:[ \t]*([A-Za-z][A-Za-z0-9_.-]{0,63})[ \t]*$",
    re.MULTILINE,
)
REQUEST_FENCE = re.compile(
    r"\A[ \t\r\n]*```(http|http2|raw-http)[ \t]*\r?\n(.*?)\r?\n```[ \t]*(?=\r?\n|\Z)",
    re.DOTALL | re.IGNORECASE,
)
MAX_MARKDOWN_BYTES = 10 * 1024 * 1024
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_REQUESTS = 10_000
MAX_CAPTURE_REQUEST_BYTES = 16 * 1024 * 1024
SENSITIVE_PARAMETER = re.compile(
    r"(?:^|[_-])(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|secret|"
    r"password|passwd|api[_-]?key|session|authorization)(?:$|[_-])",
    re.IGNORECASE,
)
SIGNATURE_HEADER = re.compile(
    r"^(?:signature|signature-input|content-digest|digest|x-[a-z0-9-]*signature)$",
    re.IGNORECASE,
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o600)
    os.replace(temporary, path)


def _atomic_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _strict_json(payload: bytes, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise WebContractError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=unique)
    except UnicodeDecodeError as exc:
        raise WebContractError(f"{label} must be UTF-8 JSON") from exc
    except json.JSONDecodeError as exc:
        raise WebContractError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise WebContractError(f"{label} root must be an object")
    return value


def _require_external_original(source: Path, contract: WebCampaignContract) -> None:
    try:
        source.resolve().relative_to(contract.path.parent.resolve())
    except ValueError:
        return
    raise WebContractError(
        "original request captures must remain outside model-readable campaign storage"
    )


def _capture_origin(
    contract: WebCampaignContract, url: str
) -> tuple[str, str, str]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise WebContractError("captured request URL must be absolute HTTP(S)")
    if parsed.username is not None or parsed.password is not None:
        raise WebContractError("captured request URL cannot contain userinfo credentials")
    if parsed.fragment:
        raise WebContractError("captured request URL cannot contain a fragment")
    origin = canonical_origin(f"{parsed.scheme}://{parsed.netloc}")
    matches = [item for item in contract.origins.values() if item.origin == origin]
    if len(matches) != 1:
        raise WebContractError("captured request has an undeclared origin")
    target = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
    return matches[0].id, origin, target


def _reject_unmodelled_credentials(
    *, target: str, headers: list[tuple[str, str]], body: bytes
) -> None:
    for name, _value in parse_qsl(
        urlsplit(target).query,
        keep_blank_values=True,
        strict_parsing=False,
        encoding="utf-8",
        errors="replace",
    ):
        if SENSITIVE_PARAMETER.search(name):
            raise WebContractError(
                "captured query contains credential-like material; replace it with a "
                "reviewed secret adapter before import"
            )
    content_type = next(
        (value.lower() for name, value in headers if name.lower() == "content-type"),
        "",
    )
    if not body:
        return
    names: list[str] = []
    if "application/x-www-form-urlencoded" in content_type:
        try:
            names = [
                name
                for name, _value in parse_qsl(
                    body.decode("utf-8"),
                    keep_blank_values=True,
                    strict_parsing=False,
                )
            ]
        except UnicodeDecodeError as exc:
            raise WebContractError("captured form body is not UTF-8") from exc
    elif "application/json" in content_type:
        try:
            value = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            value = None

        def keys(item: Any) -> list[str]:
            if isinstance(item, dict):
                return [str(key) for key in item] + [
                    nested for child in item.values() for nested in keys(child)
                ]
            if isinstance(item, list):
                return [nested for child in item for nested in keys(child)]
            return []

        names = keys(value)
    elif "multipart/form-data" in content_type:
        names = [
            value.decode("utf-8", errors="replace")
            for value in re.findall(
                rb"(?i)content-disposition:[^\r\n]*\bname=\"([^\"]+)\"",
                body,
            )
        ]
    if any(SENSITIVE_PARAMETER.search(name) for name in names):
        raise WebContractError(
            "captured body contains credential-like fields; use explicit secret "
            "references instead of exposing them to workers"
        )


def _store_capture_secret(
    *, identity: Any, literal: str, store: SecretStore | None
) -> dict[str, str]:
    if store is None:
        raise WebContractError(
            "literal credentials in HAR or Burp input require a private "
            "--secret-store outside the campaign"
        )
    retained = store.put(
        identity.credential_ref,
        literal,
        kind=identity.credential_type,
        expires_at=(
            identity.expires_at.isoformat()
            if identity.expires_at is not None
            else None
        ),
        version=identity.secret_version,
    )
    return {
        "reference": retained["reference"],
        "version": retained["version"],
        "kind": retained["kind"],
    }


def _redact_cookie_value(value: str, identity: Any) -> tuple[str, str | None]:
    pieces = value.split(";")
    matches: list[tuple[int, str]] = []
    for index, piece in enumerate(pieces):
        stripped = piece.strip()
        name, separator, cookie_value = stripped.partition("=")
        if separator and name == identity.cookie_name:
            matches.append((index, cookie_value))
    if len(matches) != 1:
        raise WebContractError(
            "captured cookie header must contain exactly one configured identity cookie"
        )
    index, credential = matches[0]
    placeholder = SECRET_PLACEHOLDER.fullmatch(credential)
    expected_ref = identity.credential_ref.removeprefix("secret://")
    if placeholder and placeholder.group(1) != expected_ref:
        raise WebContractError("captured cookie placeholder conflicts with its identity")
    replacement = f"{identity.cookie_name}={{{{secret:{expected_ref}}}}}"
    leading = pieces[index][: len(pieces[index]) - len(pieces[index].lstrip())]
    pieces[index] = leading + replacement
    return ";".join(pieces), None if placeholder else credential


def redact_capture_headers(
    headers: list[tuple[str, str]],
    *,
    identity_id: str,
    contract: WebCampaignContract,
    store: SecretStore | None,
) -> tuple[list[tuple[str, str]], list[dict[str, str]], bool]:
    identity = contract.identity(identity_id)
    expected_name = _credential_header(identity) if identity is not None else ""
    standard_credentials = {"authorization", "cookie", "x-api-key", "api-key"}
    redacted: list[tuple[str, str]] = []
    retained: list[dict[str, str]] = []
    literal_found = False
    found = 0
    for name, value in headers:
        lowered = name.lower()
        sensitive = lowered in standard_credentials or (
            identity is not None
            and identity.credential_type == "api-key"
            and lowered == identity.api_key_header.lower()
        )
        if identity is None and sensitive:
            raise WebContractError(
                "anonymous capture contains credentials; select a verified identity"
            )
        if sensitive and lowered != expected_name:
            raise WebContractError(
                "capture contains an additional credential header not represented by "
                "the selected identity"
            )
        if identity is None or lowered != expected_name:
            redacted.append((name, value))
            continue
        found += 1
        expected_ref = identity.credential_ref.removeprefix("secret://")
        literal: str | None
        if identity.credential_type == "bearer":
            scheme, separator, credential = value.strip().partition(" ")
            if scheme.lower() != "bearer" or not separator:
                raise WebContractError("captured bearer credential has an unsupported scheme")
            placeholder = SECRET_PLACEHOLDER.fullmatch(credential)
            if placeholder and placeholder.group(1) != expected_ref:
                raise WebContractError("captured bearer placeholder conflicts with identity")
            replacement = f"Bearer {{{{secret:{expected_ref}}}}}"
            literal = None if placeholder else credential
        elif identity.credential_type == "api-key":
            credential = value.strip()
            placeholder = SECRET_PLACEHOLDER.fullmatch(credential)
            if placeholder and placeholder.group(1) != expected_ref:
                raise WebContractError("captured API-key placeholder conflicts with identity")
            replacement = f"{{{{secret:{expected_ref}}}}}"
            literal = None if placeholder else credential
        else:
            replacement, literal = _redact_cookie_value(value, identity)
        if literal:
            retained.append(
                _store_capture_secret(identity=identity, literal=literal, store=store)
            )
            literal_found = True
        redacted.append((name, replacement))
    if found > 1:
        raise WebContractError("capture contains ambiguous duplicate credential headers")
    return redacted, retained, literal_found


def request_blocks(markdown: str) -> dict[str, tuple[str, str, tuple[int, int]]]:
    headings = list(REQUEST_HEADING.finditer(markdown))
    blocks: dict[str, tuple[str, str, tuple[int, int]]] = {}
    for index, heading in enumerate(headings):
        request_id = heading.group(1)
        if request_id in blocks:
            raise WebContractError(f"duplicate request heading: {request_id}")
        end = headings[index + 1].start() if index + 1 < len(headings) else len(markdown)
        region = markdown[heading.end() : end]
        fence = REQUEST_FENCE.match(region)
        if fence is None:
            raise WebContractError(
                f"request {request_id} heading must be followed directly by one HTTP fence"
            )
        block_start = heading.end() + fence.start(2)
        block_end = heading.end() + fence.end(2)
        blocks[request_id] = (
            fence.group(1).lower(),
            fence.group(2),
            (block_start, block_end),
        )
    return blocks


def _credential_header(identity: Any) -> str:
    if identity.credential_type == "bearer":
        return "authorization"
    if identity.credential_type == "api-key":
        return identity.api_key_header.lower()
    return "cookie"


def redact_request_credentials(
    raw: str,
    *,
    request_id: str,
    identity_id: str,
    contract: WebCampaignContract,
    store: SecretStore | None,
) -> tuple[str, list[dict[str, str]], bool]:
    identity = contract.identity(identity_id)
    line_separator = "\r\n" if "\r\n" in raw else "\n"
    head, separator, body = raw.partition(line_separator + line_separator)
    lines = head.split(line_separator)
    start = 0 if lines and lines[0].startswith(":") else 1
    secret_versions: list[dict[str, str]] = []
    literal_found = False
    if identity is None:
        forbidden = {"authorization", "cookie", "x-api-key", "api-key"}
        for line in lines[start:]:
            if ":" in line and line.split(":", 1)[0].lower() in forbidden:
                raise WebContractError(
                    f"anonymous request {request_id} contains a credential header"
                )
        return raw, secret_versions, literal_found
    expected_name = _credential_header(identity)
    found = 0
    for index in range(start, len(lines)):
        line = lines[index]
        if line.startswith(":"):
            match = re.match(r"^(:[a-z0-9-]+):", line)
            if match:
                continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.lower() != expected_name:
            continue
        found += 1
        value = value.lstrip(" \t")
        if identity.credential_type == "bearer":
            scheme, separator_value, credential = value.partition(" ")
            if scheme.lower() != "bearer" or not separator_value:
                raise WebContractError(
                    f"request {request_id} bearer credential has an unsupported scheme"
                )
            placeholder = SECRET_PLACEHOLDER.fullmatch(credential)
            replacement = f"Bearer {{{{secret:{identity.credential_ref.removeprefix('secret://')}}}}}"
            literal = credential if placeholder is None else ""
            if placeholder and placeholder.group(1) != identity.credential_ref.removeprefix(
                "secret://"
            ):
                raise WebContractError(
                    f"request {request_id} secret placeholder conflicts with its identity"
                )
        elif identity.credential_type == "api-key":
            placeholder = SECRET_PLACEHOLDER.fullmatch(value)
            replacement = f"{{{{secret:{identity.credential_ref.removeprefix('secret://')}}}}}"
            literal = value if placeholder is None else ""
            if placeholder and placeholder.group(1) != identity.credential_ref.removeprefix(
                "secret://"
            ):
                raise WebContractError(
                    f"request {request_id} secret placeholder conflicts with its identity"
                )
        else:
            cookie_value = value
            expected_prefix = identity.cookie_name + "="
            if not cookie_value.startswith(expected_prefix):
                raise WebContractError(
                    f"request {request_id} cookie does not match the identity cookie name"
                )
            raw_value = cookie_value[len(expected_prefix) :]
            placeholder = SECRET_PLACEHOLDER.fullmatch(raw_value)
            replacement = (
                f"{identity.cookie_name}="
                f"{{{{secret:{identity.credential_ref.removeprefix('secret://')}}}}}"
            )
            literal = raw_value if placeholder is None else ""
            if placeholder and placeholder.group(1) != identity.credential_ref.removeprefix(
                "secret://"
            ):
                raise WebContractError(
                    f"request {request_id} secret placeholder conflicts with its identity"
                )
        if literal:
            if store is None:
                raise WebContractError(
                    "literal credentials require a private --secret-store outside the campaign"
                )
            retained = store.put(
                identity.credential_ref,
                literal,
                kind=identity.credential_type,
                expires_at=(
                    identity.expires_at.isoformat()
                    if identity.expires_at is not None
                    else None
                ),
                version=identity.secret_version,
            )
            secret_versions.append(
                {
                    "reference": retained["reference"],
                    "version": retained["version"],
                    "kind": retained["kind"],
                }
            )
            literal_found = True
        lines[index] = f"{name}: {replacement}"
    if found > 1:
        raise WebContractError(
            f"request {request_id} has ambiguous duplicate credential headers"
        )
    redacted = line_separator.join(lines)
    if separator:
        redacted += line_separator + line_separator + body
    return redacted, secret_versions, literal_found


def import_markdown(
    *,
    contract: WebCampaignContract,
    source: Path,
    output: Path,
    redacted_copy: Path,
    secret_store: SecretStore | None,
) -> dict[str, Any]:
    _require_external_original(source, contract)
    payload = source.read_bytes()
    if len(payload) > MAX_MARKDOWN_BYTES:
        raise WebContractError("Markdown request bundle exceeds the 10 MiB import limit")
    try:
        markdown = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WebContractError(
            "Markdown must be UTF-8; use a restricted sidecar for binary request bodies"
        ) from exc
    if output.resolve() == source.resolve():
        raise WebContractError("refusing to overwrite the original request bundle")
    metadata_matches = list(METADATA_BLOCK.finditer(markdown))
    if len(metadata_matches) != 1:
        raise WebContractError("Markdown requires exactly one yaml krineon-web block")
    metadata = validate_metadata(
        load_metadata(metadata_matches[0].group(1)), contract
    )
    blocks = request_blocks(markdown)
    if set(blocks) != set(metadata["requests"]):
        missing = set(metadata["requests"]).difference(blocks)
        extra = set(blocks).difference(metadata["requests"])
        raise WebContractError(
            "request metadata and fenced blocks differ; missing="
            + ",".join(sorted(missing))
            + " extra="
            + ",".join(sorted(extra))
        )
    replacements: list[tuple[int, int, str]] = []
    imported: list[dict[str, Any]] = []
    secret_versions: list[dict[str, str]] = []
    literal_found = False
    for request_id, request_metadata in metadata["requests"].items():
        fence, raw, span = blocks[request_id]
        redacted, retained_versions, had_literal = redact_request_credentials(
            raw,
            request_id=request_id,
            identity_id=request_metadata["identity"],
            contract=contract,
            store=secret_store,
        )
        parsed = parse_http_request(
            redacted,
            fence=fence,
            metadata=request_metadata,
            contract=contract,
            source_dir=source.parent,
        )
        if had_literal:
            parsed["byteExact"] = False
            parsed["nonByteExactReasons"].append(
                "trusted importer replaced literal credentials with a runtime secret reference"
            )
        imported.append(
            {
                "id": request_id,
                "identityId": request_metadata["identity"],
                "workflowId": request_metadata["workflow"],
                "purpose": request_metadata["purpose"],
                "effectClass": request_metadata["effect"],
                "resource": {
                    "id": request_metadata["ownedResource"],
                    "kind": request_metadata["resourceKind"],
                    "expectedOwner": request_metadata["expectedOwner"],
                },
                "expectedRule": request_metadata["expectedRule"],
                "dependsOn": request_metadata["dependsOn"],
                "request": parsed,
            }
        )
        replacements.append((span[0], span[1], redacted))
        secret_versions.extend(retained_versions)
        literal_found = literal_found or had_literal
    redacted_markdown = markdown
    for start, end, value in sorted(replacements, reverse=True):
        redacted_markdown = redacted_markdown[:start] + value + redacted_markdown[end:]
    if redacted_copy.resolve() == source.resolve():
        raise WebContractError("refusing to overwrite the original request bundle")
    _atomic_text(redacted_copy, redacted_markdown)
    workflows: dict[str, list[str]] = {}
    for item in imported:
        workflows.setdefault(item["workflowId"], []).append(item["id"])
    distinct_identities = sorted({item["identityId"] for item in imported})
    authenticated_identities = [
        contract.identity(value)
        for value in distinct_identities
        if value != "anonymous"
    ]
    independent_credentials = {
        value.credential_ref
        for value in authenticated_identities
        if value is not None and value.credential_ref
    }
    independent_tenants = {
        value.expected_tenant
        for value in authenticated_identities
        if value is not None and value.expected_tenant
    }
    unique_secret_versions = {
        (item["reference"], item["version"]): item for item in secret_versions
    }
    result = {
        "schemaVersion": 1,
        "kind": "krineon-web-request-bundle",
        "sourceType": "markdown",
        "source": {
            "originalSha256": sha256_bytes(payload),
            "redactedSha256": sha256_bytes(redacted_markdown.encode("utf-8")),
            "redactedCopy": redacted_copy.name,
            "originalOverwritten": False,
            "literalCredentialsExtracted": literal_found,
        },
        "contractSha256": contract.digest,
        "authorityDerivedOnlyFromContract": True,
        "markdownProseExecutable": False,
        "executable": False,
        "requiresCoordinatorApproval": True,
        "metadata": metadata,
        "requests": imported,
        "workflows": [
            {"id": workflow_id, "requestIds": request_ids}
            for workflow_id, request_ids in sorted(workflows.items())
        ],
        "coverage": {
            "identityLabels": distinct_identities,
            "independentAuthenticatedIdentityCount": len(independent_credentials),
            "independentTenantCount": len(independent_tenants),
            "crossUserCoverageAvailable": len(independent_credentials) >= 2,
            "crossTenantCoverageAvailable": (
                len(independent_credentials) >= 2 and len(independent_tenants) >= 2
            ),
        },
        "secretVersions": [
            unique_secret_versions[key] for key in sorted(unique_secret_versions)
        ],
        "unsupportedAdapters": ["openapi"],
    }
    atomic_json(output, result, mode=0o600)
    return result


def _capture_coverage(
    contract: WebCampaignContract, identity_ids: set[str]
) -> dict[str, Any]:
    authenticated = [
        contract.identity(identity_id)
        for identity_id in sorted(identity_ids)
        if identity_id != "anonymous"
    ]
    credentials = {
        identity.credential_ref
        for identity in authenticated
        if identity is not None and identity.credential_ref
    }
    tenants = {
        identity.expected_tenant
        for identity in authenticated
        if identity is not None and identity.expected_tenant
    }
    return {
        "identityLabels": sorted(identity_ids),
        "independentAuthenticatedIdentityCount": len(credentials),
        "independentTenantCount": len(tenants),
        "crossUserCoverageAvailable": len(credentials) >= 2,
        "crossTenantCoverageAvailable": len(credentials) >= 2 and len(tenants) >= 2,
    }


def _capture_envelope(
    *,
    request_id: str,
    identity_id: str,
    workflow_id: str,
    purpose: str,
    effect_class: str,
    parsed: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": request_id,
        "identityId": identity_id,
        "workflowId": workflow_id,
        "purpose": purpose,
        "effectClass": effect_class,
        "resource": {
            "id": request_id,
            "kind": "captured-request",
            "expectedOwner": identity_id if identity_id != "anonymous" else "public",
        },
        "expectedRule": (
            "the captured operation remains within the selected identity, tenant, "
            "origin, path, method, and effect policy"
        ),
        "dependsOn": [],
        "request": parsed,
    }


def _captured_request(
    *,
    contract: WebCampaignContract,
    url: str,
    method: str,
    http_version: str,
    headers: list[tuple[str, str]],
    body: bytes,
    identity_id: str,
    effect_class: str,
    secret_store: SecretStore | None,
) -> tuple[dict[str, Any], list[tuple[str, str]], list[dict[str, str]], bool]:
    origin_id, origin, target = _capture_origin(contract, url)
    normalized_method = method.upper()
    if not re.fullmatch(r"[A-Za-z]+", normalized_method):
        raise WebContractError("captured request method is invalid")
    for name, value in headers:
        if not HEADER_NAME.fullmatch(name):
            raise WebContractError(f"captured request has invalid header name: {name}")
        if "\r" in value or "\n" in value:
            raise WebContractError("captured request header contains a line break")
    host_values = [value for name, value in headers if name.lower() == "host"]
    if len(host_values) > 1:
        raise WebContractError("captured request contains ambiguous Host headers")
    if host_values:
        scheme = urlsplit(origin).scheme
        if canonical_origin(f"{scheme}://{host_values[0]}") != origin:
            raise WebContractError("captured URL conflicts with Host authority")
    IdentityBroker(contract).authorize(
        identity_id,
        origin_id=origin_id,
        path_or_url=target,
        transport="http",
    )
    admitted = contract.admitted_request(
        origin_id=origin_id,
        path_or_url=target,
        method=normalized_method,
        effect_class=effect_class,
        require_live_authorization=False,
    )
    if len(body) > min(MAX_CAPTURE_REQUEST_BYTES, admitted["maxRequestBodyBytes"]):
        raise WebContractError("captured request body exceeds its action-policy limit")
    redacted, retained, literal_found = redact_capture_headers(
        headers,
        identity_id=identity_id,
        contract=contract,
        store=secret_store,
    )
    identity = contract.identity(identity_id)
    if identity is not None and secret_store is not None:
        try:
            secret_value = secret_store.get(
                identity.credential_ref,
                version=None
                if identity.secret_version == "unversioned"
                else identity.secret_version,
            )
        except WebContractError:
            secret_value = b""
        if secret_value:
            try:
                secret_text = secret_value.decode("utf-8")
            except UnicodeDecodeError:
                secret_text = ""
            if secret_value in body or (secret_text and secret_text in target):
                raise WebContractError(
                    "configured credential also appears outside its approved header; "
                    "use a reviewed protocol-specific secret adapter"
                )
    _reject_unmodelled_credentials(target=target, headers=redacted, body=body)
    parsed_url = urlsplit(target)
    protocol = "http/2" if "2" in http_version and "1." not in http_version else "http/1.1"
    if not any(value in http_version.upper() for value in ("HTTP/1.0", "HTTP/1.1", "HTTP/2", "H2")):
        raise WebContractError("capture uses an unsupported HTTP protocol")
    pseudo_headers: list[dict[str, str]] = []
    if protocol == "http/2":
        split = urlsplit(url)
        pseudo_headers = [
            {"name": ":method", "value": normalized_method},
            {"name": ":scheme", "value": split.scheme},
            {"name": ":authority", "value": split.netloc},
            {"name": ":path", "value": target},
        ]
    signed_fields = sorted(
        {name.lower() for name, _value in redacted if SIGNATURE_HEADER.fullmatch(name)}
    )
    parsed = {
        "schemaVersion": 1,
        "protocol": protocol,
        "byteExact": False,
        "nonByteExactReasons": [
            "HAR and capture metadata do not retain an exact HTTP wire representation"
        ],
        "exactReplay": {
            "wireAvailable": False,
            "rawBlockBase64": None,
            "rawRequestLineBase64": None,
            "headers": [
                {"name": name, "value": value} for name, value in redacted
            ],
            "pseudoHeaders": pseudo_headers,
            "pseudoHeadersSynthesizedFromUrl": bool(pseudo_headers),
            "bodyBase64": base64.b64encode(body).decode("ascii"),
            "immutableAuthenticationFields": signed_fields,
        },
        "semantic": {
            "method": normalized_method,
            "httpVersion": http_version,
            "originId": origin_id,
            "origin": origin,
            "target": target,
            "path": parsed_url.path or "/",
            "rawQuery": parsed_url.query,
            "query": [
                {"name": name, "value": value}
                for name, value in parse_qsl(
                    parsed_url.query,
                    keep_blank_values=True,
                    strict_parsing=False,
                    encoding="utf-8",
                    errors="replace",
                )
            ],
            "headers": [
                {"name": name, "value": value} for name, value in redacted
            ],
            "pseudoHeaders": pseudo_headers,
            "bodyBase64": base64.b64encode(body).decode("ascii"),
            "bodyBytes": len(body),
            "actionPolicyId": admitted["actionPolicyId"],
        },
        "signed": bool(signed_fields),
        "resigningRequiredForMutation": bool(signed_fields),
    }
    if literal_found:
        parsed["nonByteExactReasons"].append(
            "trusted importer replaced literal credentials with a runtime secret reference"
        )
    return parsed, redacted, retained, literal_found


def _capture_bundle(
    *,
    contract: WebCampaignContract,
    source_type: str,
    source_payload: bytes,
    redacted_payload: bytes,
    redacted_copy: Path,
    requests: list[dict[str, Any]],
    secret_versions: list[dict[str, str]],
    literal_found: bool,
) -> dict[str, Any]:
    workflow_map: dict[str, list[str]] = {}
    for request in requests:
        workflow_map.setdefault(request["workflowId"], []).append(request["id"])
    unique_versions = {
        (value["reference"], value["version"]): value for value in secret_versions
    }
    result = {
        "schemaVersion": 1,
        "kind": "krineon-web-request-bundle",
        "sourceType": source_type,
        "source": {
            "originalSha256": sha256_bytes(source_payload),
            "redactedSha256": sha256_bytes(redacted_payload),
            "redactedCopy": redacted_copy.name,
            "originalOverwritten": False,
            "literalCredentialsExtracted": literal_found,
            "responsesImported": False,
        },
        "contractSha256": contract.digest,
        "authorityDerivedOnlyFromContract": True,
        "captureAnnotationsExecutable": False,
        "executable": False,
        "requiresCoordinatorApproval": True,
        "requests": requests,
        "workflows": [
            {"id": workflow_id, "requestIds": request_ids}
            for workflow_id, request_ids in sorted(workflow_map.items())
        ],
        "coverage": _capture_coverage(
            contract, {request["identityId"] for request in requests}
        ),
        "secretVersions": [
            unique_versions[key] for key in sorted(unique_versions)
        ],
        "unsupportedAdapters": ["openapi"],
    }
    return result


def import_har(
    *,
    contract: WebCampaignContract,
    source: Path,
    output: Path,
    redacted_copy: Path,
    secret_store: SecretStore | None,
    identity_id: str,
    effect_class: str,
    workflow_id: str,
) -> dict[str, Any]:
    _require_external_original(source, contract)
    payload = source.read_bytes()
    if len(payload) > MAX_CAPTURE_BYTES:
        raise WebContractError("HAR exceeds the 64 MiB import limit")
    if source.resolve() in {output.resolve(), redacted_copy.resolve()}:
        raise WebContractError("refusing to overwrite the original HAR")
    value = _strict_json(payload, "HAR")
    log = value.get("log")
    if not isinstance(log, dict) or str(log.get("version")) != "1.2":
        raise WebContractError("HAR must contain a version 1.2 log")
    entries = log.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_CAPTURE_REQUESTS:
        raise WebContractError("HAR entries must be an array within the import limit")
    imported: list[dict[str, Any]] = []
    sanitized_entries: list[dict[str, Any]] = []
    secret_versions: list[dict[str, str]] = []
    literal_found = False
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            raise WebContractError(f"HAR entry {index + 1} has no request object")
        request = entry["request"]
        method = str(request.get("method") or "")
        url = str(request.get("url") or "")
        http_version = str(request.get("httpVersion") or "HTTP/1.1")
        header_values = request.get("headers", [])
        if not isinstance(header_values, list):
            raise WebContractError(f"HAR entry {index + 1} headers must be an array")
        headers: list[tuple[str, str]] = []
        for header in header_values:
            if not isinstance(header, dict):
                raise WebContractError("HAR header must be an object")
            headers.append((str(header.get("name") or ""), str(header.get("value") or "")))
        cookie_values = request.get("cookies", [])
        if not isinstance(cookie_values, list):
            raise WebContractError(f"HAR entry {index + 1} cookies must be an array")
        if cookie_values and not any(name.lower() == "cookie" for name, _ in headers):
            identity = contract.identity(identity_id)
            if identity is None or identity.credential_type not in {
                "cookie",
                "browser-session",
            }:
                raise WebContractError(
                    "HAR contains cookie credentials not represented by the selected identity"
                )
            cookie_parts: list[str] = []
            for cookie in cookie_values:
                if not isinstance(cookie, dict):
                    raise WebContractError("HAR cookie must be an object")
                name = str(cookie.get("name") or "")
                value = str(cookie.get("value") or "")
                if not name or any(character in name for character in "=;\r\n"):
                    raise WebContractError("HAR cookie name is invalid")
                if any(character in value for character in ";\r\n"):
                    raise WebContractError("HAR cookie value is invalid")
                cookie_parts.append(f"{name}={value}")
            headers.append(("Cookie", "; ".join(cookie_parts)))
        post_data = request.get("postData")
        body = b""
        mime_type = ""
        if post_data is not None:
            if not isinstance(post_data, dict):
                raise WebContractError("HAR postData must be an object")
            mime_type = str(post_data.get("mimeType") or "")
            text_value = str(post_data.get("text") or "")
            encoding = str(post_data.get("encoding") or post_data.get("_encoding") or "")
            if encoding:
                if encoding.lower() != "base64":
                    raise WebContractError("HAR postData uses an unsupported encoding")
                try:
                    body = base64.b64decode(text_value, validate=True)
                except (ValueError, binascii.Error) as exc:
                    raise WebContractError("HAR postData base64 is invalid") from exc
            else:
                body = text_value.encode("utf-8")
        parsed, redacted_headers, retained, had_literal = _captured_request(
            contract=contract,
            url=url,
            method=method,
            http_version=http_version,
            headers=headers,
            body=body,
            identity_id=identity_id,
            effect_class=effect_class,
            secret_store=secret_store,
        )
        stable = sha256_bytes(
            json.dumps(
                {
                    "method": method.upper(),
                    "url": url,
                    "headers": redacted_headers,
                    "body": base64.b64encode(body).decode("ascii"),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )[:12]
        request_id = f"har-{index + 1}-{stable}"
        origin_id, _origin, _target = _capture_origin(contract, url)
        imported.append(
            _capture_envelope(
                request_id=request_id,
                identity_id=identity_id,
                workflow_id=workflow_id,
                purpose=contract.origins[origin_id].purpose,
                effect_class=effect_class,
                parsed=parsed,
            )
        )
        sanitized_request: dict[str, Any] = {
            "method": method.upper(),
            "url": url,
            "httpVersion": http_version,
            "headers": [
                {"name": name, "value": value} for name, value in redacted_headers
            ],
            "queryString": [
                {"name": name, "value": value}
                for name, value in parse_qsl(
                    urlsplit(url).query,
                    keep_blank_values=True,
                    strict_parsing=False,
                    encoding="utf-8",
                    errors="replace",
                )
            ],
            "cookies": [],
            "headersSize": -1,
            "bodySize": len(body),
        }
        if body:
            sanitized_request["postData"] = {
                "mimeType": mime_type or "application/octet-stream",
                "text": base64.b64encode(body).decode("ascii"),
                "encoding": "base64",
            }
        sanitized_entries.append(
            {"request": sanitized_request, "_krineonRequestId": request_id}
        )
        secret_versions.extend(retained)
        literal_found = literal_found or had_literal
    sanitized = {
        "log": {
            "version": "1.2",
            "creator": {"name": "Krineon trusted redaction", "version": "1"},
            "entries": sanitized_entries,
        }
    }
    redacted_payload = (
        json.dumps(sanitized, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    _atomic_bytes(redacted_copy, redacted_payload)
    result = _capture_bundle(
        contract=contract,
        source_type="har-1.2",
        source_payload=payload,
        redacted_payload=redacted_payload,
        redacted_copy=redacted_copy,
        requests=imported,
        secret_versions=secret_versions,
        literal_found=literal_found,
    )
    atomic_json(output, result, mode=0o600)
    return result


def _split_raw_http_request(
    raw: bytes,
) -> tuple[bytes, list[tuple[bytes, str, str]], bytes, bytes]:
    if len(raw) > MAX_CAPTURE_REQUEST_BYTES:
        raise WebContractError("Burp request exceeds the 16 MiB request limit")
    if b"\r\n\r\n" in raw:
        separator = b"\r\n"
        head, body = raw.split(b"\r\n\r\n", 1)
    elif b"\n\n" in raw:
        separator = b"\n"
        head, body = raw.split(b"\n\n", 1)
    else:
        raise WebContractError("Burp request has no HTTP header terminator")
    lines = head.split(separator)
    if not lines:
        raise WebContractError("Burp request is empty")
    try:
        request_line = lines[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise WebContractError("Burp request line must be ASCII") from exc
    parts = request_line.split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise WebContractError(
            "Burp XML adapter accepts exact HTTP/1.x requests only; HTTP/2 requires "
            "a dedicated structured capture"
        )
    headers: list[tuple[bytes, str, str]] = []
    for line in lines[1:]:
        if line.startswith((b" ", b"\t")):
            raise WebContractError("obsolete folded Burp headers are unsupported")
        name_bytes, colon, value_bytes = line.partition(b":")
        if not colon:
            raise WebContractError("Burp request header is missing a colon")
        try:
            name = name_bytes.decode("ascii")
            value = value_bytes.lstrip(b" \t").decode("latin-1")
        except UnicodeDecodeError as exc:
            raise WebContractError("Burp request header encoding is invalid") from exc
        headers.append((line, name, value))
    return lines[0], headers, body, separator


def _url_for_raw_burp_request(
    contract: WebCampaignContract,
    request_line: bytes,
    headers: list[tuple[bytes, str, str]],
) -> str:
    try:
        _method, target, _version = request_line.decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError) as exc:
        raise WebContractError("Burp request line is invalid") from exc
    parsed = urlsplit(target)
    if parsed.scheme:
        _capture_origin(contract, target)
        return target
    host_values = [
        value for _raw, name, value in headers if name.lower() == "host"
    ]
    if len(host_values) != 1:
        raise WebContractError(
            "raw Burp request requires exactly one Host header when its target is relative"
        )
    matches = []
    for origin in contract.origins.values():
        scheme = urlsplit(origin.origin).scheme
        try:
            candidate = canonical_origin(f"{scheme}://{host_values[0]}")
        except WebContractError:
            continue
        if candidate == origin.origin:
            matches.append(origin)
    if len(matches) != 1:
        raise WebContractError(
            "raw Burp request Host does not select one exact authorized origin"
        )
    if not target.startswith("/"):
        raise WebContractError("raw Burp request target must be absolute or origin-form")
    return matches[0].origin + target


def _redact_burp_request(
    raw: bytes,
    *,
    identity_id: str,
    contract: WebCampaignContract,
    store: SecretStore | None,
) -> tuple[bytes, list[tuple[str, str]], list[dict[str, str]], bool, bytes, bytes]:
    request_line, raw_headers, body, separator = _split_raw_http_request(raw)
    pairs = [(name, value) for _line, name, value in raw_headers]
    redacted, retained, literal_found = redact_capture_headers(
        pairs,
        identity_id=identity_id,
        contract=contract,
        store=store,
    )
    rebuilt: list[bytes] = [request_line]
    for (raw_line, original_name, original_value), (name, value) in zip(
        raw_headers, redacted, strict=True
    ):
        if name == original_name and value == original_value:
            rebuilt.append(raw_line)
        else:
            rebuilt.append(name.encode("ascii") + b": " + value.encode("latin-1"))
    redacted_raw = separator.join(rebuilt) + separator + separator + body
    return redacted_raw, redacted, retained, literal_found, body, separator


def import_burp(
    *,
    contract: WebCampaignContract,
    source: Path,
    output: Path,
    redacted_copy: Path,
    secret_store: SecretStore | None,
    identity_id: str,
    effect_class: str,
    workflow_id: str,
) -> dict[str, Any]:
    _require_external_original(source, contract)
    payload = source.read_bytes()
    if len(payload) > MAX_CAPTURE_BYTES:
        raise WebContractError("Burp export exceeds the 64 MiB import limit")
    if source.resolve() in {output.resolve(), redacted_copy.resolve()}:
        raise WebContractError("refusing to overwrite the original Burp export")
    is_xml = payload.lstrip().startswith(b"<")
    capture_items: list[tuple[bytes, str, bool]] = []
    if is_xml:
        upper = payload.upper()
        if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
            raise WebContractError("Burp XML DTDs and entities are forbidden")
        try:
            root = ET.fromstring(payload)
        except ET.ParseError as exc:
            raise WebContractError(f"invalid Burp XML export: {exc}") from exc
        if root.tag != "items":
            raise WebContractError("Burp export root must be items")
        items = list(root.findall("item"))
        if len(items) > MAX_CAPTURE_REQUESTS:
            raise WebContractError("Burp export exceeds the request-count limit")
        for index, item in enumerate(items):
            request_node = item.find("request")
            url_node = item.find("url")
            if request_node is None or url_node is None or not (url_node.text or "").strip():
                raise WebContractError(f"Burp item {index + 1} lacks request or URL data")
            encoded = str(request_node.get("base64") or "false").lower() == "true"
            request_text = request_node.text or ""
            if encoded:
                try:
                    raw = base64.b64decode(request_text, validate=True)
                except (ValueError, binascii.Error) as exc:
                    raise WebContractError(
                        f"Burp item {index + 1} request base64 is invalid"
                    ) from exc
            else:
                raw = request_text.encode("latin-1")
            capture_items.append((raw, (url_node.text or "").strip(), encoded))
    else:
        request_line, headers, _body, _separator = _split_raw_http_request(payload)
        capture_items.append(
            (payload, _url_for_raw_burp_request(contract, request_line, headers), True)
        )
    imported: list[dict[str, Any]] = []
    secret_versions: list[dict[str, str]] = []
    literal_found = False
    sanitized_root = ET.Element("items", {"burpVersion": "redacted", "exportTime": "omitted"})
    raw_redacted_payload = b""
    for index, (raw, url, encoded) in enumerate(capture_items):
        redacted_raw, redacted_headers, retained, had_literal, body, separator = (
            _redact_burp_request(
                raw,
                identity_id=identity_id,
                contract=contract,
                store=secret_store,
            )
        )
        request_line = redacted_raw.split(separator, 1)[0].decode("ascii")
        method, target, http_version = request_line.split(" ")
        _origin_id, _origin, url_target = _capture_origin(contract, url)
        raw_target = urlsplit(target)
        normalized_target = (
            (raw_target.path or "/")
            + ("?" + raw_target.query if raw_target.query else "")
            if raw_target.scheme
            else target
        )
        if normalized_target != url_target:
            raise WebContractError("Burp URL metadata conflicts with the raw request target")
        parsed, _ignored_headers, _ignored_retained, _ignored_literal = _captured_request(
            contract=contract,
            url=url,
            method=method,
            http_version=http_version,
            headers=redacted_headers,
            body=body,
            identity_id=identity_id,
            effect_class=effect_class,
            secret_store=None,
        )
        raw_lines = redacted_raw.split(separator + separator, 1)[0].split(separator)
        parsed["exactReplay"] = {
            "wireAvailable": True,
            "rawBlockBase64": base64.b64encode(redacted_raw).decode("ascii"),
            "rawRequestLineBase64": base64.b64encode(raw_lines[0]).decode("ascii"),
            "headers": [
                {
                    "name": name,
                    "value": value,
                    "rawLineBase64": base64.b64encode(raw_line).decode("ascii"),
                }
                for raw_line, (name, value) in zip(
                    raw_lines[1:], redacted_headers, strict=True
                )
            ],
            "pseudoHeaders": [],
            "bodyBase64": base64.b64encode(body).decode("ascii"),
            "immutableAuthenticationFields": parsed["exactReplay"][
                "immutableAuthenticationFields"
            ],
        }
        parsed["byteExact"] = bool(separator == b"\r\n" and encoded and not had_literal)
        parsed["nonByteExactReasons"] = []
        if not encoded:
            parsed["nonByteExactReasons"].append(
                "Burp XML request was not exported as base64 bytes"
            )
        if separator != b"\r\n":
            parsed["nonByteExactReasons"].append(
                "Burp request did not retain CRLF wire delimiters"
            )
        if had_literal:
            parsed["nonByteExactReasons"].append(
                "trusted importer replaced literal credentials with a runtime secret reference"
            )
        stable = sha256_bytes(redacted_raw)[:12]
        request_id = f"burp-{index + 1}-{stable}"
        origin_id, _origin, _target = _capture_origin(contract, url)
        imported.append(
            _capture_envelope(
                request_id=request_id,
                identity_id=identity_id,
                workflow_id=workflow_id,
                purpose=contract.origins[origin_id].purpose,
                effect_class=effect_class,
                parsed=parsed,
            )
        )
        if is_xml:
            sanitized_item = ET.SubElement(sanitized_root, "item")
            ET.SubElement(sanitized_item, "url").text = url
            ET.SubElement(sanitized_item, "method").text = method.upper()
            sanitized_request = ET.SubElement(
                sanitized_item, "request", {"base64": "true"}
            )
            sanitized_request.text = base64.b64encode(redacted_raw).decode("ascii")
            ET.SubElement(sanitized_item, "krineonRequestId").text = request_id
        else:
            raw_redacted_payload = redacted_raw
        secret_versions.extend(retained)
        literal_found = literal_found or had_literal
    redacted_payload = (
        ET.tostring(sanitized_root, encoding="utf-8", xml_declaration=True)
        if is_xml
        else raw_redacted_payload
    )
    _atomic_bytes(redacted_copy, redacted_payload)
    result = _capture_bundle(
        contract=contract,
        source_type="burp-xml" if is_xml else "burp-request",
        source_payload=payload,
        redacted_payload=redacted_payload,
        redacted_copy=redacted_copy,
        requests=imported,
        secret_versions=secret_versions,
        literal_found=literal_found,
    )
    atomic_json(output, result, mode=0o600)
    return result


def import_url(
    *,
    contract: WebCampaignContract,
    url: str,
    identity_id: str,
    output: Path,
) -> dict[str, Any]:
    contract.require_live_authorization()
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise WebContractError("URL import requires an absolute HTTP(S) URL")
    origin_value = canonical_origin(f"{parsed.scheme}://{parsed.netloc}")
    matches = [item for item in contract.origins.values() if item.origin == origin_value]
    if len(matches) != 1:
        raise WebContractError("URL does not match one exact contract origin")
    path = (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
    identity = IdentityBroker(contract).authorize(
        identity_id,
        origin_id=matches[0].id,
        path_or_url=url,
        transport="http",
    )
    admitted = contract.admitted_request(
        origin_id=matches[0].id,
        path_or_url=url,
        method="GET",
        effect_class="read-only",
    )
    result = {
        "schemaVersion": 1,
        "kind": "krineon-web-request-bundle",
        "sourceType": "url",
        "contractSha256": contract.digest,
        "authorityDerivedOnlyFromContract": True,
        "executable": False,
        "requiresCoordinatorApproval": True,
        "requests": [
            {
                "id": "url-discovery",
                "identityId": identity.id if identity else "anonymous",
                "workflowId": "url-discovery",
                "purpose": matches[0].purpose,
                "effectClass": "read-only",
                "resource": {
                    "id": "discovery-root",
                    "kind": "application-url",
                    "expectedOwner": identity.id if identity else "public",
                },
                "expectedRule": "only content authorized for this exact identity is returned",
                "dependsOn": [],
                "request": {
                    "schemaVersion": 1,
                    "protocol": "semantic-url",
                    "byteExact": False,
                    "nonByteExactReasons": [
                        "URL-only intake has no caller-supplied wire representation"
                    ],
                    "exactReplay": None,
                    "semantic": {
                        "method": "GET",
                        "originId": matches[0].id,
                        "origin": matches[0].origin,
                        "target": path,
                        "path": parsed.path or "/",
                        "rawQuery": parsed.query,
                        "headers": [],
                        "bodyBase64": "",
                        "bodyBytes": 0,
                        "actionPolicyId": admitted["actionPolicyId"],
                    },
                    "signed": False,
                    "resigningRequiredForMutation": False,
                },
            }
        ],
        "workflows": [{"id": "url-discovery", "requestIds": ["url-discovery"]}],
        "coverage": {
            "identityLabels": [identity.id if identity else "anonymous"],
            "independentAuthenticatedIdentityCount": 1 if identity else 0,
            "independentTenantCount": 1 if identity and identity.expected_tenant else 0,
            "crossUserCoverageAvailable": False,
            "crossTenantCoverageAvailable": False,
        },
        "secretVersions": [],
        "unsupportedAdapters": ["openapi"],
    }
    atomic_json(output, result, mode=0o600)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    markdown_parser = sub.add_parser("markdown")
    markdown_parser.add_argument("contract")
    markdown_parser.add_argument("source")
    markdown_parser.add_argument("--output", required=True)
    markdown_parser.add_argument("--redacted-copy", required=True)
    markdown_parser.add_argument("--secret-store")
    markdown_parser.add_argument("--worktree-root", action="append", default=[])
    url_parser = sub.add_parser("url")
    url_parser.add_argument("contract")
    url_parser.add_argument("url")
    url_parser.add_argument("--identity", default="anonymous")
    url_parser.add_argument("--output", required=True)
    for capture_kind in ("har", "burp", "burp-request"):
        capture_parser = sub.add_parser(capture_kind)
        capture_parser.add_argument("contract")
        capture_parser.add_argument("source")
        capture_parser.add_argument("--output", required=True)
        capture_parser.add_argument("--redacted-copy", required=True)
        capture_parser.add_argument("--secret-store")
        capture_parser.add_argument("--worktree-root", action="append", default=[])
        capture_parser.add_argument("--identity", default="anonymous")
        capture_parser.add_argument("--effect", default="read-only")
        capture_parser.add_argument("--workflow", default="imported-capture")
    args = parser.parse_args(argv)
    try:
        contract_path = Path(args.contract).expanduser().resolve()
        contract = WebCampaignContract.load(contract_path)
        output = Path(args.output).expanduser().resolve()
        if args.command in {"markdown", "har", "burp", "burp-request"}:
            source = Path(args.source).expanduser().resolve()
            secret_store = (
                SecretStore(
                    args.secret_store,
                    forbidden_root=contract_path.parent,
                    forbidden_roots=args.worktree_root,
                )
                if args.secret_store
                else None
            )
            common = {
                "contract": contract,
                "source": source,
                "output": output,
                "redacted_copy": Path(args.redacted_copy).expanduser().resolve(),
                "secret_store": secret_store,
            }
            if args.command == "markdown":
                result = import_markdown(**common)
            elif args.command == "har":
                result = import_har(
                    **common,
                    identity_id=args.identity,
                    effect_class=args.effect,
                    workflow_id=args.workflow,
                )
            else:
                result = import_burp(
                    **common,
                    identity_id=args.identity,
                    effect_class=args.effect,
                    workflow_id=args.workflow,
                )
        else:
            result = import_url(
                contract=contract,
                url=args.url,
                identity_id=args.identity,
                output=output,
            )
        print(
            json.dumps(
                {
                    "requests": len(result["requests"]),
                    "identities": result["coverage"][
                        "independentAuthenticatedIdentityCount"
                    ],
                    "crossUserCoverageAvailable": result["coverage"][
                        "crossUserCoverageAvailable"
                    ],
                    "executable": False,
                },
                indent=2,
            )
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
