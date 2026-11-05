#!/usr/bin/env python3
"""Runtime identity, credential, session, and authentication-state controls."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import json
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from .web_contract import (
        IdentityPolicy,
        WebCampaignContract,
        WebContractError,
        path_matches_prefix,
        utc_now,
    )
    from .web_secret_store import SecretStore
except ImportError:
    from web_contract import (
        IdentityPolicy,
        WebCampaignContract,
        WebContractError,
        path_matches_prefix,
        utc_now,
    )
    from web_secret_store import SecretStore


class AuthInconclusive(WebContractError):
    """The requested identity cannot currently produce trustworthy observations."""


class IdentityLease:
    """Serialize login, refresh, logout, CSRF rotation, and session mutation."""

    def __init__(self, root: Path, identity_id: str, operation: str):
        safe_id = re.sub(r"[^A-Za-z0-9_.-]", "_", identity_id)
        self.path = root / f"{safe_id}.lock"
        self.identity_id = identity_id
        self.operation = operation
        self.stream: Any | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.stream = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self.stream.close()
            self.stream = None
            raise AuthInconclusive(
                f"auth-inconclusive: identity {self.identity_id} has an active session mutation"
            ) from exc
        self.stream.seek(0)
        self.stream.truncate()
        self.stream.write(
            json.dumps(
                {
                    "identityId": self.identity_id,
                    "operation": self.operation,
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

    def __enter__(self) -> "IdentityLease":
        self.acquire()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.release()


class IdentityBroker:
    """Authorize and inject one contract identity immediately before dispatch."""

    def __init__(
        self,
        contract: WebCampaignContract,
        *,
        secret_store: SecretStore | None = None,
        lease_root: Path | None = None,
    ):
        self.contract = contract
        self.secret_store = secret_store
        self.lease_root = lease_root

    def authorize(
        self,
        identity_id: str | None,
        *,
        origin_id: str,
        path_or_url: str,
        transport: str,
    ) -> IdentityPolicy | None:
        identity = self.contract.identity_for_origin(identity_id, origin_id)
        if identity is None:
            return None
        if identity.verification_status != "verified":
            raise AuthInconclusive(
                f"auth-inconclusive: identity {identity.id} has not been verified"
            )
        if not identity.expected_tenant.strip():
            raise AuthInconclusive(
                f"auth-inconclusive: identity {identity.id} has no verified tenant"
            )
        if identity.expires_at is not None and identity.expires_at <= utc_now():
            raise AuthInconclusive(
                f"auth-inconclusive: identity {identity.id} credential expired"
            )
        if transport not in identity.allowed_transports:
            raise AuthInconclusive(
                f"auth-inconclusive: identity {identity.id} is not valid for {transport}"
            )
        parsed = urlsplit(path_or_url)
        path = parsed.path if parsed.scheme else urlsplit(path_or_url).path
        path = path or "/"
        if not any(path_matches_prefix(path, value) for value in identity.allowed_path_prefixes):
            raise AuthInconclusive(
                f"auth-inconclusive: identity {identity.id} is not permitted for this path"
            )
        return identity

    def resolve_reference(self, reference: str, *, version: str = "") -> str:
        """Resolve one opaque reference without exposing it to worker artifacts."""

        name = reference.removeprefix("secret://")
        environment_name = "KRINEON_SECRET_" + re.sub(
            r"[^A-Za-z0-9]", "_", name
        ).upper()
        environment_value = os.environ.get(environment_name)
        if environment_value:
            return environment_value
        if self.secret_store is not None:
            try:
                return self.secret_store.get(
                    reference,
                    version=None if version == "unversioned" else version or None,
                ).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise AuthInconclusive(
                    "auth-inconclusive: credential cannot be injected as an HTTP value"
                ) from exc
        raise AuthInconclusive(
            f"auth-inconclusive: fresh secret {reference} is unavailable"
        )

    def resolve(self, identity: IdentityPolicy) -> str:
        if identity.credential_type == "form-login":
            raise AuthInconclusive(
                f"auth-inconclusive: identity {identity.id} requires browser form login"
            )
        if not identity.credential_ref:
            raise AuthInconclusive(
                f"auth-inconclusive: identity {identity.id} has no runtime credential"
            )
        return self.resolve_reference(
            identity.credential_ref, version=identity.secret_version
        )

    def form_login_credentials(self, identity: IdentityPolicy) -> tuple[str, str]:
        if identity.credential_type != "form-login" or not isinstance(identity.login, dict):
            raise AuthInconclusive(
                f"auth-inconclusive: identity {identity.id} has no form-login contract"
            )
        username = self.resolve_reference(
            str(identity.login["usernameRef"]),
            version=str(identity.login["usernameVersion"]),
        )
        password = self.resolve_reference(
            str(identity.login["passwordRef"]),
            version=str(identity.login["passwordVersion"]),
        )
        return username, password

    def injection_headers(
        self, identity: IdentityPolicy, credential: str
    ) -> list[tuple[str, str]]:
        if "\r" in credential or "\n" in credential:
            raise AuthInconclusive("auth-inconclusive: credential contains a line break")
        if identity.credential_type == "bearer":
            return [("Authorization", f"Bearer {credential}")]
        if identity.credential_type == "api-key":
            return [(identity.api_key_header, credential)]
        if identity.credential_type in {"cookie", "browser-session"}:
            value = credential
            if "=" in credential:
                supplied_name, supplied_value = credential.split("=", 1)
                if supplied_name != identity.cookie_name:
                    raise AuthInconclusive(
                        "auth-inconclusive: cookie name does not match identity policy"
                    )
                value = supplied_value
            return [("Cookie", f"{identity.cookie_name}={value}")]
        if identity.credential_type == "form-login":
            return []
        raise AuthInconclusive("auth-inconclusive: unsupported credential type")

    def lease(self, identity_id: str, operation: str) -> IdentityLease:
        if self.lease_root is None:
            raise WebContractError("identity lease root is not configured")
        return IdentityLease(self.lease_root, identity_id, operation)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("contract")
    parser.add_argument("identity")
    parser.add_argument("origin")
    parser.add_argument("path")
    parser.add_argument("--transport", choices=("http", "browser"), default="http")
    args = parser.parse_args(argv)
    try:
        contract = WebCampaignContract.load(args.contract)
        broker = IdentityBroker(contract)
        identity = broker.authorize(
            args.identity,
            origin_id=args.origin,
            path_or_url=args.path,
            transport=args.transport,
        )
        print(
            json.dumps(
                {
                    "identityId": identity.id if identity else "anonymous",
                    "expectedTenant": identity.expected_tenant if identity else "",
                    "status": "verified" if identity else "anonymous",
                    "credentialResolved": False,
                },
                indent=2,
            )
        )
        return 0
    except (OSError, ValueError, WebContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
