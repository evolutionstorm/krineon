#!/usr/bin/env python3
"""Private, model-inaccessible storage for imported web credentials.

The store must be outside the campaign worktree. It intentionally exposes only
opaque secret references and keyed fingerprints to model-visible artifacts.
Same-UID processes are not treated as a confidentiality boundary; callers must
combine this store with worker process isolation when workers are untrusted.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

try:
    from .web_contract import SECRET_REF, WebContractError
except ImportError:
    from web_contract import SECRET_REF, WebContractError


MAX_SECRET_BYTES = 1024 * 1024
ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def _atomic_bytes(path: Path, value: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class SecretStore:
    """Restricted secret versions indexed by ``secret://`` references."""

    def __init__(
        self,
        root: Path | str,
        *,
        forbidden_root: Path | str | None = None,
        forbidden_roots: list[Path | str] | tuple[Path | str, ...] = (),
    ):
        self.root = Path(root).expanduser().resolve()
        denied_roots = list(forbidden_roots)
        if forbidden_root is not None:
            denied_roots.append(forbidden_root)
        for denied in denied_roots:
            forbidden = Path(denied).expanduser().resolve()
            if _inside(self.root, forbidden) or _inside(forbidden, self.root):
                raise WebContractError(
                    "secret store must be outside the campaign and worktree"
                )
        if self.root.exists() and self.root.is_symlink():
            raise WebContractError("secret store root cannot be a symlink")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self.values = self.root / "values"
        self.keys = self.root / "keys"
        self.values.mkdir(exist_ok=True, mode=0o700)
        self.keys.mkdir(exist_ok=True, mode=0o700)
        os.chmod(self.values, 0o700)
        os.chmod(self.keys, 0o700)
        self.manifest_path = self.root / "manifest.json"
        self.key_path = self.keys / "fingerprint.key"
        if not self.key_path.exists():
            _atomic_bytes(self.key_path, secrets.token_bytes(32), 0o600)
        self._require_private(self.key_path)

    @staticmethod
    def _require_private(path: Path) -> None:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise WebContractError(f"secret store path is accessible by other users: {path}")

    def _manifest(self) -> dict[str, Any]:
        if not self.manifest_path.exists():
            return {"schemaVersion": 1, "secrets": {}}
        self._require_private(self.manifest_path)
        value = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or value.get("schemaVersion") != 1:
            raise WebContractError("secret store manifest is invalid")
        secrets_value = value.get("secrets")
        if not isinstance(secrets_value, dict):
            raise WebContractError("secret store manifest has no secrets mapping")
        return value

    def _write_manifest(self, value: dict[str, Any]) -> None:
        payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
        _atomic_bytes(self.manifest_path, payload, 0o600)

    def _fingerprint(self, value: bytes) -> str:
        key = self.key_path.read_bytes()
        return "hmac-sha256:" + hmac.new(key, value, hashlib.sha256).hexdigest()

    def put(
        self,
        reference: str,
        value: str | bytes,
        *,
        kind: str,
        expires_at: str | None = None,
        version: str | None = None,
    ) -> dict[str, str]:
        if not SECRET_REF.fullmatch(reference):
            raise WebContractError("secret store references must use secret://")
        payload = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        if not payload or len(payload) > MAX_SECRET_BYTES:
            raise WebContractError("secret value is empty or exceeds the import limit")
        if kind not in {"bearer", "cookie", "api-key", "browser-session"}:
            raise WebContractError("secret kind is unsupported")
        manifest = self._manifest()
        entries = manifest["secrets"].setdefault(reference, [])
        if not isinstance(entries, list):
            raise WebContractError("secret store reference history is invalid")
        version = version or f"sv-{secrets.token_hex(12)}"
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", version):
            raise WebContractError("secret version must be an opaque stable identifier")
        existing = next(
            (entry for entry in entries if entry.get("version") == version), None
        )
        if existing is not None:
            if hmac.compare_digest(
                self._fingerprint(payload), str(existing.get("fingerprint") or "")
            ):
                return {
                    "reference": reference,
                    "version": version,
                    "kind": str(existing.get("kind") or kind),
                    "fingerprint": str(existing.get("fingerprint") or ""),
                }
            raise WebContractError(
                "secret version already exists with a different credential value"
            )
        opaque_file = f"sec-{secrets.token_hex(24)}.bin"
        target = self.values / opaque_file
        _atomic_bytes(target, payload, 0o600)
        entry = {
            "version": version,
            "file": opaque_file,
            "kind": kind,
            "fingerprint": self._fingerprint(payload),
            "expiresAt": expires_at,
        }
        entries.append(entry)
        self._write_manifest(manifest)
        return {
            "reference": reference,
            "version": version,
            "kind": kind,
            "fingerprint": entry["fingerprint"],
        }

    def get(self, reference: str, *, version: str | None = None) -> bytes:
        if not SECRET_REF.fullmatch(reference):
            raise WebContractError("secret store references must use secret://")
        entries = self._manifest()["secrets"].get(reference)
        if not isinstance(entries, list) or not entries:
            raise WebContractError("secret reference is unavailable in the private store")
        selected = next(
            (entry for entry in reversed(entries) if version in {None, entry.get("version")}),
            None,
        )
        if not isinstance(selected, dict):
            raise WebContractError("requested secret version is unavailable")
        filename = str(selected.get("file") or "")
        if not re.fullmatch(r"sec-[0-9a-f]{48}\.bin", filename):
            raise WebContractError("secret store contains an unsafe value path")
        path = self.values / filename
        if path.is_symlink() or not path.is_file():
            raise WebContractError("secret value file is unavailable")
        self._require_private(path)
        payload = path.read_bytes()
        if not hmac.compare_digest(self._fingerprint(payload), str(selected.get("fingerprint"))):
            raise WebContractError("secret value fingerprint does not match the manifest")
        return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("store")
    parser.add_argument("--forbidden-root")
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--put-reference",
        help="store one secret:// reference without placing its value in arguments",
    )
    parser.add_argument(
        "--kind",
        choices=("bearer", "cookie", "api-key", "browser-session"),
    )
    parser.add_argument("--version")
    parser.add_argument("--expires-at")
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--prompt",
        action="store_true",
        help="read the value from a no-echo interactive prompt",
    )
    source.add_argument(
        "--env",
        metavar="NAME",
        help="read the value from this environment-variable name",
    )
    source.add_argument(
        "--secret-file",
        help="read the value from a non-symlink file restricted to its owner",
    )
    args = parser.parse_args(argv)
    try:
        store = SecretStore(args.store, forbidden_root=args.forbidden_root)
        if args.check and args.put_reference:
            raise WebContractError("--check and --put-reference are mutually exclusive")
        if any((args.prompt, args.env, args.secret_file)) and not args.put_reference:
            raise WebContractError("secret input requires --put-reference")
        if args.put_reference:
            if not args.kind:
                raise WebContractError("--put-reference requires --kind")
            selected = sum(bool(value) for value in (args.prompt, args.env, args.secret_file))
            if selected != 1:
                raise WebContractError(
                    "--put-reference requires exactly one of --prompt, --env, or --secret-file"
                )
            if args.prompt:
                value: str | bytes = getpass.getpass("Secret value: ")
            elif args.env:
                if not ENVIRONMENT_NAME.fullmatch(args.env):
                    raise WebContractError("--env must name one valid environment variable")
                if args.env not in os.environ:
                    raise WebContractError("the selected environment variable is unavailable")
                value = os.environ[args.env]
            else:
                supplied_path = Path(args.secret_file).expanduser()
                if supplied_path.is_symlink():
                    raise WebContractError("secret file must be a regular non-symlink file")
                secret_path = supplied_path.resolve()
                if not secret_path.is_file():
                    raise WebContractError("secret file must be a regular non-symlink file")
                store._require_private(secret_path)
                value = secret_path.read_bytes()
            retained = store.put(
                args.put_reference,
                value,
                kind=args.kind,
                expires_at=args.expires_at,
                version=args.version,
            )
            print(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        **retained,
                        "secretValueExposed": False,
                    },
                    indent=2,
                )
            )
            return 0
        if args.check:
            manifest = store._manifest()
            print(
                json.dumps(
                    {
                        "schemaVersion": 1,
                        "references": sorted(manifest["secrets"]),
                        "secretValuesExposed": False,
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
