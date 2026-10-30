#!/usr/bin/env python3
"""Create and verify coordinator-signed experiment approvals and observations."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


class ExperimentControlError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def openssl(arguments: list[str], *, label: str) -> subprocess.CompletedProcess[bytes]:
    executable = shutil.which("openssl")
    if executable is None:
        raise ExperimentControlError("OpenSSL is required for controlled experiment signing")
    completed = subprocess.run(
        [executable, *arguments],
        check=False,
        capture_output=True,
        timeout=60,
    )
    if completed.returncode != 0:
        diagnostic = completed.stderr.decode("utf-8", "replace")[-2000:]
        raise ExperimentControlError(f"{label} failed: {diagnostic}")
    return completed


def authority_paths(root: Path) -> tuple[Path, Path]:
    root = root.resolve()
    identity = hashlib.sha256(str(root).encode()).hexdigest()[:20]
    private = root.parent / ".krineon-authority" / f"{root.name}-{identity}.pem"
    public = root / "evidence" / "control" / "coordinator-public.pem"
    return private, public


def ensure_authority(root: Path) -> dict[str, str]:
    private, public = authority_paths(root)
    if not private.exists():
        private.parent.mkdir(parents=True, exist_ok=True)
        openssl(
            [
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                str(private),
            ],
            label="coordinator private-key generation",
        )
        private.chmod(0o600)
    public.parent.mkdir(parents=True, exist_ok=True)
    temporary = public.with_name(f".{public.name}.{os.getpid()}.tmp")
    openssl(
        ["pkey", "-in", str(private), "-pubout", "-out", str(temporary)],
        label="coordinator public-key derivation",
    )
    os.replace(temporary, public)
    return {
        "algorithm": "ECDSA-P256-SHA256",
        "publicKey": public.relative_to(root).as_posix(),
        "publicKeySha256": sha256_file(public),
        "privateKey": str(private),
    }


def sign_file(private_key: Path, value: Path, signature: Path) -> None:
    signature.parent.mkdir(parents=True, exist_ok=True)
    temporary = signature.with_name(f".{signature.name}.{os.getpid()}.tmp")
    openssl(
        [
            "dgst",
            "-sha256",
            "-sign",
            str(private_key),
            "-out",
            str(temporary),
            str(value),
        ],
        label="experiment record signing",
    )
    os.replace(temporary, signature)


def verify_file(public_key: Path, value: Path, signature: Path) -> bool:
    if not public_key.is_file() or not value.is_file() or not signature.is_file():
        return False
    try:
        openssl(
            [
                "dgst",
                "-sha256",
                "-verify",
                str(public_key),
                "-signature",
                str(signature),
                str(value),
            ],
            label="experiment signature verification",
        )
    except ExperimentControlError:
        return False
    return True


def control_public_key(root: Path) -> Path:
    campaign_path = root / "campaign.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    authority = campaign.get("experimentAuthority")
    if not isinstance(authority, dict):
        raise ExperimentControlError("campaign has no experiment authority")
    relative = Path(str(authority.get("publicKey") or ""))
    if relative.is_absolute() or ".." in relative.parts:
        raise ExperimentControlError("experiment public key path is unsafe")
    public = (root / relative).resolve()
    public.relative_to(root.resolve())
    if sha256_file(public) != authority.get("publicKeySha256"):
        raise ExperimentControlError("experiment public key hash changed")
    return public


def verify_signed_record(
    root: Path,
    record_path: Path,
    signature_path: Path,
    *,
    producer: str,
) -> tuple[bool, list[str], dict[str, Any]]:
    errors: list[str] = []
    try:
        public = control_public_key(root)
    except (OSError, ValueError, json.JSONDecodeError, ExperimentControlError) as error:
        return False, [f"authority:{error}"], {}
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return False, [f"record:{error}"], {}
    if not isinstance(record, dict):
        return False, ["record:not-object"], {}
    if record.get("producer") != producer:
        errors.append("producer:mismatch")
    if not verify_file(public, record_path, signature_path):
        errors.append("signature:invalid")
    return not errors, errors, record


def safe_record_path(root: Path, value: Any) -> Path:
    relative = Path(str(value or ""))
    if relative.is_absolute() or ".." in relative.parts:
        raise ExperimentControlError("signed record contains an unsafe path")
    candidate = (root / relative).resolve()
    candidate.relative_to(root.resolve())
    return candidate


def verify_controlled_observation(
    root: Path,
    observation_path: Path,
    signature_path: Path,
) -> dict[str, Any]:
    passed, errors, record = verify_signed_record(
        root,
        observation_path,
        signature_path,
        producer="krineon-controlled-runner",
    )
    linked_records: dict[str, dict[str, Any]] = {}
    linked_paths: dict[str, Path] = {}
    for field, producer in (
        ("approval", "krineon-coordinator"),
        ("attestation", None),
    ):
        value = record.get(field)
        if not isinstance(value, dict):
            errors.append(f"{field}:missing")
            continue
        try:
            path = safe_record_path(root, value.get("path"))
            linked_paths[field] = path
            if sha256_file(path) != value.get("sha256"):
                errors.append(f"{field}:hash")
            if producer:
                signature = safe_record_path(root, value.get("signature"))
                signed, signed_errors, linked = verify_signed_record(
                    root, path, signature, producer=producer
                )
                if not signed:
                    errors.extend(f"{field}:{error}" for error in signed_errors)
                else:
                    linked_records[field] = linked
        except (OSError, ValueError, ExperimentControlError) as error:
            errors.append(f"{field}:{error}")
    attestation_validation: dict[str, Any] = {}
    if "attestation" in linked_paths:
        try:
            try:
                from .reality_evidence import validate_attestation
            except ImportError:
                from reality_evidence import validate_attestation
            attestation_validation = validate_attestation(
                root,
                linked_paths["attestation"],
                expected_finding_id=str(record.get("taskId") or ""),
                expected_worker_id="coordinator",
                expected_role="coordinator",
            )
            if not attestation_validation.get("passed"):
                errors.extend(
                    f"attestation:{error}"
                    for error in attestation_validation.get("errors", [])
                )
        except (OSError, ValueError, json.JSONDecodeError) as error:
            errors.append(f"attestation:{error}")
    approval = linked_records.get("approval", {})
    attestation_record = attestation_validation.get("record", {})
    if approval and attestation_record:
        if approval.get("taskId") != record.get("taskId"):
            errors.append("approval:task")
        if approval.get("recipe", {}).get("sha256") != attestation_record.get(
            "recipe", {}
        ).get("sha256"):
            errors.append("approval:recipe")
        if approval.get("subjectArtifact") != attestation_record.get(
            "subjectArtifact", {}
        ).get("path"):
            errors.append("approval:subject")
        if approval.get("subjectArgvIndex") != attestation_record.get(
            "subjectArtifact", {}
        ).get("argvIndex"):
            errors.append("approval:subject-index")
        approved_targets = sorted(
            (
                str(value.get("path")),
                str(value.get("sha256")),
            )
            for value in approval.get("targetArtifacts", [])
            if isinstance(value, dict)
        )
        observed_targets = sorted(
            (
                str(value.get("path")),
                str(value.get("sha256")),
            )
            for value in attestation_record.get("targetArtifacts", [])
            if isinstance(value, dict)
        )
        if approved_targets != observed_targets:
            errors.append("approval:targets")
    artifacts = record.get("rawArtifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("rawArtifacts:missing")
    else:
        for index, artifact in enumerate(artifacts):
            if not isinstance(artifact, dict):
                errors.append(f"rawArtifacts[{index}]")
                continue
            try:
                path = safe_record_path(root, artifact.get("path"))
                if sha256_file(path) != artifact.get("sha256"):
                    errors.append(f"rawArtifacts[{index}]:hash")
            except (OSError, ValueError, ExperimentControlError) as error:
                errors.append(f"rawArtifacts[{index}]:{error}")
    return {
        "passed": passed and not errors,
        "errors": list(dict.fromkeys(errors)),
        "record": record,
        "observationSha256": sha256_file(observation_path),
    }

