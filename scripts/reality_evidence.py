#!/usr/bin/env python3
"""Shared validators for executable Krineon reality attestations.

An attestation is useful only when its assertions can be recomputed from raw
process output, its recipe and target artifacts still hash to the recorded
values, and every case was launched as a distinct process.  This module does
not claim that an instrumented observer is infallible; it makes the observer,
command, target, challenges, and raw observations reviewable instead of
accepting prose as execution evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


SHA256_RE = re.compile(r"[0-9a-f]{64}")
SAFE_CASES = {"baseline", "negative", "positive"}
CHALLENGE_BOUND_ASSERTIONS = {
    "stdout-contains-challenge",
    "controlled-write",
    "controlled-pc",
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def safe_campaign_path(root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("artifact path is empty")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"artifact path must be campaign-relative: {value}")
    candidate = (root / relative).resolve()
    candidate.relative_to(root.resolve())
    return candidate


def json_observation(stdout: bytes) -> dict[str, Any] | None:
    for raw in reversed(stdout.decode("utf-8", "replace").splitlines()):
        raw = raw.strip()
        if not raw:
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None


def integer_address(value: Any) -> int | None:
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]+", value):
        return int(value, 16)
    return None


def _allocation(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    address = integer_address(value.get("address"))
    size = value.get("size")
    allocation_id = value.get("allocationId")
    generation = value.get("generation")
    stack_hash = value.get("allocationStackSha256")
    if (
        address is None
        or not isinstance(size, int)
        or size <= 0
        or not isinstance(allocation_id, str)
        or not allocation_id
        or not isinstance(generation, (str, int))
        or not isinstance(stack_hash, str)
        or not SHA256_RE.fullmatch(stack_hash)
    ):
        return None
    return {
        "address": address,
        "size": size,
        "allocationId": allocation_id,
        "generation": str(generation),
        "allocationStackSha256": stack_hash,
    }


def evaluate_assertion(
    assertion: dict[str, Any],
    *,
    return_code: int | None,
    process_id: int,
    challenge_hex: str,
    stdout: bytes,
    stderr: bytes,
) -> tuple[bool, dict[str, Any]]:
    """Recompute one assertion from raw process observations."""

    kind = str(assertion.get("kind") or "")
    if kind == "exit-code":
        expected = int(assertion.get("equals"))
        return return_code == expected, {"expected": expected, "actual": return_code}
    if kind in {"stdout-contains", "stdout-not-contains"}:
        needle = str(assertion.get("value") or "").encode()
        present = bool(needle) and needle in stdout
        matched = present if kind == "stdout-contains" else not present
        return matched, {"needleSha256": sha256_bytes(needle), "present": present}
    if kind in {"stdout-contains-challenge", "stdout-not-contains-challenge"}:
        present = challenge_hex.encode("ascii") in stdout
        matched = present if kind == "stdout-contains-challenge" else not present
        return matched, {"challengePresent": present}

    observation = json_observation(stdout)
    if observation is None:
        return False, {"error": "stdout has no JSON observation"}
    if observation.get("targetPid") != process_id:
        return False, {
            "error": "observation targetPid does not identify the launched process",
            "targetPid": observation.get("targetPid"),
            "launchedPid": process_id,
        }
    if kind == "no-memory-write":
        observed = observation.get("writeObserved") is True
        return not observed, {"writeObserved": observed}
    if kind == "controlled-pc":
        control = observation.get("programCounter")
        if not isinstance(control, dict):
            return False, {"error": "programCounter observation is absent"}
        requested = str(control.get("requestedHex") or "").lower()
        observed = str(control.get("observedHex") or "").lower()
        expected = challenge_hex.lower()
        matched = requested == expected and observed == expected
        return matched, {
            "requestedHex": requested,
            "observedHex": observed,
            "challengeHex": expected,
        }
    if kind == "controlled-write":
        original = _allocation(observation.get("originalAllocation"))
        replacement = _allocation(observation.get("replacementAllocation"))
        write = observation.get("write")
        claim = str(assertion.get("claim") or "controlled-write")
        if original is None or not isinstance(write, dict):
            return False, {"error": "allocation or write observation is incomplete"}
        address = integer_address(write.get("address"))
        before_hex = str(write.get("beforeHex") or "").lower()
        after_hex = str(write.get("afterHex") or "").lower()
        if address is None:
            return False, {"error": "write address is invalid"}
        challenge = challenge_hex.lower()
        bounds_ok = original["address"] <= address
        bounds_ok = bounds_ok and address + len(bytes.fromhex(challenge)) <= (
            original["address"] + original["size"]
        )
        bytes_ok = after_hex == challenge and before_hex != after_hex
        identity_ok = True
        if claim == "uaf-write":
            identity_ok = bool(
                replacement
                and replacement["address"] == original["address"]
                and replacement["allocationId"] != original["allocationId"]
                and replacement["generation"] != original["generation"]
            )
        return bounds_ok and bytes_ok and identity_ok, {
            "claim": claim,
            "boundsMatched": bounds_ok,
            "chosenBytesMatched": bytes_ok,
            "allocationIdentityMatched": identity_ok,
            "originalAllocation": original,
            "replacementAllocation": replacement,
            "writeAddress": address,
            "beforeHex": before_hex,
            "afterHex": after_hex,
            "challengeHex": challenge,
        }
    return False, {"error": f"unsupported assertion kind: {kind}"}


def validate_attestation(
    root: Path,
    attestation_path: Path,
    *,
    expected_finding_id: str | None = None,
    expected_worker_id: str | None = None,
    expected_role: str | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    root = root.resolve()
    attestation_path = attestation_path.resolve()
    try:
        attestation_path.relative_to(root)
    except ValueError:
        return {"passed": False, "errors": ["attestation:outside-campaign"]}
    try:
        record = read_object(attestation_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return {"passed": False, "errors": [f"attestation:unreadable:{error}"]}
    if record.get("schemaVersion") != 1:
        errors.append("schemaVersion:1")
    if record.get("producer") != "krineon-reality-runner":
        errors.append("producer:krineon-reality-runner")
    if record.get("status") != "passed":
        errors.append("status:passed")
    if expected_finding_id is not None and record.get("findingId") != expected_finding_id:
        errors.append("findingId:mismatch")
    if expected_worker_id is not None and record.get("workerId") != expected_worker_id:
        errors.append("workerId:mismatch")
    if expected_role is not None and record.get("role") != expected_role:
        errors.append("role:mismatch")

    recipe = record.get("recipe") if isinstance(record.get("recipe"), dict) else {}
    try:
        recipe_path = safe_campaign_path(root, recipe.get("path"))
        if not recipe_path.is_file():
            errors.append("recipe:missing")
        elif sha256_file(recipe_path) != recipe.get("sha256"):
            errors.append("recipe:hash-mismatch")
        recipe_record = read_object(recipe_path) if recipe_path.is_file() else {}
    except (OSError, ValueError, json.JSONDecodeError):
        errors.append("recipe:invalid")
        recipe_record = {}

    target_hashes: list[str] = []
    target_paths: set[Path] = set()
    artifacts = record.get("targetArtifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("targetArtifacts")
        artifacts = []
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            errors.append(f"targetArtifacts[{index}]")
            continue
        try:
            path = safe_campaign_path(root, artifact.get("path"))
            actual = sha256_file(path)
        except (OSError, ValueError):
            errors.append(f"targetArtifacts[{index}]:missing")
            continue
        if actual != artifact.get("sha256"):
            errors.append(f"targetArtifacts[{index}]:hash-mismatch")
        target_hashes.append(actual)
        target_paths.add(path.resolve())

    recipe_cases = recipe_record.get("cases")
    recipe_by_name = {
        str(case.get("name")): case
        for case in recipe_cases
        if isinstance(case, dict) and case.get("name")
    } if isinstance(recipe_cases, list) else {}
    cases = record.get("cases")
    if not isinstance(cases, dict) or set(cases) != SAFE_CASES:
        errors.append("cases:baseline-negative-positive-exact")
        cases = {}
    all_pids: list[int] = []
    assertion_index: dict[str, dict[str, list[dict[str, Any]]]] = {}
    challenge_hashes: set[str] = set()
    for case_name in sorted(SAFE_CASES):
        runs = cases.get(case_name)
        recipe_case = recipe_by_name.get(case_name, {})
        recipe_assertions = recipe_case.get("assertions")
        assertions_by_id = {
            str(item.get("id")): item
            for item in recipe_assertions
            if isinstance(item, dict) and item.get("id")
        } if isinstance(recipe_assertions, list) else {}
        if not isinstance(runs, list) or not runs:
            errors.append(f"cases.{case_name}:runs")
            continue
        assertion_index[case_name] = {}
        for run_index, run in enumerate(runs):
            prefix = f"cases.{case_name}[{run_index}]"
            if not isinstance(run, dict):
                errors.append(prefix)
                continue
            pid = run.get("pid")
            if not isinstance(pid, int) or pid <= 0:
                errors.append(prefix + ":pid")
                continue
            all_pids.append(pid)
            command = run.get("command")
            cwd_value = run.get("cwd")
            invoked_targets: set[Path] = set()
            if isinstance(command, list) and isinstance(cwd_value, str):
                try:
                    cwd_path = safe_campaign_path(root, cwd_value)
                    for argument in command:
                        if not isinstance(argument, str):
                            continue
                        candidate = Path(argument)
                        if candidate.is_absolute():
                            resolved = candidate.resolve()
                        elif "/" in argument or "\\" in argument:
                            resolved = (cwd_path / candidate).resolve()
                        else:
                            continue
                        if resolved in target_paths:
                            invoked_targets.add(resolved)
                except ValueError:
                    pass
            if not invoked_targets:
                errors.append(prefix + ":command-does-not-invoke-target-artifact")
            challenge_hex = str(run.get("challengeHex") or "").lower()
            if not re.fullmatch(r"[0-9a-f]{16,128}", challenge_hex):
                errors.append(prefix + ":challenge")
            else:
                challenge_hashes.add(sha256_bytes(bytes.fromhex(challenge_hex)))
            raw = run.get("raw") if isinstance(run.get("raw"), dict) else {}
            try:
                stdout_path = safe_campaign_path(root, raw.get("stdoutPath"))
                stderr_path = safe_campaign_path(root, raw.get("stderrPath"))
                stdout = stdout_path.read_bytes()
                stderr = stderr_path.read_bytes()
            except (OSError, ValueError):
                errors.append(prefix + ":raw-output")
                continue
            if sha256_bytes(stdout) != raw.get("stdoutSha256"):
                errors.append(prefix + ":stdout-hash")
            if sha256_bytes(stderr) != raw.get("stderrSha256"):
                errors.append(prefix + ":stderr-hash")
            recorded_assertions = run.get("assertions")
            recorded_by_id = {
                str(item.get("id")): item
                for item in recorded_assertions
                if isinstance(item, dict) and item.get("id")
            } if isinstance(recorded_assertions, list) else {}
            if set(recorded_by_id) != set(assertions_by_id):
                errors.append(prefix + ":assertion-set")
            for assertion_id, assertion in assertions_by_id.items():
                matched, observed = evaluate_assertion(
                    assertion,
                    return_code=run.get("returnCode"),
                    process_id=pid,
                    challenge_hex=challenge_hex,
                    stdout=stdout,
                    stderr=stderr,
                )
                retained = recorded_by_id.get(assertion_id, {})
                if retained.get("matched") is not matched or retained.get("observed") != observed:
                    errors.append(prefix + f":assertion-recompute:{assertion_id}")
                if not matched:
                    errors.append(prefix + f":assertion-failed:{assertion_id}")
                assertion_index[case_name].setdefault(assertion_id, []).append(
                    {
                        "matched": matched,
                        "observed": observed,
                        "pid": pid,
                        "kind": str(assertion.get("kind") or ""),
                        "challengeBound": str(assertion.get("kind") or "")
                        in CHALLENGE_BOUND_ASSERTIONS,
                    }
                )
    if len(all_pids) != len(set(all_pids)):
        errors.append("processes:not-fresh-distinct-pids")
    return {
        "passed": not errors,
        "errors": list(dict.fromkeys(errors)),
        "record": record,
        "assertions": assertion_index,
        "targetHashes": sorted(target_hashes),
        "challengeHashes": sorted(challenge_hashes),
        "processIds": all_pids,
        "attestationSha256": sha256_file(attestation_path),
    }


def evidence_reference(
    root: Path,
    reference: Any,
    *,
    expected_finding_id: str,
) -> tuple[bool, list[str], dict[str, Any]]:
    if not isinstance(reference, dict):
        return False, ["reference:not-object"], {}
    path_value = reference.get("attestation")
    try:
        path = safe_campaign_path(root, path_value)
    except ValueError as error:
        return False, [f"reference:path:{error}"], {}
    result = validate_attestation(root, path, expected_finding_id=expected_finding_id)
    errors = list(result["errors"])
    if reference.get("sha256") != result.get("attestationSha256"):
        errors.append("reference:attestation-hash")
    case = str(reference.get("case") or "")
    assertion_id = str(reference.get("assertionId") or "")
    observations = result.get("assertions", {}).get(case, {}).get(assertion_id, [])
    if not observations or not all(item.get("matched") is True for item in observations):
        errors.append("reference:matched-assertion")
    return not errors, errors, {
        "attestation": str(path_value),
        "case": case,
        "assertionId": assertion_id,
        "observations": len(observations),
        "assertionKind": observations[0].get("kind") if observations else None,
        "challengeBound": bool(
            observations and all(item.get("challengeBound") is True for item in observations)
        ),
    }
