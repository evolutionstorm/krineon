#!/usr/bin/env python3
"""Find evidence-bound runtime fingerprint disagreements without making verdicts.

The engine is offline. It compares observations that already exist in a
campaign, validates every evidence digest, and emits planning-only experiments.
It never probes a target or maps a version string to a known vulnerability.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


KIND = "krineon-fingerprint-observation-set"
OUTPUT_KIND = "krineon-fingerprint-disagreement-analysis"
OBSERVER_KINDS = {"tool", "browser", "http", "artifact", "runtime", "source"}
SCOPE_FIELDS = (
    "origin",
    "hostname",
    "port",
    "route",
    "method",
    "actor",
    "session",
    "backend",
    "deploymentEpoch",
)
SPLIT_FIELDS = ("origin", "hostname", "port", "route", "method", "actor", "session", "backend")
SECRET_PATTERNS = (
    re.compile(r"(?i)authorization\s*:\s*bearer\s+\S+"),
    re.compile(r"(?i)(?:cookie|set-cookie)\s*:\s*[^\s]{8,}"),
    re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|refresh[_-]?token)\s*[:=]\s*\S+"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


class FingerprintError(ValueError):
    """The observation contract is invalid or its evidence is not trustworthy."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest_object(value: Any) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def require_text(value: Any, field: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FingerprintError(f"{field} must be a non-empty string")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise FingerprintError(f"{field} exceeds {maximum} characters")
    return normalized


def safe_evidence_path(root: Path, value: Any) -> Path:
    raw = require_text(value, "evidence.path", maximum=1024)
    candidate = Path(raw)
    if candidate.is_absolute():
        raise FingerprintError("evidence paths must be campaign-relative")
    resolved_root = root.resolve()
    unresolved = resolved_root / candidate
    current = resolved_root
    for part in candidate.parts:
        current /= part
        if current.is_symlink():
            raise FingerprintError(f"evidence path must not traverse a symlink: {raw}")
    resolved = unresolved.resolve()
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise FingerprintError(f"evidence path escapes campaign root: {raw}")
    if not resolved.is_file():
        raise FingerprintError(f"evidence path is not a regular campaign file: {raw}")
    return resolved


def normalize_value(value: Any, field: str) -> dict[str, Any]:
    if isinstance(value, bool):
        normalized: Any = value
    elif isinstance(value, int) and not isinstance(value, bool):
        normalized = value
    elif isinstance(value, str):
        normalized = require_text(value, field, maximum=512)
        if any(pattern.search(normalized) for pattern in SECRET_PATTERNS):
            raise FingerprintError(f"{field} appears to contain a credential or secret")
    else:
        raise FingerprintError(f"{field} must be a string, integer, or boolean fingerprint")
    return {"value": normalized, "canonical": canonical_json(normalized)}


def normalize_scope(raw: Any, inherited_epoch: str, field: str) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise FingerprintError(f"{field} must be an object")
    result: dict[str, str] = {}
    for name in SCOPE_FIELDS:
        value = raw.get(name)
        if name == "deploymentEpoch" and not value:
            value = inherited_epoch
        if value is None:
            value = ""
        if not isinstance(value, (str, int)):
            raise FingerprintError(f"{field}.{name} must be a string or integer")
        result[name] = str(value).strip()
    if not result["origin"]:
        raise FingerprintError(f"{field}.origin is required")
    if not result["deploymentEpoch"]:
        raise FingerprintError(f"{field}.deploymentEpoch is required")
    result["method"] = result["method"].upper()
    return result


def normalize_evidence(root: Path, raw: Any, field: str) -> list[dict[str, str]]:
    if not isinstance(raw, list) or not raw:
        raise FingerprintError(f"{field} must contain at least one evidence reference")
    retained: list[dict[str, str]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise FingerprintError(f"{field}[{index}] must be an object")
        path = safe_evidence_path(root, item.get("path"))
        expected = require_text(item.get("sha256"), f"{field}[{index}].sha256", maximum=64)
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise FingerprintError(f"{field}[{index}].sha256 must be lowercase SHA-256")
        observed = sha256_file(path)
        if observed != expected:
            raise FingerprintError(f"evidence digest mismatch: {path.relative_to(root.resolve())}")
        retained.append(
            {
                "path": path.relative_to(root.resolve()).as_posix(),
                "sha256": observed,
                "selector": require_text(
                    item.get("selector"), f"{field}[{index}].selector", maximum=512
                ),
            }
        )
    return retained


def parse_time(value: Any, field: str) -> str:
    text = require_text(value, field, maximum=64)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise FingerprintError(f"{field} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise FingerprintError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_file(root: Path, path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not path.is_file():
        raise FingerprintError(f"observation input does not exist: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or raw.get("kind") != KIND or raw.get("schemaVersion") != 1:
        raise FingerprintError(f"not a schemaVersion 1 {KIND}: {path}")
    target = raw.get("target")
    if not isinstance(target, dict):
        raise FingerprintError(f"target must be an object: {path}")
    target_id = require_text(target.get("id"), "target.id")
    epoch = require_text(target.get("deploymentEpoch"), "target.deploymentEpoch")
    observations = raw.get("observations")
    if not isinstance(observations, list) or not observations:
        raise FingerprintError(f"observations must be a non-empty list: {path}")
    source = {
        "path": path.resolve().as_posix(),
        "sha256": sha256_file(path),
        "targetId": target_id,
        "deploymentEpoch": epoch,
    }
    normalized: list[dict[str, Any]] = []
    for observation_index, observation in enumerate(observations):
        field = f"observations[{observation_index}]"
        if not isinstance(observation, dict):
            raise FingerprintError(f"{field} must be an object")
        observation_id = require_text(observation.get("id"), f"{field}.id")
        observer = observation.get("observer")
        if not isinstance(observer, dict):
            raise FingerprintError(f"{field}.observer must be an object")
        observer_kind = require_text(observer.get("kind"), f"{field}.observer.kind").lower()
        if observer_kind not in OBSERVER_KINDS:
            raise FingerprintError(f"{field}.observer.kind is unsupported: {observer_kind}")
        observer_id = require_text(observer.get("id"), f"{field}.observer.id")
        observer_family = require_text(observer.get("family"), f"{field}.observer.family")
        scope = normalize_scope(observation.get("scope"), epoch, f"{field}.scope")
        evidence = normalize_evidence(root, observation.get("evidence"), f"{field}.evidence")
        observed_at = parse_time(observation.get("observedAt"), f"{field}.observedAt")
        signals = observation.get("signals")
        if not isinstance(signals, list) or not signals:
            raise FingerprintError(f"{field}.signals must be a non-empty list")
        for signal_index, signal in enumerate(signals):
            signal_field = f"{field}.signals[{signal_index}]"
            if not isinstance(signal, dict):
                raise FingerprintError(f"{signal_field} must be an object")
            signal_id = require_text(signal.get("id"), f"{signal_field}.id")
            value = normalize_value(signal.get("value"), f"{signal_field}.value")
            normalized.append(
                {
                    "id": f"{observation_id}:{signal_id}",
                    "observationId": observation_id,
                    "signalId": signal_id,
                    "targetId": target_id,
                    "component": require_text(signal.get("component"), f"{signal_field}.component"),
                    "property": require_text(signal.get("property"), f"{signal_field}.property"),
                    "value": value["value"],
                    "canonicalValue": value["canonical"],
                    "observer": {
                        "id": observer_id,
                        "family": observer_family,
                        "kind": observer_kind,
                    },
                    "scope": scope,
                    "observedAt": observed_at,
                    "evidence": evidence,
                    "sourceInput": source,
                }
            )
    return source, normalized


def scope_tuple(scope: dict[str, str]) -> tuple[str, ...]:
    return tuple(scope[field] for field in SCOPE_FIELDS)


def subject_tuple(signal: dict[str, Any]) -> tuple[str, str, str]:
    return signal["targetId"], signal["component"], signal["property"]


def value_groups(signals: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for signal in signals:
        grouped[signal["canonicalValue"]].append(signal)
    result: list[dict[str, Any]] = []
    for canonical, members in sorted(grouped.items()):
        result.append(
            {
                "canonicalValue": canonical,
                "value": members[0]["value"],
                "signalIds": sorted(member["id"] for member in members),
                "observerFamilies": sorted({member["observer"]["family"] for member in members}),
                "evidence": sorted(
                    {
                        (item["path"], item["sha256"], item["selector"])
                        for member in members
                        for item in member["evidence"]
                    }
                ),
            }
        )
    return result


def disagreement_id(kind: str, material: Any) -> str:
    return f"fp-{kind}-{digest_object(material)[:16]}"


def direct_disagreements(signals: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for signal in signals:
        groups[(*subject_tuple(signal), *scope_tuple(signal["scope"]))].append(signal)
    disagreements: list[dict[str, Any]] = []
    agreements: list[dict[str, Any]] = []
    for _, members in sorted(groups.items(), key=lambda item: canonical_json(item[0])):
        values = value_groups(members)
        families = sorted({member["observer"]["family"] for member in members})
        base = members[0]
        material = {
            "subject": subject_tuple(base),
            "scope": base["scope"],
            "values": [value["canonicalValue"] for value in values],
        }
        if len(values) > 1:
            classification = "observer-conflict" if len(families) > 1 else "same-scope-instability"
            identifier = disagreement_id(classification, material)
            disagreements.append(
                {
                    "id": identifier,
                    "classification": classification,
                    "subject": {
                        "targetId": base["targetId"],
                        "component": base["component"],
                        "property": base["property"],
                    },
                    "scope": base["scope"],
                    "values": values,
                    "independentObserverFamilies": families,
                    "confidence": "source-hypothesis",
                    "promotionEligible": False,
                    "competingExplanations": [
                        "observers interpret the same retained response or artifact differently",
                        "the target varies within a scope dimension that was not measured",
                        "the deployment changed inside the claimed observation epoch",
                    ],
                    "nextExperiment": {
                        "objective": "repeat the same exact scope through independent observers and bind each result to one content hash",
                        "changedVariables": [],
                        "requiredControls": [
                            "same retained bytes parsed by every observer",
                            "fresh collection with one deployment epoch",
                            "raw content hash and backend markers retained",
                        ],
                    },
                }
            )
        elif len(families) > 1:
            agreements.append(
                {
                    "subject": {
                        "targetId": base["targetId"],
                        "component": base["component"],
                        "property": base["property"],
                    },
                    "scope": base["scope"],
                    "value": values[0]["value"],
                    "independentObserverFamilies": families,
                }
            )
    return disagreements, agreements


def scope_splits(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    subjects: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for signal in signals:
        subjects[
            (
                *subject_tuple(signal),
                signal["scope"]["deploymentEpoch"],
            )
        ].append(signal)
    retained: dict[str, dict[str, Any]] = {}
    for members in subjects.values():
        ordered = sorted(members, key=lambda value: value["id"])
        for left_index, left in enumerate(ordered):
            for right in ordered[left_index + 1 :]:
                if left["canonicalValue"] == right["canonicalValue"]:
                    continue
                differences = [
                    field
                    for field in SPLIT_FIELDS
                    if left["scope"][field] != right["scope"][field]
                ]
                if len(differences) != 1:
                    continue
                dimension = differences[0]
                constant_scope = {
                    field: left["scope"][field]
                    for field in SCOPE_FIELDS
                    if field != dimension
                }
                material = {
                    "subject": subject_tuple(left),
                    "dimension": dimension,
                    "constantScope": constant_scope,
                    "variants": sorted(
                        [
                            (left["scope"][dimension], left["canonicalValue"]),
                            (right["scope"][dimension], right["canonicalValue"]),
                        ]
                    ),
                }
                identifier = disagreement_id("scope-split", material)
                variants = sorted(
                    [
                        {
                            "scopeValue": left["scope"][dimension],
                            "value": left["value"],
                            "signalId": left["id"],
                            "observerFamily": left["observer"]["family"],
                            "evidence": left["evidence"],
                        },
                        {
                            "scopeValue": right["scope"][dimension],
                            "value": right["value"],
                            "signalId": right["id"],
                            "observerFamily": right["observer"]["family"],
                            "evidence": right["evidence"],
                        },
                    ],
                    key=lambda value: (value["scopeValue"], canonical_json(value["value"])),
                )
                retained[identifier] = {
                    "id": identifier,
                    "classification": "scope-split",
                    "subject": {
                        "targetId": left["targetId"],
                        "component": left["component"],
                        "property": left["property"],
                    },
                    "differingDimension": dimension,
                    "constantScope": constant_scope,
                    "variants": variants,
                    "confidence": "source-hypothesis",
                    "promotionEligible": False,
                    "securityQuestions": [
                        "do authorization, normalization, cache, or parser semantics also differ across these cohorts",
                        "can one attacker select the weaker cohort while preserving the protected operation",
                    ],
                    "competingExplanations": [
                        f"the {dimension} dimension selects a different production consumer or backend cohort",
                        f"the {dimension} difference is an intended representation or policy distinction",
                        "the retained observations straddle unrecorded deployment drift",
                    ],
                    "nextExperiment": {
                        "objective": f"replay one bounded pair that changes only {dimension} and compare a security-relevant invariant",
                        "changedVariables": [dimension],
                        "requiredControls": [
                            "same deployment epoch and target artifact",
                            "equal actor authority unless actor is the named variable",
                            "content and backend identity recorded independently",
                            "no known-vulnerability lookup used as the oracle",
                        ],
                    },
                }
    return [retained[key] for key in sorted(retained)]


def analyze(campaign_root: Path, inputs: list[Path]) -> dict[str, Any]:
    root = campaign_root.resolve()
    if not root.is_dir():
        raise FingerprintError(f"campaign root does not exist: {campaign_root}")
    sources: list[dict[str, Any]] = []
    signals: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in inputs:
        source, normalized = normalize_file(root, path.resolve())
        sources.append(source)
        for signal in normalized:
            if signal["id"] in seen:
                raise FingerprintError(f"duplicate fingerprint signal id: {signal['id']}")
            seen.add(signal["id"])
            signals.append(signal)
    direct, agreements = direct_disagreements(signals)
    splits = scope_splits(signals)
    disagreements = sorted([*direct, *splits], key=lambda value: value["id"])
    candidates = [
        {
            "id": f"experiment-{item['id']}",
            "state": "planning-only",
            "mechanism": "runtime-fingerprint-disagreement",
            "disagreementId": item["id"],
            "objective": item["nextExperiment"]["objective"],
            "promotionEligible": False,
        }
        for item in disagreements
    ]
    return {
        "schemaVersion": 1,
        "kind": OUTPUT_KIND,
        "generatedAt": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "inputs": sorted(sources, key=lambda value: value["path"]),
        "signalCount": len(signals),
        "disagreementCount": len(disagreements),
        "agreementCount": len(agreements),
        "disagreements": disagreements,
        "agreements": agreements,
        "plannerCandidates": candidates,
        "policy": {
            "networkTraffic": False,
            "knownVulnerabilityLookup": False,
            "vulnerabilityVerdicts": False,
            "promotionRequiresIndependentExperiment": True,
        },
    }


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--input", action="append", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = analyze(args.campaign_root, list(args.input))
    except (FingerprintError, json.JSONDecodeError, OSError) as error:
        parser.error(str(error))
    atomic_json(args.output, result)
    print(
        f"retained {result['disagreementCount']} fingerprint disagreement(s); "
        f"planning candidates: {len(result['plannerCandidates'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
