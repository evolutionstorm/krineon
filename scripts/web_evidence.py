#!/usr/bin/env python3
"""Validate deployment-bound web evidence without inventing source provenance."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    from .web_contract import WebContractError, atomic_json
except ImportError:
    from web_contract import WebContractError, atomic_json


PROVENANCE_MODES = {"blackbox", "source-supplied", "source-verified"}


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


def text_list(value: Any, field: str, *, empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not empty and not value):
        raise WebContractError(f"{field} must be a{' possibly empty' if empty else ' non-empty'} list")
    return [text(item, f"{field}[]") for item in value]


def timestamp(value: Any, field: str) -> str:
    raw = text(value, field)
    try:
        parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise WebContractError(f"{field} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise WebContractError(f"{field} must include a timezone")
    return parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def sha(value: Any, field: str) -> str:
    digest = text(value, field).lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise WebContractError(f"{field} must be a SHA-256 digest")
    return digest


def validate_evidence(raw: dict[str, Any]) -> dict[str, Any]:
    if raw.get("schemaVersion") != 1 or raw.get("kind") != "krineon-web-evidence":
        raise WebContractError("input is not Krineon web evidence")
    finding_id = text(raw.get("findingId"), "findingId")
    experiment_id = text(raw.get("experimentId"), "experimentId")
    target = raw.get("target")
    if not isinstance(target, dict):
        raise WebContractError("target must be an object")
    urls = text_list(target.get("scopedUrls"), "target.scopedUrls")
    for index, url in enumerate(urls):
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise WebContractError(f"target.scopedUrls[{index}] is not an exact HTTP URL")
        if "*" in url:
            raise WebContractError("target.scopedUrls cannot contain wildcards")
    observed_from = timestamp(target.get("observedFrom"), "target.observedFrom")
    observed_until = timestamp(target.get("observedUntil"), "target.observedUntil")
    if observed_from > observed_until:
        raise WebContractError("target observation timestamps are reversed")
    tls = target.get("tlsObservations")
    if not isinstance(tls, list) or not tls:
        raise WebContractError("target.tlsObservations must be non-empty")
    for index, item in enumerate(tls):
        if not isinstance(item, dict):
            raise WebContractError("TLS observations must be objects")
        text(item.get("host"), f"target.tlsObservations[{index}].host")
        text(item.get("protocol"), f"target.tlsObservations[{index}].protocol")
        sha(item.get("certificateSha256"), f"target.tlsObservations[{index}].certificateSha256")
    markers = target.get("deploymentMarkers")
    if not isinstance(markers, list):
        raise WebContractError("target.deploymentMarkers must be a list")
    for index, marker in enumerate(markers):
        if not isinstance(marker, dict):
            raise WebContractError("deployment markers must be objects")
        text(marker.get("name"), f"deploymentMarkers[{index}].name")
        text(marker.get("value"), f"deploymentMarkers[{index}].value")
        if marker.get("confidence") not in {"response-claim", "observed", "owner-supplied"}:
            raise WebContractError("deployment marker confidence is unsupported")
    text_list(target.get("configurationAssumptions", []), "target.configurationAssumptions", empty=True)
    versions = target.get("clientVersions")
    if not isinstance(versions, dict):
        raise WebContractError("target.clientVersions must be an object")
    text(versions.get("transport"), "target.clientVersions.transport")
    text(versions.get("browser"), "target.clientVersions.browser")

    epoch = raw.get("observationEpoch")
    if not isinstance(epoch, dict):
        raise WebContractError("observationEpoch must be an object")
    epoch_id = text(epoch.get("id"), "observationEpoch.id")
    epoch_start = timestamp(epoch.get("start"), "observationEpoch.start")
    epoch_end = timestamp(epoch.get("end"), "observationEpoch.end")
    if epoch_start > epoch_end:
        raise WebContractError("observation epoch timestamps are reversed")
    prerequisite = text(epoch.get("prerequisiteVersion"), "observationEpoch.prerequisiteVersion")
    baseline = epoch.get("baseline")
    if not isinstance(baseline, dict):
        raise WebContractError("observationEpoch.baseline must be an object")
    baseline_sha = sha(baseline.get("sha256"), "observationEpoch.baseline.sha256")
    text_list(baseline.get("stableComponents"), "observationEpoch.baseline.stableComponents")
    text_list(
        baseline.get("excludedVolatileFields", []),
        "observationEpoch.baseline.excludedVolatileFields",
        empty=True,
    )
    if epoch.get("expired") is not False:
        raise WebContractError("expired observation evidence cannot enter the finding gate")

    identities = raw.get("identities")
    fixtures = raw.get("fixtures")
    scenarios = raw.get("scenarios")
    if not isinstance(identities, list) or not identities:
        raise WebContractError("identities must be non-empty")
    identity_ids: set[str] = set()
    for index, identity in enumerate(identities):
        if not isinstance(identity, dict) or identity.get("owned") is not True:
            raise WebContractError("every evidence identity must be owned")
        identity_id = text(identity.get("id"), f"identities[{index}].id")
        if identity_id in identity_ids:
            raise WebContractError("identity ids must be unique")
        identity_ids.add(identity_id)
        text(identity.get("tenant"), f"identities[{index}].tenant")
        text(identity.get("secretRef"), f"identities[{index}].secretRef")
        text(identity.get("bindingVersion"), f"identities[{index}].bindingVersion")
    if not isinstance(fixtures, list) or not fixtures:
        raise WebContractError("fixtures must be non-empty")
    fixture_ids: set[str] = set()
    for index, fixture in enumerate(fixtures):
        if not isinstance(fixture, dict) or fixture.get("owned") is not True:
            raise WebContractError("every evidence fixture must be owned")
        fixture_id = text(fixture.get("id"), f"fixtures[{index}].id")
        fixture_ids.add(fixture_id)
        text(fixture.get("namespace"), f"fixtures[{index}].namespace")
        sha(fixture.get("creationEvidenceSha256"), f"fixtures[{index}].creationEvidenceSha256")
        if fixture.get("cleanupStatus") not in {"verified", "not-required"}:
            raise WebContractError("fixture cleanup must be verified or not required")
    if not isinstance(scenarios, list) or not scenarios:
        raise WebContractError("scenarios must be non-empty")
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            raise WebContractError("scenarios must be objects")
        text(scenario.get("id"), f"scenarios[{index}].id")
        sha(scenario.get("requestSha256"), f"scenarios[{index}].requestSha256")
        sha(scenario.get("scenarioSha256"), f"scenarios[{index}].scenarioSha256")
        if scenario.get("prerequisiteVersion") != prerequisite:
            raise WebContractError("scenario prerequisiteVersion differs from the observation epoch")
        if not set(text_list(scenario.get("actors"), f"scenarios[{index}].actors")).issubset(identity_ids):
            raise WebContractError("scenario references an unverified identity")
        if not set(text_list(scenario.get("resources"), f"scenarios[{index}].resources")).issubset(fixture_ids):
            raise WebContractError("scenario references an unowned fixture")

    provenance = raw.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("mode") not in PROVENANCE_MODES:
        raise WebContractError("provenance mode is unsupported")
    mode = provenance["mode"]
    source_revision = provenance.get("sourceRevision")
    source_evidence = provenance.get("sourceEvidence", [])
    if mode == "blackbox":
        if source_revision not in {None, ""} or source_evidence not in (None, []):
            raise WebContractError("black-box evidence cannot claim a source pin")
    else:
        text(source_revision, "provenance.sourceRevision")
        text_list(source_evidence, "provenance.sourceEvidence")
    if provenance.get("responseVersionIsSourcePin") is not False:
        raise WebContractError("a response version claim cannot be treated as a source pin")

    tiers = raw.get("artifactTiers")
    if not isinstance(tiers, dict):
        raise WebContractError("artifactTiers must be an object")
    private = tiers.get("private")
    reviewer = tiers.get("reviewer")
    if not isinstance(private, dict) or private.get("restricted") is not True or private.get("encrypted") is not True:
        raise WebContractError("private raw evidence must be encrypted and restricted")
    if not isinstance(reviewer, dict) or reviewer.get("redacted") is not True or reviewer.get("syntheticDataOnly") is not True:
        raise WebContractError("reviewer artifacts must be redacted and synthetic")
    for tier_name, tier in (("private", private), ("reviewer", reviewer)):
        for field in ("retention", "access", "export", "deletion"):
            text(tier.get(field), f"artifactTiers.{tier_name}.{field}")
    if raw.get("unexpectedThirdPartyData") is not False:
        raise WebContractError("unexpected third-party data requires an immediate stop")
    if raw.get("autonomousPublicationAllowed") is not False:
        raise WebContractError("Krineon cannot autonomously publish web evidence")

    return {
        **raw,
        "findingId": finding_id,
        "experimentId": experiment_id,
        "observationEpoch": {
            **epoch,
            "id": epoch_id,
            "start": epoch_start,
            "end": epoch_end,
            "prerequisiteVersion": prerequisite,
            "baseline": {**baseline, "sha256": baseline_sha},
        },
    }


def evaluate_drift(evidence_raw: dict[str, Any], current_raw: dict[str, Any]) -> dict[str, Any]:
    evidence = validate_evidence(evidence_raw)
    if current_raw.get("schemaVersion") != 1 or current_raw.get("kind") != "krineon-web-baseline":
        raise WebContractError("current baseline is not a Krineon web baseline")
    current_sha = sha(current_raw.get("sha256"), "currentBaseline.sha256")
    expected = evidence["observationEpoch"]["baseline"]["sha256"]
    drifted = current_sha != expected
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-drift-verdict",
        "findingId": evidence["findingId"],
        "experimentId": evidence["experimentId"],
        "observationEpoch": evidence["observationEpoch"]["id"],
        "expectedBaselineSha256": expected,
        "currentBaselineSha256": current_sha,
        "outcome": "expired-security-baseline" if drifted else "same-observation-epoch",
        "experimentsExpired": drifted,
        "independentReplayProvesEarlierDeployment": not drifted,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("evidence", type=Path)
    validate.add_argument("--output", type=Path, required=True)
    drift = sub.add_parser("drift")
    drift.add_argument("evidence", type=Path)
    drift.add_argument("baseline", type=Path)
    drift.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = (
            validate_evidence(load_object(args.evidence))
            if args.command == "validate"
            else evaluate_drift(load_object(args.evidence), load_object(args.baseline))
        )
        atomic_json(args.output.expanduser().resolve(), result, mode=0o600)
        print(json.dumps({"accepted": True, "kind": result.get("kind")}, indent=2))
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, WebContractError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
