#!/usr/bin/env python3
"""Derive and execute Next.js authorization-to-route semantic experiments."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from experiment_control import (
    atomic_json,
    ensure_authority,
    sha256_file,
    sign_file,
    verify_signed_record,
)


PRODUCER = "krineon-nextjs-route-semantics"
MAX_BODY = 2 * 1024 * 1024


def read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError(f"expected JSON object: {path}")
    return value


def campaign_root(value: str) -> Path:
    root = Path(value).expanduser().resolve()
    campaign = read_object(root / "campaign.json")
    authorization = campaign.get("authorization")
    if not isinstance(authorization, dict) or authorization.get("confirmed") is not True:
        raise RuntimeError("semantic experiments require confirmed campaign authorization")
    return root


def retain_authority(root: Path) -> dict[str, str]:
    authority = ensure_authority(root)
    campaign_path = root / "campaign.json"
    campaign = read_object(campaign_path)
    campaign["experimentAuthority"] = {
        key: authority[key]
        for key in ("algorithm", "publicKey", "publicKeySha256")
    }
    atomic_json(campaign_path, campaign)
    return authority


def mutations(path: str) -> list[dict[str, str]]:
    path = path if path.startswith("/") else "/" + path
    values: list[dict[str, str]] = []

    def add(family: str, candidate: str) -> None:
        if candidate != path and candidate not in {row["path"] for row in values}:
            values.append({"family": family, "path": candidate})

    add("trailing-slash", path.rstrip("/") + "/")
    segments = path.split("/")
    first = next((index for index, value in enumerate(segments) if value), None)
    if first is not None:
        casefolded = list(segments)
        casefolded[first] = casefolded[first].swapcase()
        add("case-fold", "/".join(casefolded))
        encoded = list(segments)
        token = encoded[first]
        if token:
            encoded[first] = "%" + format(ord(token[0]), "02x") + token[1:]
            add("percent-unreserved", "/".join(encoded))
        dotted = list(segments)
        dotted.insert(first, ".")
        add("dot-segment", "/".join(dotted))
    add("duplicate-slash", path.replace("/", "//", 1))
    return values


def derive_models(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    if analysis.get("producer") != "krineon-framework-analysis":
        raise RuntimeError("input is not a Krineon framework analysis record")
    if analysis.get("framework") != "nextjs":
        raise RuntimeError("the first semantic pilot supports only Next.js")
    facts = {str(row.get("id")): row for row in analysis.get("facts", []) if isinstance(row, dict)}
    models: list[dict[str, Any]] = []
    for relation in analysis.get("relations", []):
        if not isinstance(relation, dict) or relation.get("kind") != "middleware-route":
            continue
        auth_facts = [
            *relation.get("handlerAuthSignals", []),
            *relation.get("middlewareAuthSignals", []),
        ]
        matched = relation.get("matchedMiddleware", [])
        if not auth_facts and not matched:
            continue
        route = str(relation.get("concretePath") or relation.get("route") or "/")
        evidence = [str(relation.get("routeFact") or ""), *map(str, auth_facts), *map(str, matched)]
        identity = hashlib.sha256(
            json.dumps([route, sorted(set(evidence))], separators=(",", ":")).encode()
        ).hexdigest()[:20]
        models.append(
            {
                "id": f"SH-{identity}",
                "state": "proposed",
                "ecosystem": "nextjs",
                "boundary": "authorization-to-route-execution",
                "route": route,
                "attackerControlledValues": [
                    {"name": "request.method", "value": "GET", "ingress": "unauthenticated HTTP"},
                    {"name": "request.path", "value": route, "ingress": "unauthenticated HTTP"},
                    {"name": "request.headers", "value": "unauthenticated control", "ingress": "unauthenticated HTTP"},
                ],
                "operations": [
                    {
                        "component": "Proxy or Middleware matcher",
                        "operation": "classify the raw request path and apply the authorization decision",
                        "evidenceFacts": sorted(set(map(str, [*matched, *auth_facts]))),
                    },
                    {
                        "component": "production route resolver",
                        "operation": "normalize the request and select the emitted route artifact",
                        "evidenceFacts": [str(relation.get("routeFact") or "")],
                    },
                ],
                "checks": [
                    {
                        "check": facts.get(str(value), {}).get("callee", "middleware matcher"),
                        "dominates": "authorization decision only; execution dominance must be measured",
                        "evidenceFact": str(value),
                    }
                    for value in sorted(set([*auth_facts, *matched]))
                ],
                "interpretations": [
                    {"consumer": "authorization", "value": "raw or matcher-normalized pathname"},
                    {"consumer": "execution", "value": "framework-normalized route identity"},
                ],
                "stateOwnership": {
                    "owner": "request pipeline",
                    "mutableRepresentations": ["raw URL", "parsed pathname", "locale/base-path normalized pathname"],
                    "lifetimeQuestion": "whether authorization and execution consume the same representation before it changes",
                },
                "competingExplanations": [
                    {"id": "E-agree", "claim": "authorization and execution resolve the same route"},
                    {"id": "E-normalization", "claim": "one representation bypasses authorization but executes the protected route"},
                    {"id": "E-alias", "claim": "a successful variant executes a different public route"},
                    {"id": "E-unprotected", "claim": "the baseline route is not protected at runtime"},
                ],
                "oracle": {
                    "kind": "authorization-execution-resource-agreement",
                    "promise": "an unauthenticated representation must not execute the authenticated control's route identity when the baseline is blocked",
                },
                "experiment": {
                    "baseline": {"method": "GET", "path": route, "authenticated": False},
                    "authenticatedControl": {"method": "GET", "path": route, "authenticated": True},
                    "variants": mutations(route),
                    "cost": {"requests": 2 + len(mutations(route)), "priority": "cheapest-one-dimension-first"},
                },
                "evidenceFacts": sorted(set(value for value in evidence if value)),
                "revision": 0,
                "eliminatedMechanisms": [],
            }
        )
    return models


def cmd_derive(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    analysis_path = Path(args.analysis).expanduser().resolve()
    analysis = read_object(analysis_path)
    models = derive_models(analysis)
    output = Path(args.output).expanduser().resolve()
    record = {
        "schemaVersion": 1,
        "producer": PRODUCER,
        "kind": "experiment-proposal",
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "analysis": {"path": str(analysis_path), "sha256": sha256_file(analysis_path)},
        "models": models,
        "vulnerabilityVerdictsProduced": False,
    }
    atomic_json(output, record)
    print(json.dumps({"proposal": str(output), "hypotheses": len(models)}, indent=2))
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    proposal = Path(args.proposal).expanduser().resolve()
    record = read_object(proposal)
    if record.get("producer") != PRODUCER or record.get("kind") != "experiment-proposal":
        raise RuntimeError("not a semantic experiment proposal")
    authority = retain_authority(root)
    signature = proposal.with_suffix(proposal.suffix + ".sig")
    sign_file(Path(authority["privateKey"]), proposal, signature)
    print(json.dumps({"proposal": str(proposal), "sha256": sha256_file(proposal), "signature": str(signature), "signatureSha256": sha256_file(signature)}, indent=2))
    return 0


def parse_auth_header(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise RuntimeError("authenticated header environment value must be 'Name: value'")
    name, header_value = value.split(":", 1)
    if not re.fullmatch(r"[A-Za-z0-9-]+", name.strip()) or not header_value.strip():
        raise RuntimeError("authenticated header is invalid")
    return name.strip(), header_value.strip()


def request(base: str, path: str, header: tuple[str, str] | None, timeout: float) -> dict[str, Any]:
    parsed = urlsplit(base)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}:
        raise RuntimeError("semantic HTTP execution is restricted to an owned loopback HTTP target")
    connection_class = http.client.HTTPConnection
    connection = connection_class(parsed.hostname, parsed.port or 80, timeout=timeout)
    headers = {header[0]: header[1]} if header else {}
    started = time.monotonic()
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    body = response.read(MAX_BODY + 1)
    elapsed = time.monotonic() - started
    response_headers = {name.lower(): value for name, value in response.getheaders()}
    connection.close()
    truncated = len(body) > MAX_BODY
    body = body[:MAX_BODY]
    page = None
    match = re.search(rb'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>', body, re.S)
    if match:
        try:
            data = json.loads(match.group(1).decode("utf-8", "replace"))
            page = data.get("page") if isinstance(data, dict) else None
        except json.JSONDecodeError:
            page = None
    route_identity = (
        response_headers.get("x-nextjs-matched-path")
        or response_headers.get("x-matched-path")
        or (str(page) if page else None)
        or "body-sha256:" + hashlib.sha256(body).hexdigest()
    )
    location = response_headers.get("location", "")
    blocked = response.status in {401, 403} or (
        300 <= response.status < 400
        and any(token in location.lower() for token in ("login", "signin", "auth"))
    )
    return {
        "path": path,
        "status": response.status,
        "location": location,
        "bodySha256": hashlib.sha256(body).hexdigest(),
        "bodyBytes": len(body),
        "bodyTruncated": truncated,
        "routeIdentity": route_identity,
        "blocked": blocked,
        "elapsedSeconds": elapsed,
    }


def evaluate(model: dict[str, Any], baseline: dict[str, Any], authenticated: dict[str, Any], variants: list[dict[str, Any]]) -> dict[str, Any]:
    eliminated: list[dict[str, str]] = []
    violations: list[dict[str, Any]] = []
    if not baseline["blocked"]:
        eliminated.append({"mechanism": "protected-route-bypass", "reason": "unauthenticated baseline was not blocked"})
        verdict = "inconclusive-unprotected-baseline"
    elif authenticated["blocked"] or not 200 <= authenticated["status"] < 300:
        eliminated.append({"mechanism": "authenticated-route-control", "reason": "owned authenticated control did not reach the route"})
        verdict = "inconclusive-auth-control"
    else:
        for variant in variants:
            observation = variant["observation"]
            if observation["blocked"]:
                eliminated.append({"mechanism": variant["family"], "reason": "authorization blocked the mutated representation"})
            elif observation["routeIdentity"] != authenticated["routeIdentity"]:
                eliminated.append({"mechanism": variant["family"], "reason": "the representation selected a different route identity"})
            elif 200 <= observation["status"] < 300:
                violations.append(variant)
        verdict = "oracle-violated" if violations else "no-violation-in-tested-families"
    return {
        "hypothesisId": model["id"],
        "oracle": model["oracle"],
        "verdict": verdict,
        "violations": violations,
        "eliminatedMechanisms": eliminated,
        "informationGain": len(eliminated) + len(violations),
        "nextExperiment": (
            "minimize and independently replay the first violating representation"
            if violations
            else "derive a new representation family from the exact normalization steps; do not retry eliminated families"
        ),
    }


def cmd_run(args: argparse.Namespace) -> int:
    root = campaign_root(args.campaign_dir)
    proposal = Path(args.proposal).expanduser().resolve()
    signature = Path(args.signature).expanduser().resolve()
    signed, errors, record = verify_signed_record(
        root, proposal, signature, producer=PRODUCER
    )
    if not signed:
        raise RuntimeError("proposal approval is invalid: " + ", ".join(errors))
    auth_value = os.environ.get(args.auth_header_env, "")
    auth_header = parse_auth_header(auth_value)
    selected = [model for model in record.get("models", []) if isinstance(model, dict) and (not args.hypothesis or model.get("id") == args.hypothesis)]
    if not selected:
        raise RuntimeError("no matching semantic hypothesis")
    started = time.monotonic()
    results: list[dict[str, Any]] = []
    for model in selected:
        baseline = request(args.base_url, model["experiment"]["baseline"]["path"], None, args.timeout)
        authenticated = request(args.base_url, model["experiment"]["authenticatedControl"]["path"], auth_header, args.timeout)
        variants = [
            {**variant, "observation": request(args.base_url, variant["path"], None, args.timeout)}
            for variant in model["experiment"]["variants"]
        ]
        results.append({
            "model": model,
            "baseline": baseline,
            "authenticatedControl": authenticated,
            "authenticatedHeaderSha256": hashlib.sha256(auth_value.encode()).hexdigest(),
            "variants": variants,
            "evaluation": evaluate(model, baseline, authenticated, variants),
        })
    output = Path(args.output).expanduser().resolve()
    observation = {
        "schemaVersion": 1,
        "producer": "krineon-semantic-observation",
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat(),
        "proposal": {"path": str(proposal), "sha256": sha256_file(proposal), "signatureSha256": sha256_file(signature)},
        "baseUrl": args.base_url,
        "results": results,
        "cost": {"wallSeconds": time.monotonic() - started, "requests": sum(2 + len(row["variants"]) for row in results)},
    }
    atomic_json(output, observation)
    authority = retain_authority(root)
    output_signature = output.with_suffix(output.suffix + ".sig")
    sign_file(Path(authority["privateKey"]), output, output_signature)
    print(json.dumps({"observation": str(output), "sha256": sha256_file(output), "signature": str(output_signature), "oracleViolations": sum(len(row["evaluation"]["violations"]) for row in results)}, indent=2))
    return 0


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    sub = value.add_subparsers(dest="command", required=True)
    derive = sub.add_parser("derive")
    derive.add_argument("campaign_dir")
    derive.add_argument("--analysis", required=True)
    derive.add_argument("--output", required=True)
    derive.set_defaults(func=cmd_derive)
    approve = sub.add_parser("approve")
    approve.add_argument("campaign_dir")
    approve.add_argument("--proposal", required=True)
    approve.set_defaults(func=cmd_approve)
    run = sub.add_parser("run")
    run.add_argument("campaign_dir")
    run.add_argument("--proposal", required=True)
    run.add_argument("--signature", required=True)
    run.add_argument("--base-url", required=True)
    run.add_argument("--auth-header-env", default="KRINEON_AUTH_HEADER")
    run.add_argument("--hypothesis")
    run.add_argument("--timeout", type=float, default=10.0)
    run.add_argument("--output", required=True)
    run.set_defaults(func=cmd_run)
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if getattr(args, "timeout", 1) <= 0 or getattr(args, "timeout", 1) > 60:
        raise SystemExit("--timeout must be greater than 0 and at most 60 seconds")
    try:
        return int(args.func(args))
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
