#!/usr/bin/env python3
"""Derive executable semantic experiments from framework and native analyses."""

from __future__ import annotations

import argparse
import base64
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
            values.append(
                {
                    "family": family,
                    "path": candidate,
                    "origin": "supplemental-dictionary",
                    "sourceFact": "none",
                }
            )

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


def transformation_variants(path: str, callee: str) -> list[tuple[str, str]]:
    """Return only mutations justified by one recognized transformation."""

    path = path if path.startswith("/") else "/" + path
    values: list[tuple[str, str]] = []
    lowered = callee.lower()
    segments = path.split("/")
    first = next((index for index, value in enumerate(segments) if value), None)
    if first is not None and any(
        token in lowered for token in ("tolowercase", "tolower", "locale")
    ):
        candidate = list(segments)
        candidate[first] = candidate[first].swapcase()
        values.append(("case-fold", "/".join(candidate)))
    if first is not None and any(
        token in lowered for token in ("decodeuri", "decodeuricomponent", "unescape")
    ):
        candidate = list(segments)
        token = candidate[first]
        if token:
            candidate[first] = "%" + format(ord(token[0]), "02x") + token[1:]
            values.append(("percent-unreserved", "/".join(candidate)))
    if any(token in lowered for token in ("normalize", "resolve", "canonical")):
        if first is not None:
            candidate = list(segments)
            candidate.insert(first, ".")
            values.append(("dot-segment", "/".join(candidate)))
        values.append(("duplicate-slash", path.replace("/", "//", 1)))
    if any(token in lowered for token in ("trim", "trailingslash")):
        values.append(("trailing-slash", path.rstrip("/") + "/"))
    return [(family, candidate) for family, candidate in values if candidate != path]


def source_derived_mutations(
    path: str, transformation_flows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    path = path if path.startswith("/") else "/" + path
    values: list[dict[str, Any]] = []
    seen: set[tuple[str, str, tuple[str, ...]]] = set()
    for flow in transformation_flows:
        if flow.get("status") != "scope-aware-def-use-candidate-runtime-trace-required":
            continue
        transformations = flow.get("transformations")
        if not isinstance(transformations, list) or not transformations:
            transformations = [
                {
                    "fact": flow.get("transformationFact"),
                    "callee": flow.get("transformationCallee"),
                }
            ]
        frontier = [(path, [])]
        for transformation in transformations:
            fact_id = str(transformation.get("fact") or "")
            callee = str(transformation.get("callee") or "")
            next_frontier: list[tuple[str, list[str]]] = []
            for current, composition in frontier:
                for family, candidate in transformation_variants(current, callee):
                    composed = [*composition, fact_id]
                    key = (family, candidate, tuple(composed))
                    if key in seen:
                        continue
                    seen.add(key)
                    values.append(
                        {
                            "family": family,
                            "path": candidate,
                            "origin": "tentative-source-flow",
                            "sourceFact": fact_id,
                            "sourceFacts": composed,
                            "flowId": str(flow.get("id") or ""),
                            "validatedFact": str(flow.get("validatedFact") or ""),
                            "consumerFact": str(flow.get("consumerFact") or ""),
                            "resultSymbol": str(flow.get("resultSymbol") or ""),
                            "composition": composed,
                        }
                    )
                    next_frontier.append((candidate, composed))
            # If this transformation has no dictionary mapping, retain the
            # existing path so a later, understood transformation can still be
            # exercised, but never call the unknown operation source-derived.
            frontier = next_frontier or frontier
    return values


def unknown_transformation_experiments(
    path: str, transformation_flows: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Turn unfamiliar transformations into value-trace experiments."""

    experiments: list[dict[str, Any]] = []
    for flow in transformation_flows:
        for transformation in flow.get("transformations", []):
            callee = str(transformation.get("callee") or "")
            if transformation_variants(path, callee):
                continue
            experiments.append(
                {
                    "id": "UT-" + hashlib.sha256(
                        json.dumps(
                            [flow.get("id"), transformation.get("fact"), callee],
                            separators=(",", ":"),
                        ).encode()
                    ).hexdigest()[:16],
                    "status": "runtime-value-trace-required",
                    "flowId": str(flow.get("id") or ""),
                    "transformationFact": str(transformation.get("fact") or ""),
                    "callee": callee,
                    "question": "What semantic equivalence classes does this target-specific transformation create?",
                    "tracePlan": {
                        "captureAt": [
                            str(flow.get("validatedFact") or ""),
                            str(transformation.get("fact") or ""),
                            str(flow.get("consumerFact") or ""),
                        ],
                        "values": [
                            "validated input bytes and parsed value",
                            "transformation result bytes and parsed value",
                            "consumer-selected resource identity",
                        ],
                        "discriminator": "two representations pass the check but select different protected resources",
                    },
                }
            )
    return experiments


def derive_workerd_models(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    models: list[dict[str, Any]] = []
    for value in analysis.get("candidates", []):
        if not isinstance(value, dict):
            continue
        candidate_id = str(value.get("id") or "")
        family = str(value.get("family") or "")
        if not candidate_id or not family:
            continue
        models.append(
            {
                "id": "SH-" + hashlib.sha256(candidate_id.encode()).hexdigest()[:20],
                "state": "proposed",
                "ecosystem": "workerd",
                "boundary": family,
                "sourceCandidate": value,
                "attackerControlledValues": [
                    {
                        "name": "owned test input",
                        "value": "candidate-specific JavaScript or request sequence",
                        "ingress": "authorized disposable workerd fixture",
                    }
                ],
                "competingExplanations": [
                    {"id": "E-safe", "claim": "the implementation preserves the ownership or affinity invariant"},
                    {"id": "E-violation", "claim": "the emitted runtime event sequence violates that invariant"},
                    {"id": "E-observer", "claim": "the instrumentation changes or misidentifies the state transition"},
                ],
                "oracle": value.get("oracle"),
                "experiment": {
                    "kind": "instrumented-workerd-lifetime-trace",
                    "instrumentation": value.get("instrumentation", []),
                    "executeWith": "an unchanged production-equivalent workerd target plus a separately reviewed trace patch",
                    "evaluateWith": "scripts/workerd_lifetime_oracle.py",
                    "requiredControls": [
                        "same input without the lifetime-changing transition",
                        "same transition without the stale use or cross-context callback",
                        "independent replay of the raw JSONL trace",
                    ],
                },
                "evidenceFacts": [str(value.get("source") or "")],
                "revision": 0,
                "eliminatedMechanisms": [],
            }
        )
    return models


def derive_models(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    if analysis.get("producer") == "krineon-workerd-lifetime-analysis":
        return derive_workerd_models(analysis)
    if analysis.get("producer") != "krineon-framework-analysis":
        raise RuntimeError("input is not a supported Krineon analysis record")
    if analysis.get("framework") != "nextjs":
        raise RuntimeError("framework semantic HTTP execution currently supports Next.js")
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
        operation_fact_ids = list(map(str, relation.get("operationFacts", [])))
        operation_facts = [facts[value] for value in operation_fact_ids if value in facts]
        transformation_flows = [
            row
            for row in relation.get("transformationFlows", [])
            if isinstance(row, dict)
        ]
        source_variants = source_derived_mutations(route, transformation_flows)
        unknown_experiments = unknown_transformation_experiments(
            route, transformation_flows
        )
        tentative_operation_facts = {
            str(value)
            for flow in transformation_flows
            for value in flow.get("transformationFacts", [flow.get("transformationFact")])
            if value
        }
        transformation_candidates = [
            {
                "sourceFact": str(item.get("id") or ""),
                "callee": str(item.get("callee") or ""),
                "status": "candidate-not-source-derived",
                "reason": "no same-scope assignment-aware candidate flow reaches this call",
            }
            for item in operation_facts
            if str(item.get("id") or "") not in tentative_operation_facts
            and transformation_variants(route, str(item.get("callee") or ""))
        ]
        variants = list(source_variants)
        for variant in mutations(route):
            if variant["path"] not in {row["path"] for row in variants}:
                variants.append(variant)
        evidence = [
            str(relation.get("routeFact") or ""),
            *map(str, auth_facts),
            *map(str, matched),
            *operation_fact_ids,
                    *[
                        str(value)
                        for flow in transformation_flows
                        for value in (
                            flow.get("validatedFact"),
                            flow.get("consumerFact"),
                        )
                        if value
                    ],
        ]
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
                    *[
                        {
                            "component": (
                                "tentative validation-to-consumer transformation"
                                if str(item.get("id") or "") in tentative_operation_facts
                                else "source-observed call candidate"
                            ),
                            "operation": str(item.get("callee") or "unknown call"),
                            "evidenceFacts": [str(item.get("id"))],
                            "sourceDerived": str(item.get("id") or "")
                            in tentative_operation_facts,
                        }
                        for item in operation_facts
                    ],
                ],
                "assumptionFlow": {
                    "validatedProperty": "the authorization consumer accepts or rejects the request-path representation",
                    "transformationAfterCheck": transformation_flows,
                    "transformationCandidates": transformation_candidates,
                    "unknownTransformationExperiments": unknown_experiments,
                    "consumerAssumption": "route execution receives the same protected resource identity",
                    "executableDiscriminator": "baseline blocked, authenticated control reaches route R, and a transformed anonymous request also reaches R",
                    "sourceDerivedWitnessAvailable": bool(source_variants),
                    "sourceFlowStatus": "tentative-until-runtime-values-confirmed",
                },
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
                    "executableOracle": {
                        "executable": True,
                        "runner": "semantic_hypothesis_loop.py run",
                        "sameBuildRequired": True,
                        "oneVariable": "request-path representation",
                        "retainsRawRequestResponse": True,
                        "automaticInterpreter": "evaluate",
                        "coordinatorExecution": True,
                        "cases": [
                            {"name": "baseline", "authority": "anonymous", "path": route},
                            {"name": "negative", "authority": "owned-authenticated", "path": route},
                            {"name": "positive", "authority": "anonymous", "path": "one generated variant"},
                        ],
                        "expectedObservations": {
                            "H1": "the positive reaches the authenticated resource identity while the baseline remains blocked",
                            "H2": "the anonymous baseline reaches the same resource identity",
                            "H3": "the positive does not reach the authenticated resource identity",
                            "H4": "the request representation changes before the mapped checker",
                        },
                    },
                    "baseline": {"method": "GET", "path": route, "authenticated": False},
                    "authenticatedControl": {"method": "GET", "path": route, "authenticated": True},
                    "variants": variants,
                    "cost": {"requests": 2 + len(variants), "priority": "source-derived-one-dimension-first"},
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
    host_header = parsed.hostname or "localhost"
    if parsed.port and parsed.port != 80:
        host_header += f":{parsed.port}"
    request_lines = [f"GET {path} HTTP/1.1", f"Host: {host_header}"]
    request_lines.extend(f"{name}: {value}" for name, value in headers.items())
    request_bytes = ("\r\n".join(request_lines) + "\r\n\r\n").encode()
    started = time.monotonic()
    connection.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
    connection.putheader("Host", host_header)
    for name, value in headers.items():
        connection.putheader(name, value)
    connection.endheaders()
    response = connection.getresponse()
    body = response.read(MAX_BODY + 1)
    elapsed = time.monotonic() - started
    response_header_rows = response.getheaders()
    response_headers = {name.lower(): value for name, value in response_header_rows}
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
        "retainedExchange": {
            "request": {
                "wireSha256": hashlib.sha256(request_bytes).hexdigest(),
                "wireBase64": (
                    base64.b64encode(request_bytes).decode("ascii") if header is None else None
                ),
                "redacted": header is not None,
                "authenticationHeaderName": header[0] if header else None,
            },
            "response": {
                "statusLine": f"HTTP/{response.version // 10}.{response.version % 10} {response.status} {response.reason}",
                "headers": [[name, value] for name, value in response_header_rows],
                "decodedBodyBase64": base64.b64encode(body).decode("ascii"),
                "decodedBodySha256": hashlib.sha256(body).hexdigest(),
                "decodedBodyTruncated": truncated,
                "wireFraming": {
                    "contentLength": response_headers.get("content-length"),
                    "transferEncoding": response_headers.get("transfer-encoding"),
                },
            },
        },
    }


def evaluate(model: dict[str, Any], baseline: dict[str, Any], authenticated: dict[str, Any], variants: list[dict[str, Any]]) -> dict[str, Any]:
    eliminated: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    def negative(mechanism: str, inputs: list[str], guard: str, consumer: str, observation: str, reopening: list[str]) -> dict[str, Any]:
        return {
            "mechanism": mechanism,
            "inputs": inputs,
            "conditions": [
                f"route={model['route']}",
                f"baselineStatus={baseline['status']}",
                f"authenticatedStatus={authenticated['status']}",
            ],
            "guard": guard,
            "consumer": consumer,
            "observation": observation,
            "evidence": [baseline["bodySha256"], authenticated["bodySha256"]],
            "reopeningConditions": reopening,
        }
    if not baseline["blocked"]:
        eliminated.append(negative("protected-route-bypass", [baseline["path"]], "baseline protection absent", "authorization", "unauthenticated baseline was not blocked", ["a route whose anonymous baseline is blocked"]))
        verdict = "inconclusive-unprotected-baseline"
    elif authenticated["blocked"] or not 200 <= authenticated["status"] < 300:
        eliminated.append(negative("authenticated-route-control", [authenticated["path"]], "owned control did not establish route identity", "execution", "authenticated control did not reach the route", ["a valid owned session that reaches the route"]))
        verdict = "inconclusive-auth-control"
    else:
        for variant in variants:
            observation = variant["observation"]
            if observation["blocked"]:
                eliminated.append(negative(variant["family"], [variant["path"]], "authorization blocked this exact representation", "authorization", "mutated representation remained blocked", ["a different source-observed transformation", "a changed matcher or normalization configuration"]))
            elif observation["routeIdentity"] != authenticated["routeIdentity"]:
                eliminated.append(negative(variant["family"], [variant["path"]], "route identities disagreed", "route resolver", "the representation selected a different route identity", ["a representation that preserves the authenticated route identity", "a changed route manifest"]))
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
    if any(model.get("ecosystem") != "nextjs" for model in selected):
        raise RuntimeError(
            "native proposals use their recorded trace runner and workerd_lifetime_oracle.py, not the Next.js HTTP executor"
        )
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
