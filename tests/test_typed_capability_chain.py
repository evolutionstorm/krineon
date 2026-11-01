from __future__ import annotations

import copy
import unittest

from scripts.chain_reasoning import analyze_chain


def context(
    *,
    principal: str = "attacker",
    session: str = "session-a",
    tenant: str = "tenant-a",
    process: str = "server",
    origin: str = "https://app.test",
    cache: str = "none",
    epoch: str = "epoch-1",
) -> dict[str, str]:
    return {
        "principal": principal,
        "actorSession": session,
        "tenant": tenant,
        "process": process,
        "namespace": "owned-fixture",
        "runtime": "production-equivalent",
        "origin": origin,
        "cacheLayer": cache,
        "observationEpoch": epoch,
    }


def binding(
    capability: str,
    *,
    resource: str,
    owner: str,
    operation: str,
    scope: str,
    provider_process: str = "server",
    provider_origin: str = "https://app.test",
    provider_cache: str = "none",
    consumer_process: str = "server",
    consumer_origin: str = "https://app.test",
    consumer_cache: str = "none",
    epoch: str = "epoch-1",
) -> dict[str, object]:
    return {
        "type": capability,
        "properties": ["owned-fixture", "measured"],
        "limitations": [],
        "forbiddenLimitations": [],
        "binding": {
            "actorSession": "session-a",
            "tenant": "tenant-a",
            "resourceIdentity": resource,
            "resourceOwner": owner,
            "operation": operation,
            "permittedScope": scope,
            "parameterConstraints": ["owned-synthetic-data"],
            "lifetime": ["epoch-1"],
            "invalidation": ["session-revocation"],
            "provider": {
                "process": provider_process,
                "origin": provider_origin,
                "cacheLayer": provider_cache,
            },
            "consumer": {
                "process": consumer_process,
                "origin": consumer_origin,
                "cacheLayer": consumer_cache,
            },
            "observationEpoch": epoch,
            "configuration": ["fixture-config-v1"],
            "acquisitionPrerequisites": ["owned-session-a"],
            "measuredEffect": f"{operation}:{resource}",
            "evidenceConfidence": "runtime-observed",
            "status": "runtime-observed",
        },
    }


def constraints(*, provided: list[str] | None = None) -> dict[str, list[str]]:
    return {
        "lifetime": ["epoch=epoch-1"],
        "ordering": [],
        "deployment": ["deployment=fixture-v1"],
        "acquisition": ["owned=true"],
        "requiredState": [],
        "providedState": provided or [],
        "invalidatedState": [],
    }


def primitive(
    identifier: str,
    produces: list[dict[str, object]],
    requires: list[dict[str, object]],
    *,
    ingress: bool = False,
    operation_context: dict[str, str] | None = None,
    transition: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "id": identifier,
        "attackerControlledInputs": ["owned HTTP request"] if ingress else [],
        "produces": produces,
        "requires": requires,
        "context": operation_context or context(),
        "contextTransition": transition,
        "constraints": constraints(provided=[identifier]),
        "objects": {"requires": [], "produces": [], "invalidates": []},
        "invalidatesCapabilities": [],
        "stateSequence": {
            "initialState": "fresh",
            "transitions": [],
            "reductionMustPreserve": [],
        },
        "sourceEvidence": [f"fixture/{identifier}.json"],
        "runtimeEvidence": [f"evidence/{identifier}.json"],
        "progress": {
            "milestones": ["attacker-capability-controlled"],
            "resolvedPreconditions": [],
            "falsifiedPreconditions": [],
            "connectedPrimitives": [],
            "uncertaintiesResolved": [],
        },
        "negativeKnowledge": [],
        "inputType": "owned fixture request",
        "outputAuthority": produces[0]["type"],
        "acquisition": {
            "method": "owned production-equivalent replay",
            "attackerAccessible": True,
            "evidence": [f"evidence/{identifier}-acquisition.json"],
        },
        "reliability": {
            "successes": 1,
            "attempts": 1,
            "evidence": [f"evidence/{identifier}-replay.json"],
        },
        "unresolvedAssumptions": [],
    }


def boundary(
    identifier: str,
    operation: str,
    requirement: dict[str, object],
    *,
    boundary_context: dict[str, str] | None = None,
) -> dict[str, object]:
    return {
        "id": identifier,
        "operation": operation,
        "terminalClass": operation,
        "eventualImpact": operation,
        "intermediateCapability": requirement["type"],
        "requiredCapabilities": [copy.deepcopy(requirement)],
        "context": boundary_context or context(),
        "constraints": constraints(),
        "objects": {"requires": [], "produces": [], "invalidates": []},
        "sourceEvidence": [f"fixture/{identifier}.json"],
    }


class TypedCapabilityChainTests(unittest.TestCase):
    def test_cross_tenant_chain_requires_exact_resource_identity_and_epoch(self) -> None:
        owned = binding(
            "read-owned-private-record",
            resource="record-a",
            owner="actor-a",
            operation="read",
            scope="tenant-a-owned-records",
        )
        crossed = binding(
            "cross-tenant-record-read",
            resource="record-b",
            owner="actor-b",
            operation="read",
            scope="tenant-b-record-b",
        )
        document = {
            "schemaVersion": 3,
            "prerequisiteVersion": "fixture-v1",
            "primitives": [
                primitive("owned-read", [owned], [], ingress=True),
                primitive("binding-confusion", [crossed], [owned]),
            ],
            "boundaries": [
                boundary(
                    "cross-tenant-read",
                    "cross-tenant-authorization",
                    crossed,
                )
            ],
        }
        result = analyze_chain(document)
        self.assertIn(
            ["owned-read", "binding-confusion", "boundary:cross-tenant-read"],
            result["completeBoundaryPaths"],
        )

        incompatible = copy.deepcopy(document)
        incompatible["boundaries"][0]["requiredCapabilities"][0]["binding"][
            "resourceIdentity"
        ] = "record-c"
        incompatible["boundaries"][0]["requiredCapabilities"][0]["binding"][
            "observationEpoch"
        ] = "epoch-2"
        blocked = analyze_chain(incompatible)
        self.assertEqual(blocked["completeBoundaryPaths"], [])

    def test_cache_to_browser_chain_requires_explicit_transition_and_origin(self) -> None:
        cache_influence = binding(
            "shared-cache-response-influence",
            resource="cache-key-owned-1",
            owner="shared-cache",
            operation="write-response-variant",
            scope="owned-cache-namespace",
            provider_cache="shared-route-cache",
            consumer_process="browser",
            consumer_cache="browser-http-cache",
        )
        browser_execution = binding(
            "browser-origin-code-execution",
            resource="owned-page-1",
            owner="actor-b",
            operation="execute-script",
            scope="https://app.test",
            provider_process="browser",
            consumer_process="browser",
        )
        server_context = context(cache="shared-route-cache")
        browser_context = context(
            principal="owned-victim",
            session="session-b",
            tenant="tenant-b",
            process="browser",
            cache="browser-http-cache",
        )
        transition = {
            "from": server_context,
            "to": browser_context,
            "transport": "victim-navigation-through-shared-cache",
            "authorityChange": "attacker cache influence becomes victim browser input",
            "preservesCapabilities": ["shared-cache-response-influence"],
            "crosses": ["principal", "tenant", "browser-origin", "cache-layer"],
            "evidence": ["evidence/cache-victim-transition.json"],
        }
        document = {
            "schemaVersion": 3,
            "prerequisiteVersion": "fixture-v1",
            "primitives": [
                primitive(
                    "cache-prime",
                    [cache_influence],
                    [],
                    ingress=True,
                    operation_context=server_context,
                ),
                primitive(
                    "victim-consume",
                    [browser_execution],
                    [cache_influence],
                    operation_context=server_context,
                    transition=transition,
                ),
            ],
            "boundaries": [
                boundary(
                    "browser-exec",
                    "browser-origin-code-execution",
                    browser_execution,
                    boundary_context=browser_context,
                )
            ],
        }
        result = analyze_chain(document)
        self.assertIn(
            ["cache-prime", "victim-consume", "boundary:browser-exec"],
            result["completeBoundaryPaths"],
        )

        incompatible = copy.deepcopy(document)
        incompatible["boundaries"][0]["requiredCapabilities"][0]["binding"][
            "consumer"
        ]["origin"] = "https://other.test"
        self.assertEqual(analyze_chain(incompatible)["completeBoundaryPaths"], [])


if __name__ == "__main__":
    unittest.main()
