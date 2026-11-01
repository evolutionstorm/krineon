from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.web_boundary_adapters import validate_adapter
from scripts.web_cache_research import evaluate as evaluate_cache
from scripts.web_cache_research import validate_experiment as validate_cache
from scripts.web_contract import WebCampaignContract, WebContractError
from scripts.web_deserialization_research import evaluate as evaluate_deserialization
from scripts.web_deserialization_research import generate_variants
from scripts.web_workflow import validate_workflow
from tests.test_web_app_profile import contract_value, workflow_value


ROOT = Path(__file__).resolve().parents[1]


def asset(name: str) -> dict:
    return json.loads((ROOT / "assets" / name).read_text(encoding="utf-8"))


def executable_cache_spec(*, mode: str = "poisoning") -> dict:
    spec = asset("web-cache-experiment.template.json")
    spec["id"] = f"owned-{mode}"
    spec["prerequisiteVersion"] = "fixture-v1"
    spec["isolation"].update(
        {
            "planningOnly": False,
            "established": True,
            "basis": "isolated-owned-cache-fixture",
            "evidence": ["evidence/cache-isolation.json"],
        }
    )
    if mode == "deception":
        spec["mode"] = "deception"
        spec["identities"]["privateOwner"] = copy.deepcopy(spec["identities"]["attacker"])
        spec["canary"]["privateToActorRef"] = spec["identities"]["privateOwner"]["actorRef"]
        spec["steps"].extend(
            [
                {
                    "id": "canonical-authenticated",
                    "role": "canonical-authenticated",
                    "workflowRef": "web/canonical-authenticated.json",
                    "actorRef": "owned-actor-a",
                    "resourceRef": "owned-cache-resource",
                    "ordinaryRepresentation": True,
                },
                {
                    "id": "canonical-anonymous-control",
                    "role": "canonical-anonymous-control",
                    "workflowRef": "web/canonical-anonymous.json",
                    "actorRef": "owned-anonymous",
                    "resourceRef": "owned-cache-resource",
                    "ordinaryRepresentation": True,
                },
            ]
        )
    return spec


def cache_observation(
    step: dict,
    *,
    canary: bool,
    private: bool = False,
    layer: str = "cdn",
    shared: bool = True,
    generic_shell: bool = False,
    profile_ref: str | None = None,
) -> dict:
    return {
        "id": f"observation-{step['id']}",
        "stepId": step["id"],
        "actorRef": step["actorRef"],
        "profileRef": profile_ref or (
            "owned-profile-a" if step["actorRef"] == "owned-actor-a" else f"profile-{step['actorRef']}"
        ),
        "method": "GET",
        "resourceIdentity": step["resourceRef"],
        "ordinaryRequest": step["ordinaryRepresentation"],
        "disputedInputPresent": step["role"] == "attacker-prime",
        "response": {
            "status": 200,
            "bodySha256": "body-with-canary" if canary or private else "clean-body",
            "canarySha256": "replace-with-private-synthetic-canary-sha256" if canary or private else None,
            "syntheticCanarySeen": canary,
            "privateCanarySeen": private,
            "genericShell": generic_shell,
            "redirect": False,
            "publicContent": False,
            "requestSpecificReflection": False,
            "provenance": {
                "layer": layer,
                "sharedReuseProved": shared,
                "evidence": [f"evidence/{step['id']}-provenance.json"],
            },
        },
        "cacheMetadata": {
            "age": 1,
            "via": "owned-cache-fixture",
            "vary": "Accept-Encoding",
            "etag": "owned-etag",
            "timestamp": "2026-11-01T12:00:00Z",
            "cookiesPresent": step["actorRef"] == "owned-actor-a",
            "cachePartitionSignals": ["profile", "credential-binding", "resource"],
        },
    }


def cache_document(spec: dict, *, victim_canary: bool = True, victim_layer: str = "cdn") -> dict:
    observations = []
    for step in spec["steps"]:
        role = step["role"]
        if spec["mode"] == "poisoning":
            canary = role in {"attacker-prime", "victim-fetch"} and (
                role != "victim-fetch" or victim_canary
            )
            private = False
        else:
            canary = False
            private = role in {"canonical-authenticated", "attacker-prime", "victim-fetch"} and (
                role != "victim-fetch" or victim_canary
            )
        observations.append(
            cache_observation(
                step,
                canary=canary,
                private=private,
                layer=victim_layer if role == "victim-fetch" else "application-cache",
                shared=(victim_layer in {"cdn", "reverse-proxy", "application-cache"}),
                profile_ref=(
                    spec["identities"]["attacker"]["profileRef"]
                    if role in {"attacker-prime", "cleanup-verify"}
                    else spec["identities"].get("privateOwner", spec["identities"]["attacker"])["profileRef"]
                    if role == "canonical-authenticated"
                    else spec["identities"]["victim"]["profileRef"]
                ),
            )
        )
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-cache-observations",
        "prerequisiteVersion": spec["prerequisiteVersion"],
        "observations": observations,
        "cleanup": {
            "ownedEntryExpiredOrRemoved": True,
            "broaderEffectObserved": False,
            "evidence": ["evidence/cleanup.json"],
        },
    }


def deserialization_spec() -> tuple[dict, dict]:
    spec = asset("web-deserialization-experiment.template.json")
    spec["id"] = "owned-typed-json-boundary"
    spec["prerequisiteVersion"] = "fixture-v1"
    baseline = {"ownedField": "ordinary", "resource": "owned-a"}
    payload = json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()
    spec["baseline"]["sha256"] = hashlib.sha256(payload).hexdigest()
    return spec, baseline


def case(
    case_id: str,
    *,
    parsed: bool,
    constructed: bool,
    unsafe: bool = False,
    effect: bool = False,
    signature: bool = True,
) -> dict:
    return {
        "caseId": case_id,
        "runnerEvidence": [f"evidence/{case_id}.json"],
        "parsingAccepted": parsed,
        "objectConstructed": constructed,
        "unsafeTypeOrAuthoritySelected": unsafe,
        "ownedCanaryEffectObserved": effect,
        "canaryEffectKind": "owned-dispatch-selection-observation" if effect else None,
        "ownedResource": True,
        "independentControlPassed": True,
        "acquisitionComplete": True,
        "signatureAccepted": signature,
        "crashObserved": False,
        "externalEffectObserved": False,
    }


def deserialization_document(spec: dict, observations: list[dict]) -> dict:
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-deserialization-observations",
        "prerequisiteVersion": spec["prerequisiteVersion"],
        "independentReplay": {
            "status": "confirmed",
            "freshRunner": True,
            "samePrerequisiteVersion": True,
            "evidenceRef": spec["controls"]["independentReplayRef"],
        },
        "observations": observations,
    }


class CacheAndDeserializationResearchTests(unittest.TestCase):
    def test_true_cache_poisoning_passes_but_keyed_and_browser_only_cases_do_not(self) -> None:
        spec = executable_cache_spec()
        self.assertEqual(
            evaluate_cache(spec, cache_document(spec))["outcome"],
            "confirmed-cache-poisoning-primitive",
        )
        self.assertEqual(
            evaluate_cache(spec, cache_document(spec, victim_canary=False))["outcome"],
            "invariant-preserved",
        )
        self.assertEqual(
            evaluate_cache(spec, cache_document(spec, victim_layer="browser-disk"))["outcome"],
            "invariant-preserved",
        )

    def test_cache_isolation_cannot_rely_on_random_marker(self) -> None:
        spec = executable_cache_spec()
        spec["isolation"].update(
            {
                "liveSharedCacheMutation": True,
                "basis": "cache-key-proof",
                "randomMarkerIsSoleBasis": True,
                "exactSharedEffectApproved": True,
                "approvalEvidence": ["owner approval"],
            }
        )
        with self.assertRaisesRegex(WebContractError, "random query or path marker"):
            validate_cache(spec)

    def test_true_cache_deception_passes_but_generic_shell_does_not(self) -> None:
        spec = executable_cache_spec(mode="deception")
        document = cache_document(spec)
        self.assertEqual(
            evaluate_cache(spec, document)["outcome"],
            "confirmed-cache-deception-disclosure",
        )
        shell = copy.deepcopy(document)
        victim_step = next(value for value in spec["steps"] if value["role"] == "victim-fetch")
        victim = next(value for value in shell["observations"] if value["stepId"] == victim_step["id"])
        victim["response"]["genericShell"] = True
        self.assertEqual(evaluate_cache(spec, shell)["outcome"], "invariant-preserved")
        private_but_keyed = cache_document(spec, victim_canary=False)
        self.assertEqual(
            evaluate_cache(spec, private_but_keyed)["outcome"], "invariant-preserved"
        )

    def test_deserialization_generator_is_structured_and_bounded(self) -> None:
        spec, baseline = deserialization_spec()
        generated = generate_variants(spec, baseline)
        self.assertEqual(len(generated["cases"]), 1)
        self.assertEqual(generated["cases"][0]["payload"]["ownedField"]["candidate"], "bounded-structured-value")
        self.assertFalse(generated["evaluatedInsideKrineon"])

    def test_rejected_signed_object_is_not_a_finding(self) -> None:
        spec, _ = deserialization_spec()
        spec["boundary"]["integrityBoundary"] = "signed"
        spec["signaturePolicy"].update(
            {
                "mode": "invalid-signature-control",
                "invalidSignatureControlId": "invalid-signature",
            }
        )
        spec["controls"]["invalidSignatureControlId"] = "invalid-signature"
        document = deserialization_document(
            spec,
            [
                case("legitimate-baseline", parsed=True, constructed=True),
                case("benign-type-control", parsed=True, constructed=True),
                case("invalid-signature", parsed=False, constructed=False, signature=False),
                case("small-type-change", parsed=False, constructed=False, signature=False),
            ],
        )
        self.assertEqual(evaluate_deserialization(spec, document)["outcome"], "invariant-preserved")

    def test_unsafe_owned_fixture_requires_full_security_consequence(self) -> None:
        spec, _ = deserialization_spec()
        document = deserialization_document(
            spec,
            [
                case("legitimate-baseline", parsed=True, constructed=True),
                case("benign-type-control", parsed=True, constructed=True),
                case(
                    "small-type-change",
                    parsed=True,
                    constructed=True,
                    unsafe=True,
                    effect=True,
                ),
            ],
        )
        result = evaluate_deserialization(spec, document)
        self.assertEqual(result["outcome"], "confirmed-deserialization-invariant-break")
        self.assertFalse(result["remoteExecutionClaimed"])

    def test_bounded_adapter_rejects_unapproved_desynchronization(self) -> None:
        adapter = asset("web-boundary-adapter.template.json")
        self.assertTrue(validate_adapter(adapter)["admitted"])
        adapter["family"] = "http-desynchronization"
        adapter["options"] = {
            "explicitExactAuthorization": False,
            "isolatedTopology": True,
            "sharedLiveService": False,
            "maxConnections": 2,
            "maxBytes": 4096,
        }
        with self.assertRaisesRegex(WebContractError, "exact authorization"):
            validate_adapter(adapter)

    def test_web_profile_schedules_semantic_cache_and_deserialization_lanes(self) -> None:
        profile = asset("../profiles/web-app.json")
        lanes = {value["id"]: value for value in profile["lanes"]}
        for lane in (
            "web-cache-semantic-research",
            "web-deserialization-semantic-research",
            "web-bounded-boundary-adapters",
        ):
            self.assertIn(lane, lanes)
            self.assertIn("web-controlled-execution", lanes[lane]["dependsOn"])

    def test_target_runner_blocks_deserialization_and_desync_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "web-campaign.json"
            path.write_text(
                json.dumps(contract_value("http://127.0.0.1:1", confirmed=False)),
                encoding="utf-8",
            )
            contract = WebCampaignContract.load(path)
            for operation_class, flag in (
                ("deserialization-experiment", "allowDeserializationExperiments"),
                ("http-desynchronization", "allowHttpDesynchronization"),
            ):
                workflow = workflow_value()
                workflow["steps"][0]["operationClass"] = operation_class
                with self.assertRaisesRegex(WebContractError, flag):
                    validate_workflow(workflow, contract, dynamic=False)


if __name__ == "__main__":
    unittest.main()
