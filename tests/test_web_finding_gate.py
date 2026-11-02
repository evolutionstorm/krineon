from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from scripts.web_contract import WebContractError
from scripts.web_evidence import evaluate_drift, validate_evidence
from scripts.web_finding_gate import validate_finding


DIGEST = "a" * 64


def evidence() -> dict:
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-evidence",
        "findingId": "WF-1",
        "experimentId": "WE-1",
        "target": {
            "scopedUrls": ["https://owned.example.test/private/record"],
            "observedFrom": "2026-11-01T00:00:00Z",
            "observedUntil": "2026-11-01T00:10:00Z",
            "tlsObservations": [
                {
                    "host": "owned.example.test",
                    "protocol": "TLSv1.3",
                    "certificateSha256": DIGEST,
                }
            ],
            "deploymentMarkers": [
                {
                    "name": "version-header",
                    "value": "claimed-v1",
                    "confidence": "response-claim",
                }
            ],
            "configurationAssumptions": ["ordinary production routing"],
            "clientVersions": {"transport": "HTTP/2", "browser": "Chrome fixture"},
        },
        "observationEpoch": {
            "id": "epoch-1",
            "start": "2026-11-01T00:00:00Z",
            "end": "2026-11-01T00:10:00Z",
            "prerequisiteVersion": "prerequisite-v1",
            "baseline": {
                "sha256": DIGEST,
                "stableComponents": ["status and normalized body shape"],
                "excludedVolatileFields": ["request id"],
            },
            "expired": False,
        },
        "identities": [
            {
                "id": "actor-a",
                "tenant": "tenant-a",
                "owned": True,
                "secretRef": "secret://actor-a",
                "bindingVersion": "actor-a-v1",
            },
            {
                "id": "actor-b",
                "tenant": "tenant-b",
                "owned": True,
                "secretRef": "secret://actor-b",
                "bindingVersion": "actor-b-v1",
            },
        ],
        "fixtures": [
            {
                "id": "record-b",
                "namespace": "owned-test-records",
                "owned": True,
                "creationEvidenceSha256": DIGEST,
                "cleanupStatus": "verified",
            }
        ],
        "scenarios": [
            {
                "id": "cross-tenant-read",
                "requestSha256": DIGEST,
                "scenarioSha256": DIGEST,
                "prerequisiteVersion": "prerequisite-v1",
                "actors": ["actor-a", "actor-b"],
                "resources": ["record-b"],
            }
        ],
        "provenance": {
            "mode": "blackbox",
            "sourceRevision": None,
            "sourceEvidence": [],
            "responseVersionIsSourcePin": False,
        },
        "artifactTiers": {
            "private": {
                "encrypted": True,
                "restricted": True,
                "retention": "campaign",
                "access": "operators",
                "export": "review only",
                "deletion": "verified expiry",
            },
            "reviewer": {
                "redacted": True,
                "syntheticDataOnly": True,
                "retention": "report",
                "access": "reviewers",
                "export": "manual",
                "deletion": "verified close",
            },
        },
        "unexpectedThirdPartyData": False,
        "autonomousPublicationAllowed": False,
    }


def finding(private_sha: str, reviewer_sha: str) -> dict:
    return {
        "schemaVersion": 1,
        "kind": "krineon-web-finding",
        "id": "WF-1",
        "experimentId": "WE-1",
        "title": "Owned tenant boundary violation",
        "profile": "web-app",
        "autonomousSubmissionAllowed": False,
        "approvalBinding": {
            "findingId": "WF-1",
            "experimentId": "WE-1",
            "observationEpoch": "epoch-1",
            "recipeSha256": DIGEST,
            "authorizationContractSha256": DIGEST,
            "identityBindings": [
                {"id": "actor-a", "bindingVersion": "actor-a-v1"},
                {"id": "actor-b", "bindingVersion": "actor-b-v1"},
            ],
            "resourceIds": ["record-b"],
            "oracleEvidenceSha256": DIGEST,
        },
        "attackerStartingPoint": {
            "identity": "actor-a",
            "tenant": "tenant-a",
            "privilege": "ordinary user",
            "prerequisites": ["owned account"],
        },
        "ingress": {
            "url": "https://owned.example.test/private/record",
            "method": "GET",
            "observed": True,
            "inScope": True,
            "evidenceSha256": DIGEST,
        },
        "violatedRule": {"claim": "A cannot read B", "basis": "owned baseline"},
        "ownedResourceIds": ["record-b"],
        "semanticControls": {
            name: [{"claim": name, "evidenceSha256": DIGEST}]
            for name in ("positive", "negative", "counterfactual")
        },
        "effect": {
            "impactClass": "cross-tenant-authority",
            "claim": "A read B's synthetic record",
            "boundaryCrossed": "tenant A to tenant B",
            "terminalClass": "cross-tenant-authorization",
            "independentlyVerified": True,
            "oracleEvidenceSha256": DIGEST,
        },
        "supportedClaim": {
            "complete": True,
            "statement": "A reads B's owned synthetic record",
            "conditions": ["same deployment epoch"],
            "unknowns": ["internal root cause"],
            "internalRootCauseStatus": "unknown",
            "sourceLocations": [],
        },
        "severityAssessment": {
            "startingPrivileges": "ordinary user",
            "prerequisites": "owned account",
            "boundaryCrossed": "cross tenant",
            "consequence": "confidentiality",
            "programRating": "High",
        },
        "independentReplay": {
            "freshSecretBindings": True,
            "freshFixtureGenerations": True,
            "isolatedBrowserSession": True,
            "staleCookieJarReused": False,
            "workflowPreconditionsPreserved": True,
            "cachePreconditionsPreserved": True,
            "originatorInterpretationAcceptedWithoutChallenge": False,
            "prerequisiteVersion": "prerequisite-v1",
            "observationEpoch": "epoch-1",
            "observerChallengeOutcome": "survived",
            "evidenceSha256": DIGEST,
        },
        "cleanup": {"status": "verified", "evidence": "cleanup.json"},
        "artifacts": {
            "private": [
                {
                    "path": "private/raw.bin",
                    "sha256": private_sha,
                    "classification": "private",
                    "restricted": True,
                    "encrypted": True,
                }
            ],
            "reviewer": [
                {
                    "path": "reviewer/proof.json",
                    "sha256": reviewer_sha,
                    "classification": "reviewer",
                    "sanitized": True,
                    "syntheticDataOnly": True,
                }
            ],
            "reviewerSanitization": {
                "coveredSurfaces": [
                    "request-headers",
                    "request-bodies",
                    "response-headers",
                    "response-bodies",
                    "urls",
                    "html-dom",
                    "screenshots",
                    "downloads",
                    "browser-storage",
                    "har-cdp-logs",
                    "nuclei-output",
                    "exception-traces",
                    "generated-commands",
                ],
                "unexpectedThirdPartyData": False,
                "leakScanPassed": True,
                "leakScanEvidenceSha256": DIGEST,
            },
        },
    }


class WebFindingGateTests(unittest.TestCase):
    def test_blackbox_authority_violation_passes_without_source_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "private").mkdir()
            (root / "reviewer").mkdir()
            private = root / "private" / "raw.bin"
            reviewer = root / "reviewer" / "proof.json"
            private.write_bytes(b"encrypted-private-evidence")
            reviewer.write_bytes(b'{"value":"SYNTHETIC_RECORD_B"}')
            verdict = validate_finding(
                finding(
                    hashlib.sha256(private.read_bytes()).hexdigest(),
                    hashlib.sha256(reviewer.read_bytes()).hexdigest(),
                ),
                evidence(),
                package_root=root,
            )
            self.assertTrue(verdict["passed"])
            self.assertTrue(verdict["blackboxRootCauseMayRemainUnknown"])
            self.assertEqual(verdict["severityBand"], "High")

            critical = finding(
                hashlib.sha256(private.read_bytes()).hexdigest(),
                hashlib.sha256(reviewer.read_bytes()).hexdigest(),
            )
            critical["severityAssessment"]["programRating"] = "Critical"
            self.assertEqual(
                validate_finding(critical, evidence(), package_root=root)["severityBand"],
                "Critical",
            )

            medium = finding(
                hashlib.sha256(private.read_bytes()).hexdigest(),
                hashlib.sha256(reviewer.read_bytes()).hexdigest(),
            )
            medium["severityAssessment"]["programRating"] = "Medium"
            with self.assertRaisesRegex(WebContractError, "High or Critical"):
                validate_finding(medium, evidence(), package_root=root)

    def test_deployment_drift_expires_the_prior_experiment(self) -> None:
        verdict = evaluate_drift(
            evidence(),
            {"schemaVersion": 1, "kind": "krineon-web-baseline", "sha256": "b" * 64},
        )
        self.assertTrue(verdict["experimentsExpired"])
        self.assertFalse(verdict["independentReplayProvesEarlierDeployment"])

    def test_blackbox_source_certainty_and_refuted_observer_are_rejected(self) -> None:
        value = evidence()
        value["provenance"]["sourceRevision"] = "invented-revision"
        with self.assertRaisesRegex(WebContractError, "source pin"):
            validate_evidence(value)

    def test_reviewer_package_leak_check_blocks_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "private").mkdir()
            (root / "reviewer").mkdir()
            private = root / "private" / "raw.bin"
            reviewer = root / "reviewer" / "proof.json"
            private.write_bytes(b"encrypted")
            reviewer.write_bytes(b"Authorization: Bearer real-looking-secret-token-123")
            value = finding(
                hashlib.sha256(private.read_bytes()).hexdigest(),
                hashlib.sha256(reviewer.read_bytes()).hexdigest(),
            )
            with self.assertRaisesRegex(WebContractError, "leak check"):
                validate_finding(value, evidence(), package_root=root)

    def test_approval_cannot_be_reused_for_other_identity_resource_or_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "private").mkdir()
            (root / "reviewer").mkdir()
            private = root / "private" / "raw.bin"
            reviewer = root / "reviewer" / "proof.json"
            private.write_bytes(b"encrypted")
            reviewer.write_bytes(b'{"value":"SYNTHETIC_RECORD_B"}')
            value = finding(
                hashlib.sha256(private.read_bytes()).hexdigest(),
                hashlib.sha256(reviewer.read_bytes()).hexdigest(),
            )
            value["approvalBinding"]["resourceIds"] = ["record-a"]
            with self.assertRaisesRegex(WebContractError, "resource bindings"):
                validate_finding(value, evidence(), package_root=root)


if __name__ == "__main__":
    unittest.main()
