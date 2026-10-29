from __future__ import annotations


def complete_path_proof() -> dict[str, object]:
    evidence = "evidence/path-proof/trace.json"
    return {
        "schemaVersion": 1,
        "findingId": "FPATH",
        "complete": True,
        "entryPoint": {
            "source": "src/request.cc:40-58",
            "symbol": "parse_request",
            "interface": "unauthenticated HTTP body",
            "attackerInput": "the declared and encoded body lengths",
            "evidence": [evidence],
        },
        "sink": {
            "source": "src/copy.cc:91-104",
            "symbol": "copy_decoded",
            "effect": "attacker-sized copy into a fixed-size destination",
            "evidence": [evidence],
        },
        "steps": [
            {
                "ordinal": 1,
                "source": "src/request.cc:40-58",
                "symbol": "parse_request",
                "operation": "parses the request-controlled encoded length",
                "attackerControlledValue": "encoded_length = 257",
                "transitionToNext": "passes encoded_length to decode_record",
                "conditionIds": ["C1"],
                "sourceEvidence": [evidence],
                "runtimeEvidence": [evidence],
            },
            {
                "ordinal": 2,
                "source": "src/copy.cc:91-104",
                "symbol": "copy_decoded",
                "operation": "copies decoded bytes using encoded_length",
                "attackerControlledValue": "encoded_length remains 257",
                "transitionToNext": "terminal sink",
                "conditionIds": [],
                "sourceEvidence": [evidence],
                "runtimeEvidence": [evidence],
            },
        ],
        "conditions": [
            {
                "id": "C1",
                "source": "src/request.cc:48",
                "symbol": "parse_request",
                "expression": "encoded_length <= protocol_max",
                "requiredOutcome": "true",
                "attackerMechanism": "choose 257, below protocol_max 4096",
                "concreteInputOrState": "encoded_length=257; protocol_max=4096",
                "sourceEvidence": [evidence],
                "runtimeEvidence": [evidence],
                "observed": True,
            }
        ],
        "conditionCoverage": {
            "method": "line-by-line exact source walk from ingress to sink",
            "functionsReviewed": [
                {
                    "source": "src/request.cc",
                    "symbol": "parse_request and copy_decoded",
                    "range": "40-104",
                    "sourceSha256": "a" * 64,
                    "conditionIds": ["C1"],
                }
            ],
            "allPathConditionsEnumerated": True,
            "noConditionsReason": "",
        },
        "assumptions": [],
        "contradictionChecks": [
            {
                "challenge": "the destination may be resized before the copy",
                "challenger": "worker-reviewer",
                "result": "resolved-no-contradiction",
                "resolution": "the retained trace and source show a fixed 256-byte destination",
                "evidence": [evidence],
            }
        ],
        "falsification": {
            "negativeControls": [evidence],
            "disprovingObservationsChecked": [evidence],
        },
        "review": {
            "originator": "worker-originator",
            "reviewer": "worker-reviewer",
            "reviewedAt": "2026-10-29T12:00:00Z",
            "notes": "Re-derived every transition and branch from the retained source and trace.",
        },
    }
