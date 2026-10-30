#!/usr/bin/env python3
"""Generate history-preserving operation sequences from an explicit state graph."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"{field} must be non-empty text")
    return value.strip()


def generate(document: dict[str, Any], maximum_length: int) -> dict[str, Any]:
    if document.get("schemaVersion") != 1:
        raise RuntimeError("state graph requires schemaVersion 1")
    initial = require_text(document.get("initialState"), "initialState")
    raw = document.get("operations")
    if not isinstance(raw, list) or not raw:
        raise RuntimeError("operations must be a non-empty list")
    operations: list[dict[str, str]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise RuntimeError(f"operations[{index}] must be an object")
        operation = {
            name: require_text(item.get(name), f"operations[{index}].{name}")
            for name in ("id", "from", "to", "authority", "ownership", "invariant")
        }
        operations.append(operation)
    if len({item["id"] for item in operations}) != len(operations):
        raise RuntimeError("operation IDs must be unique")
    by_state: dict[str, list[dict[str, str]]] = {}
    for operation in operations:
        by_state.setdefault(operation["from"], []).append(operation)
    sequences: list[dict[str, Any]] = []

    def walk(state: str, path: list[dict[str, str]]) -> None:
        if path:
            sequences.append(
                {
                    "operationIds": [item["id"] for item in path],
                    "states": [initial, *[item["to"] for item in path]],
                    "transitionPairs": [[item["from"], item["to"]] for item in path],
                    "invariants": [item["invariant"] for item in path],
                    "historyPreserved": True,
                }
            )
        if len(path) >= maximum_length:
            return
        for operation in by_state.get(state, []):
            if sum(item["id"] == operation["id"] for item in path) >= 1:
                continue
            walk(operation["to"], [*path, operation])

    walk(initial, [])
    required = document.get("requiredTransitionPairs", [])
    if not isinstance(required, list):
        raise RuntimeError("requiredTransitionPairs must be a list")
    required_pairs = {
        tuple(pair)
        for pair in required
        if isinstance(pair, list) and len(pair) == 2 and all(isinstance(v, str) for v in pair)
    }
    for sequence in sequences:
        observed = {tuple(pair) for pair in sequence["transitionPairs"]}
        sequence["coversRequiredPairs"] = sorted([list(pair) for pair in required_pairs & observed])
        sequence["missingRequiredPairs"] = sorted([list(pair) for pair in required_pairs - observed])
    return {
        "schemaVersion": 1,
        "producer": "krineon-state-sequence-generator",
        "initialState": initial,
        "maximumLength": maximum_length,
        "sequences": sequences,
        "mutationPolicy": {
            "onlyStateValidSequencesEmitted": True,
            "historyIsNeverReorderedIntoAnInvalidTransition": True,
            "reductionsMustRetainRequiredTransitionPairs": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("spec", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--maximum-length", type=int, default=6)
    args = parser.parse_args(argv)
    try:
        if not 1 <= args.maximum_length <= 32:
            raise RuntimeError("--maximum-length must be between 1 and 32")
        document = json.loads(args.spec.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise RuntimeError("state graph must be a JSON object")
        result = generate(document, args.maximum_length)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(args.output)
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
