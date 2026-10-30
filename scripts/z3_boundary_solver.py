#!/usr/bin/env python3
"""Emit concrete constraint models with honest target-source provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def bv_literal(value: int, bits: int) -> str:
    return f"(_ bv{value % (1 << bits)} {bits})"


LEGACY_KINDS = {
    "truncate", "add-wrap", "sub-wrap", "mul-wrap", "narrowing-collision"
}


def smt_for_values(
    *,
    kind: str,
    bits: int,
    target: int,
    min_x: int,
    max_x: int,
    min_y: int,
    max_y: int,
) -> tuple[str, list[str]]:
    variables = ["x"] if kind == "truncate" else ["x", "y"]
    declarations = "\n".join(f"(declare-const {name} Int)" for name in variables)
    bounds = [f"(assert (>= x {min_x}))", f"(assert (<= x {max_x}))"]
    if "y" in variables:
        bounds.extend(
            (f"(assert (>= y {min_y}))", f"(assert (<= y {max_y}))")
        )
    expression = {
        "truncate": "x",
        "add-wrap": "(+ x y)",
        "sub-wrap": "(- x y)",
        "mul-wrap": "(* x y)",
        "narrowing-collision": "x",
    }[kind]
    assertions = [
        f"(assert (= ((_ int2bv {bits}) {expression}) {bv_literal(target, bits)}))"
    ]
    if kind == "narrowing-collision":
        assertions.extend(
            (
                "(assert (not (= x y)))",
                f"(assert (= ((_ int2bv {bits}) x) ((_ int2bv {bits}) y)))",
            )
        )
    smt = "\n".join(
        [
            "(set-option :produce-models true)", declarations, *bounds, *assertions,
            "(check-sat)", f"(get-value ({' '.join(variables)}))", "",
        ]
    )
    return smt, variables


def custom_smt(spec: dict[str, Any]) -> tuple[str, list[str]]:
    variables = spec.get("variables")
    assertions = spec.get("assertions")
    if not isinstance(variables, list) or not variables:
        raise RuntimeError("custom-smt requires a non-empty variables list")
    if not isinstance(assertions, list) or not assertions:
        raise RuntimeError("custom-smt requires a non-empty assertions list")
    names: list[str] = []
    declarations: list[str] = []
    bounds: list[str] = []
    for variable in variables:
        if not isinstance(variable, dict):
            raise RuntimeError("custom-smt variable entries must be objects")
        name = str(variable.get("name") or "")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise RuntimeError(f"invalid custom-smt variable name: {name}")
        if variable.get("sort", "Int") != "Int":
            raise RuntimeError("custom-smt currently supports Int variables only")
        if name in names:
            raise RuntimeError(f"duplicate custom-smt variable: {name}")
        names.append(name)
        declarations.append(f"(declare-const {name} Int)")
        if "min" in variable:
            bounds.append(f"(assert (>= {name} {int(variable['min'])}))")
        if "max" in variable:
            bounds.append(f"(assert (<= {name} {int(variable['max'])}))")
    normalized_assertions: list[str] = []
    for assertion in assertions:
        value = str(assertion).strip()
        if not value.startswith("(assert ") or not value.endswith(")"):
            raise RuntimeError("custom-smt assertions must be complete (assert ...) forms")
        normalized_assertions.append(value)
    return "\n".join(
        [
            "(set-option :produce-models true)", *declarations, *bounds,
            *normalized_assertions, "(check-sat)",
            f"(get-value ({' '.join(names)}))", "",
        ]
    ), names


def smt_for_spec(spec: dict[str, Any]) -> tuple[str, list[str]]:
    kind = str(spec.get("kind") or "")
    if kind == "custom-smt":
        return custom_smt(spec)
    if kind not in LEGACY_KINDS:
        raise RuntimeError(f"unsupported model kind: {kind}")
    required = ("bits", "target", "maxX")
    missing = [field for field in required if field not in spec]
    if missing:
        raise RuntimeError("model spec missing: " + ", ".join(missing))
    return smt_for_values(
        kind=kind,
        bits=int(spec["bits"]),
        target=int(spec["target"]),
        min_x=int(spec.get("minX", 0)),
        max_x=int(spec["maxX"]),
        min_y=int(spec.get("minY", 0)),
        max_y=int(spec.get("maxY", 0)),
    )


def parse_model(output: str, variables: list[str]) -> dict[str, int]:
    if not output.lstrip().startswith("sat"):
        raise RuntimeError(f"Z3 did not find a model: {output.strip()}")
    values: dict[str, int] = {}
    for name in variables:
        match = re.search(
            rf"\({re.escape(name)}\s+(?:(-?\d+)|\(-\s+(\d+)\))\)", output
        )
        if not match:
            raise RuntimeError(f"Z3 output omitted {name}: {output.strip()}")
        values[name] = int(match.group(1)) if match.group(1) else -int(match.group(2))
    return values


def encode_value(value: int, consumer_bits: int) -> dict[str, Any]:
    unsigned = value % (1 << consumer_bits)
    wire_unsigned = value if value >= 0 else unsigned
    byte_length = max(1, math.ceil(max(wire_unsigned.bit_length(), consumer_bits) / 8))
    signed = unsigned - (1 << consumer_bits) if unsigned >= (1 << (consumer_bits - 1)) else unsigned
    return {
        "integer": value,
        "decimalAscii": str(value),
        "hexAscii": format(value, "x"),
        "bigEndianHex": wire_unsigned.to_bytes(byte_length, "big", signed=False).hex(),
        "littleEndianHex": wire_unsigned.to_bytes(byte_length, "little", signed=False).hex(),
        "consumerUnsigned": unsigned,
        "consumerSigned": signed,
    }


def normalized_source(value: str) -> str:
    return " ".join(value.split())


def validate_implementation_binding(
    spec: dict[str, Any], source_root: Path | None
) -> dict[str, Any]:
    binding = spec.get("implementationBinding")
    if not isinstance(binding, dict):
        return {
            "sourceBound": False,
            "implementationMatched": False,
            "constraintExtraction": "generic-user-specified-model",
        }
    if source_root is None:
        raise RuntimeError("implementationBinding requires --source-root")
    relative = Path(str(binding.get("sourceFile") or ""))
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise RuntimeError("implementationBinding.sourceFile must be a safe relative path")
    root = source_root.expanduser().resolve()
    if root.is_file():
        root = root.parent
    source_path = (root / relative).resolve()
    try:
        source_path.relative_to(root)
    except ValueError as exc:
        raise RuntimeError("implementation binding escapes source root") from exc
    if not source_path.is_file():
        raise RuntimeError(f"implementation binding source is absent: {relative}")
    start = int(binding.get("startLine", 0))
    end = int(binding.get("endLine", 0))
    if start < 1 or end < start:
        raise RuntimeError("implementation binding lines are invalid")
    lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    if end > len(lines):
        raise RuntimeError("implementation binding exceeds source file")
    fragment = "\n".join(lines[start - 1:end]) + "\n"
    expected_expression = str(binding.get("expression") or "").strip()
    if not expected_expression:
        raise RuntimeError("implementation binding requires expression")
    if normalized_source(expected_expression) not in normalized_source(fragment):
        raise RuntimeError("bound expression is absent from the pinned source fragment")
    extraction = str(binding.get("constraintExtraction") or "manual-transcription")
    if extraction != "manual-transcription":
        raise RuntimeError(
            "this solver does not implement source-to-SMT extraction; "
            "constraintExtraction must be manual-transcription"
        )
    return {
        "sourceBound": True,
        "sourceFragmentMatched": True,
        "implementationMatched": False,
        "constraintExtraction": extraction,
        "sourceFile": relative.as_posix(),
        "startLine": start,
        "endLine": end,
        "sourceSha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
        "fragmentSha256": hashlib.sha256(fragment.encode()).hexdigest(),
        "expression": expected_expression,
    }


def legacy_spec(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "kind": args.kind,
        "bits": args.bits,
        "target": args.target,
        "minX": args.min_x,
        "maxX": args.max_x,
        "minY": args.min_y,
        "maxY": args.max_y,
    }


def solve(args: argparse.Namespace) -> dict[str, Any]:
    executable = shutil.which(args.z3)
    if executable is None:
        raise RuntimeError(f"Z3 executable not found: {args.z3}")
    spec = json.loads(args.spec.read_text(encoding="utf-8")) if args.spec else legacy_spec(args)
    if not isinstance(spec, dict):
        raise RuntimeError("model spec must be a JSON object")
    smt, variables = smt_for_spec(spec)
    binding = validate_implementation_binding(spec, args.source_root)
    completed = subprocess.run(
        [executable, "-in"],
        input=smt,
        check=False,
        capture_output=True,
        text=True,
        timeout=args.timeout,
    )
    if completed.returncode:
        raise RuntimeError(f"Z3 failed: {completed.stderr.strip()}")
    values = parse_model(completed.stdout, variables)
    bits = int(spec.get("bits") or spec.get("consumerBits") or 64)
    if bits < 1 or bits > 256:
        raise RuntimeError("consumer bits must be between 1 and 256")
    encoded = {name: encode_value(value, bits) for name, value in values.items()}
    return {
        "schemaVersion": 2,
        "tool": "z3",
        "kind": spec.get("kind"),
        "consumerBits": bits,
        "target": spec.get("target"),
        "model": encoded,
        "smtlib": smt,
        "implementationBinding": binding,
        "provenance": {
            "staticConstraintLead": True,
            "runtimeValidated": False,
            "sourceBound": binding["sourceBound"],
            "implementationMatched": binding["implementationMatched"],
            "note": "A satisfiable model is a concrete testcase, not exploit evidence.",
        },
    }


def emit_payloads(result: dict[str, Any], directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, encoded in result["model"].items():
        (directory / f"{name}.decimal.txt").write_text(
            encoded["decimalAscii"] + "\n", encoding="ascii"
        )
        (directory / f"{name}.hex.txt").write_text(
            encoded["hexAscii"] + "\n", encoding="ascii"
        )
        (directory / f"{name}.big-endian.bin").write_bytes(
            bytes.fromhex(encoded["bigEndianHex"])
        )
        (directory / f"{name}.little-endian.bin").write_bytes(
            bytes.fromhex(encoded["littleEndianHex"])
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, help="JSON constraint spec; supports custom-smt")
    parser.add_argument("--source-root", type=Path, help="pinned source root for implementationBinding")
    parser.add_argument("--kind", choices=sorted(LEGACY_KINDS))
    parser.add_argument("--bits", type=int)
    parser.add_argument("--target", type=int)
    parser.add_argument("--min-x", type=int, default=0)
    parser.add_argument("--max-x", type=int)
    parser.add_argument("--min-y", type=int, default=0)
    parser.add_argument("--max-y", type=int, default=0)
    parser.add_argument("--z3", default="z3")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--emit-dir", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.spec is None:
        if args.kind is None or args.bits is None or args.target is None or args.max_x is None:
            raise SystemExit("legacy mode requires --kind, --bits, --target, and --max-x")
        if args.bits < 1 or args.bits > 256:
            raise SystemExit("--bits must be between 1 and 256")
        if args.min_x < 0 or args.max_x < args.min_x:
            raise SystemExit("x bounds must be nonnegative and ordered")
        if args.kind != "truncate" and (args.min_y < 0 or args.max_y < args.min_y):
            raise SystemExit("y bounds must be nonnegative and ordered")
    try:
        result = solve(args)
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.emit_dir:
        emit_payloads(result, args.emit_dir.expanduser().resolve())
    payload = json.dumps(result, indent=2) + "\n"
    if args.output:
        output = args.output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
