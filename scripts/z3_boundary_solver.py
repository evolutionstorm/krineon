#!/usr/bin/env python3
"""Use the Z3 binary to emit concrete integer-boundary testcase inputs."""

from __future__ import annotations

import argparse
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


def smt_for(args: argparse.Namespace) -> str:
    variables = ["x"] if args.kind == "truncate" else ["x", "y"]
    declarations = "\n".join(f"(declare-const {name} Int)" for name in variables)
    bounds = [f"(assert (>= x {args.min_x}))", f"(assert (<= x {args.max_x}))"]
    if "y" in variables:
        bounds.extend(
            (f"(assert (>= y {args.min_y}))", f"(assert (<= y {args.max_y}))")
        )
    expression = {
        "truncate": "x",
        "add-wrap": "(+ x y)",
        "mul-wrap": "(* x y)",
    }[args.kind]
    return "\n".join(
        [
            "(set-option :produce-models true)",
            declarations,
            *bounds,
            f"(assert (= ((_ int2bv {args.bits}) {expression}) "
            f"{bv_literal(args.target, args.bits)}))",
            "(check-sat)",
            f"(get-value ({' '.join(variables)}))",
            "",
        ]
    )


def parse_model(output: str, variables: list[str]) -> dict[str, int]:
    if not output.lstrip().startswith("sat"):
        raise RuntimeError(f"Z3 did not find a model: {output.strip()}")
    values: dict[str, int] = {}
    for name in variables:
        match = re.search(rf"\({re.escape(name)}\s+(-?\d+)\)", output)
        if not match:
            raise RuntimeError(f"Z3 output omitted {name}: {output.strip()}")
        values[name] = int(match.group(1))
    return values


def encode_value(value: int, consumer_bits: int) -> dict[str, Any]:
    byte_length = max(1, math.ceil(max(value.bit_length(), consumer_bits) / 8))
    unsigned = value % (1 << consumer_bits)
    signed = unsigned - (1 << consumer_bits) if unsigned >= (1 << (consumer_bits - 1)) else unsigned
    return {
        "integer": value,
        "decimalAscii": str(value),
        "hexAscii": format(value, "x"),
        "bigEndianHex": value.to_bytes(byte_length, "big", signed=False).hex(),
        "littleEndianHex": value.to_bytes(byte_length, "little", signed=False).hex(),
        "consumerUnsigned": unsigned,
        "consumerSigned": signed,
    }


def solve(args: argparse.Namespace) -> dict[str, Any]:
    executable = shutil.which(args.z3)
    if executable is None:
        raise RuntimeError(f"Z3 executable not found: {args.z3}")
    smt = smt_for(args)
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
    variables = ["x"] if args.kind == "truncate" else ["x", "y"]
    values = parse_model(completed.stdout, variables)
    encoded = {name: encode_value(value, args.bits) for name, value in values.items()}
    return {
        "schemaVersion": 1,
        "tool": "z3",
        "kind": args.kind,
        "consumerBits": args.bits,
        "target": args.target,
        "model": encoded,
        "smtlib": smt,
        "provenance": {
            "staticConstraintLead": True,
            "runtimeValidated": False,
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
    parser.add_argument("--kind", choices=("truncate", "add-wrap", "mul-wrap"), required=True)
    parser.add_argument("--bits", type=int, required=True)
    parser.add_argument("--target", type=int, required=True)
    parser.add_argument("--min-x", type=int, default=0)
    parser.add_argument("--max-x", type=int, required=True)
    parser.add_argument("--min-y", type=int, default=0)
    parser.add_argument("--max-y", type=int, default=0)
    parser.add_argument("--z3", default="z3")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--emit-dir", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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
