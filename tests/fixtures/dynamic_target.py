#!/usr/bin/env python3
"""Deterministic local fixture for dynamic_harness integration tests."""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path


def main() -> int:
    data = Path(sys.argv[1]).read_bytes() if len(sys.argv) > 1 else sys.stdin.buffer.read()
    edges = ["entry"]
    if data.startswith(b"A"):
        edges.append("prefix:A")
    if data.startswith(b"AA"):
        edges.append("prefix:AA")
    coverage = os.environ.get("KRINEON_COVERAGE_FILE")
    if coverage:
        Path(coverage).write_text("\n".join(edges) + "\n", encoding="utf-8")

    if data.startswith(b"SLEEP"):
        time.sleep(30)
    if data.startswith(b"NOISY"):
        sys.stdout.buffer.write(b"x" * 100000)
        sys.stdout.buffer.flush()
        return 0
    if data.startswith(b"BENIGN"):
        sys.stdout.write("no runtime error: nothing happened\n")
        return 0
    if data.startswith(b"SANITIZER"):
        sys.stderr.write("ERROR: AddressSanitizer: container-overflow without fatal signal\n")
        return 0
    if data.startswith((b"CRASH1", b"CRASH2")):
        os.kill(os.getpid(), signal.SIGSEGV)
    if data.startswith(b"EXIT"):
        return 7
    if data.startswith(b"\xff"):
        sys.stderr.write(
            "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x12345678\n"
            "#0 0x12345678 in fixture_parse tests/fixtures/dynamic_target.py:32\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow in fixture_parse\n"
        )
        sys.stderr.flush()
        os.kill(os.getpid(), signal.SIGABRT)
    if data.startswith(b"\xfe"):
        sys.stderr.write(
            "ERROR: AddressSanitizer: stack-buffer-overflow on address 0x87654321\n"
            "#0 0x87654321 in other_parser tests/fixtures/dynamic_target.py:40\n"
            "SUMMARY: AddressSanitizer: stack-buffer-overflow in other_parser\n"
        )
        sys.stderr.flush()
        os.kill(os.getpid(), signal.SIGABRT)
    sys.stdout.write(f"accepted {len(data)} bytes\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
