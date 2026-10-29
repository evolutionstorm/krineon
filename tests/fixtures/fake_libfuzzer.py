#!/usr/bin/env python3
"""libFuzzer-shaped fixture for the external-fuzzer integration test."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    arguments = sys.argv[1:]
    if "-runs=1" in arguments:
        data = Path(arguments[-1]).read_bytes()
        if b"CRASH" in data:
            sys.stderr.write(
                "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234\n"
                "WRITE of size 8 at 0x1234 thread T0\n"
                "#0 0x1 in fixture_target /src/fixture.cc:10\n"
            )
            return 1
        return 0
    corpus = next(Path(value) for value in arguments if not value.startswith("-"))
    prefix = next(
        Path(value.split("=", 1)[1])
        for value in arguments
        if value.startswith("-artifact_prefix=")
    )
    corpus.mkdir(parents=True, exist_ok=True)
    prefix.mkdir(parents=True, exist_ok=True)
    (corpus / "engine-discovery").write_bytes(b"DISCOVERY")
    (prefix / "crash-fixture").write_bytes(b"CRASH")
    print("#2 DONE cov: 2 ft: 2 corp: 2/16b")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
