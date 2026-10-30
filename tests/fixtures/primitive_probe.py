#!/usr/bin/env python3
"""Owned chosen-byte/allocation-identity probe fixture."""

from __future__ import annotations

import hashlib
import json
import os


def main() -> int:
    challenge = os.environ["KRINEON_CHALLENGE_HEX"]
    case = os.environ["KRINEON_CASE"]
    if case != "positive":
        print(json.dumps({"targetPid": os.getpid(), "writeObserved": False}))
        return 0
    print(
        json.dumps(
            {
                "targetPid": os.getpid(),
                "writeObserved": True,
                "originalAllocation": {
                    "address": "0x100000",
                    "size": 128,
                    "allocationId": "original-object",
                    "generation": 1,
                    "allocationStackSha256": hashlib.sha256(b"allocation-site").hexdigest(),
                },
                "replacementAllocation": {
                    "address": "0x100000",
                    "size": 128,
                    "allocationId": "replacement-object",
                    "generation": 2,
                    "allocationStackSha256": hashlib.sha256(b"allocation-site").hexdigest(),
                },
                "write": {
                    "address": "0x100008",
                    "beforeHex": "00" * (len(challenge) // 2),
                    "afterHex": challenge,
                },
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
