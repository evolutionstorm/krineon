#!/usr/bin/env python3
"""Owned process fixture for executable path-proof attestations."""

from __future__ import annotations

import json
import os
import sys


def main() -> int:
    challenge = os.environ["KRINEON_CHALLENGE_HEX"]
    case = os.environ["KRINEON_CASE"]
    if case == "baseline":
        label = "baseline-ok"
    elif case == "negative":
        label = "negative-blocked"
    else:
        label = f"terminal:{challenge}"
    print(label)
    print(json.dumps({"targetPid": os.getpid(), "writeObserved": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
