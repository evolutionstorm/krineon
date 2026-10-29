#!/usr/bin/env python3
"""afl-showmap-shaped fixture that emits stable edge IDs."""

from __future__ import annotations

import sys
from pathlib import Path


arguments = sys.argv[1:]
output = Path(arguments[arguments.index("-o") + 1])
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text("000001:1\n000002:3\n", encoding="utf-8")
