#!/usr/bin/env python3
"""Build fixture that records injected compiler flags and installs a target."""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path


target = Path(sys.argv[1])
source = Path(sys.argv[2])
environment = Path(sys.argv[3])
shutil.copyfile(source, target)
target.chmod(0o755)
environment.write_text(
    json.dumps(
        {
            key: os.environ.get(key)
            for key in ("CC", "CXX", "CFLAGS", "CXXFLAGS", "LDFLAGS")
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
