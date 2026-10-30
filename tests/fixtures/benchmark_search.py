#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


parser = argparse.ArgumentParser()
parser.add_argument("identity")
args = parser.parse_args()

corpus = Path(os.environ["KRINEON_BENCHMARK_CORPUS"])
assert any(path.is_file() for path in corpus.rglob("*"))
print(json.dumps({"identity": args.identity, "source": "fixture-search"}), flush=True)
