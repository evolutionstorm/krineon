from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
SCORE = PROJECT / "scripts" / "search_score.py"


class SearchScoreTests(unittest.TestCase):
    def test_ablation_deletes_subsystem_that_moves_no_metric(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "campaign.json").write_text("{}\n")
            before = root / "before.json"
            after = root / "after.json"
            vector = {
                "newEdgesPerHour": 4.0,
                "uniqueStackClusters": 2,
                "hoursToFirstRediscovery": 1.5,
            }
            before.write_text(json.dumps({"score": vector}) + "\n")
            after.write_text(json.dumps({"score": vector}) + "\n")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCORE),
                    "compare",
                    str(root),
                    "--subsystem",
                    "name-query",
                    "--before",
                    str(before),
                    "--after",
                    str(after),
                    "--enforce",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 1)
            decision = json.loads(
                (root / "metrics" / "ablations" / "name-query.json").read_text()
            )
            self.assertEqual(decision["verdict"], "delete")

    def test_ablation_keeps_subsystem_when_rediscovery_is_faster(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "campaign.json").write_text("{}\n")
            before = root / "before.json"
            after = root / "after.json"
            before.write_text(
                json.dumps(
                    {
                        "score": {
                            "newEdgesPerHour": 4,
                            "uniqueStackClusters": 2,
                            "hoursToFirstRediscovery": 2,
                        }
                    }
                )
                + "\n"
            )
            after.write_text(
                json.dumps(
                    {
                        "score": {
                            "newEdgesPerHour": 4,
                            "uniqueStackClusters": 2,
                            "hoursToFirstRediscovery": 1,
                        }
                    }
                )
                + "\n"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCORE),
                    "compare",
                    str(root),
                    "--subsystem",
                    "differential",
                    "--before",
                    str(before),
                    "--after",
                    str(after),
                    "--enforce",
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
