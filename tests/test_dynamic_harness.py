from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = PROJECT / "scripts" / "research_harness.py"
DYNAMIC = PROJECT / "scripts" / "dynamic_harness.py"
FIXTURE = PROJECT / "tests" / "fixtures" / "dynamic_target.py"
PRIMITIVE_FIXTURE = PROJECT / "tests" / "fixtures" / "primitive_probe.py"
REALITY = PROJECT / "scripts" / "reality_runner.py"
PRIMITIVE = PROJECT / "scripts" / "primitive_verifier.py"


class DynamicHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.campaign = self.base / "campaign"
        self.target = self.base / "dynamic_target.py"
        self.target.write_bytes(FIXTURE.read_bytes())
        completed = subprocess.run(
            [
                sys.executable,
                str(HARNESS),
                "init",
                str(self.campaign),
                "--target",
                "dynamic-fixture",
                "--repo",
                "https://example.invalid/repository",
                "--commit",
                "0123456789abcdef",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.authorize()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def authorize(self) -> None:
        path = self.campaign / "campaign.json"
        campaign = json.loads(path.read_text())
        campaign["authorization"]["confirmed"] = True
        campaign["authorization"]["basis"] = "owned local test fixture"
        path.write_text(json.dumps(campaign, indent=2) + "\n")

    def run_dynamic(self, *args: str, expected: int = 0, timeout: int = 60) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [sys.executable, str(DYNAMIC), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        self.assertEqual(
            completed.returncode,
            expected,
            msg=f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}",
        )
        return completed

    def target_args(self, *extra: str) -> list[str]:
        return [
            "--name",
            "fixture",
            "--cwd",
            str(self.base),
            "--target-artifact",
            str(self.target),
            "--timeout-ms",
            "2000",
            *extra,
            "--",
            sys.executable,
            str(self.target),
        ]

    def run_input(self, data: bytes, *extra: str) -> tuple[str, dict]:
        input_path = self.base / "single-input.bin"
        input_path.write_bytes(data)
        completed = self.run_dynamic(
            "run",
            str(self.campaign),
            "--input-file",
            str(input_path),
            *self.target_args(*extra),
        )
        run_id = next(line.split(": ", 1)[1] for line in completed.stdout.splitlines() if line.startswith("run: "))
        run_dir = self.campaign / "dynamic" / "runs" / run_id
        return run_id, json.loads((run_dir / "cases" / "00000000" / "result.json").read_text())

    def only_crash(self) -> tuple[str, Path, dict]:
        crashes = list((self.campaign / "dynamic" / "crashes").iterdir())
        self.assertEqual(len(crashes), 1)
        crash_dir = crashes[0]
        return crash_dir.name, crash_dir, json.loads((crash_dir / "crash.json").read_text())

    def test_authorization_is_required(self) -> None:
        path = self.campaign / "campaign.json"
        campaign = json.loads(path.read_text())
        campaign["authorization"]["confirmed"] = False
        path.write_text(json.dumps(campaign))
        input_path = self.base / "input.bin"
        input_path.write_bytes(b"benign")
        completed = self.run_dynamic(
            "run",
            str(self.campaign),
            "--input-file",
            str(input_path),
            *self.target_args(),
            expected=1,
        )
        self.assertIn("authorization.confirmed", completed.stderr)
        self.assertFalse((self.campaign / "dynamic").exists())

    def test_crash_dedup_minimize_replay_and_regression(self) -> None:
        original = b"\xff" + b"unnecessary-payload" * 4
        _, first = self.run_input(original)
        self.assertEqual(first["outcome"], "crash")
        self.assertEqual(first["signal"], "SIGABRT")
        self.run_input(original)

        crash_id, crash_dir, record = self.only_crash()
        self.assertEqual(record["occurrences"], 2)
        self.assertEqual((crash_dir / "input.bin").read_bytes(), original)
        self.assertIn(b"AddressSanitizer", (crash_dir / "stderr.bin").read_bytes())
        self.assertEqual(len((crash_dir / "occurrences.jsonl").read_text().splitlines()), 2)

        self.run_dynamic("replay", "crash", str(self.campaign), crash_id[:12])
        self.run_dynamic("minimize", str(self.campaign), crash_id, "--max-tests", "100")
        self.assertEqual((crash_dir / "minimized.bin").read_bytes(), b"\xff")
        self.run_dynamic("replay", "crash", str(self.campaign), crash_id, "--minimized")
        self.run_dynamic("regression", str(self.campaign))

    def test_file_input_and_coverage_contract(self) -> None:
        input_path = self.base / "coverage-input.bin"
        input_path.write_bytes(b"AA")
        completed = self.run_dynamic(
            "run",
            str(self.campaign),
            "--input-file",
            str(input_path),
            "--name",
            "fixture",
            "--input-mode",
            "file",
            "--cwd",
            str(self.base),
            "--target-artifact",
            str(self.target),
            "--",
            sys.executable,
            str(self.target),
            "{input}",
        )
        run_id = next(line.split(": ", 1)[1] for line in completed.stdout.splitlines() if line.startswith("run: "))
        result = json.loads(
            (
                self.campaign
                / "dynamic"
                / "runs"
                / run_id
                / "cases"
                / "00000000"
                / "result.json"
            ).read_text()
        )
        self.assertEqual(result["outcome"], "ok")
        self.assertEqual(result["coverage"], ["entry", "prefix:A", "prefix:AA"])
        self.assertIn(result["platform"]["architecture"], {"arm64", "x86_64"})
        self.assertIn("resourceLimits", result)

    def test_timeout_and_nonzero_are_distinct_from_crashes(self) -> None:
        _, timeout = self.run_input(b"SLEEP", "--timeout-ms", "100")
        self.assertEqual(timeout["outcome"], "timeout")
        self.assertTrue(timeout["timedOut"])

        _, exit_result = self.run_input(b"EXIT")
        self.assertEqual(exit_result["outcome"], "exit")
        self.assertNotIn("fingerprint", exit_result)

        _, crash_result = self.run_input(b"EXIT", "--crash-on-nonzero")
        self.assertEqual(crash_result["outcome"], "crash")
        self.assertIn("fingerprint", crash_result)

    def test_fuzzing_is_deterministic_and_discovers_a_crash(self) -> None:
        seed = self.base / "seed.bin"
        seed.write_bytes(b"\x00")
        run_ids = []
        for _ in range(2):
            completed = self.run_dynamic(
                "fuzz",
                str(self.campaign),
                "--seed-file",
                str(seed),
                "--iterations",
                "256",
                "--rng-seed",
                "7",
                "--stop-on-crash",
                "--no-load-corpus",
                *self.target_args(),
                timeout=120,
            )
            self.assertIn("unique crashes seen: 1", completed.stdout)
            run_ids.append(
                next(line.split(": ", 1)[1] for line in completed.stdout.splitlines() if line.startswith("run: "))
            )

        event_inputs = []
        for run_id in run_ids:
            run_dir = self.campaign / "dynamic" / "runs" / run_id
            events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text().splitlines()]
            event_inputs.append([event["inputSha256"] for event in events])
            record = json.loads((run_dir / "run.json").read_text())
            self.assertEqual(record["status"], "completed")
            self.assertGreaterEqual(record["summary"]["coverageEdges"], 1)
        self.assertEqual(event_inputs[0], event_inputs[1])
        _, _, record = self.only_crash()
        self.assertEqual(record["occurrences"], 2)

    def test_output_limit_does_not_create_a_crash(self) -> None:
        _, result = self.run_input(b"NOISY", "--max-output-bytes", "64")
        self.assertEqual(result["outcome"], "ok")
        self.assertEqual(result["stdoutSize"], 100000)
        self.assertEqual(result["stdoutCapturedSize"], 64)
        self.assertTrue(result["stdoutTruncated"])

    def test_sanitizer_detection_is_anchored_and_does_not_need_a_signal(self) -> None:
        _, benign = self.run_input(b"BENIGN")
        self.assertEqual(benign["outcome"], "ok")
        _, sanitizer = self.run_input(b"SANITIZER")
        self.assertEqual(sanitizer["outcome"], "crash")
        self.assertIn("AddressSanitizer", sanitizer["sanitizer"])

    def test_no_output_crashes_and_distinct_stacks_do_not_merge(self) -> None:
        self.run_input(b"CRASH1")
        self.run_input(b"CRASH2")
        self.run_input(b"\xff")
        self.run_input(b"\xfe")
        crash_dirs = list((self.campaign / "dynamic" / "crashes").iterdir())
        self.assertEqual(len(crash_dirs), 4)

    def test_first_fault_labels_do_not_imply_control_and_clusters_grow(self) -> None:
        self.run_input(b"UAFWRITE-one")
        self.run_input(b"OOBREAD-two")
        records = []
        for crash_dir in (self.campaign / "dynamic" / "crashes").iterdir():
            triage = json.loads((crash_dir / "triage.json").read_text())
            records.append(triage)
        self.assertEqual(len(records), 2)
        by_class = {item["firstFault"]["class"]: item for item in records}
        uaf = by_class["heap-use-after-free"]
        oob = by_class["heap-buffer-overflow"]
        self.assertEqual(uaf["firstFault"]["access"], "write")
        self.assertEqual(oob["firstFault"]["access"], "read")
        self.assertEqual(
            uaf["automatedExploitability"]["verdict"],
            "unverified-lifetime-write-lead",
        )
        self.assertEqual(
            oob["automatedExploitability"]["verdict"],
            "potential-read-primitive",
        )
        self.assertFalse(uaf["automatedExploitability"]["machinePromotionEligible"])
        self.assertEqual(uaf["controlEvidence"]["status"], "unverified")
        self.assertFalse(uaf["controlEvidence"]["chosenBytes"])
        self.assertEqual(uaf["stack"]["clusterId"], oob["stack"]["clusterId"])
        index = json.loads(
            (self.campaign / "dynamic" / "triage" / "index.json").read_text()
        )
        self.assertEqual(index["crashCount"], 2)
        self.assertEqual(index["clusterCount"], 1)
        self.assertEqual(len(index["clusters"][0]["crashIds"]), 2)

    def test_control_flow_evidence_is_prioritized_but_never_auto_promoted(self) -> None:
        _, result = self.run_input(b"PCCTRL")
        crash_dir = self.campaign / "dynamic" / "crashes" / result["fingerprint"]
        triage = json.loads((crash_dir / "triage.json").read_text())
        self.assertEqual(triage["firstFault"]["class"], "control-flow-corruption")
        self.assertEqual(triage["firstFault"]["access"], "execute")
        self.assertEqual(triage["controlEvidence"]["status"], "unverified")
        self.assertFalse(triage["controlEvidence"]["chosenProgramCounter"])
        self.assertEqual(
            triage["automatedExploitability"]["verdict"],
            "unverified-control-flow-corruption-lead",
        )
        self.assertFalse(triage["automatedExploitability"]["machinePromotionEligible"])

    def test_triage_cli_links_machine_verdict_to_finding_gate(self) -> None:
        _, result = self.run_input(b"UAFWRITE-link")
        registered = subprocess.run(
            [
                sys.executable,
                str(HARNESS),
                "register",
                str(self.campaign),
                "F900",
                "--title",
                "Triage linkage fixture",
                "--lane",
                "v8-crash-triage",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(registered.returncode, 0, registered.stderr)
        self.run_dynamic(
            "triage",
            str(self.campaign),
            "--crash-id",
            result["fingerprint"][:16],
            "--finding-id",
            "F900",
            "--reviewed-by",
            "reviewer-a",
            "--review-note",
            "The sanitizer establishes a reproducible write-oriented lifetime lead, not RCE.",
            "--json",
        )
        finding = json.loads(
            (self.campaign / "findings" / "F900.json").read_text()
        )
        linked = finding["dynamicTriage"]
        self.assertTrue(linked["required"])
        self.assertTrue(linked["reviewed"])
        self.assertEqual(linked["crashIds"], [result["fingerprint"]])
        self.assertEqual(
            linked["machineVerdicts"][result["fingerprint"]],
            "unverified-lifetime-write-lead",
        )
        self.assertTrue(finding["gates"]["automated_triage_reviewed"])
        gate = subprocess.run(
            [
                sys.executable,
                str(HARNESS),
                "gate",
                str(self.campaign),
                "F900",
                "--level",
                "candidate",
                "--json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(gate.returncode, 1)
        gate_result = json.loads(gate.stdout)
        self.assertIn(
            f"dynamicTriage.unverifiedPrimitive:{result['fingerprint']}",
            gate_result["missingFields"],
        )

    def test_uaf_control_requires_chosen_bytes_allocation_identity_and_stability(self) -> None:
        _, result = self.run_input(b"UAFWRITE-reality")
        crash_id = result["fingerprint"]
        probe = self.campaign / "evidence" / "bin" / "primitive_probe.py"
        probe.parent.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(PRIMITIVE_FIXTURE.read_bytes())
        recipe = self.campaign / "evidence" / "recipes" / "primitive.json"
        recipe.parent.mkdir(parents=True, exist_ok=True)
        recipe.write_text(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "findingId": "FPRIM",
                    "targetArtifacts": ["evidence/bin/primitive_probe.py"],
                    "subjectArtifact": "evidence/bin/primitive_probe.py",
                    "subjectArgvIndex": 1,
                    "cases": [
                        {
                            "name": name,
                            "command": [sys.executable, "evidence/bin/primitive_probe.py"],
                            "assertions": assertions,
                        }
                        for name, assertions in (
                            ("baseline", [{"id": "baseline-no-write", "kind": "no-memory-write"}]),
                            ("negative", [{"id": "negative-no-write", "kind": "no-memory-write"}]),
                            (
                                "positive",
                                [{"id": "chosen-uaf-write", "kind": "controlled-write", "claim": "uaf-write"}],
                            ),
                        )
                    ],
                },
                indent=2,
            )
            + "\n"
        )
        execution = subprocess.run(
            [
                sys.executable,
                str(REALITY),
                str(self.campaign),
                "FPRIM",
                "--recipe",
                recipe.relative_to(self.campaign).as_posix(),
                "--worker-id",
                "primitive-reviewer",
                "--role",
                "reviewer",
                "--repetitions",
                "3",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(execution.returncode, 0, execution.stderr)
        attestation = json.loads(execution.stdout)
        verified = subprocess.run(
            [
                sys.executable,
                str(PRIMITIVE),
                str(self.campaign),
                crash_id,
                "--attestation",
                attestation["attestation"],
                "--claim",
                "uaf-write",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr)
        self.run_dynamic("triage", str(self.campaign), "--crash-id", crash_id)
        triage = json.loads(
            (self.campaign / "dynamic" / "crashes" / crash_id / "triage.json").read_text()
        )
        self.assertEqual(triage["controlEvidence"]["status"], "verified")
        self.assertTrue(triage["controlEvidence"]["chosenBytes"])
        self.assertTrue(triage["controlEvidence"]["allocationIdentity"])
        self.assertTrue(triage["controlEvidence"]["crossProcessStability"])
        self.assertEqual(
            triage["automatedExploitability"]["verdict"],
            "verified-chosen-byte-uaf-write",
        )

    def test_case_replay_compares_the_recorded_result(self) -> None:
        run_id, original = self.run_input(b"AA")
        self.assertEqual(original["outcome"], "ok")
        self.run_dynamic("replay", "case", str(self.campaign), run_id, "0")

    def test_dynamic_artifacts_are_in_the_campaign_manifest(self) -> None:
        run_id, _ = self.run_input(b"AA")
        completed = subprocess.run(
            [sys.executable, str(HARNESS), "hash", str(self.campaign)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        manifest = (self.campaign / "SHA256SUMS").read_text()
        self.assertIn(f"dynamic/runs/{run_id}/cases/00000000/input.bin", manifest)
        self.assertIn(f"dynamic/runs/{run_id}/run.json", manifest)

    def test_persistent_corpus_is_loaded_by_default(self) -> None:
        first_seed = self.base / "first-seed.bin"
        second_seed = self.base / "second-seed.bin"
        first_seed.write_bytes(b"A")
        second_seed.write_bytes(b"B")
        self.run_dynamic(
            "fuzz",
            str(self.campaign),
            "--seed-file",
            str(first_seed),
            "--iterations",
            "0",
            "--no-load-corpus",
            *self.target_args(),
        )
        self.run_dynamic(
            "fuzz",
            str(self.campaign),
            "--seed-file",
            str(second_seed),
            "--iterations",
            "0",
            *self.target_args(),
        )
        runs = []
        for path in (self.campaign / "dynamic" / "runs").iterdir():
            record = json.loads((path / "run.json").read_text())
            if record["kind"] == "fuzz":
                runs.append(record)
        second = max(runs, key=lambda record: record["createdAt"])
        self.assertEqual(len(second["loadedCorpus"]), 1)
        self.assertEqual(second["summary"]["cases"], 2)

    def test_replay_refuses_a_changed_target(self) -> None:
        self.run_input(b"\xffpayload")
        crash_id, _, _ = self.only_crash()
        self.target.write_bytes(self.target.read_bytes() + b"\n# changed after recording\n")
        completed = self.run_dynamic("replay", "crash", str(self.campaign), crash_id, expected=1)
        self.assertIn("target artifact changed", completed.stderr)


if __name__ == "__main__":
    unittest.main()
