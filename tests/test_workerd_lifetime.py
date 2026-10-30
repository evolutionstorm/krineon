from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "scripts"))
from reality_evidence import evaluate_assertion
from semantic_hypothesis_loop import derive_models

ANALYSIS = PROJECT / "scripts" / "workerd_lifetime_analysis.py"
ORACLE = PROJECT / "scripts" / "workerd_lifetime_oracle.py"


class WorkerdLifetimeTests(unittest.TestCase):
    def test_source_analysis_emits_operational_native_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "workerd"
            checkout.mkdir()
            (checkout / "fixture.c++").write_text(
                "struct Holder {\n"
                "  jsg::V8Ref<v8::Value> value;\n"
                "  void visitForGc(Visitor& visitor) { visitor.touch(other); }\n"
                "};\n"
                "void moveHandle() { auto next = kj::mv(handle); consume(handle); }\n"
                "void borrowValue() { auto ptr = owner.get(); callback(); consume(ptr); }\n"
                "void bufferValue() { auto ptr = buffer.Data(); callback(); consume(ptr); }\n"
                "void cancelRequest() { onCancel(callback); }\n"
                "void scheduleIo() { IoContext* context; promise.then(callback); }\n",
                encoding="utf-8",
            )
            output = root / "analysis.json"
            completed = subprocess.run(
                [sys.executable, str(ANALYSIS), "--checkout", str(checkout), "--output", str(output)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            record = json.loads(output.read_text())
            families = set(record["families"])
            self.assertTrue(
                {
                    "missing-gc-visitation",
                    "traced-handle-move",
                    "borrowed-pointer-js-reentry",
                    "arraybuffer-detach-resize-ownership",
                    "cancellation-destructor-ordering",
                    "iocontext-affinity",
                }.issubset(families)
            )
            self.assertFalse(record["vulnerabilityVerdictsProduced"])
            self.assertTrue(all(value["instrumentation"] for value in record["candidates"]))
            models = derive_models(record)
            self.assertTrue(models)
            self.assertTrue(all(value["ecosystem"] == "workerd" for value in models))

    def test_runtime_oracle_detects_each_invariant_and_retains_raw_trace_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace = root / "trace.jsonl"
            events = [
                {"event": "register-traced", "object": "holder", "field": "value"},
                {"event": "gc-begin"},
                {"event": "gc-end"},
                {"event": "handle-use", "object": "holder", "field": "value", "alive": False},
                {"event": "handle-move", "from": "h1", "to": "h2", "generation": 4},
                {"event": "handle-use", "handle": "h1", "generation": 4},
                {"event": "owner-register", "object": "owner", "generation": 1},
                {"event": "borrow", "object": "owner", "pointer": "p1", "generation": 1},
                {"event": "js-reentry"},
                {"event": "owner-generation", "object": "owner", "generation": 2},
                {"event": "pointer-use", "pointer": "p1"},
                {"event": "object-register", "object": "request"},
                {"event": "cancel-or-destroy", "object": "request"},
                {"event": "callback-enter", "object": "request"},
                {"event": "buffer-register", "object": "buffer", "generation": 1},
                {"event": "pointer-acquire", "object": "buffer", "pointer": "p2", "generation": 1},
                {"event": "buffer-detach-or-resize", "object": "buffer", "generation": 2},
                {"event": "pointer-use", "pointer": "p2"},
                {"event": "io-schedule", "callback": "cb", "context": "io-a"},
                {"event": "callback-enter", "callback": "cb", "context": "io-b", "explicitTransfer": False},
            ]
            trace.write_text("".join(json.dumps(value) + "\n" for value in events), encoding="utf-8")
            output = root / "oracle.json"
            completed = subprocess.run(
                [sys.executable, str(ORACLE), "--trace", str(trace), "--output", str(output)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 1, completed.stderr)
            record = json.loads(output.read_text())
            self.assertEqual(
                {value["family"] for value in record["confirmedDisagreements"]},
                {
                    "missing-gc-visitation",
                    "traced-handle-move",
                    "borrowed-pointer-js-reentry",
                    "arraybuffer-detach-resize-ownership",
                    "cancellation-destructor-ordering",
                    "iocontext-affinity",
                },
            )
            self.assertEqual(record["outcome"], "confirmed-invariant-disagreement")
            self.assertFalse(record["vulnerabilityVerdictProduced"])
            self.assertRegex(record["trace"]["sha256"], r"^[0-9a-f]{64}$")

    def test_runtime_oracle_distinguishes_preservation_from_missing_telemetry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def invoke(name: str, events: list[dict[str, object]], expected: int) -> dict:
                trace = root / f"{name}.jsonl"
                output = root / f"{name}.json"
                trace.write_text(
                    "".join(json.dumps(value) + "\n" for value in events),
                    encoding="utf-8",
                )
                completed = subprocess.run(
                    [sys.executable, str(ORACLE), "--trace", str(trace), "--output", str(output)],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(completed.returncode, expected, completed.stderr)
                return json.loads(output.read_text())

            preserved = invoke(
                "preserved",
                [
                    {"event": "register-traced", "object": "holder", "field": "value"},
                    {"event": "gc-begin"},
                    {"event": "gc-visit", "object": "holder", "field": "value"},
                    {"event": "gc-end"},
                    {"event": "handle-use", "object": "holder", "field": "value", "alive": True},
                    {"event": "handle-move", "from": "h1", "to": "h2", "generation": 1},
                    {"event": "handle-use", "handle": "h1", "generation": 2},
                    {"event": "owner-register", "object": "owner", "generation": 1},
                    {"event": "borrow", "object": "owner", "pointer": "p1", "generation": 1},
                    {"event": "js-reentry"},
                    {"event": "owner-generation", "object": "owner", "generation": 1},
                    {"event": "pointer-use", "pointer": "p1"},
                    {"event": "object-register", "object": "request"},
                    {"event": "callback-enter", "object": "request"},
                    {"event": "buffer-register", "object": "buffer", "generation": 1},
                    {"event": "pointer-acquire", "object": "buffer", "pointer": "p2", "generation": 1},
                    {"event": "buffer-generation", "object": "buffer", "generation": 1},
                    {"event": "pointer-use", "pointer": "p2"},
                    {"event": "io-schedule", "callback": "cb", "context": "io-a"},
                    {"event": "callback-enter", "callback": "cb", "context": "io-a", "explicitTransfer": False},
                    {"event": "trace-end"},
                ],
                0,
            )
            self.assertEqual(preserved["outcome"], "observed-invariant-preservation")
            self.assertFalse(preserved["confirmedDisagreements"])
            self.assertFalse(preserved["inconclusive"])

            incomplete = invoke(
                "incomplete",
                [
                    {"event": "owner-register", "object": "owner", "generation": 1},
                    {"event": "borrow", "object": "owner", "pointer": "p1", "generation": 1},
                    {"event": "js-reentry"},
                    {"event": "pointer-use", "pointer": "p1"},
                    {"event": "buffer-register", "object": "buffer", "generation": 1},
                    {"event": "pointer-acquire", "object": "buffer", "pointer": "p2", "generation": 1},
                    {"event": "pointer-use", "pointer": "p2"},
                    {"event": "trace-end"},
                ],
                3,
            )
            self.assertEqual(incomplete["outcome"], "inconclusive-missing-telemetry")
            self.assertFalse(incomplete["confirmedDisagreements"])
            self.assertEqual(
                {value["family"] for value in incomplete["inconclusive"]},
                {
                    "borrowed-pointer-js-reentry",
                    "arraybuffer-detach-resize-ownership",
                },
            )
            borrow = next(
                value
                for value in incomplete["inconclusive"]
                if value["family"] == "borrowed-pointer-js-reentry"
            )
            self.assertEqual(
                borrow["missingTelemetry"], ["owner-generation after js-reentry"]
            )

    def test_target_authored_json_cannot_prove_controlled_pc(self) -> None:
        challenge = "0000414141414141"
        stdout = json.dumps(
            {"targetPid": 1234, "requestedPc": challenge, "observedPc": challenge}
        ).encode()
        matched, observed = evaluate_assertion(
            {"id": "pc", "kind": "controlled-pc"},
            return_code=-11,
            process_id=1234,
            challenge_hex=challenge,
            stdout=stdout,
            stderr=b"",
        )
        self.assertFalse(matched)
        self.assertIn("trusted debugger", observed["error"])


if __name__ == "__main__":
    unittest.main()
