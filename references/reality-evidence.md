# Executable reality evidence

Krineon distinguishes three things that were previously conflated:

- a first-fault label says what the sanitizer reported;
- a primitive attestation says which bytes, allocation generation, or program
  counter value an experiment actually observed;
- a path proof says how attacker input reaches the terminal and which runtime
  assertions witnessed every selected transition and branch.

None can substitute for the others.

## Reality recipe

Store a schema-version 1 recipe under `evidence/recipes/`. It must declare
hashed target artifacts and exactly three cases: `baseline`, `negative`, and
`positive`. Commands are argument vectors and never run through a shell.

```json
{
  "schemaVersion": 1,
  "findingId": "F001",
  "targetArtifacts": ["evidence/bin/owned-probe"],
  "subjectArtifact": "evidence/bin/owned-probe",
  "subjectArgvIndex": 0,
  "cases": [
    {
      "name": "baseline",
      "command": ["evidence/bin/owned-probe", "{case}", "{challengeHex}"],
      "assertions": [
        {"id": "baseline-ok", "kind": "exit-code", "equals": 0}
      ]
    },
    {
      "name": "negative",
      "command": ["evidence/bin/owned-probe", "{case}", "{challengeHex}"],
      "assertions": [
        {"id": "negative-blocked", "kind": "stdout-not-contains", "value": "terminal:"}
      ]
    },
    {
      "name": "positive",
      "command": ["evidence/bin/owned-probe", "{case}", "{challengeHex}"],
      "assertions": [
        {"id": "terminal", "kind": "stdout-contains-challenge"}
      ]
    }
  ]
}
```

Run it separately for the originator and reviewer. The runner generates each
challenge after invocation, launches every case in a distinct process, and
retains raw stdout and stderr.

```bash
python3 scripts/reality_runner.py CAMPAIGN F001 \
  --recipe evidence/recipes/F001.json --worker-id worker-a --role originator
```

The validator re-reads the recipe and raw bytes, re-hashes the targets, and
recomputes assertions. `subjectArgvIndex` binds the actual executed argument to
the reviewed target, so merely mentioning a target path in an unused argument
does not satisfy the gate. Editing `matched: true` does not make an assertion
pass.

For queue submissions, the worker proposes the recipe. The coordinator records
and signs an approval containing the recipe hash, frozen target hashes, exact
subject binding, repetitions, and timeout. It then executes the recipe outside
the scheduler write transaction. Each process starts in its own process group;
a timeout kills the group, including descendants. The controlled runner signs
an observation that binds the approval, machine attestation, and every raw
stdout and stderr hash. Candidate promotion verifies those signatures and
hashes again. The worker workspace never receives the private signing key.

## Memory and PC observations

For a UAF-write claim, use at least three repetitions for every case. Positive
observations must contain:

- a launched-process PID;
- the original allocation address, size, allocation ID, generation, and
  allocation-stack hash;
- the replacement allocation with the same address but a different ID and
  generation;
- the exact write address and before/after bytes; and
- after-bytes equal to the runner's fresh challenge.

Baseline and negative observations must report no write. Then bind the result
to the crash:

```bash
python3 scripts/primitive_verifier.py CAMPAIGN CRASH_ID \
  --attestation evidence/machine-runs/F001/RUN/attestation.json \
  --claim uaf-write
python3 scripts/dynamic_harness.py triage CAMPAIGN --crash-id CRASH_ID
```

`controlled-pc` does not accept a JSON observation written by the target. The
case must declare an operating-system-managed GDB or LLDB observer:

```json
{
  "name": "positive",
  "command": ["evidence/bin/owned-probe", "{challengeHex}"],
  "stdinTemplate": "",
  "observer": {"kind": "debugger", "tool": "gdb"},
  "assertions": [{"id": "chosen-pc", "kind": "controlled-pc"}]
}
```

Run PC recipes with `--challenge-bytes 8`. The runner chooses a fresh canonical
48-bit address, launches the subject under a root-owned, non-writable system
debugger, and retains raw debugger output plus debugger binary and version
hashes. Validation re-checks the trust policy, hashes, target PID, and register
value. An echo program that prints the requested PID or PC cannot pass. A
sanitizer address, one constant marker, or repeated crashes at one address do
not establish control.

## Trust boundary

This machinery makes evidence recomputable; it does not magically make every
custom allocator or engine observer correct. Chosen-PC evidence is deliberately
limited to trusted debugger output. For allocation identity and engine state,
retain instrumentation as a separate reviewed artifact and require a second,
independent invariant that does not derive the claimed value from the expected
result.
The adversarial reviewer should try to replace the target with an echo program;
if the recipe would still pass, the assertion is not a useful security proof.
The reviewer must also identify how the observer itself could lie or
misclassify the result and bind an alternate assertion from the reviewer run.
Repeating the original assertion without that observer challenge does not pass
independent replay.
