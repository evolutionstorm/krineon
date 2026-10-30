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
recomputes assertions. Editing `matched: true` does not make an assertion pass.

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

`controlled-pc` similarly requires the requested and observed PC to equal the
fresh challenge across repeated processes. A sanitizer address, one constant
marker, or repeated crashes at one address do not establish control.

## Trust boundary

This machinery makes evidence recomputable; it does not magically make a
custom observer correct. Retain the observer as a hashed target artifact,
review its source, and prefer debugger, sanitizer, allocator, or engine-native
observations that do not derive the claimed value from the expected result.
The adversarial reviewer should try to replace the target with an echo program;
if the recipe would still pass, the assertion is not a useful security proof.
