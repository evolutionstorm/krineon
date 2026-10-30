# Frozen-corpus rediscovery benchmark

## What it measures

Krineon does not treat a lane description, task count, crash count, or generated
report as evidence that its search method works. The empirical metric is:

- elapsed seconds and hours from process start to the first independently
  matched target-owned oracle;
- recall across all evaluator-selected oracles; and
- the exact frozen corpus, target artifacts, command, stdout, stderr, and
  hashes used for that run.

An unmeasured profile is a collection of research hypotheses. It may be useful,
but its efficacy is documentation only.

## Oracle boundary

An oracle must come from the pinned target revision itself:

- a checked-in regression or conformance test;
- an assertion that names an invariant;
- a fuzz target with a concrete target-owned failure condition; or
- a checked-in fixture that distinguishes valid from invalid behavior.

Do not construct the oracle by reading a fixing commit, security patch,
advisory, issue report, changelog, or another revision. The benchmark is not an
n-day rediscovery exercise.

The evaluator keeps the oracle JSON outside the worker workspace. Krineon
records its SHA-256 and count but does not copy oracle identities into the
campaign. Filesystem permissions and worker isolation remain the evaluator's
responsibility; a process that can read the sealed file is not blind.

Oracle format:

```json
{
  "oracles": [
    {
      "id": "target-test-001",
      "basis": "target-test",
      "sourcePath": "test/regress/example.cc",
      "sourceSha256": "required SHA-256; recomputed when frozen and run",
      "identity": "invariant:stable-semantic-identity-produced-by-search"
    }
  ]
}
```

`basis` is limited to `target-test` and `target-invariant`.

## Search event protocol

The search command receives:

- `KRINEON_BENCHMARK_CORPUS`;
- `KRINEON_BENCHMARK_CHECKOUT`; and
- `KRINEON_BENCHMARK_NAME`.

It emits one JSON object per line. A rediscovery event needs an `identity`
matching the semantic identity the independent evaluator derived from the
target-owned oracle:

```json
{"identity":"invariant:...","artifact":"campaign-relative-lead.json"}
```

The runner timestamps the first matching line while the process is running. It
does not trust a worker-supplied elapsed time.

## Commands

```bash
python3 scripts/rediscovery_benchmark.py freeze CAMPAIGN NAME \
  --checkout /pinned/target \
  --corpus /owned/corpus \
  --sealed-oracles /evaluator/oracles.json \
  --target-artifact /pinned/target/out/release-target

python3 scripts/rediscovery_benchmark.py run CAMPAIGN NAME \
  --sealed-oracles /evaluator/oracles.json \
  --command-json '["/owned/search-driver","--jsonl"]' \
  --timeout-seconds 21600

python3 scripts/rediscovery_benchmark.py status CAMPAIGN NAME
```

Mutation of the frozen corpus, target artifacts, oracle file, or target-owned
oracle source invalidates the run.

## Interpretation

Report the number as observed, including failures:

- `hoursToFirstRediscovery: null` means no oracle was rediscovered before the
  command exited or timed out;
- recall is matched-oracle count divided by frozen oracle count; and
- results apply only to the recorded target revision, corpus, resources,
  timeout, toolchain, and search command.

Do not extrapolate one successful benchmark into universal effectiveness. Use
multiple frozen corpora and retain unsuccessful runs.
