# External coverage-guided fuzzing

`dynamic_harness.py fuzz` is a deterministic smoke mutator for checking target
plumbing and replay. It is not the zero-day fuzzing engine. Serious campaigns
use `scripts/fuzzer_orchestrator.py` with a pinned AFL++, libFuzzer, or Fuzzilli
binary and a separately pinned instrumented target.

The orchestrator never downloads a tool or silently patches a target. It runs
only in an authorized `source` or `local-lab` campaign and retains the exact
engine, target, instrumentation, commands, corpus transitions, crashes, and
coverage rebuilds.

## Register and instrument

Register an exact tool/target pair. A libFuzzer target contains its own engine,
so `--engine-binary` is unnecessary:

```bash
python3 scripts/fuzzer_orchestrator.py register CAMPAIGN parser \
  --engine libfuzzer --target /owned/out/parser_fuzzer \
  --revision TARGET_AND_TOOL_REVISION
```

Build through the orchestrator so compiler instrumentation is explicit and
retained:

```bash
python3 scripts/fuzzer_orchestrator.py instrument CAMPAIGN parser \
  --kind libfuzzer-clang \
  --build-command-json '["ninja","-C","out/asan","parser_fuzzer"]' \
  --verify-command-json '["out/asan/parser_fuzzer","-help=1"]'
```

Supported injected environments are:

- `afl-clang-fast`: `afl-clang-fast`/`afl-clang-fast++`, ASan, and CmpLog;
- `libfuzzer-clang`: `fuzzer-no-link` compile flags plus fuzzer/ASan/UBSan
  link flags;
- `sanitizer-coverage`: ASan/UBSan plus trace-pc-guard, trace-cmp,
  indirect-call, and counter instrumentation;
- `fuzzilli-reprl`: a recorded target-specific REPRL build command. Because
  REPRL switches differ by engine, the command and verification evidence must
  come from the pinned source's supported build configuration. The command
  token `{instrumentation_flags}` expands to `v8_enable_fuzzilli=true`; this
  mode also requires a verification command and an expected output marker.

If the target was already instrumented, register it with
`--preinstrumented-kind` and at least one hashed
`--instrumentation-evidence` artifact. `launch` refuses profiles without
verified instrumentation.

Fuzzing builds are diagnostic artifacts. Reproduce promoted behavior in the
separate release/stock build before claiming production impact.

## Harvest and generate seeds

Harvest checked-in tests, parser fixtures, examples, and existing corpora with
content deduplication and provenance:

```bash
python3 scripts/fuzzer_orchestrator.py seed-harvest CAMPAIGN parser \
  --source /owned/source/testdata --source /owned/source/tests \
  --extension .json --extension .bin
```

For grammars, AST emitters, protocol state-sequence generators, Wasm builders,
or other structured producers, pass a JSON command array. No shell is used.
The tokens `{output}`, `{index}`, `{seed}`, and `{corpus}` are available:

```bash
python3 scripts/fuzzer_orchestrator.py structured-generate CAMPAIGN parser \
  --command-json '["python3","tools/generate.py","--seed","{seed}","--out","{output}"]' \
  --count 10000 --seed 1 --suffix .json
```

Fuzzilli is itself the structured JavaScript/state-sequence generator. Do not
flatten its programs into byte-mutation inputs merely to fit the smoke mutator.

## Launch native parallel workers

```bash
python3 scripts/fuzzer_orchestrator.py launch CAMPAIGN parser \
  --workers 16 --duration-seconds 21600 \
  --sync-interval-seconds 30 --forward-crashes
```

Parallelism follows each engine's native model:

- libFuzzer uses one coordinator with `-jobs` and `-workers` against the
  canonical shared corpus;
- AFL++ launches one `-M` master and multiple `-S` secondaries in one sync
  directory;
- Fuzzilli uses native `--jobs` and a persistent storage corpus.

Each process has an isolated output directory and bounded stdout/stderr.
Corpus inputs are content-addressed under
`dynamic/fuzzers/PROFILE/corpus/`; provenance is append-only and protected by
an advisory file lock. The launch record retains initial and final corpus
digests, commands, engine stats, exact artifacts, worker exits, and crash
origins. `sync` can import queues/corpora from completed or externally copied
runs:

The built-in globs follow standard engine layouts. When a pinned engine version
uses another layout, register explicit repeatable `--corpus-glob` and
`--crash-glob` patterns rather than copying artifacts by hand.

```bash
python3 scripts/fuzzer_orchestrator.py sync CAMPAIGN parser --forward-crashes
```

External crash files are leads. `--forward-crashes` replays each with
`dynamic_harness.py run`; only a replay that produces a Krineon crash ID enters
`dynamic/crashes/` and automatic first-fault triage. OOM, timeout, assertion,
and non-reproducing artifacts stay visibly unconfirmed.

## Rebuild coverage from the retained corpus

AFL edge reconstruction:

```bash
python3 scripts/fuzzer_orchestrator.py coverage-rebuild CAMPAIGN parser \
  --mode afl-showmap --tool /owned/afl/bin/afl-showmap
```

LLVM source coverage reconstruction:

```bash
python3 scripts/fuzzer_orchestrator.py coverage-rebuild CAMPAIGN parser \
  --mode llvm --llvm-profdata /owned/llvm/bin/llvm-profdata \
  --llvm-cov /owned/llvm/bin/llvm-cov
```

The first mode executes every canonical input through `afl-showmap` and stores
the union of edge IDs. The second emits one `.profraw` file per input, merges
them, and retains `llvm-cov export` output. Coverage is evidence about explored
code, not proof that an unvisited path is safe. Rebuild after material corpus
growth and use the gaps to redirect structured generators and source-derived
seed harvesting.

## Operational boundaries

Run fuzzers inside disposable workers. Process limits and output caps do not
provide filesystem or network containment. Keep source/build storage and the
canonical corpus persistent, but do not place cloud credentials, personal
profiles, or unrelated data in the worker image. Stop and preserve state when
the program's authorization or infrastructure budget is reached.
