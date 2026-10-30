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

For JavaScript framework inputs, prefer the built-in semantic generators. They
cover JSON, URLs, ordered duplicate headers, multipart, RSC, Server Actions,
and manifests, and retain a semantic-group hash across representation variants:

```bash
python3 scripts/fuzzer_orchestrator.py framework-generate CAMPAIGN parser \
  --spec generator.json --count 1000 --seed 1
```

For persistent Node execution and native V8/Istanbul coverage, including
source-map remapping and Next.js server/client boundary classification, read
[javascript-coverage-generation.md](javascript-coverage-generation.md) and use
`scripts/js_coverage_harness.py`. Manual `KRINEON_COVERAGE_FILE` hooks remain a
fixture/debugging contract; they are not required for JavaScript targets.

## Launch native parallel workers

```bash
python3 scripts/fuzzer_orchestrator.py launch CAMPAIGN parser \
  --workers 16 --duration-seconds 21600 \
  --sync-interval-seconds 30 --plateau-seconds 900 --forward-crashes
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
`dynamic_harness.py run`. A reproducing crash is minimized before triage, then
deduplicated by its normalized stack hash. Only the first minimized
representative of a stack cluster can create a validation task. OOM, timeout,
assertion, duplicate-stack, and non-reproducing artifacts remain recorded but
do not enter the queue.

Each run retains a native edge timeline, new edges per hour, corpus growth, and
the seconds since the last new edge. `plateau.reached` is data, not a reason to
stop: use it to redirect structured generation toward the next measured
coverage hole.

## Rebuild coverage from the retained corpus

AFL edge reconstruction:

```bash
python3 scripts/fuzzer_orchestrator.py coverage-rebuild CAMPAIGN parser \
  --mode afl-showmap --tool /owned/afl/bin/afl-showmap \
  --edge-universe CAMPAIGN/tools/parser-edge-universe.json
```

LLVM source coverage reconstruction:

```bash
python3 scripts/fuzzer_orchestrator.py coverage-rebuild CAMPAIGN parser \
  --mode llvm --llvm-profdata /owned/llvm/bin/llvm-profdata \
  --llvm-cov /owned/llvm/bin/llvm-cov
```

The first mode executes every canonical input through `afl-showmap` and stores
the union of edge IDs. The second emits one `.profraw` file per input, merges
them, retains `llvm-cov export`, and derives stable covered-region IDs. Each
rebuild records new edges and new edges per hour. An optional hashed edge
universe produces `coverage-holes.json`; the highest uncovered edge becomes the
next structured-generation task. Coverage remains exploration evidence, not a
proof that an unvisited path is safe.

Take score snapshots before and after changing a subsystem:

```bash
python3 scripts/search_score.py snapshot CAMPAIGN \
  --profile parser --benchmark frozen-oracles --output before.json
python3 scripts/search_score.py compare CAMPAIGN \
  --subsystem grammar-mutator --before before.json --after after.json --enforce
```

If the subsystem improves neither edge velocity, unique stack clusters, nor
hours-to-rediscover, remove it from the campaign.

## Operational boundaries

Run fuzzers inside disposable workers. Process limits and output caps do not
provide filesystem or network containment. Keep source/build storage and the
canonical corpus persistent, but do not place cloud credentials, personal
profiles, or unrelated data in the worker image. Stop and preserve state when
the program's authorization or infrastructure budget is reached.
