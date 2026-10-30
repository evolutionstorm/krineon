# JavaScript coverage and semantic generation

Use `scripts/js_coverage_harness.py` for framework entry points that run in
Node or consume browser bundles. It loads the target module once per worker and
sends many inputs over JSONL, avoiding a process and module initialization for
every input.

```bash
python3 scripts/js_coverage_harness.py CAMPAIGN js-coverage.json \
  CAMPAIGN/evidence/js-coverage/run-01 \
  --previous-coverage CAMPAIGN/evidence/js-coverage/run-00/edge-ids.txt \
  --edge-universe edge-universe.json
```

The worker enables native `NODE_V8_COVERAGE` and inspector precise coverage.
The former supplies source-mappable generated ranges; the latter records exact
per-input novelty without sending a large edge set over the worker protocol.
Each worker retains a content-addressable edge set and an event timeline, and
the coordinator removes duplicates across workers before computing the global
timeline and plateau. If the loaded bundle exposes Istanbul's
`globalThis.__coverage__`, that data is retained too. The existing Chromium
replay starts CDP precise coverage and writes `v8-coverage.json`; list that file
under `additionalV8CoverageFiles` to merge client execution with server
execution.

The remapper reads external or inline Source Map v3 data using Node's built-in
`SourceMap` implementation. It emits stable edge IDs with generated and
original locations and classifies generated Next.js paths as `server`, `edge`,
or `client`. No package installation or manually written edge-ID hook is
required.

```json
{
  "schemaVersion": 1,
  "profile": "next-production",
  "projectRoot": "/owned/next-app",
  "runtime": "/opt/node-24/bin/node",
  "module": ".next/server/app/api/fuzz/route.js",
  "export": "fuzz",
  "resetExport": "resetForNextInput",
  "inputMode": "buffer",
  "inputs": ["corpus/**/*"],
  "workers": 8,
  "maxInputBytes": 16777216,
  "inputTimeoutSeconds": 5,
  "plateauSeconds": 300,
  "includePatterns": ["[\\\\/].next[\\\\/]"],
  "excludePatterns": ["node_modules"],
  "additionalV8CoverageFiles": ["browser-replay/v8-coverage.json"]
}
```

The target export may accept a `Buffer`, UTF-8 text, or parsed JSON according
to `inputMode`. A reset export is optional. When state isolation matters,
provide one and make its effects part of the target's invariant; otherwise the
persistent state is intentional and should be tested as such.

Each worker record contains one PID and a processed-input count. A valid
persistent run therefore proves that a worker handled more than one input. A
fatal worker exit fails the run and retains stderr rather than silently
converting the crash into an ordinary exception.

Coverage output includes new edges per hour, boundary counts, mapped edge
locations, per-input native novelty, a measured plateau, and optional holes.
The plateau is computed from globally unique inspector ranges, not by summing
per-worker counters. When orchestration is active, the first measured hole
creates a `coverage-hole` task. `scripts/search_score.py` reads registered
JavaScript runs by profile name, so JavaScript instrumentation is subject to the
same keep/delete ablation rule as native fuzzing.

## Semantic structured inputs

`scripts/structured_input_generator.py` has built-in producers for:

- `json` and framework `manifest` documents;
- URLs with equivalent host case and percent encodings;
- ordered duplicate headers with equivalent casing and optional whitespace;
- multipart bodies with fresh boundaries and equivalent part content;
- RSC/Flight row streams with equivalent row IDs and JSON encodings;
- Server Action form data represented as URL-encoded or multipart bodies.

Every output carries `semanticGroupSha256`, computed from a normalized semantic
model rather than from the bytes. Differential runs should compare outputs only
inside one semantic group. This prevents a generator from claiming that an
arbitrary mutation preserved meaning. Before retaining a file, the generator
parses the concrete representation back into the normalized model and rejects
it if the round trip changes meaning.

Generate directly:

```bash
python3 scripts/structured_input_generator.py generator.json outputs \
  --count 1000 --seed 1
```

Or import the generated variants into an existing fuzzer profile with retained
provenance:

```bash
python3 scripts/fuzzer_orchestrator.py framework-generate CAMPAIGN profile \
  --spec generator.json --count 1000 --seed 1
```

Server Action outputs use a small JSON envelope containing `contentType` and
`bodyBase64`, because URL-encoded and multipart bodies need their media type to
remain meaningful. The target wrapper must unpack that envelope before handing
the body to the framework. Other kinds emit their native bytes directly.

