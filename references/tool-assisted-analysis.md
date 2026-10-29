# First-principles tool-assisted analysis

Tools accelerate coverage of the pinned tree. They generate source-derived
leads; runtime evidence decides whether a chain link exists.

## Prohibited discovery inputs

Do not use Trailmark diffs, Git history, changelogs, advisories, issue trackers,
patched versions, or internet-derived code comparisons to locate defects. Use
one exact revision. Ordinary worktree diffs for Krineon's own edits are not
vulnerability discovery.

## Tool probe

Run `python3 scripts/tool_probe.py --json` and retain the result. Do not assume
Trailmark, Tree-sitter, Joern, Z3, language frontends, or build databases are
installed.

## Executable lead pipeline

Run available analyzers and immediately enqueue the retained leads:

```bash
python3 scripts/static_analysis_pipeline.py run CAMPAIGN \
  --language javascript --ingest
```

The runner stores the exact command, timestamps, exit status, stdout, stderr,
CPG, TSV, census, and solver artifacts under `tools/static/RUN_ID/`. It writes
normalized leads to that run's `run.json`, merges them into
`tools/static-leads.json`, and creates one idempotent
`static-lead-validation` task per stable lead ID. The task objective carries
the campaign commit, actual Git/source-file identity, source location, run
record, tool output, and approach family. It requires manual source review plus
a bounded runtime discriminator. It does not register a finding.

Use `--tool` repeatedly to select analyzers. Tree-sitter records an explicit
failure when the language bindings are unavailable. Joern query failures are
retained rather than treated as empty results. Trailmark requires
`--language`. Z3 runs only for explicit source-derived `--z3-spec` inputs.

## Trailmark

Use a single-revision structural snapshot to enumerate exports, public entry
points, call edges, privileged sinks, and bounded source neighborhoods:

```bash
trailmark analyze SOURCE --language javascript --summary
trailmark entrypoints SOURCE --language javascript --json
trailmark diagram --target SOURCE --language javascript \
  --type call-graph --focus SYMBOL --depth 5
```

Do not use Trailmark's before/after or patch-diff modes in a Krineon campaign.

## Tree-sitter

Use syntax-aware queries to census:

- public handler and parser registrations;
- execution, native, module, file-write, unsafe memory, and callback sinks;
- validators, capability checks, length conversions, object construction, and
  cleanup ordering;
- sibling consumers of the same current-revision representation.

The bundled `scripts/tree_sitter_census.py` parses syntax nodes and emits
normalized ingress, guard, execution, code-loading, and memory/native leads.
It does not fall back to comment-matching regexes when Tree-sitter is missing.
An empty result means only that the census did not find a path.

## Joern

Use a current-revision code property graph for bounded questions:

- Which public handlers reach a selected execution/native sink?
- Which attacker-controlled values reach sizes, paths, modules, function IDs,
  memory operations, or authority decisions?
- Which guards dominate the sink, and which same-revision paths avoid them?
- Where does ownership change before async, error, or concurrent consumption?

Treat graph edges as leads until manual source review and runtime evidence
confirm dispatch and attacker control.

The pipeline builds a CPG with `joern-parse` and executes both bundled queries:

- `queries/joern/critical-sink-reachability.sc`
- `queries/joern/missing-validation.sc`

Each query emits TSV that is retained even when it produces no rows. Query or
CPG failures remain visible as failed tool records; they are never converted
to "no vulnerability" conclusions.

## Z3

Model the implementation's exact bit widths, signedness, truncation,
normalization, encoding, and state transitions. Use it to produce concrete
inputs for integer wrap, parser/serializer disagreement, non-injective keys,
object-shape collisions, and capability-state combinations. A satisfiable
model is a testcase, not an exploit.

The bundled solver uses the Z3 binary directly and emits concrete payloads:

```bash
python3 scripts/z3_boundary_solver.py \
  --kind truncate --bits 32 --target 0 \
  --min-x 1 --max-x 4294967296 \
  --emit-dir tools/z3-u32-zero
```

For pipeline use, encode those same bounds as JSON (see
`examples/z3/u32-truncates-to-zero.json`) and pass `--z3-spec`. Supported
models are integer truncation, addition wrap, and multiplication wrap. Add new
models only after deriving their constraints from the pinned implementation.

## Targeted source search

Use `rg` against the pinned tree for handlers, decoders, allocators, loaders,
function constructors, native boundaries, process APIs, executable memory,
deserialization, manifest resolution, and checked-in tests. Do not run `git
log`, `git blame`, historical tag comparisons, or patch-oriented web searches.

## Runtime verification

Ask whether the path is shipped, attacker-controlled, guarded, and capable of
reaching the next chain link. Use sanitizers, debuggers, packet captures, or
bounded instrumentation only in owned environments. Return to an unmodified
stock build before promotion.

Recommended flow:

1. The pipeline runs Trailmark against one revision and retains entry points.
2. Tree-sitter emits a syntax-aware census.
3. Joern executes sink-reachability and missing-validation queries over a CPG.
4. Explicit Z3 specs produce implementation-matched concrete payloads.
5. Normalized leads become durable tasks with immutable provenance.
6. Manual source reading explains or falsifies the invariant and chain link.
7. Runtime controls confirm or falsify it before any finding is registered.

For sustained coverage-guided work, read [fuzzing.md](fuzzing.md). Use the
external-fuzzer orchestrator for instrumentation, AFL++/libFuzzer/Fuzzilli
parallelism, corpus exchange, structured generation, crash forwarding, and
coverage rebuilding. The dynamic harness's deterministic byte mutator is only
a plumbing smoke test.
