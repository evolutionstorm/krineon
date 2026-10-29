# Tool-Assisted Analysis

Static tools accelerate coverage and produce reviewable inventories. They do
not prove exploitability. Generated code, runtime dispatch, native boundaries,
reflection, dependency injection, and protocol state can invalidate any one
tool's graph.

## Tool probe first

Run:

```bash
python3 scripts/tool_probe.py --json
```

Record the result in the campaign. Do not assume Trailmark, Tree-sitter, Joern,
Z3, language frontends, or build databases are present.

## Trailmark

Use Trailmark for fast structure, entry-point, call-graph, and before/after
comparisons:

```bash
trailmark analyze SOURCE --language javascript --summary
trailmark entrypoints SOURCE --language javascript --json
trailmark diagram --target SOURCE --language javascript \
  --type call-graph --focus SYMBOL --depth 4
trailmark diff BEFORE AFTER --language javascript --json
```

Good uses:

- enumerate exported or externally reachable surfaces;
- compare a security patch with a surviving sibling path;
- focus manual review around a sink or validator;
- retain a machine-readable structural snapshot.

Limitations:

- inherited, generated, dynamic, native, and framework-wired edges may be absent;
- a call graph shows possible structure, not attacker control;
- a diff highlights change, not completeness or security intent.

## Tree-sitter

Use Tree-sitter for syntax-aware census and local transformations:

- find every call to a validator, decoder, allocator, cache-key function, or
  privileged sink;
- compare sibling branches without comment/string false positives;
- enumerate exports, imports, decorators, handler registrations, and option
  defaults;
- verify statement ordering around validation, state mutation, and cleanup.

Example query shape for JavaScript call sites:

```scheme
(call_expression
  function: [
    (identifier) @callee
    (member_expression property: (property_identifier) @callee)
  ]
  arguments: (arguments) @arguments)
```

Keep queries in the campaign `tools/` directory and retain their output. If the
standalone CLI or language binding is unavailable, use Trailmark or the
repository's existing parser and record the limitation instead of silently
falling back to regex.

## Joern

Use Joern after the project can be parsed reliably:

```bash
joern-parse SOURCE --output tools/cpg.bin
joern-scan --cpg tools/cpg.bin --output tools/joern-scan
joern tools/cpg.bin
```

High-value queries answer bounded questions:

- Which public handlers can reach this sink?
- Does untrusted input reach a size, path, module, header, key, or identity?
- Which validators dominate the sink, and which paths avoid them?
- Is the same object mutated before an async/error path consumes it?
- Which sibling callers omit a guard present in the expected path?

Illustrative Scala query fragments:

```scala
cpg.method.name(".*handler.*").call.name(".*exec.*|.*require.*|.*write.*").path.l
cpg.call.name("decode.*").argument.reachableBy(cpg.method.parameter).p
cpg.call.name("privilegedSink").whereNot(_.controlledBy.isCall.name("validate.*")).l
```

Adapt names and frontends to the language. Treat an empty result as “not found
by this graph,” not proof that the path is impossible.

## Z3

Use Z3 after translating a bounded implementation question into the same bit
widths, signedness, truncation, encoding, and state transitions used by the
target. High-value models include:

- integer wrap, length truncation, and signed-versus-unsigned comparisons;
- parser and serializer disagreements over the same protocol field;
- non-injective cache keys, identifiers, or binary encodings;
- authorization, feature-flag, and lifecycle combinations that make a guarded
  state reachable;
- the smallest concrete input satisfying a suspected boundary violation.

Retain the model, solver version, constraints, result, and generated input. A
satisfiable model produces a candidate test case, not an exploit. An
unsatisfiable result excludes only the encoded model, not the real program.
Confirm every useful result against the exact shipped implementation and a
runtime control matrix.

## Targeted text and history

Use `rg` for exact constants, error messages, header names, option defaults,
tests, and generated copies. Use version history to establish when and why a
security invariant was introduced:

```bash
rg -n "validator|internalHeader|cacheKey|deserialize|exec" SOURCE
git log -S 'security-relevant-token' -- SOURCE_FILE
git blame TESTED_COMMIT -- SOURCE_FILE
git diff OLD_TAG..NEW_TAG -- SECURITY_FILES
```

Tests and documentation often establish intended behavior more strongly than
comments. Search regression test names, issue references, threat models, and
release notes.

## Runtime verification

Static output becomes evidence only after a runtime experiment answers:

- Is the path compiled and shipped?
- Can attacker-controlled data reach it?
- Does the expected guard run?
- Does the stock runtime produce the effect?
- Does a clean or patched control block it?

Instrument with logs, packet captures, sanitizers, debugger traces, or bounded
markers only in owned environments. Preserve raw output and avoid changing the
state transition being tested. For local process targets,
`scripts/dynamic_harness.py` provides pinned execution, deterministic fuzzing,
optional file-based coverage feedback, crash minimization, and replay. Its
resource limits are not a substitute for a disposable VM or container.

## Recommended combined workflow

1. Trailmark creates a rapid surface and diff map.
2. Tree-sitter produces exact syntax censuses and ordering checks.
3. Joern investigates data flow, reachability, and missing dominance.
4. Z3 solves bounded representation and state constraints and generates
   candidate inputs.
5. `rg`, tests, docs, and history verify intent and completeness.
6. Manual source reading explains semantics.
7. Runtime differential tests decide the claim.

If tools disagree, reduce the question until the discrepancy can be explained.
