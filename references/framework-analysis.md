# Next, React, and Node production analysis

Use `scripts/framework_analysis_pipeline.py` after building the actual
production artifact. The pipeline maps source structure to shipped runtime
structure and emits experiments that still need execution. It does not label a
fact, relation, or hypothesis as a vulnerability.

```bash
python3 scripts/framework_analysis_pipeline.py CAMPAIGN analysis.json \
  CAMPAIGN/evidence/framework-analysis/run-01
```

When the campaign scheduler is initialized, add `--ingest` to create one
runtime-validation task per hypothesis. Those tasks require the production
framework adapter, raw protocol or browser replay, negative controls, and
source-mapped coverage. Re-running ingestion is idempotent.

## What is mapped

The analyzer links these evidence types:

- App Router, Pages Router, route-handler, and programmatic Node entry points;
- Next.js route, middleware, prerender, build, and server-reference manifests;
- middleware matchers, handler-local authentication signals, and middleware
  authentication signals without treating source names as proof of dominance;
- `'use client'`, `'use server'`, and `'use cache'` directives across static
  and dynamic module edges;
- dynamic `import()` and `require()` sites plus manifest module identities;
- cache and revalidation operations;
- `process.env`-dependent runtime selection;
- generated server/client bundles and selected vendored framework runtime code;
- source lines to generated bundle lines through Source Map v3 VLQ mappings.

JavaScript is structurally tokenized. Comments and regular-expression bodies
are excluded, so a string such as `auth()` in a comment cannot create an
authentication fact. Configurable signal names create only call-site facts.
They never establish authorization, reachability, exploitability, or impact.

For semantic transformations, the analyzer records call receivers, argument
symbols, assigned result symbols, and source order. It emits a transformation
flow only when a value seen by a validation call reaches a transformation
result and that exact result reaches a later consumer. Other calls remain
candidates. A matching callee name elsewhere in the file is not a flow.

The source-map index is reverse-oriented: a source fact is connected to the
concrete generated bundle locations that encode that source line. The record
retains hashes for every parsed source, generated, vendored, manifest, source
map, analyzer, spec, and optional adapter artifact.

## Runtime-hypothesis contract

Every hypothesis has:

- exact fact IDs and manifest or source locations;
- a concrete production entry point or operation;
- baseline and negative or independent controls;
- the response, module, cache, middleware, or coverage observations to retain;
- a discriminator that says what difference to measure;
- `state: not-executed` and `conclusion: none-until-runtime-discriminator`.

The generated families cover:

- route-to-emitted-artifact alignment;
- middleware and handler execution order;
- client/server directive crossings;
- dynamic module identity;
- cache-key and revalidation isolation;
- environment-dependent production branches.

An observed difference is still a research lead. Feed the exact hypothesis to
`framework_adapter.py`, `http_protocol_harness.py`,
`js_coverage_harness.py`, or `chromium_replay.py`. Only the normal candidate
and independent-replay gates can promote a later complete chain.

The first automated semantic step is intentionally narrower than this
structural map. `semantic_hypothesis_loop.py` consumes only Next.js
middleware-route relations with authorization evidence. It makes attacker
control, checks, dominance uncertainty, competing interpretations, and state
ownership explicit, then generates an authorization-to-route agreement oracle.
See [semantic experiments](semantic-experiments.md). Do not describe the other
framework-analysis families as autonomous semantic vulnerability discovery.

## Production binding

Set `adapterRecord` to a passed `krineon-framework-adapter` record when one is
available. The analyzer rejects an adapter produced for a different project or
framework. Omitting it is allowed for source-only mapping, but runtime tasks
still have to produce a bound adapter record before claiming reachability.

Use the framework-specific defaults or override the `sourceGlobs`,
`generatedGlobs`, `vendoredGlobs`, `manifestGlobs`, and `sourceMapGlobs` fields.
File-count and parsed-byte limits are explicit in the run record; truncation is
never silent.
