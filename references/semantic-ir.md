# Semantic intermediate representation

`scripts/framework_analysis_pipeline.py` emits `semantic-ir.json` beside its
analysis record. The IR is evidence plumbing, not a vulnerability verdict.

It contains:

- function-scoped operations, definitions, uses, assignments, aliases, and
  object-property mutations;
- conservative control-flow graphs with explicit confidence labels;
- static imports, their local bindings, target exports, and linked
  cross-module call sites;
- request-representation transformations from a validated value to the
  consumer that selects a resource;
- authority and state-ownership transitions;
- source-map links from source facts to generated bundles; and
- runtime observations keyed to the exact source fact.

Every security path answers six questions:

1. Which attacker-controlled value reaches the consumer?
2. Which transformations occur between ingress and consumption?
3. Which check is a candidate dominator?
4. Can reassignment, aliasing, or property mutation invalidate that check?
5. Did the check and consumer resolve the same resource identity?
6. Did object identity, generation, principal, process, and runtime remain
   continuous?

The structural JavaScript extractor does not claim exact JavaScript semantics.
Control-flow dominance and unfamiliar transformations remain unknown until a
target CPG or runtime observation proves them. Unknowns become experiment
candidates. They do not become findings.

Runtime observations should name a `factId` and include:

```json
{
  "factId": "FF-...",
  "resourceIdentity": "route:/admin",
  "objectIdentity": "request-17",
  "generation": 1,
  "principal": "anonymous",
  "process": "next-server-912",
  "runtime": "node-production"
}
```

Missing identity telemetry yields `unknown`. It never yields an inferred
invariant violation.

## Cross-module resolution

The extractor resolves relative ESM imports and records default, named, and
namespace bindings. A call becomes `statically-linked-export` only when the
target module contains the named export in the same pinned tree. Otherwise it
is `target-export-runtime-resolution-required` and must be measured in the
shipped artifact.

## Queue boundary

IR experiment candidates initially carry `executableOracle: false`. A target
adapter must bind source facts to a production request or instrumented recipe
with baseline, enforcing-negative, and positive cases before the experiment
can enter the runtime queue.
