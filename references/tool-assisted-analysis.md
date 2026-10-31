# Differential, first-principles tool assistance

Tools may nominate boundaries in one pinned tree. They do not create queue
entries merely because source text contains a suspicious name, operator, or
sink. A lead enters the queue only after two real consumers process the same
hashed input and Krineon records a disagreement plus an equal-observation
control.

## Discovery boundary

Do not use patch diffs, Git history, blame, changelogs, advisories, issue
trackers, or another revision to locate defects. Checked-in tests, assertions,
fuzz targets, invariant comments, and fixtures in the pinned revision are
allowed local oracles.

Trailmark, Tree-sitter, Joern, language frontends, and manual source reading may
help identify candidate pairs such as serializer versus decoder, validator
versus executor, interpreter versus optimizing tier, parser versus re-parser,
copy versus zero-copy consumer, synchronous versus deferred path, or owner
versus concurrent consumer.

The static pipeline invokes every installed compatible core analyzer:
Trailmark for structure and entry points, Joern for CPG construction, cppcheck
for C/C++ diagnostics, and Z3 for supplied source-bound constraints. An
installed tool may be marked not applicable only after the pipeline exercises
its capability and records why the target or current hypothesis does not fit.
Missing specifications never permit a fabricated model.

Their inventories and graphs remain researcher notes. The former syntax census
and bundled Joern queries were removed because they did not produce executable
differentials or improve the measured search vector.

For Next, React, and Node production builds,
`framework_analysis_pipeline.py` turns route and runtime relationships into
**experiment tasks**, not security leads. Each task already specifies the
production entry point, controls, observations, and discriminator needed to
create a later differential. It cannot populate the findings registry or claim
dominance from an authentication call name. Read
[framework-analysis.md](framework-analysis.md) when analyzing those targets.

## Freeze one component first

Use `component_freeze.py` to build one bounded component with ASan, UBSan, and
frame pointers. The command records the exact source, compiler, command,
binary, corpus, and hashes:

```bash
python3 scripts/component_freeze.py \
  examples/frozen-component/component.json \
  CAMPAIGN/frozen/row-length
```

When the output is inside a campaign, the binary is added to the
coordinator-owned `frozenTargetArtifacts` set. Worker runtime claims may only
re-execute one of those frozen artifacts.

## Record an executable differential

A differential spec contains exactly two consumers, hashed target artifacts,
the same hashed inputs, and an output normalizer. Commands are argv arrays and
must contain `{input}`. Run:

```bash
python3 scripts/differential_witness.py \
  --spec CAMPAIGN/tools/differentials/PAIR.json \
  --output CAMPAIGN/tools/differentials/PAIR-witness.json
```

The runner starts a fresh process for each consumer/input pair. It refuses to
produce a witness unless at least one input gives equal normalized observations.
A disagreement records both return codes, stdout/stderr hashes, normalized
observations, the exact input hash, and a stable witness ID.

Pass one or more executable specs to the lead pipeline:

```bash
python3 scripts/static_analysis_pipeline.py run CAMPAIGN \
  --source PINNED_CHECKOUT --tool differential \
  --differential-spec CAMPAIGN/tools/differentials/PAIR.json --ingest
```

Only recorded disagreements become validation tasks. A task must still explain
the source invariant, every condition from ingress to the disagreement,
attacker control, and the next independently meaningful chain link.

## Z3

Z3 may generate concrete inputs, but it does not discover target semantics. A
pipeline spec must cite an exact file, line range, expression, and extraction
method from the pinned checkout. `manual-transcription` remains labelled and
sets `implementationMatched: false`. Generic models may be retained with
`--allow-unbound-z3`, but they do not enter the target lead queue. Feed solver
outputs to both real consumers to obtain a differential witness.

## Evidence-rate ablation

Measure tools instead of defending them by description:

```bash
python3 scripts/search_score.py snapshot CAMPAIGN \
  --profile parser --benchmark frozen-oracles --output before.json
# enable or disable one subsystem, then repeat the same budget
python3 scripts/search_score.py snapshot CAMPAIGN \
  --profile parser --benchmark frozen-oracles --output after.json
python3 scripts/search_score.py compare CAMPAIGN \
  --subsystem candidate-tool --before before.json --after after.json --enforce
```

The retained vector is new edges per hour, unique normalized stack clusters,
and hours to first rediscovery. If none improves, the decision is `delete`.
Do not retain a subsystem because its output looks sophisticated.
