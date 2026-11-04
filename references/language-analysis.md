# Language-specific static analysis

Krineon runs installed language analyzers only when the pinned target contains
compatible source or an exact analysis artifact. Their output supports a
hypothesis. It does not create a finding or validation task.

The static pipeline currently integrates:

- SVF whole-program pointer analysis through `wpa`;
- PhASAR IFDS and IDE analysis through `phasar-cli`;
- Pysa through `pyre analyze`;
- Infer Pulse through `infer run`; and
- Go SSA call graphs through `golang.org/x/tools/cmd/callgraph`.

Run the normal static pipeline. Installed compatible tools are selected
automatically:

```bash
scripts/static_analysis_pipeline.py run CAMPAIGN --source PINNED_CHECKOUT
```

Every adapter retains the executable hash, exact command, working directory,
source manifest, raw stdout and stderr, generated artifacts, a normalized
semantic summary, and explicit coverage gaps.

## Analyze LLVM modules

SVF and PhASAR operate on LLVM IR. If the source contains exactly one `.ll` or
`.bc` file, Krineon selects it. Otherwise, identify the exact artifact:

```bash
scripts/static_analysis_pipeline.py run CAMPAIGN \
  --source PINNED_CHECKOUT \
  --llvm-module BUILD/component.bc \
  --llvm-provenance BUILD/llvm-build-manifest.json
```

The provenance manifest should identify:

- source and dependency revisions;
- applied patches;
- compiler and LLVM revisions;
- effective compile and link flags;
- target architecture;
- sanitizer, LTO, and optimization settings; and
- the command that produced the module.

Without that manifest, Krineon labels the result as incomplete build
provenance. The result can still guide research, but it cannot establish that
the analyzed IR matches the shipped target.

SVF defaults to Andersen analysis. Select its flow-sensitive analysis only
when the target and budget justify the additional cost:

```bash
scripts/static_analysis_pipeline.py run CAMPAIGN \
  --source PINNED_CHECKOUT \
  --llvm-module BUILD/component.bc \
  --svf-analysis fspta
```

PhASAR builds its program structures even without a selected data-flow
analysis. Select a built-in analysis and a reviewed source/sink configuration
when appropriate:

```bash
scripts/static_analysis_pipeline.py run CAMPAIGN \
  --source PINNED_CHECKOUT \
  --llvm-module BUILD/component.bc \
  --phasar-analysis ide-xtaint \
  --phasar-config ANALYSIS/phasar-taint.json
```

Do not describe a points-to, alias, or taint edge as attacker-reachable until a
runtime experiment resolves the entry point and every intervening condition.

## Analyze Python with Pysa

Pysa runs only when Python source and a reviewed `.pyre_configuration` are
present. Include target dependencies in `search_path` and provide models for
framework boundaries, otherwise Krineon records incomplete coverage.

Model verification remains enabled by default. Use `--pysa-no-verify` only to
diagnose an incomplete model set. Krineon records that verification was
disabled and does not treat the result as stronger evidence.

## Analyze native or Java builds with Infer

Infer must capture the real target build. Supply a JSON recipe with an argv
array. Shell strings are not accepted:

```json
{
  "command": ["cmake", "--build", "build", "--parallel", "8"],
  "workingDirectory": "."
}
```

Then run:

```bash
scripts/static_analysis_pipeline.py run CAMPAIGN \
  --source PINNED_CHECKOUT \
  --infer-build-spec ANALYSIS/infer-build.json
```

The working directory must remain inside the pinned source tree. Krineon does
not run a clean command implicitly. Prepare a reproducible clean build before
the pipeline when the build system would otherwise omit compilation units.

## Analyze Go call relationships

Go call-graph analysis defaults to class hierarchy analysis over `./...`:

```bash
scripts/static_analysis_pipeline.py run CAMPAIGN \
  --source PINNED_CHECKOUT \
  --go-callgraph-algorithm cha \
  --go-pattern ./...
```

Available algorithms are `static`, `cha`, `rta`, and `vta`. A call graph is an
overapproximation or underapproximation according to its selected algorithm.
Built-in calls are not represented. Use it to nominate compatible producers
and consumers, then execute a distinguishing experiment.

## Evidence boundary

Language-analyzer artifacts enter `languageSemanticArtifacts` in the static
run record and `languageAnalysisEvidence` in Krineon's semantic IR. The
contract explicitly states that this evidence creates no verdict.

Advance a candidate only after the campaign supplies:

1. An attacker-controlled production entry point.
2. A step-by-step path with every conditional resolved.
3. A target-specific executable security oracle.
4. Baseline, positive, and enforcing-negative controls.
5. Coordinator execution and independent replay.

