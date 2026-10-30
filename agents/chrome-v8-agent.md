# Chrome/V8 research agent contract

Use this contract only for an authorized `chrome-v8` Krineon campaign. Read
`AUTHORIZATION.md`, `campaign.json`, the claimed task packet, and
`references/chrome-v8.md` before running code.

## Operating boundary

- Work only in the isolated workspace returned by `claim`.
- Execute testcases only in an owned disposable VM or container.
- Do not browse third-party sites, reuse a personal browser profile, access
  other users' data, disable cloud isolation, or target a production service.
- Treat the dynamic runner's limits as resource controls, not containment.
- Use a renewable task lease and submit a JSON result through Krineon.

## Required reasoning discipline

1. State the exact V8 and Chromium commits and binary SHA-256 values.
2. Separate source inference from a runtime result.
3. Treat static tooling only as a way to nominate exact consumer pairs. Queue
   a lead only after both consumers execute the same hashed input, an equal
   control passes, and `differential_witness.py` records their disagreement. Prioritize
   representation changes, producer/consumer domain mismatches, state committed
   before fallible effects, lifetime escape, indirect dispatch, and shared-value
   differences. A function or call name containing `parse`, `exec`, `handler`,
   or `memcpy` is not a lead by itself. Generic Z3 mathematics is not target
   evidence; require a verified source binding and label constraints as manual
   transcription. Do not claim implementation matching until a verified
   source-to-SMT extractor exists.
4. Record whether a testcase needs `--allow-natives-syntax`, `--expose-gc`, a
   stress flag, a non-default feature, or an instrumented shell.
5. Do not promote an internal-flag-only or DCHECK-only failure as web-reachable.
6. Locate the earliest invalid state or memory access, not merely the final
   signal.
7. Run `dynamic_harness.py triage` for every retained crash. Preserve the exact
   crash ID separately from the normalized stack cluster. Treat access direction
   as a first-fault label, not control. For a claimed primitive, use generated
   challenges to prove chosen bytes or PC, allocation identity where relevant,
   controls, and fresh-process stability.
8. For sustained fuzzing, use `fuzzer_orchestrator.py`; the built-in
   deterministic mutator is only a target-plumbing smoke test. Retain the
   instrumented-build record, engine identity, initial/final corpus digest,
   native worker topology, crash-forwarding result, and an AFL/LLVM coverage
   rebuild. Record new edges per hour, plateau duration, unique stack clusters,
   and the next coverage-hole task. Minimize and stack-deduplicate before queue
   admission. For JavaScript, prefer Fuzzilli or another structured generator.
9. Preserve a working baseline and a negative control differing only in the
   disputed state transition.
10. Minimize the testcase without changing its crash fingerprint.
11. Replay across release, ASan, and debug builds. Measure `N/M` in fresh
   processes if scheduling, concurrent compilation, GC, or allocation matters.
12. Move the testcase to full Chromium only after the engine result survives
   triage. Use `chrome_v8_harness.py browser-replay` with an owned local origin,
   a separate negative-control entry, fresh processes, and the sandbox enabled.
   Retain the replay ID and machine record; a screenshot alone is insufficient.
13. Call a result a sandbox escape only after demonstrating a separate,
    bounded sandbox-boundary violation. Renderer memory corruption alone is
    not a sandbox escape.
14. Do not use changelogs, advisories, Git history, historical commits,
    patched-version comparisons, or internet-derived patch diffs for discovery.
    Do read checked-in target tests, assertions, fuzz targets, and invariant
    comments from the pinned revision as local semantic oracles.
15. Retain unique minimized stack clusters, invariant breaks, and verified
    primitives in `taskResult.researchLeads` and advance their next experiments.
    Do not promote them as findings without a bounded execution chain or
    explicit program-defined Critical terminal.
16. Before candidate promotion, complete the linked structured path proof.
    Walk from the owned web entry point to the claimed sink, list every
    conditional and exact attacker-controlled outcome, retain source and
    machine evidence for each step, resolve all contradiction challenges, and
    leave the assumptions list empty. The reviewer must execute the same recipe
    with new challenges and processes; aliases and prose-only replay do not count.

## Open-ended search mandate

The profile lanes and examples are launch axes, not the boundary of the audit.
Follow new reducer families, builtin variants, representation transitions,
concurrent states, generated-code paths, architecture specializations, and
cross-component compositions exposed by evidence. Create durable tasks with
`task-add` instead of leaving promising branches in prose.

If a path stops, identify the actual blocker. Distinguish a missing artifact or
tool from missing observability, nondeterminism, environment mismatch,
unreachable state, unsupported configuration, and a true falsification. Submit
the structured blocker contract and schedule the safest high-value unblock
experiment. Return to an unmodified supported build before promoting a claim.
Never route around an authorization boundary.

## Fuzzing contract

Fuzzilli, V8's JS fuzzer, FuzzTest, libFuzzer, or a custom generator may produce
leads. Record the fuzzer revision, build profile, full command array, corpus
digest, seed, worker architecture, execution rate, duration, and synchronization
method. Store corpora outside ephemeral workers and submit only minimized,
reproducible artifacts to the finding pipeline.

Do not infer security impact from coverage, a differential, a timeout, an OOM,
or an assertion. These results identify the next experiment.

Do not infer search efficacy from this contract either. Compare
`search_score.py` snapshots for edge velocity, unique stack yield, and frozen
hours-to-rediscover. Delete a subsystem that moves none of them.

## Handoff result

Start from `KRINEON_TASK_RESULT.template.json` for the scheduler contract and
`KRINEON_REFERENCES/chrome-v8-result.template.json` for the Chrome/V8 evidence
fields. The submitted JSON should identify:

- task and worker identity;
- V8 and Chromium revisions;
- registered build names and hashes;
- testcase and matrix artifact paths;
- outcome per build;
- baseline, negative, and positive controls;
- required flags and whether they exist in normal web execution;
- first-fault explanation;
- exact crash fingerprint, stack-cluster ID, access direction, verified or
  unverified control evidence, automated verdict, and reviewer interpretation;
- reliability;
- remaining browser or sandbox blocker;
- cleanup state.

For independent replay, include the exact `independentReplay` object and reality
attestation required by the task packet. The originating worker cannot perform
that replay, and copied originator output is not an independent experiment.
