# Critical/RCE research methodology

## Objective

Derive one complete chain from the pinned code:

```text
attacker-controlled ingress
  -> target-owned invariant violation
  -> useful read/write/call/load/authority primitive
  -> public acquisition of every required coordinate
  -> stock or supported privileged sink
  -> bounded real execution or program-defined Critical impact
```

An assertion, crash, denial of service, parser discrepancy, memory corruption,
or callable gadget is not a finding by itself. Preserve it as a chain link and
assign the missing links to other workers. Do not prepare lower-severity
reports.

## Discovery boundary

Use only the pinned source tree, checked-in generated code, dependency locks,
tests and documentation present at that revision, exact-revision builds, and
runtime behavior. During discovery and chain construction, do not use:

- changelogs, release notes, advisories, CVEs, issue trackers, or security PRs;
- `git log`, `git blame`, historical commits, or commit messages;
- diffs against earlier, later, fixed, canary, or patched versions;
- internet searches intended to reveal fixes or vulnerable locations; or
- known PoCs as maps to defects in the target.

Ordinary worktree diffs for changes to Krineon are unrelated. Scope and
duplicate checks may occur after independent validation, but cannot supply the
root cause or missing exploit links.

## Phase 0: pin authority and artifacts

Record the exact repository, commit, dependency lock, compiler, runtime,
program asset, Critical eligibility rule, authorization, owned environment,
cleanup, and stop conditions. Build the unmodified target and hash every
load-bearing artifact.

## Phase 1: map both ends of the chain

In parallel, map:

- unauthenticated and low-privilege entry points and attacker-controlled data;
- process creation, function construction, executable memory, dynamic module
  loading, native calls, unsafe deserialization, write-then-load, and equivalent
  program-defined Critical sinks;
- memory, ownership, lifetime, integer, parser, serializer, capability,
  manifest, and namespace invariants between those ends.

Work forward from ingress and backward from sinks. Record guard dominance,
identity, provenance, and every required state transition.

Execute `scripts/static_analysis_pipeline.py` during this phase. Its Trailmark
entrypoints, Tree-sitter census, Joern CPG queries, and explicit Z3 models must
be retained under the campaign and ingested as durable validation tasks. A
machine lead never satisfies this phase by itself: a worker must inspect the
source semantics and confirm or falsify the path at runtime. This turns static
coverage into experiments while keeping tool output distinct from evidence of
impact.

For fuzzing, use `scripts/fuzzer_orchestrator.py` with verified compiler or
REPRL instrumentation. Harvest source tests and fixtures, preserve structured
generators, use the engine's native parallel/corpus-sharing model, and rebuild
coverage from the canonical corpus. The deterministic byte mutator is only a
smoke test. Forward external crash artifacts through bounded stock-target
replay before first-fault triage.

## Phase 2: formulate chain-link hypotheses

Write each hypothesis as:

> Input X reaches boundary Y. Component A establishes invariant P, but
> component B consumes state Q. This yields primitive Z, which can reach sink S
> if acquisition condition R is satisfied. Control C falsifies the link.

Assign a stable ID. Record exact source references, expected primitive,
falsification condition, and missing predecessor and successor links.

## Phase 3: compose aggressively

Keep every safe runtime slot active; four or more agents may work concurrently
when capacity permits. Do not assign a fixed number of agents to any method or
lane. Workers claim the highest-value ready task from the shared queue while
the coordinator combines ingress, invariant, primitive, acquisition, and sink
evidence continuously. Create, split, merge, reprioritize, or cancel focused
tasks as the chain changes rather than waiting for every broad seed lane to
finish. When a path blocks, classify the blocker and test the smallest
first-principles experiment that can remove it.

Reject primary chains that require an application-authored command callback,
an unrelated downstream system the target neither ships nor invokes,
undocumented insecure configuration, private target artifacts, direct state
injection, debugger mutation, forced sleeps, or unrealistic resources. Do not
reject a chain merely because a bug is inside an exact bundled or runtime
dependency. Instead prove the target-selected revision, supported integration,
attacker reachability, cross-library transformations, and scope ownership. See
[dependencies.md](dependencies.md).

## Phase 4: prove the ladder

Promote incrementally:

1. Source invariant contradiction.
2. Minimal deterministic harness at the same revision.
3. Automated first-fault classification, normalized stack clustering, and
   reviewed controllability assessment for any crash-backed primitive.
4. Unmodified shipped component or bundle.
5. Supported production-equivalent or release entrypoint; development servers
   and development builds remain lead-only.
6. Supported application or protocol ingress.
7. Attacker acquisition of every ID, address, module, path, and timing fact.
8. Useful primitive with attacker-controlled arguments.
9. Bounded real execution or explicit program-defined Critical effect.
10. Fresh-process controls and independent replay.

At each step, state which artificial mechanism was removed.

## Phase 5: isolate causality

Use the same pinned revision for the minimum truth table:

| Case | Input/state | Expected result |
| --- | --- | --- |
| Baseline | legitimate input | feature works |
| Enforcing control | exploit-shaped input with the disputed invariant preserved | no terminal |
| Positive | only the disputed invariant differs | bounded terminal occurs |
| Invariant-restored | copied, sanitized, or structurally safe carrier | no terminal |

Do not require a patched-version control. For races, allocator effects, ASLR,
or retries, measure `N/M` across fresh processes. Assisted scheduling may
explain consequence but cannot replace unassisted reachability.

## Phase 6: prove attacker acquisition and deployment

Classify every coordinate as attacker-supplied, public protocol output,
deterministic from the public version, boundedly searched, private, or obtained
only by target-local inspection. A remote claim cannot depend on the last two.

Measure platform, topology, memory, storage, timing, interaction, and request
affinity conditions. Confirm they fit a stock default or documented supported
deployment. Configuration flexibility is not proof of realistic exposure.

## Phase 7: validate a safe terminal

Use a disposable owned environment and an unmodified target. Prefer a bounded
command such as `id`, `whoami`, `uname`, or a timestamp, with exact stdout and
process evidence. For program-defined Critical non-RCE impact, quote the scope
rule and demonstrate the exact forbidden operation with owned data.

Never read real credentials, contact third parties, persist access, move
unowned funds, or degrade a shared service.

## Phase 8: prove the complete path and eliminate assumptions

Create the finding's structured path proof. Walk from the exact attacker entry
point to the exact sink in execution order. Record every transition and every
conditional statement encountered. For each condition, state the required
outcome, the exact attacker-controlled input or state that produces it, and the
retained runtime observation. Hash the reviewed source ranges, retain negative
controls, and list observations that would disprove the claim.

The proof must contain no unresolved assumptions. A different worker must try
to contradict the entry point, attacker control, each transition, each branch,
the sink, and the impact. Candidate promotion remains blocked until all
contradictions are resolved with evidence and `scripts/path_proof.py audit`
passes. See [false-positive-control.md](false-positive-control.md).

## Phase 9: independent falsification

Two workers with distinct runtime-agent identities that did not originate the
chain rebuild and replay it from the pinned source and public prerequisites.
Separate adversarial workers throughout the research rounds try to reduce the
claim to crash-only behavior, application misuse, unsupported configuration,
unavailable coordinates, synthetic evidence, or an unproven boundary.

If the complete Critical/RCE chain does not survive, retain the primitive and
blocker evidence. Do not emit a lower-severity bounty report.
