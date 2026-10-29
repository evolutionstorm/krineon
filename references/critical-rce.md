# First-principles Critical/RCE campaigns

## Mission

Krineon exists to assemble and prove a complete Critical/RCE chain from the
code under review. A useful result connects:

```text
attacker-controlled public ingress
  -> violated invariant or memory-safety defect
  -> useful read/write/call/load/authority primitive
  -> attacker acquisition of every required coordinate
  -> stock or supported execution boundary
  -> bounded real command or program-defined Critical impact
```

A parser discrepancy, crash, assertion, memory corruption, module-selection
primitive, or command gadget is not a finding by itself. Keep it as one link in
the chain and assign separate agents to the missing links.

## First-principles discovery boundary

During discovery and chain construction, analyze only the pinned target tree,
its checked-in generated artifacts, its dependency lock, and behavior produced
by builds of that exact revision. Do not use:

- changelogs, release notes, advisories, CVEs, or issue trackers as lead lists;
- `git log`, `git blame`, historical commits, commit messages, or security PRs;
- source diffs against earlier, later, fixed, canary, or patched revisions;
- internet searches intended to reveal patched code or prior vulnerability
  locations; or
- known PoCs as templates for locating defects in the target.

This restriction applies to vulnerability discovery. Ordinary worktree diffs
used to review Krineon's own files are unrelated. If filing-day scope or
duplicate checks are required after the chain is independently confirmed, keep
them outside discovery, record them separately, and do not let them substitute
for source-derived evidence.

## Aggressive multi-agent operation

Use the runtime's safe concurrency limit continuously after setup. Give every
worker one independent source question and one evidence contract. Keep the
coordinator synthesizing rather than duplicating a worker. As soon as a worker
finishes or blocks, claim the next dependency-ready task or create a focused
task for a missing chain link.

Run complementary agents in parallel for:

- public ingress and attacker authority;
- backward reachability from execution and native sinks;
- memory, ownership, lifetime, and numeric invariants;
- parser, serializer, and representation disagreement; and
- capabilities, manifests, module loading, and callback authority.

Then rotate agents into composition, acquisition, primitive escalation,
stock-deployment replay, controls, and falsification. Do not assign the
originator to independent replay. Do not spend concurrency on overlapping
keyword searches or on lower-severity report drafting.

## Promotion bar

Promote a chain only when evidence establishes all of these:

1. The input is controlled by the stated attacker through a realistic public
   interface.
2. The defect is in the target or an exact dependency the supported target
   ships or invokes through the demonstrated path, not an application-authored
   unsafe callback or unrelated vulnerable downstream system. Root-cause and
   bounty-scope ownership remain explicit.
3. Every identifier, address, timing fact, build value, and carrier is publicly
   obtainable, deterministic, or measured with a bounded acquisition method.
4. The primary result works in an unmodified stock or supported build without
   debugger mutation, forced sleeps, direct heap edits, hidden harness state,
   or a test-only hook.
5. The terminal is reproduced through a supported production-equivalent or
   release entrypoint. A development server, development build, hot-reload
   path, test server, fixture server, preview-only runtime, or debug-only path
   cannot support a finding.
6. The terminal is bounded real execution such as `id`, `whoami`, `uname`, or a
   timestamp, or another concrete impact the program explicitly rates Critical.
7. Baseline, enforcing negative, and positive cases isolate the root cause.
8. Race, allocator, ASLR, or retry dependence has an `N/M` fresh-process rate.
9. A different worker reproduces the chain from clean source and public inputs.

If any link is missing, record the exact blocker and schedule focused
experiments. If evidence disproves a link, preserve that result and explore a
different source-derived path. If only lower-severity or denial-of-service
impact survives, do not create a bounty report.

## Safe terminal

Validate only in a disposable owned environment. Prefer a single bounded
command whose stdout proves execution in the target process. Do not read real
secrets, contact third parties, persist access, move funds, weaken unrelated
controls, or degrade shared services. Stop when the execution boundary and
claimed privileges are demonstrated.
