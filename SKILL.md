---
name: krineon
description: Run authorized zero-day, Critical/RCE, source-audit, and local-fuzzing campaigns with independent agents, machine-backed evidence, and replay. Use for full campaigns against pinned source or owned labs, including Next.js, React, and Node.js; not for unapproved live testing, narrow reviews, or patch-diff discovery.
---

# Krineon Security Research

Krineon searches for complete Critical/RCE chains in code and systems the user
is authorized to test. Its filing objective is strict: a supported ingress,
proved invariant failure, attacker-controlled primitive, and bounded real
Critical/RCE terminal. Its internal search objective is broader: retain unique
minimized stacks, invariant breaks, verified primitives, blockers, and chain
hypotheses without mislabeling them as findings. Never invent a missing link to
advance the queue. Read
[the promotion contract](references/critical-rce.md) before discovery.

## Runtime setup

Resolve `scripts/`, `references/`, `assets/`, and `profiles/` from the physical
skill directory, never from the target checkout or an assumed current working
directory. Give workers absolute skill, campaign, authorization, claimed
workspace, evidence, and result-template paths. Runtime permissions do not
broaden campaign authorization.

On Codex, invoke `$krineon`, keep the root agent as coordinator, and read the
[Codex runtime adapter](references/codex.md) before launching workers. Use
`list_agents` for capacity, `spawn_agent` with `fork_turns="none"` by default,
`send_message` for active steering, `followup_task` only to reuse an idle
identity, `interrupt_agent` for unsafe or superseded work, and `wait_agent` only
when no useful coordinator work remains. A child final response is a
notification, not durable task completion.

On OpenCode, load `krineon` through the native `skill` tool and keep the primary
agent as coordinator. Use the `task` tool for bounded, non-overlapping workers:
`explore` for read-only analysis and `general` for workers that write artifacts
or run authorized local experiments. Launch independent tasks in parallel
within safe capacity. Every task has fresh context, so provide absolute skill,
campaign, authorization, and workspace paths plus the claim instruction, exact
revision, deliverables, evidence contract, and stop conditions. Assign a
distinct registered identity such as `opencode:worker-a` to each fresh task and
record its returned `task_id` as the runtime handle. Resuming a task preserves
its identity; independent replay requires a fresh task and worker identity.
Never register multiple worker names for one OpenCode task or session.

On OMP, invoke `/skill:krineon`, resolve supporting resources through
`skill://krineon`, and follow the
[OMP binding](references/orchestration.md#omp-oh-my-pi). Use only collaboration
tools exposed by the active runtime.

## Intake and authority

When the user supplies program rules and scope, preserve them verbatim and use
them as campaign intake. Resolve an unambiguous public source repository and
exact revision when possible. Ask only when a choice changes the asset,
authority, credentials, meaningful cost, or safety boundary. Never infer
permission for live systems, testnets, accounts, wallets, or shared data from
source-code scope. Read [program intake](references/program-intake.md) and
[safety](references/safety.md).

Before dynamic work, record:

- target, repository, revision, and deployed artifact;
- authorized assets, environment, methods, and accounts;
- exclusions, resource limits, cleanup, and stop conditions; and
- whether external network or state-changing actions are allowed.

Prefer an owned disposable local fixture. Production-equivalent means a
supported release build and configuration, not a development server. Dev and
debug builds may explain a lead but cannot be the primary finding terminal.

## First-principles discovery

Analyze one pinned tree and its exact-revision build. Do not use changelogs,
advisories, Git history or blame, security commits, other revisions,
patched-version comparisons, or internet patch diffs to discover candidates.
The target's checked-in tests, assertions, fuzz targets, fixtures, generated
code, and invariant comments are valid local oracles. External scope and
documentation checks belong to pre-filing review after a chain is complete.

Map these directly from code:

1. attacker-controlled ingress and representation changes;
2. trust, authorization, isolation, and lifetime boundaries;
3. producers and consumers that interpret the same state differently;
4. caches, manifests, module identity, generated or vendored runtimes;
5. native parsing, memory ownership, code loading, and execution authority;
6. platform and production-runtime branches; and
7. every conditional between ingress and the proposed terminal.

Create a campaign `third_party/` directory. Derive dependency revisions from
lockfiles, manifests, bundles, build graphs, or runtime linkage and pin only
high-leverage sources there. Audit both the dependency and the caller boundary.
Read [dependencies](references/dependencies.md).

Static analysis is a hypothesis generator. Tree-sitter, Joern, Trailmark, and
Z3 output does not become a candidate by itself. Prefer differential witnesses:
two real pinned consumers, one hashed input, a recorded disagreement, and an
equal control. Bind solver constraints to an exact source fragment and execute
the result through both consumers. Read
[tool-assisted analysis](references/tool-assisted-analysis.md).

Semantic discovery currently has one deliberately narrow pilot: Next.js
authorization to production route execution. It models attacker-controlled
path representations, the checks that classify them, the route resolver that
consumes them, and ownership of each intermediate representation. It then
generates the cheapest experiment that separates agreement, normalization
bypass, public alias, and unprotected-baseline explanations. Do not claim this
depth for other ecosystems until an equally concrete boundary adapter exists.
Read [semantic experiments](references/semantic-experiments.md).

## Campaign orchestration

Use Krineon's durable scheduler as the source of truth. Before scaling, run its
gate self-test with one worker and require the coordinator to re-execute and
reject the intentionally false claim. Then use all safe runtime capacity for
dependency-ready, non-overlapping work. Do not assign a fixed number of agents
to any strategy and do not let one attractive family monopolize the campaign.

Maintain semantic approach-family IDs defined by boundary, mechanism, and
invariant, not wording. Keep several incompatible routes alive through multiple
rounds. Allow independent routes to mature before cross-pollination. Pair every
concrete bug with a different-agent adversarial review, and assign any replay
to a fresh identity that did not originate or previously review it. Aliases and
follow-ups do not create independence.

Every worker must register its immutable runtime identity, atomically claim a
ready task, work in the returned isolated workspace, heartbeat long work, write
the required machine-readable result, and submit idempotently under its lease.
The coordinator repeatedly synthesizes, challenges assumptions, redirects weak
routes, creates missing-link tasks, recovers expired leases, and backfills free
slots. Read [orchestration](references/orchestration.md),
[Codex operation](references/codex.md), and
[approach families](references/approach-families.md).

Workers propose experiments. They do not execute self-approved evidence for
promotion. The coordinator signs the exact recipe and target hashes, releases
the scheduler write lock, and a controlled runner executes the approved recipe
with bounded process-group timeouts. The runner signs raw observations using a
private key kept outside worker workspaces. Promotion recomputes signatures,
hashes, subject binding, and assertions instead of trusting a stored Boolean.

## Persistence without fabrication

A failed approach or “no findings” result is not a campaign stop condition.
For each blocked route, retain:

- the exact missing link or enforcing guard;
- concrete evidence for why the current mechanism fails;
- source-derived alternative producers, consumers, representations, or sinks;
- the cheapest safe discriminating experiment; and
- a semantic mechanism fingerprint.

Create fresh-agent breakout and composition tasks for plausible new mechanisms.
Reopen a route only when evidence establishes a genuinely different mechanism,
not renamed inputs or more retries. Never route around authorization, safety,
budget, or program exclusions. Stop only for an explicit user stop, missing
authority, exhausted campaign budget, or unsafe/out-of-scope boundary. Read
[blocker resolution](references/blocker-resolution.md).

Treat failed experiments as semantic information. Eliminate the disproved
mechanism, not only the tested bytes. A coverage plateau must identify the
unreached consumer and justify a grammar or harness change. A verified
primitive must create a concrete missing-link experiment. Allocate budget by
validated root causes and security explanations eliminated per unit cost, then
by minimized stacks and coverage; task volume is not progress.

## Target-specific execution

Load only references relevant to the active target:

- Next.js, React, and Node production builds, protocol sequences, and shipped
  bundle mapping: [framework adapters](references/framework-adapters.md),
  [HTTP harness](references/http-protocol-harness.md),
  [framework analysis](references/framework-analysis.md), and
  [JavaScript coverage](references/javascript-coverage-generation.md). For the
  current semantic boundary, also read
  [semantic experiments](references/semantic-experiments.md).
- AFL++, libFuzzer, or Fuzzilli operation, corpus exchange, coverage plateaus,
  stack deduplication, and minimization: [fuzzing](references/fuzzing.md).
- Chrome/V8 release, sanitizer, debug, and owned-page Chromium replay:
  [Chrome/V8](references/chrome-v8.md) and
  [the worker profile](agents/chrome-v8-agent.md).
- Native Apple Silicon execution, Mach-O architecture evidence, and Darwin
  Seatbelt validation: [macOS arm64](references/macos-arm64.md).
- Search efficacy on a frozen local corpus with evaluator-held target oracles:
  [rediscovery benchmark](references/rediscovery-benchmark.md).

Run the real supported production configuration when one is available. For web
chains, retain raw requests and responses, duplicate-header/framing behavior,
redirects, concurrent/stateful sequences, independent roles or tenants, and
proxy/framework/origin differentials. For JavaScript, attribute generated
coverage back through source maps and preserve client/server boundaries.

Fuzzer crashes and differentials are leads. Cluster by normalized first fault,
minimize before queueing, and re-execute retained artifacts. Do not score
controllability from a bug-class label. Prove chosen bytes, allocation identity
and generation, stable reachability, or exact state influence as applicable.
Measure race and allocator reliability as `N/M` across fresh processes.

## False-positive and evidence gate

Before promotion, write an exact source-to-terminal path. For every conditional
on that path, record the concrete attacker action or target state that produces
the required outcome. Then re-execute machine assertions for those conditions
and check for contradictions. The assumptions list must be empty.

Require all of the following:

- source and runtime artifacts pinned and hashed;
- attacker control proved at the actual ingress;
- stock or supported production-equivalent reachability;
- baseline, enforcing negative control, and attack case differing only in the
  disputed condition;
- a harmless real terminal, not a synthetic callback or modified target state;
- raw evidence, environment, cleanup, and negative results;
- measured preconditions and reliability;
- no application-authored unsafe sink standing in for a framework defect; and
- independent replay by distinct verified identities in fresh processes.

The coordinator must re-run the artifact; file existence, non-empty prose,
agent agreement, or a Boolean in JSON is not proof. Independent review must
name a hypothesis failure mode and an observer failure mode, then bind an
alternate oracle to a recomputed reviewer attestation. Keep first-fault
classification, controllability, web reachability, renderer compromise, and
sandbox escape as separate evidence levels. Read
[false-positive control](references/false-positive-control.md),
[evidence gates](references/evidence-gates.md), and
[reality evidence](references/reality-evidence.md).

## Promotion and reporting

Promote only a complete Critical/RCE chain that meets the program's own impact
definition. Do not package lower-impact leads merely to produce a report. State
all deployment and attacker preconditions, distinguish tested facts from source
inference, and describe root cause before gadgets. Validate affected versions
only by supported evidence; do not silently generalize from one run.

After promotion, check current scope, official documentation, eligibility,
duplicate risk, and coordinated disclosure without using those sources to mine
the bug. Produce a root-cause-first report, self-contained reproduction,
machine-readable results, hashes, and a bounded proof. Krineon does not submit
reports or attack third-party targets autonomously. Read
[pre-filing](references/pre-filing.md) and
[reporting](references/reporting.md).
