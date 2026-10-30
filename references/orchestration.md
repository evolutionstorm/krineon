# Multi-Agent Orchestration

## Roles

The root agent is the campaign coordinator. It owns authorization, scope,
revision pinning, the registry, evidence quality, cross-agent synthesis, and the
final claim. Workers own bounded questions and return evidence, not prose-only
opinions.

Start with one worker. Before registering a second identity, run:

```bash
python3 scripts/research_harness.py gate-self-test CAMPAIGN
```

The coordinator executes an intentionally false positive recipe against a
frozen local target and must reject the worker's claimed positive observation.
`worker-register` blocks scale-out until that machine gate passes. Runtime
leads later require their own `taskResult.coordinatorReplay`; the coordinator
executes the frozen artifact itself and ignores a worker-supplied `passed`
label.

After this gate, use every safe worker slot exposed by the runtime continuously.
Four or more workers may run concurrently when runtime capacity and independent
work permit. Keep the root agent coordinating and synthesizing while workers
pull non-overlapping chain questions from the shared queue. Never reserve a
fixed number of workers for a lane or strategy. When a worker finishes or
blocks, claim from the least-loaded and least-covered runnable semantic family,
then use task priority within that balanced set. Split promising missing links
without concentrating workers in that family. Merge or cancel stale work as
evidence changes. Do not waste slots on duplicate keyword searches.

## Wave plan

### Wave 0: coordinator setup

The coordinator:

1. freezes the source, one ASan/UBSan component, and runtime revision;
2. records authorization and scope;
3. runs the tool probe;
4. inventories public entry points and privileged sinks;
5. creates stable hypothesis IDs;
6. proves the coordinator lie-detection gate before scale-out;
7. generates agent task packets with the harness.

### Wave 1: independent discovery

Seed the queue with complementary first-principles questions such as:

- **ingress mapper:** public handlers, parsers, attacker fields, and authority;
- **execution-sink tracer:** work backward from process, module, native,
  executable-memory, unsafe deserialization, and callback sinks;
- **memory/lifetime auditor:** allocation, numeric domains, ownership, pooling,
  concurrency, recycling, and cleanup;
- **representation auditor:** producer/consumer lengths, encodings, shapes, and
  state machines; and
- **capability auditor:** manifests, namespaces, functions, modules, plugins,
  templates, and code-loading authority.

These are search axes, not fixed worker roles or staffing quotas. Any eligible
worker may claim any ready task, and a lane may be split or merged when the
evidence warrants it. Each worker must provide exact source references, a minimal hypothesis, a
disproof condition, and a registry update. “Nothing found” is valid only with a
searched-surface inventory.

### Wave 2: targeted expansion

Compose surviving links continuously and run complementary tasks for:

- complete ingress-to-sink chain construction;
- attacker acquisition of every identifier, address, module, and timing fact;
- primitive-to-execution escalation with attacker-controlled arguments;
- stock/supported deployment reachability; and
- focused blocker breakout for missing links.

Workers should attack assumptions exposed by Wave 1, not restart general
auditing.

### Wave 3: independent validation

The originating worker must not validate its own candidate. Assign:

- clean replay against an unmodified supported build;
- baseline, enforcing negative, positive, and same-revision
  invariant-restored controls;
- bounded real command or explicit program-defined Critical effect;
- fresh-process reliability and cleanup measurement; and
- adversarial attempts to reduce the chain to crash-only behavior, app misuse,
  unsupported configuration, unavailable coordinates, or synthetic evidence.

The fresh reviewer also executes the retained recipe with new harness-generated
challenges and completes the structured source-to-sink path proof. It
must enumerate every conditional, record the concrete attacker mechanism and
observed outcome for each branch, challenge contradictions, and leave no
unresolved assumptions. Distinct worker IDs that map to the same runtime-agent
identity do not count as independent review, and a prose-only replay result is
rejected even when it says `passed: true`.

### Wave 4: synthesis

The coordinator resolves contradictions and packages a report only if every
Critical/RCE gate passes. Otherwise it retains the chain links and blockers
without producing a lower-severity report. If source reasoning conflicts with
runtime behavior, the contradiction must be explained before promotion.

## Durable coordinator

`launch-plan.json` is configuration, not runtime state. Run `queue` to
materialize it into `orchestration.db`. SQLite transactions serialize claims,
so two workers cannot receive the same task. The database records workers,
task states, dependencies, attempts, leases, timeouts, workspaces, accepted
submissions, and an append-only event stream.

Task states are:

- `queued`: waiting for dependencies and an eligible worker;
- `running`: owned by one worker and one unguessable lease token;
- `completed`: accepted successful result;
- `failed`: worker submitted failure or exhausted a lease retry;
- `timed-out`: per-attempt wall-clock limit elapsed;
- `cancelled`: coordinator stopped the task;
- `blocked`: the worker submitted a structured blocker, or a dependency ended
  unsuccessfully and the blocked state propagated downstream.

Only `completed` satisfies a dependency. `recover` atomically requeues expired
leases while attempts remain, marks timeouts, and propagates dependency failure.
The campaign deadline, concurrency mode or explicit safety ceiling, per-task
timeout, lease duration, and attempt budget come from the reviewed launch plan.
With `maxConcurrency: "auto"`, every distinct active runtime-agent identity
contributes one slot. Registering more genuine agents expands capacity without
reserving headcount for any lane; aliases do not add capacity because one agent
may hold only one live lease. `orchestration-status` reports both work claimable
by current identities and a scale-out opportunity when exclusions or demand
require another independent agent.

## Worker protocol

Every worker has a stable `worker_id`, runtime/agent identity, and role. It must
be registered before it can claim work:

```bash
python3 scripts/research_harness.py worker-register CAMPAIGN worker-a \
  --agent codex:session-a --role originator
python3 scripts/research_harness.py claim CAMPAIGN worker-a --json
```

The claim returns a task packet, isolated workspace, attempt number, lease
token, expiry, and timeout. The lease token is a capability and must not be
placed in public evidence. Long-running workers renew it with `heartbeat`.

If the campaign records `localCheckout`, the scheduler creates a detached Git
worktree at the pinned commit. Otherwise it creates a distinct empty workspace.
Every workspace receives the task and assignment, campaign and authorization
records, the Critical/RCE reference, and `KRINEON_TASK_RESULT.template.json`.
An external runtime adapter may hydrate that directory but must not share
another worker's tree.

Workers submit one JSON result:

```bash
python3 scripts/research_harness.py submit CAMPAIGN worker-a TASK_ID \
  --lease-token TOKEN --result result.json \
  --idempotency-key TASK_ID-attempt-1
```

Normal completion must follow `KRINEON_TASK_RESULT.template.json`: exact task
ID, summary, conclusion, searched surface, pinned source references, evidence,
hypotheses, next tasks, and first-principles provenance. The result is copied
into `results/TASK_ID/`, hashed, and recorded in the same transaction that
completes the task. Retrying the identical submission is a no-op; reusing the
key with different data fails.

## Repeated independent-route rounds

Use `round-plan` with `assets/research-round.template.json` to launch each
research round. A valid plan contains at least three routes with distinct
semantic families and reciprocal incompatibility declarations. In one round,
the scheduler will not assign two route-development tasks to the same runtime
agent identity.

Each development task unlocks an adversarial task. The developer's runtime
identity cannot claim the review of its own route. The adversary records the
strongest counterargument, reproduced evidence, sanity outcome, and unresolved
gaps before helping repair or compose the route.

Only a registered coordinator can claim the round-synthesis task. Its result
must compare at least three routes, retain strengths and gaps, issue new
challenges and redirects, and state whether another round should launch. The
coordinator then supplies the next plan. A cross-pollination entry is accepted
only after each source route has completed two earlier development rounds and
two corresponding adversarial rounds.

Every route result must include fresh ideas even when the present experiments
produce no bug. Record intermediate bugs as primitives with evidence and chain
hypotheses. Once an adversary sanity-checks such a bug, Krineon automatically
schedules a fresh-agent composition task, excludes the developer and reviewer
identities, and adds the new task as a synthesis dependency.

`launchNextRound: false` is rejected unless `hardStop` records an explicit user
stop, missing authorization, exhausted campaign budget, or an unsafe/out-of-
scope boundary with evidence. Failed approaches and “no findings” require new
directions and another round; they are not terminal states.

When `launchNextRound` is true, Krineon schedules a coordinator-only
`next-round-planning` task. Its completion is rejected until the coordinator
has run `round-plan` and the next round's root-synthesis task exists. This keeps
the campaign live across coordinator or worker restarts instead of relying on a
prose reminder to launch again.

## Independent replay

Register each finding with its originating worker, then create a dedicated
replay task:

```bash
python3 scripts/research_harness.py register CAMPAIGN F001 \
  --title "Candidate" --lane cross-lane-chain-composition --originator worker-a
python3 scripts/research_harness.py schedule-replay CAMPAIGN F001 \
  --depends-on critical-controls-reliability
python3 scripts/research_harness.py schedule-replay CAMPAIGN F001 \
  --depends-on critical-controls-reliability
```

The scheduler excludes both the originator worker ID and its immutable runtime
agent identity, including aliases registered after scheduling. The second task
also excludes every accepted first-review agent and alias. Each reviewer result
must contain the normal completed-task contract plus the replay record:

```json
{
  "taskResult": {
    "taskId": "replay-F001-1",
    "summary": "Reproduced the complete chain in a clean workspace.",
    "conclusion": "The positive case and controls match the originating evidence.",
    "searchedSurface": ["pinned source and clean exact-revision build"],
    "sourceReferences": ["src/example.cc:42"],
    "evidence": ["evidence/replay-results.json"],
    "hypotheses": [],
    "nextTasks": [],
    "replayFindings": [],
    "analysisProvenance": {
      "firstPrinciplesOnly": true,
      "changelogUsed": false,
      "gitHistoryUsed": false,
      "advisoryMiningUsed": false,
      "patchedVersionDiffUsed": false,
      "internetPatchDiffUsed": false
    }
  },
  "independentReplay": {
    "findingId": "F001",
    "originator": "worker-a",
    "reviewer": "worker-b",
    "passed": true
  }
}
```

`submit --replay-of F001` verifies all four replay fields, the task result, the
submitting worker, and the distinct worker and agent identities before
recording the result digest. The finding's `independent_replay` gate is enabled
only after two distinct reviewer-agent identities pass. A Boolean manually placed in a launch plan
or finding file is no longer sufficient for the reportable gate. At gate time,
Krineon recomputes both result hashes and cross-checks the completed replay
tasks, accepted database submissions, identity exclusions, reviewer identities,
and JSON replay payloads.

## Runtime adapters and collaboration tools

Krineon's skill-level coordinator actively creates and backfills subagents when
the runtime exposes collaboration tools. The Python scheduler deliberately
does not embed vendor-specific process-launch APIs; a Codex, OMP, Claude Code,
OpenCode, CI, or human adapter binds each spawned runtime to the worker
protocol. Select the tools actually exposed by the runtime rather than assuming
that these API names are interchangeable:

| Operation | Codex collaboration interface | OMP interface |
| --- | --- | --- |
| Launch bounded workers | `spawn_agent` | `task` with shared `context` and per-worker `tasks[]` |
| Await completion | `wait_agent` | Automatic result delivery; `wait` only when otherwise blocked |
| Send evidence or constraints | `send_message` | `write agent://<id>` |
| Follow up with an existing worker | `followup_task` | `write agent://<id>`; parked workers can revive |
| Stop unsafe or superseded work | `interrupt_agent` | `write proc://<id>/kill` without content |

The coordinator's operational loop is:

```text
queue the reviewed launch plan
inspect orchestration-status schedulerDemand and the runtime's safe capacity
spawn and register distinct runtime agents while safe slots and ready work exist
claim diversity-balanced, dependency-ready tasks without lane quotas
spawn or instruct the runtime using the claimed packet and workspace
heartbeat long-running work and submit results idempotently
split missing links into dynamic tasks and backfill every newly free slot
recover expired leases after coordinator or worker failure
schedule finding-specific replay tasks that exclude originators
run the machine-checkable evidence gate before synthesis
```

### OMP (Oh My Pi)

Load Krineon through OMP's native skills directory and invoke `/skill:krineon`;
see [installation](../README.md#load-the-skill-in-omp). Read supporting files via
`skill://krineon/...`, but resolve executable scripts to the physical skill
directory. `agents/openai.yaml` is Codex UI metadata, not an OMP runtime adapter.

For each independent runnable slice, put a complete assignment in a `task`
item, including `task` and `solutionSpace`; put common authorization, pinned
revision, absolute skill/campaign paths, and evidence requirements in the batch's
`context`. Omit `agent` to select OMP's default full-capability worker. A
read-only scout cannot register, claim, heartbeat, or submit durable work. If
OMP exposes a flat task schema instead, use that schema rather than a batch.
Children do not inherit the coordinator's conversation. Pass all required
constraints and paths explicitly.

Have each child register and claim through the Python protocol before research;
do not preassign a queue task just because it appears in a launch plan. OMP's
`bash` tool supplies `PI_SESSION_ID` for the current session, including child
sessions. Bind the immutable Krineon agent identity to that value, not the model,
agent type, lane, or an unqualified display name that can repeat in another
session. For example, inside the child, with absolute `KRINEON_ROOT` and
`CAMPAIGN` values supplied in its assignment:

```bash
python3 "$KRINEON_ROOT/scripts/research_harness.py" worker-register \
  "$CAMPAIGN" worker-a --agent "omp:${PI_SESSION_ID:?OMP session identity required}" \
  --role worker
python3 "$KRINEON_ROOT/scripts/research_harness.py" claim \
  "$CAMPAIGN" worker-a --json
```

The coordinator uses its own `omp:$PI_SESSION_ID` identity and
`--role coordinator`. Record the mapping between worker ID, OMP session identity,
and the returned `task` agent ID for messages and cancellation. Keep the same
worker/agent binding for follow-ups and resumed sessions; a replacement child
with a different session ID needs a new worker ID. Never manufacture independent
reviewers by aliasing one session.

Run target commands with OMP `bash.cwd` set to the claim's absolute `workspace`.
OMP tasks otherwise start in the parent's directory; launching a task does not
select Krineon's detached worktree. Use the claimed workspace and its
`KRINEON_TASK.md`, `KRINEON_ASSIGNMENT.json`, authorization, reference files, and
result template. Do not add another OMP isolation/merge layer around that
workspace or merge research changes into the coordinator's checkout.

Use the absolute harness path for `heartbeat` and `submit` too. A worker must
write its JSON result to disk and successfully `submit` it under its lease
before reporting completion to OMP. An OMP task result or `agent://` artifact is
not a queue submission and cannot unlock dependencies. Preserve lease tokens
locally, not in public handoffs or report artifacts. The same independent-replay
and evidence gates apply on every runtime.

Let OMP deliver completed jobs automatically while the coordinator does useful
work. After stopping an OMP worker, reconcile its durable lease with `cancel`
for a retired task or `worker-stop --force` for work to requeue; killing the
runtime alone does not update SQLite. Recheck `orchestration-status`, recover
expired leases, and backfill only within actual runtime capacity and campaign
limits. In print mode, `--wait-async` keeps background results in the session;
without it OMP cancels outstanding jobs when the initial prompt finishes.

Example task packet:

```text
Target: exact commit and runtime
Authorization: local owned fixture only
Question: Can the public decoder's async invariant gap reach the stock module
loading or function invocation sink with attacker-controlled arguments?
In scope: listed source files and generated bundle
Out of scope: live services, DoS-only terminals, lower-severity reports,
history/changelog/advisory/patch-diff discovery, secret access
Required output:
- exact source references
- minimal deterministic harness
- baseline, negative, and same-revision invariant-restored controls
- disproof condition
- registry entry with status and blockers
Stop if: the proof would require third-party data or service degradation
```

## Handoffs

Every handoff must contain:

- stable hypothesis ID and current status;
- exact revision and environment;
- claim separated into root cause, ingress, carrier, terminal, and conditions;
- commands and artifact paths;
- what was proved, inferred, and disproved;
- unresolved blockers and the next highest-value experiment;
- cleanup state.

Use [assets/agent-handoff.template.md](../assets/agent-handoff.template.md).

## Registry states

There are two registries. `research_leads` in `orchestration.db` stores unique
minimized stacks, invariant breaks, and verified primitives. Those observations
advance through focused experiments without satisfying candidate gates.
`registry.json` stores candidate findings only after a plausible complete chain
exists. Never create or embellish a finding merely to preserve partial search
output.

Inspect ranked leads with:

```bash
python3 scripts/research_harness.py lead-status CAMPAIGN --json
```

Lead ranking is lexicographic by evidence grade, not a severity or
controllability point score: verified primitive, runtime invariant break,
unique minimized stack cluster, then source invariant break. Disproved leads
remain retained but sort after active leads.

Candidate finding states use this fixed vocabulary:

Use a small fixed vocabulary:

- `idea`: not source-confirmed;
- `source-confirmed`: invariant mismatch located;
- `primitive`: deterministic effect without complete attack path;
- `candidate`: complete Critical/RCE chain plausible and mechanically gated;
- `validated`: controls and independent replay passed;
- `reportable`: Critical/RCE, current-version, replay, scope, and package gates passed;
- `blocked`: exact missing precondition recorded;
- `disproved`: falsifying evidence retained;
- `duplicate-risk`: post-validation filing review indicates likely prior art.

Never delete blocked or disproved entries. Negative knowledge is an audit asset.

## Convergence rules

Before applying candidate-level convergence, inspect the semantic approach
registry. Agent count is not evidence of search diversity: multiple workers
testing the same boundary, mechanism, and invariant belong to one family even
when their task names differ. Do not concentrate agents because one path looks
promising or suspicious. The scheduler balances active family load, then
historical coverage, before raw priority whenever another family is runnable.
See
[approach-families.md](approach-families.md).

Stop broad discovery and focus when a candidate has:

- a framework-owned invariant violation;
- an attacker-reachable supported ingress;
- a bounded real code-execution or program-defined Critical terminal;
- one or more controls that isolate the cause;
- a feasible stock/supported deployment.

Do not stop a campaign merely because the same technical blocker survives
several attempts. Explain the mechanism, retire a route only when its required
link is falsified, and schedule alternate source-derived routes to the same
Critical/RCE boundary. Pause only when progress requires new authorization,
unsafe or out-of-scope action, exhausted campaign budget, or an external state
change. Application-authored vulnerabilities, undocumented insecure
configuration, and private local knowledge remain invalid primary-chain
substitutes, so search for a different stock or supported route.
