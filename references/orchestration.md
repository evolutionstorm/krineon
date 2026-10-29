# Multi-Agent Orchestration

## Roles

The root agent is the campaign coordinator. It owns authorization, scope,
revision pinning, the registry, evidence quality, cross-agent synthesis, and the
final claim. Workers own bounded questions and return evidence, not prose-only
opinions.

Use the environment's concurrency limit. A productive default is the root plus
three workers. Do not create more agents merely to appear exhaustive.

## Wave plan

### Wave 0: coordinator setup

The coordinator:

1. freezes the source and runtime revision;
2. records authorization and scope;
3. runs the tool probe;
4. inventories public entry points and privileged sinks;
5. creates stable hypothesis IDs;
6. generates agent task packets with the harness.

### Wave 1: independent discovery

Launch three non-overlapping workers:

- **boundary mapper:** trust, identity, provenance, authorization, manifests;
- **sink-first tracer:** work backward from execution, file, network, native,
  key, cache, or policy sinks;
- **state/lifecycle auditor:** globals, pooling, async settlement, errors,
  recycle/reuse, ownership, and cleanup.

Each worker must provide exact source references, a minimal hypothesis, a
disproof condition, and a registry update. “Nothing found” is valid only with a
searched-surface inventory.

### Wave 2: targeted expansion

For surviving candidates, run complementary tasks:

- producer/consumer or cross-layer differential analysis;
- patch, sibling-function, generated-bundle, and prior-art analysis;
- deployment, configuration, platform, and remote-acquisition matrix.

Workers should attack assumptions exposed by Wave 1, not restart general
auditing.

### Wave 3: independent validation

The originating worker must not validate its own candidate. Assign:

- clean replay against an unmodified supported build;
- baseline, negative, positive, and patched controls;
- realistic impact, reliability, and cleanup measurement;
- adversarial scope, documentation, duplicate, and severity review.

### Wave 4: synthesis

The coordinator resolves contradictions, runs the evidence gate, writes the
root-cause-first report, hashes artifacts, and checks package hygiene. If an
agent's evidence conflicts with runtime behavior, runtime behavior wins until
the contradiction is explained.

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
- `blocked`: a dependency ended unsuccessfully.

Only `completed` satisfies a dependency. `recover` atomically requeues expired
leases while attempts remain, marks timeouts, and propagates dependency failure.
The campaign deadline, maximum concurrency, per-task timeout, lease duration,
and attempt budget come from the reviewed launch plan.

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
worktree at the pinned commit. Otherwise it creates a distinct empty workspace
containing `KRINEON_TASK.md` and `KRINEON_ASSIGNMENT.json`; an external runtime
adapter may hydrate that directory but must not share another worker's tree.

Workers submit one JSON result:

```bash
python3 scripts/research_harness.py submit CAMPAIGN worker-a TASK_ID \
  --lease-token TOKEN --result result.json \
  --idempotency-key TASK_ID-attempt-1
```

The result is copied into `results/TASK_ID/`, hashed, and recorded in the same
transaction that completes the task. Retrying the identical submission is a
no-op; reusing the key with different data fails.

## Independent replay

Register each finding with its originating worker, then create a dedicated
replay task:

```bash
python3 scripts/research_harness.py register CAMPAIGN F001 \
  --title "Candidate" --lane protocol-differential --originator worker-a
python3 scripts/research_harness.py schedule-replay CAMPAIGN F001 \
  --depends-on protocol-differential
```

The scheduler excludes the originator from that task. The reviewer result must
contain:

```json
{
  "independentReplay": {
    "findingId": "F001",
    "originator": "worker-a",
    "reviewer": "worker-b",
    "passed": true
  }
}
```

`submit --replay-of F001` verifies all four fields, the submitting worker, and
the distinct identity before recording the result digest and enabling the
finding's `independent_replay` gate. A Boolean manually placed in a launch plan
or finding file is no longer sufficient for the reportable gate. At gate time,
Krineon recomputes the result hash and cross-checks the completed replay task,
accepted database submission, originator exclusion, reviewer identity, and
JSON replay payload.

## Runtime adapters and collaboration tools

Krineon schedules work but deliberately does not create model processes. A
Codex, Claude Code, OpenCode, CI, or human adapter runs the worker protocol.
When a runtime exposes collaboration tools, its coordinator can map them as
follows:

When the runtime exposes collaboration tools:

1. Use `spawn_agent` for a bounded task packet with one primary question.
2. Use `wait_agent` with a long timeout rather than polling continuously.
3. Use `send_message` to add evidence or constraints without restarting work.
4. Use `followup_task` to trigger a distinct validation pass after an agent is
   idle.
5. Use `interrupt_agent` only when the task is unsafe, redundant, or superseded.

The coordinator's operational loop is:

```text
queue the reviewed launch plan
register each runtime worker identity
claim dependency-ready tasks within the concurrency limit
spawn or instruct the runtime using the claimed packet and workspace
heartbeat long-running work and submit results idempotently
recover expired leases after coordinator or worker failure
schedule finding-specific replay tasks that exclude originators
run the machine-checkable evidence gate before synthesis
```

Example task packet:

```text
Target: exact commit and runtime
Authorization: local owned fixture only
Question: Does the async resolution path enforce the same exact-prototype
invariant as the synchronous path?
In scope: listed source files and generated bundle
Out of scope: live services, DoS, secret access
Required output:
- exact source references
- minimal deterministic harness
- baseline and negative control
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

Use a small fixed vocabulary:

- `idea`: not source-confirmed;
- `source-confirmed`: invariant mismatch located;
- `primitive`: deterministic effect without complete attack path;
- `candidate`: supported ingress and security impact plausible;
- `validated`: controls and independent replay passed;
- `reportable`: scope, prior art, current version, and package checks passed;
- `blocked`: exact missing precondition recorded;
- `disproved`: falsifying evidence retained;
- `duplicate-risk`: same root cause or patch family likely reported.

Never delete blocked or disproved entries. Negative knowledge is an audit asset.

## Convergence rules

Stop broad discovery and focus when a candidate has:

- a framework-owned invariant violation;
- an attacker-reachable supported ingress;
- a non-synthetic concrete terminal;
- one or more controls that isolate the cause;
- no obvious scope or prior-art blocker.

Stop a candidate when the same blocker survives three independent attempts, or
when the only remaining path requires an out-of-scope action, unsafe live test,
application-authored vulnerability, undocumented insecure configuration, or
private local knowledge that cannot be acquired remotely.
