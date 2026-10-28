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

## Using collaboration tools

When the runtime exposes collaboration tools:

1. Use `spawn_agent` for a bounded task packet with one primary question.
2. Use `wait_agent` with a long timeout rather than polling continuously.
3. Use `send_message` to add evidence or constraints without restarting work.
4. Use `followup_task` to trigger a distinct validation pass after an agent is
   idle.
5. Use `interrupt_agent` only when the task is unsafe, redundant, or superseded.

The coordinator's launch loop is:

```text
read launch-plan.json and the current wave
spawn one agent per complementary task packet, within the concurrency limit
wait for completed handoffs
merge source references, artifacts, blockers, and registry statuses
send targeted follow-ups for contradictions or missing controls
stop redundant agents before starting the next wave
assign surviving candidates to different agents for clean replay
run the evidence gate before root synthesis
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
