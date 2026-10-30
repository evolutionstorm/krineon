# Codex runtime adapter

Use this adapter when Krineon is loaded as a Codex skill. The durable Krineon
queue remains the source of truth; Codex collaboration tools provide worker
processes and communication, not task state.

## Resolve paths once

Record the physical directory containing the loaded `SKILL.md` as an absolute
`KRINEON_SKILL_ROOT`. Keep it separate from the target checkout and campaign
directory. Pass these absolute paths to every worker:

- the Krineon skill root;
- the campaign root;
- the claimed detached workspace;
- the authorization and scope artifacts; and
- the result template and evidence destination.

Do not assume that children inherit shell variables, the coordinator's current
directory, or its conversation. Prefer paths to retained artifacts over copied
prose so agents read the same authoritative state from disk.

## Coordinator lifecycle

The root Codex agent remains coordinator. It performs intake, runs the gate
self-test, maintains the durable scheduler, synthesizes results, and talks to
the user. It must not consume a worker slot by doing an originator's research
while runnable independent work exists.

1. Run the gate self-test before scaling beyond one worker. The coordinator
   must re-execute and reject the intentionally false artifact.
2. Use `list_agents` to observe actual runtime capacity and worker state.
3. Inspect scheduler demand and claim only dependency-ready tasks balanced by
   semantic approach family.
4. Use `spawn_agent` for each claimed independent slice. Default to
   `fork_turns="none"` and provide a complete task packet. Use inherited
   history only when essential context has not yet been retained; writing that
   context to a campaign artifact first is preferred.
5. Backfill newly available capacity while safe slots and runnable diverse work
   exist. Never preassign a fixed number of workers to one lane.
6. Use `wait_agent` only when the coordinator has no useful synthesis,
   scheduling, recovery, or user-update work available.

Every spawn message must include the exact target revision, authorization
boundary, absolute skill/campaign/workspace paths, task or claim instruction,
required controls, result schema, evidence gate, and stop conditions. A child
must register, claim, heartbeat long work, write its result artifact, and submit
it idempotently through the durable lease before returning a final message.
The child final message is only a notification; it cannot unlock dependencies.

## Identity and independence

Map each immutable Krineon worker identity to the canonical Codex task path or
agent ID returned by `spawn_agent`, for example
`codex:/root/parser_invariant_01`. Display names, roles, models, and aliases are
not identities.

- Reusing an idle agent with `followup_task` preserves that identity. It does
  not create an independent reviewer.
- A finding replay must be claimed by a fresh, distinct Codex identity that did
  not originate or previously review the finding. Spawn it with
  `fork_turns="none"` and give it only the pinned inputs and replay contract.
- `send_message` may add evidence or constraints to a running worker without
  changing ownership.
- Never manufacture independence by registering multiple worker names for one
  Codex agent.

The reportable gate must recompute the retained artifacts and verify the
originator/reviewer identity mapping. Agreement in prose is not a replay.

## Steering, cancellation, and recovery

Use `send_message` for a non-disruptive correction while a worker is active.
Use `followup_task` only for new work assigned to an idle existing identity.
Use `interrupt_agent` when work is unsafe, out of scope, superseded, or must
stop promptly. Runtime interruption alone does not update Krineon's database:
cancel or requeue the durable task, stop the worker binding, recover expired
leases, and then inspect scheduler state before backfilling the slot.

If the coordinator restarts, read campaign state from disk, recover leases,
call `list_agents`, reconcile live Codex agents with registered worker
identities, and resume from dependency-ready tasks. Do not reconstruct state
from conversation memory.

## Context and permission discipline

Keep task packets narrow. Point workers at the registry entries, source ranges,
inputs, controls, and templates they need instead of embedding the full
campaign history. Workers return paths, digests, machine observations, and
concise conclusions; large logs remain in evidence directories.

Codex filesystem or network approval is not campaign authorization. A command
may be permitted by the runtime and still be out of scope. Live services,
shared systems, accounts, wallets, testnets, and meaningful external writes
require explicit asset-specific authority. Prefer bounded owned local fixtures
and production-equivalent release builds.

When user input arrives during a campaign, the root coordinator decides whether
it replaces or extends the active objective, updates durable tasks accordingly,
and steers or cancels affected workers. Children do not independently broaden
scope.
