# Discovery depth and durable knowledge

Krineon retains discovery state across workers and rounds. These records guide
research; they do not relax the evidence or filing gates.

## Search the observation blackboard

Workers submit structured `taskResult.observations`. Each observation records a
stable mechanism, confidence, state, typed capabilities, source references,
retained evidence, relevant assets, and coverage. Search the blackboard before
starting a task so that a worker can build on facts already established by a
different lane.

Use `observation-search` to query the durable store. A search result is a lead,
not permission to assume its conclusion. Runtime and replay confidence remain
visible in every result.

## Maintain typed attack-chain todos

Use `taskResult.attackChainTodos` for a persistent, ordered path from retained
capabilities to an explicit Critical authority boundary. Every step states its
typed prerequisites, output capability, objective, success criteria, and
approach families.

When an observation satisfies a step, Krineon evaluates the remaining graph.
It schedules the highest-priority ready edge as a bounded coordinator task and
keeps unscheduled edges durable. It does not convert an unproved edge into a
capability.

## Continue and steer workers

Use `taskResult.workerContinuation` to retain the current hypothesis,
competing explanations, eliminated mechanisms, blocker, next experiment, and
artifact references. An active worker can save the same structure with the
lease-bound `worker-checkpoint` command. A later claim receives that
checkpoint. Active coordinators can attach a versioned steering message
without replacing the worker's evidence.

## Use the global asset and coverage graph

Observation asset references identify the same route, parser, consumer,
principal, process, cache, module, or protocol operation across tasks. Coverage
records state which consumer and boundary were untested, hypothesized, tested,
refuted, or verified. This prevents page counts and request counts from being
mistaken for security coverage.

## Compact settled graph regions

Krineon can compact repeated refuted or superseded observations by mechanism.
Compaction creates a deterministic digest containing every member ID, asset,
capability, and evidence reference. Original rows remain in the database and
can be expanded; active observations and unresolved chain edges are never
discarded. Search results identify matching digests, and `depth-expand`
restores their complete member records.

## Acquire client artifacts recursively

The CDP runner retains scripts loaded during an approved browser journey and
builds a recursive reference graph. Already retained chunks are traversed
immediately. Missing same-origin chunks become explicit read-only acquisition
experiments that must use the approved browser contract and budget. The graph
never fetches a URL itself.

Client routes, roles, menus, and permission strings are discovery hints only.
They help identify server authorization questions but never prove policy or
authorize endpoint execution.

## Model WebSocket and SSE protocols

The CDP runner converts retained WebSocket and Server-Sent Events into channel
and message-shape models. It records direction, structural shape, bounded
length, hashes, handshake properties, identity, tenant, journey, and deployment
epoch. It does not copy message values, secrets, event IDs, or raw payloads.

Protocol shapes generate questions about authentication, authorization,
reconnect, expiry, tenant binding, and alternate consumers. Those questions
still require separately approved bounded experiments and authoritative
readback.
