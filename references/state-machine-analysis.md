# Universal state-machine analysis

Every campaign maintains one `state-machine-inventory.json` file. Begin this
analysis with the first source or application pass and update it throughout the
campaign. This requirement is target-neutral. It applies to SDKs, applications,
frameworks, libraries, services, compilers, browsers, native runtimes, protocol
implementations, smart contracts, and mixed-language repositories.

When a pinned local checkout is available, campaign initialization performs a
bounded universal source extraction. Run it explicitly after changing the
checkout or discovery limits:

```text
scripts/state_machine_inventory.py extract \
  CAMPAIGN/state-machine-inventory.json /path/to/pinned/source
```

The extractor recognizes supported C-family, Rust, Go, JVM, JavaScript,
TypeScript, Python, Ruby, PHP, .NET, Swift, BEAM, Lua, Dart, Zig, Solidity,
Vyper, and interface-definition files. It records explicit state/status/phase
symbols, assignments, comparisons, assertions, and transition APIs. It also
prioritizes implicit lifecycle, memory-lifetime, retry, concurrency, cache,
parser, protocol, authorization, cancellation, job, transaction, and
capability machines.

Source extraction creates `source-signal-only` candidates. Lexical
co-occurrence is not data flow, an invariant failure, or a vulnerability.
Agents must resolve scope, aliases, dominance, concrete transitions, process
and principal boundaries, object identity and generation, and reachable
runtime behavior before promoting a candidate into `machines`.
Machine kinds are extensible stable identifiers, so a target-specific domain
machine does not need to be forced into a framework-oriented taxonomy.

Model both machines declared by the target and implicit machines created by:

- object allocation, ownership, borrowing, movement, detachment, and release;
- initialization, readiness, shutdown, cleanup, and destruction;
- retries, timeouts, cancellation, rollback, and idempotency;
- caches, persistence, invalidation, replication, and versioning;
- parsers, serializers, protocols, framing, and representation changes;
- authentication, authorization, identity, capability, and tenant changes;
- jobs, queues, callbacks, workers, and asynchronous completion;
- compiler tiers, optimization, deoptimization, and feedback state; and
- locking, atomics, task ordering, shared state, and concurrency.

For each machine, record:

- concrete states and their entry and exit conditions;
- invariants and the target-owned evidence supporting them;
- guarded transitions, actors, and effects;
- retry policy, idempotency or identity binding, and state after failure;
- shared state, locking or serialization, and relevant interleavings;
- unresolved states or transitions; and
- invalid states or transitions that source or runtime evidence shows are
  actually reachable.

Do not label a theoretical combination as reachable. A source-reachable entry
needs a complete branch-resolved code path. A runtime entry needs a retained
trace or replay plus an enforcing control. Include the necessary prior history,
retry sequence, or concurrency schedule.

Workers should write a proposal with the same schema and merge it through
`scripts/state_machine_inventory.py`. The merge is locked and rejects
conflicting identifiers. Version an identifier when new evidence changes an
existing interpretation instead of silently replacing prior knowledge.

Validate the populated inventory before synthesis. The coverage summary counts
explicit and implicit machines, retry and concurrency transitions, reachable
invalid states, source languages, unpromoted candidates, and machines with
unresolved questions. Unknown languages or transformations require a targeted
experiment or an additional extractor; they are not evidence that no state
machine exists.
