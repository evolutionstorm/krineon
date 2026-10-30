# Execution-boundary and chain reasoning

Start each research route at an eventual Critical authority boundary, not at a
suspicious parser or API. Name the boundary operation, the exact eventual
impact, the next intermediate capability, and the pinned source evidence that
makes the route plausible. Supported boundary classes include data becoming
executable behavior, privileged function or module selection, managed/native
ownership crossings, and lower-trust code acquiring higher-trust execution.

## Model assumption disagreements

For every producer/consumer hypothesis, record:

1. the property the first component validates;
2. the transformation that occurs after that check;
3. the later consumer's assumption; and
4. an executable discriminator that distinguishes agreement from disagreement.

Derive transformations from calls and branches in the pinned source. Fixed
encoding dictionaries are supplemental reconnaissance. A dictionary-only
negative result cannot eliminate a source mechanism.

## Compose typed primitives

Represent each primitive with attacker-controlled inputs, produced and
required capabilities, capability properties and limitations, principal,
process, namespace, runtime, state, lifetime, ordering, deployment, and
acquisition constraints. `scripts/chain_reasoning.py` joins only exact
compatible producer/consumer contracts. A Critical boundary is complete only
when all required capabilities have reachable suppliers in compatible context.

The chain analyzer never emits a vulnerability verdict. It emits compatible
edges, attacker-reachable primitives, complete boundary paths, and the cheapest
missing-link experiments. A focused-chain task is unlocked only when retained
chain evidence advances the score or connects a reachable producer to another
consumer. The scheduler gives that task one bounded slot and then returns to
approach-diverse exploration.

## Preserve state history

Authentication, cache priming, ownership transfer, worker reuse, object
generation, and independent victim reads are transitions, not isolated HTTP
requests. Each transition names its before and after state, authority,
ownership, operation, and invariant. Sequence generation may omit operations
or choose alternate state-valid paths, but reduction must preserve the
transition pairs required by the security claim.

The HTTP protocol harness rejects discontinuous histories and records exercised
and missing transition pairs. `state_sequence_generator.py` emits only
state-valid histories and marks sequences that cover the required pairs.

## Retain scoped negative knowledge

A negative result must name the mechanism, exact inputs, test conditions,
enforcing guard, downstream consumer, observation, evidence, and conditions
that would justify reopening it. It eliminates that mechanism only in that
scope. It does not establish that the feature, parser, or boundary is safe.

## Measure chain progress

Track invariant violations, controlled attacker capabilities, new consumers,
resolved acquisition prerequisites, compatible primitive edges, confirmed and
falsified preconditions, and uncertainty removed. Coverage and unique crashes
remain search proxies. Validated root causes per measured cost remain the
primary campaign outcome.

