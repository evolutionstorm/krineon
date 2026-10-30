# Execution-boundary and chain reasoning

Start each research route at an eventual Critical authority boundary, not at a
suspicious parser or API. Name the boundary operation, the exact eventual
impact, the next intermediate capability, and the pinned source evidence that
makes the route plausible. Supported boundary classes include data becoming
executable behavior, privileged function or module selection, managed/native
ownership crossings, and lower-trust code acquiring higher-trust execution.

## Prove assumption disagreements

For every producer/consumer hypothesis, record:

1. the property the first component validates;
2. the transformation that occurs after that check;
3. the later consumer's assumption; and
4. an executable discriminator that distinguishes agreement from disagreement.

Call-name proximity is not source derivation. A transformation witness must
prove an ordered path from a value observed by a validation call, through the
transformation and its result symbol, to a downstream consumer of that result.
Krineon records unproved calls as candidates and never lets an unrelated call
such as `logMessage.toLowerCase()` create a request-path witness. Ordered
transformations may compose only when the intermediate result symbol connects
them. Fixed encoding dictionaries are supplemental reconnaissance. A
dictionary-only negative result cannot eliminate a source mechanism.

## Compose feasible executions

Represent each primitive with attacker-controlled inputs, produced and required
capabilities, capability properties and limitations, principal, process,
namespace, runtime, state, lifetime, ordering, deployment, and acquisition
constraints. Also record object identity, generation, state, and explicit
capability or state invalidation. Use `key=value`, `key!=value`, or `not:key`
when lifetime, deployment, or acquisition conditions must express a concrete
contradiction.

`scripts/chain_reasoning.py` classifies each proposed connection as `feasible`,
`unknown`, or `impossible`. It explores accumulated execution states instead of
joining capability labels pairwise. Capabilities and state persist until
explicitly invalidated; object generations and invalid states do not silently
alias. A Critical boundary is complete only when all required capabilities,
objects, state, ordering, lifetime, deployment, acquisition, and context
conditions are jointly satisfied in one execution.

The analyzer never emits a vulnerability verdict. It emits the tri-state
connection assessment, attacker-reachable configurations, complete boundary
paths, and ranked missing-link experiments. Ranking considers Critical-boundary
relevance, uncertainty removed, usefulness to multiple consumers, producer
reachability, and measured setup cost when a retained timing record exists.
Without a timing record, the output labels its fallback as a state-sequence
estimate rather than presenting it as measurement.

The coordinator combines active typed leads and adversarially reviewed route
primitives in a versioned campaign graph under `evidence/chain-graphs/`. It
schedules the highest-ranked unsolved experiment, not whichever route happened
to finish first. New observations rebuild the graph, so a result can strengthen,
falsify, or redirect later composition work.

## Preserve state history

Authentication, cache priming, ownership transfer, worker reuse, object
generation, and independent victim reads are transitions, not isolated HTTP
requests. Each transition names its before and after state, authority,
ownership, operation, and invariant.

Sequence generation may repeat an operation within a declared bound, omit
operations, or choose alternate state-valid paths. It tracks allocation,
release, use, invalidation, object generations, thread identity, and explicit
`happensAfter` constraints. Reduction must preserve the transition pairs and
partial order required by the security claim. This makes allocate, release,
allocate representable without conflating the two object instances.

The HTTP protocol harness rejects discontinuous histories and records exercised
and missing transition pairs. `state_sequence_generator.py` emits only
state-valid histories and marks sequences that cover the required pairs.

## Separate observations from claims

Research records have four distinct maturity levels:

1. `observation`: a retained expected-versus-observed difference with no
   required Critical narrative;
2. `primitive`: an attacker capability with typed requirements and effects;
3. `chain-hypothesis`: a primitive mapped to an eventual Critical boundary;
4. `validated-connection`: at least two primitives connected with retained
   evidence and a jointly feasible execution contract.

Only the final filing gate may claim a vulnerability. Keeping an observation
unmapped is preferable to inventing a capability or impact merely to advance a
queue.

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
