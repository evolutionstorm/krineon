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
The lightweight extractor separates lexical function scopes, versions simple
assignments, kills overwritten values, and requires structural block-prefix
dominance. These are still heuristic def-use candidates, never proved flows.
Runtime value tracing or a target CPG must confirm the validated value,
transformation result, and consumer-selected identity. Unknown transformations
generate targeted value-trace experiments instead of disappearing because no
mutation dictionary entry exists. Fixed encoding dictionaries remain
supplemental reconnaissance. A dictionary-only negative result cannot eliminate
a source mechanism.

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

The analyzer deduplicates equivalent semantic states instead of treating every
operation ordering as distinct. Its reduction is future-aware: two states are
equivalent only when their current effects match and one state's remaining
per-primitive execution budgets dominate the other. Incomparable budgets stay
on the frontier, preventing traversal order or primitive names from erasing a
later generation-dependent composition. It prioritizes primitives found by
backward relevance from the Critical boundary while retaining unrelated
frontier states. Equivalent independent orderings are reduced; histories
remain in witnesses where ordering changes security-relevant behavior. If the budget ends first,
the result contains a checkpoint, retained frontier, and mandatory continuation
experiment. Resume that checkpoint rather than restarting or treating
truncation as a negative result.

The analyzer never emits a vulnerability verdict. It emits the tri-state
connection assessment, attacker-reachable configurations, complete boundary
paths, and ranked missing-link experiments. Ranking considers Critical-boundary
relevance, uncertainty removed, usefulness to multiple consumers, producer
reachability, and measured setup cost when a retained timing record exists.
Without a timing record, the output labels its fallback as a state-sequence
estimate rather than presenting it as measurement.

The coordinator combines active typed leads and adversarially reviewed route
primitives in a versioned campaign graph under `evidence/chain-graphs/`. Its
durable experiment frontier records `pending`, `running`, `confirmed`,
`refuted`, `inconclusive`, and `superseded` states. It schedules the
highest-value eligible experiment, even when the graph itself is unchanged or
a higher-ranked experiment already finished. Scoped negatives refute only their
matching experimental scope. Scope includes mechanism, relevant inputs,
configuration, state, and prerequisite version. A shared producer or consumer
does not imply a shared falsification. A materially changed scope gets a new
identity and can reopen investigation without erasing the earlier result.

## Preserve state history

Authentication, cache priming, ownership transfer, worker reuse, object
generation, and independent victim reads are transitions, not isolated HTTP
requests. Each transition names its before and after state, authority,
ownership, operation, and invariant.

Sequence generation may repeat an operation within a declared bound, omit
operations, or choose alternate paths. It separately records what an attacker
can attempt, what the reference security model expects, and what the real
implementation was observed to do. A released reference can therefore be used
in an attempted allocate-release-use sequence without the model assuming that
the implementation accepts it. It tracks allocation, release, use,
invalidation, object generations, thread identity, and explicit `happensAfter`
constraints. Reduction must preserve the transition pairs and partial order
required by the security claim.

Cross-principal, process, namespace, or runtime movement requires an explicit
context transition with a named transport, authority change, destination, and
capabilities preserved across it. The label `any` means unresolved; it is not a
wildcard that joins incompatible contexts. Chain primitives may opt into
bounded repeated execution when the repeated operation changes modeled state or
object generation.

The HTTP protocol harness rejects unrecorded history changes and records
exercised and missing transition pairs. `state_sequence_generator.py` retains
reference-valid transitions and explicit attacker attempts that challenge the
reference model, with an unknown, allowed, or rejected implementation outcome.

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

A negative result must name an `experimentalScope` containing the mechanism,
relevant inputs, configuration, state, and prerequisite version. It must also
retain the enforcing guard, downstream consumer, observation, evidence, and
conditions that would justify reopening it. Falsification matching is exact
across all scope dimensions and fails open when the version is unspecified. It
does not establish that the feature, parser, or boundary is safe.

## Measure chain progress

Track invariant violations, controlled attacker capabilities, new consumers,
resolved acquisition prerequisites, compatible primitive edges, confirmed and
falsified preconditions, and uncertainty removed. Coverage and unique crashes
remain search proxies. Validated root causes per measured cost remain the
primary campaign outcome.
