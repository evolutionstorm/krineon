# Semantic hypothesis experiments

Krineon's first semantic pilot is deliberately narrow: Next.js authorization
to route execution. The structural framework analyzer identifies route,
middleware, and authentication evidence. The semantic loop turns only that
evidence into a falsifiable model of one boundary:

> The authorization classifier and the production route resolver must resolve
> the same request representation to the same protected resource.

This is not a claim that Krineon derives security oracles for every framework,
browser, native library, or sandbox. Add another boundary only after this one
has measured value on a frozen corpus.

## Model contract

Each derived model records:

- attacker-controlled values and their ingress;
- the authorization and execution operations that consume them;
- every known check and whether dominance is proved or still needs measurement;
- the two interpretations of the same path;
- ownership and lifetime of the raw and normalized representations;
- competing explanations, including a public alias and an unprotected baseline;
- an executable authorization-to-resource agreement oracle; and
- the cheapest one-dimension experiment that separates those explanations.

The derivation produces an unsigned proposal, not a vulnerability verdict. The
coordinator reviews and signs the exact proposal. The controlled runner accepts
only that signed proposal, confirmed campaign authorization, a loopback HTTP
origin, and an authenticated control header supplied through the environment.
The retained observation hashes the control credential rather than storing it.

Use `scripts/semantic_hypothesis_loop.py` in three stages:

1. `derive` consumes a `krineon-framework-analysis` record and writes the
   proposal.
2. `approve` signs the exact proposal with the campaign's coordinator key.
3. `run` executes the approved baseline, authenticated control, and path
   representations against an owned loopback production fixture.

The runner identifies the executed route through framework response headers or
`__NEXT_DATA__.page`. A body hash is only a fallback identity, not proof of
route equivalence. The oracle reports a violation only when the unauthenticated
baseline is blocked, the authenticated control reaches a successful route, and
an unauthenticated variant reaches that same route identity successfully.

## Autonomous revision

Every observation records competing explanations that were eliminated, the
security information gained, requests and wall time spent, and one next
experiment. A failed variant eliminates its mechanism. The next task must not
retry that family under a new name. If all current variants fail, derive a new
representation from the exact normalization steps or change the harness only
when retained coverage shows the relevant consumer was not reached.

A verified primitive creates a missing-link experiment. It does not become a
finding. The experiment must name the next invariant, the consumer that would
turn the primitive into impact, and the cheapest control that would disprove
that composition.

Budget decisions prioritize, in order:

1. independently validated root causes per controlled process hour;
2. security-relevant explanations eliminated per hour;
3. minimized unique stacks or invariant breaks;
4. new coverage edges.

Coverage alone never outweighs a falsified security mechanism.

## Observer challenge

Independent replay must challenge both the hypothesis and its observer. A
reviewer records:

- the assumption being challenged;
- how the hypothesis could be false;
- how the original observer could produce a false positive;
- an alternate machine assertion in the reviewer attestation; and
- whether the claim survived or was refuted.

The coordinator recomputes that alternate assertion from retained raw bytes.
Replaying the same command and accepting the same Boolean is not independent
falsification.

## Expansion rule

Before adding another ecosystem or boundary, run this pilot on a frozen local
corpus and measure hours to rediscover known local invariants, validated root
causes per unit cost, and eliminated explanations. Delete or redesign any
subsystem that does not improve those measures.
