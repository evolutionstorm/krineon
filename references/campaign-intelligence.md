# Campaign intelligence plane

The campaign intelligence plane connects Krineon's source and runtime research.
It stores evidence and state in `knowledge/campaign-intelligence.db`. It never
executes a target and never converts an observation into a vulnerability
verdict.

## Canonical architecture knowledge

Record components, identities, resources, entrypoints, dependencies, trust
boundaries, consumers, state stores, and generated artifacts. Every object has
a confidence class and evidence. Relations state the exact conditions that
connect two objects.

The architecture knowledge base is shared campaign state. Workers may refine
it, but cannot silently create a second conflicting identity for the same
object.

## Source coverage

The source inventory hashes supported source files and separates production
code from tests, examples, fixtures, benchmarks, and documentation. Generated
and vendored code remains visible as a separate attribute.

Each production source file has one coverage state:

- `unassigned`
- `assigned`
- `investigating`
- `reviewed`
- `excluded`
- `blocked`

Exclusion requires a reason. A complete research stage requires every
production file to be reviewed or explicitly excluded. This ledger prevents
silent blind spots; it does not require every file to receive equal research
time.

## Enforced stages

Campaign stages are:

1. architecture
2. threat model
3. research plan
4. research
5. reconciliation
6. adversarial review
7. production critic
8. runtime confirmation
9. independent replay
10. report

Stages may be complete, partial, blocked, or skipped. Partial, blocked, and
skipped stages retain a reason. A stage cannot start before its predecessor has
a terminal state, and its machine gate must pass before a complete outcome.

## Immutable observations and reconciliation

An observation binds its producer identity and role to:

- mechanism and exact target;
- confidence class;
- content-addressed evidence files;
- admitted source locations; and
- structured payload.

A runtime differential requires baseline, enforcing-negative, and positive
cases. Reconciliation groups the immutable observations for one mechanism,
records conflicts, preserves their evidence classes, and creates a candidate
hypothesis. It does not decide that the candidate is valid.

Validated scheduler task results can be ingested into this plane. A legacy
observation labelled `runtime-differential` without all three structured cases
is retained as a generic runtime observation. Its label cannot satisfy the
differential promotion gate.

## Hypothesis accounting

Hypotheses advance one level at a time:

```text
observation
→ source-supported mechanism
→ runtime differential
→ verified primitive
→ compatible chain edge
→ complete terminal
```

The verified-primitive level requires coordinator replay. The complete-terminal
level requires independent replay. A compatible edge requires typed authority,
principal, process, runtime, acquisition, and deployment fields.

Every hypothesis remains active or receives one disposition: exploited,
refuted, blocked, inconclusive, or superseded. A blocked hypothesis records an
exact blocker and evidence-based reopening criteria.

## Production critic

The critic uses a different identity from the originator and evaluates:

- supported release;
- shipped artifact;
- external ingress;
- production entrypoint;
- optimized build;
- absence of development-only dependencies;
- absence of an artificial sink;
- remote acquisition; and
- simultaneous preconditions.

Each fact is true, false, or unknown and carries evidence. Unknown telemetry is
inconclusive rather than safe or vulnerable.

Before this stage, an adversarial reviewer with a different identity records
both a hypothesis failure mode and an observer failure mode. The reviewer must
challenge at least one exact condition and retain evidence. Repeating the
originator's reasoning is not an independent review.

## Role-isolated context

Krineon materializes separate context bundles for architect, researcher,
reviewer, replayer, and reporter roles. Each role receives an allowlisted set of
sections and tools. Secret-like fields are removed. Reviewers do not receive
the originator's conclusion or expected verdict. Replayers do not receive
originator or reviewer conclusions.

The role-view manifest states that campaign-root access and other-worker result
access are not authorized. The external agent runtime must mount only this
bundle and the explicitly allowed target workspace.

## Source-location joins

An admitted source location binds repository revision, file hash, exact line
range, snippet hash, symbol, generated artifact mapping, and optional runtime
observation. Citation rendering fails if the source file or snippet changes.
Reporters cite only admitted locations.
Before packaging a report, validate its `hypothesisIds` and
`sourceLocationIds`. Validation rejects non-terminal hypotheses, stale source,
invented free-form locations, and locations that are not bound to the terminal
hypothesis.

## Authenticated sessions

Session records contain broker references and hashes, never literal
credentials. Each session is bound to actor, role, tenant, permission version,
client type, authentication time, and expiry. A role or permission change marks
older sessions stale. Refreshing transport credentials cannot silently restore
an invalidated application permission.

## Templates

- `assets/architecture-knowledge.template.json`
- `assets/campaign-observation.template.json`
- `assets/adversarial-review.template.json`
- `assets/production-critic.template.json`
- `assets/role-context.template.json`
- `assets/web-session-binding.template.json`
- `assets/report-manifest.template.json`
