# Event-driven swarm control

Krineon's swarm control layer reacts to retained evidence without transferring
execution authority to workers. Workers and specialist services may subscribe
to typed observations and propose experiments. A coordinator must review and
materialize every proposal before it becomes a scheduler task.

## Control database

`scripts/swarm_control.py` stores its records in the campaign's durable
`orchestration.db`. Campaign initialization installs two conservative default
subscriptions:

- runtime differentials propose a fresh adversarial review; and
- coordinator-replayed observations propose a compatible chain-composition
  experiment.

Subscriptions can filter observation kind, mechanism, produced capability,
minimum trust tier, and minimum evidence confidence. Delivery is idempotent by
subscription and observation. Matching creates a pending proposal, never a
target action.

The coordinator reviews a proposal with `proposal-review`. An approved
proposal enters the scheduler only through `proposal-materialize`, which uses
the ordinary task-admission path, independent-worker exclusions, approach
families, attempt limits, and evidence contract.

## Trust and ancestry

Trust tier and evidence confidence are separate:

| Trust tier | Meaning |
| --- | --- |
| `untrusted-target` | Target responses, imported content, and other attacker-controlled material. |
| `worker-analysis` | An agent's interpretation of source or observations. |
| `tool-measurement` | A bounded machine or tool observation. |
| `coordinator-execution` | Evidence recomputed by the coordinator-controlled runner. |
| `independent-observer` | Fresh replay through an independent observer. |
| `owner-policy` | Scope or policy supplied by the authorized owner. |

Workers cannot claim a trust tier above the evidence confidence and producer
kind that the coordinator retained. Each observation records parent IDs and a
digest over the complete parent ancestry. Untrusted ancestry remains visible
through derived observations.

`owner-policy` is accepted only for an owner-rule observation retained by the
coordinator at coordinator-replayed or independently-replayed confidence. A
worker cannot self-label an observation as owner policy.

Target-controlled or worker-authored content that attempts to become policy,
authorization, or a control instruction is quarantined. Quarantined content
cannot authorize or materialize an experiment. Ordinary target data may still
generate a research proposal, but that proposal requires coordinator review.

## Independent verifier selection

Verifier profiles declare:

- observer class and independence domains;
- verification capabilities and adapter;
- expected monetary cost and duration;
- effect risk; and
- expected information gain.

Selection excludes the original observer class and any overlapping
independence domain. It then chooses the highest information gain per combined
cost, time, and effect risk. The selection receipt records all candidates and
the reason for the chosen verifier. Selection recommends an observer; it does
not execute it.

## Heterogeneous model routing

Model profiles contain no credentials. They describe provider, model family,
roles, capabilities, cost, latency, quality, and cache eligibility. The router
uses component health and selects the best eligible model. Reviewer,
adversary, critic, and replayer routes must use a different model family from
the supplied earlier routes. Prompt caching is always disabled for these
independent roles.

## Volatile observations

Observations are immutable unless the producer explicitly marks them as
`deployment`, `process`, `session`, `token`, or `ephemeral`. Those classes have
bounded lifetimes. The volatility sweep:

1. marks the observation stale;
2. removes it from active chain inputs; and
3. expires unscheduled proposals derived from it.

Source invariants, minimized crashes, and replayed primitives do not decay by
default.

## Cleanup stack

Cleanup recipes are campaign-relative JSON records based on
`assets/cleanup-recipe.template.json`. Registration requires an exact argv,
working directory, timeout, idempotency key, coordinator approval, and a
separate read-only verification command. The recipe is retained by SHA-256.

Cleanup runs in reverse registration order without a shell and with a minimal
environment. The coordinator must provide the exact reviewed recipe hash.
Success requires both the cleanup command and its verification command to
exit successfully. Interrupted actions can be recovered to pending state, and
all results produce retained receipts. A failed cleanup remains visible and
must block the affected resource namespace.

## Owned OOB oracle

The control plane issues a random positive token and independent control token
for each OOB experiment. `scripts/owned_oob_oracle.py` serves bounded HTTP
callbacks on loopback by default. It stores only selected headers, lengths,
and hashes, never callback bodies. An OOB result passes only when the positive
token is observed and the control token is not.

Non-loopback binding requires an unexpired owner approval matching
`assets/oob-approval.template.json`, the exact bind address, and the current
campaign hash. Callback count, body size, and token lifetime are bounded.

## Provider and tool observability

Provider, tool, verifier, and adapter health share one component registry.
Each invocation records operation, result, latency, tokens, cost, and artifact
references. Three consecutive failures make a component unhealthy and remove
it from verifier or model selection. Status reports aggregate proposal,
cleanup, component, cost, token, and latency state without exposing secrets.

The execution plane automatically discovers provider and model components when
it creates a model session. Every bounded runtime recipe is registered as a
tool component, and its final state, latency, and retained artifact hashes are
written to the component ledger. Other adapters use `component-observe` to
record their real provider or tool invocations; registering a component alone
does not mark it healthy.

## Templates

- `assets/swarm-subscription.template.json`
- `assets/verifier-profile.template.json`
- `assets/model-profile.template.json`
- `assets/cleanup-recipe.template.json`
- `assets/oob-approval.template.json`

All target-facing experiments still use Krineon's existing runtime or signed
web execution plane. This layer does not broaden campaign authorization.
