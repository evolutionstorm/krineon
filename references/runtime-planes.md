# Krineon runtime planes

Krineon separates research, execution, verification, and operator concerns so
that an agent cannot turn its own assertion into accepted evidence.

## Research plane

The existing semantic IR, static-analysis pipelines, fuzzing adapters, runtime
feedback, typed capability graph, observation blackboard, and hypothesis loop
form the research plane. These components propose mechanisms and experiments.
They do not grant network access or promote findings.

## Execution plane

`scripts/runtime_plane.py` maintains a separate SQLite execution ledger under
`evidence/runtime/runtime.db`. It records task-scoped model-session lineage,
correlated tool starts and finishes, execution recipes, target hashes, process
results, and immutable content-addressed artifacts.

Execution recipes are strict JSON contracts based on
`assets/runtime-recipe.template.json`. They require:

- a campaign-relative task workspace;
- an exact Docker image digest;
- an argument-array command rather than a shell string;
- explicit CPU, memory, PID, and time limits;
- one or more target-file hashes;
- a primary command and a separately executed alternate observer, each with
  machine assertions; and
- `none` or `broker-only` network policy.

The task container has a read-only root filesystem, no Linux capabilities,
`no-new-privileges`, a read-only task workspace, bounded `/tmp`, and Docker
network mode `none`. `broker-only` does not give the container general egress.
It records that any separately approved network observation must be executed
through Krineon's signed HTTP or browser broker.

Literal secret-like environment fields are rejected. Credentials remain in the
existing private web identity and secret brokers.

Initialize the runtime and register the external agent session:

```text
scripts/runtime_plane.py init CAMPAIGN
scripts/runtime_plane.py session-create CAMPAIGN \
  --session SESSION --task TASK --worker WORKER --agent AGENT \
  --provider PROVIDER --model MODEL
```

Execute a reviewed recipe stored inside the campaign:

```text
scripts/runtime_plane.py run CAMPAIGN path/to/recipe.json
```

The model-session record is an execution identity and continuation contract.
Codex, OMP, and OpenCode remain responsible for their private provider session;
they submit only an opaque checkpoint artifact to Krineon. Krineon never stores
provider credentials in the public ledger.

## Verification plane

Replay uses the original immutable recipe and target hashes but requires a new
model session whose worker and agent identities differ from the originator.
The alternate observer is a separate process invocation with its own command,
output artifacts, correlated events, and assertions. It must inspect retained
target state or evidence rather than merely restating the primary process's
claim.
The executable contract hash deliberately excludes those reviewer identity
fields. The replay passes only when:

- the original run passed;
- the primary replay assertions pass;
- the alternate observer assertions pass;
- the executable recipe is unchanged; and
- every target hash remains unchanged.

Run fresh coordinator replay with:

```text
scripts/runtime_plane.py replay CAMPAIGN ORIGINAL_RUN \
  --reviewer-session FRESH_REVIEWER_SESSION
```

This runtime replay is an input to, not a replacement for, the stronger finding
gate in `research_harness.py`. Report promotion still requires fresh challenges,
originator/reviewer separation, observer-failure analysis, and the existing
machine attestation.

## Operator plane

`scripts/operator_workbench.py` serves a loopback-only, authenticated, read-only
workbench. It displays:

- model sessions, sandbox runs, and replay verdicts;
- correlated runtime events and artifact references;
- retained observations, typed chains, chain steps, and assets;
- traffic and browser-evidence metadata without raw bodies;
- authorization record hashes; and
- active resource leases and cleanup blocks.

Start it with:

```text
scripts/operator_workbench.py CAMPAIGN --port 8788
```

The generated bearer token is stored under `private/` with mode `0600`. The
server accepts only loopback bind addresses. Its API rejects POST, PUT, PATCH,
and DELETE. It never exposes artifact contents, captured bodies, cookies, or
credentials.

## Trust boundaries

- Research workers propose experiments; they do not authorize them.
- The execution plane runs only frozen, resource-bounded recipes.
- Arbitrary task commands receive no network.
- Signed brokers remain the only path for approved web traffic.
- Runtime evidence is immutable and content-addressed.
- A different agent must replay the same executable contract.
- The operator workbench observes state but cannot mutate it.
- Only the existing evidence gate can promote a reportable finding.
