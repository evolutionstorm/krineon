# Krineon

Krineon is a multi-agent, evidence-driven Critical/RCE research harness and
durable cooperative task coordinator. It packages the methodology used across
source-code campaigns that produced multiple confirmed remote-code-execution
chains. Its central lesson is that finding a primitive is only the beginning.
Krineon follows the pinned code from attacker-controlled ingress through a
violated invariant and useful primitive to a stock execution or
program-defined Critical terminal, then requires controls and independent
replay.

That is the **filing objective**, not the internal search objective. Internally,
Krineon retains and ranks unique minimized stack clusters, target-invariant
breaks, and verified primitives. These are research leads, not findings. They
create focused follow-up tasks without pretending the missing chain already
exists. Only the final filing gate requires a complete Critical/RCE chain.

Krineon does not hunt by reading changelogs, mining advisories, walking Git
history, or comparing the target with patched, earlier, later, or internet-
discovered source. Discovery is first-principles analysis of one pinned tree,
its checked-in artifacts, exact-revision builds, and runtime behavior. The
pinned target's own tests, assertions, fuzz targets, fixtures, generated code,
and invariant comments are encouraged local oracles. Patch history, security
commits, advisories, and other revisions remain prohibited discovery inputs.

The harness is intentionally target-neutral. It supports local source audits,
owned lab environments, testnets, and program-authorized systems. It does not
automate exploitation of third-party production targets.

Development builds and development servers may be used to discover and explain
a primitive, but Krineon will not promote or package them as findings. The
candidate gate requires the primary terminal to execute in a supported
production-equivalent, release-build, or authorized production configuration,
with explicit evidence that neither a development server nor development build
was used.

## Agent compatibility

Krineon supports Codex and OMP (Oh My Pi) as skill-based coordinators. The
Python harness and worker protocol are model-vendor-neutral; process launch,
permissions, and skill discovery stay native to each runtime. Claude Code,
OpenCode, CI jobs, and human adapters can also use the same CLI protocol.
See [runtime adapters](references/orchestration.md#runtime-adapters-and-collaboration-tools)
for the tool mapping and OMP worker binding.

## Analysis coverage

Krineon combines complementary analysis tools rather than treating any single
graph or query engine as authoritative:

- **Trailmark** rapidly maps one pinned revision's repository structure, entry
  points, call graphs, and privileged sinks. Krineon does not use its diff mode.
- **Tree-sitter and Joern** may nominate producer/consumer boundaries, but
  syntax and graph hits never enter the queue directly.
- **Differential witnesses** execute two pinned consumers on one hashed input
  and retain both an equal control and the recorded disagreement.
- **Z3** generates concrete inputs from either generic mathematical models or
  constraints bound to a hashed pinned-source fragment. Manually transcribed
  constraints are labelled as such and are never called implementation-matched.

Together, these tools broaden coverage and generate concrete inputs. Tool
output remains a note or model result until source review and an executed
differential confirm the discrepancy. `static_analysis_pipeline.py` retains
the differential commands and observations and creates idempotent
provenance-bound validation tasks in `orchestration.db`. The agent first probes
which optional tools are available; the probe does not install or modify them.

## Quick start

Invoke Krineon through your coding agent; it handles campaign setup, worker
coordination, and evidence checks. Python 3 must be installed because the agent
uses the bundled harness internally, but you do not need to run Python commands
yourself. Detailed operational instructions live in [SKILL.md](SKILL.md) and
the linked reference docs.

### Load the skill in OMP

From the Krineon checkout, link the **whole directory**, not just `SKILL.md`,
into OMP's native user skill root:

```bash
mkdir -p "$HOME/.omp/agent/skills"
test ! -e "$HOME/.omp/agent/skills/krineon" &&
  test ! -L "$HOME/.omp/agent/skills/krineon" &&
  ln -s "$PWD" "$HOME/.omp/agent/skills/krineon"

# Verify discovery without making a model request.
omp read skill://krineon
```

The link command leaves an existing installation untouched. For a named OMP
profile, use `~/.omp/profiles/PROFILE/agent/skills/krineon` instead; a project-local
installation can use `TARGET/.omp/skills/krineon`. Start a new OMP session after
installing. The existing `name` and `description` frontmatter are sufficient;
no extension, custom agent, or `agents/openai.yaml` adapter is required.

Invoke it from the target workspace:

```text
/skill:krineon Audit this checkout under the attached program rules. Source
review and bounded local tests only; no live-target testing.
```

OMP exposes the skill at `skill://krineon` and its supporting files below that
URI. The agent resolves harness scripts against the physical skill directory
rather than assuming they exist in the target checkout.

For headless OMP campaigns, include `--wait-async` with `--print` so exiting the
initial turn does not cancel active workers, and set an appropriate
`--max-time` bound. Runtime approvals do not replace campaign authorization.

### Load the skill in Codex

From the Krineon checkout, link the **whole directory**, not just `SKILL.md`,
into Codex's user skill root:

```bash
CODEX_SKILLS_ROOT="${CODEX_HOME:-$HOME/.codex}/skills"
mkdir -p "$CODEX_SKILLS_ROOT"
test ! -e "$CODEX_SKILLS_ROOT/krineon" &&
  test ! -L "$CODEX_SKILLS_ROOT/krineon" &&
  ln -s "$PWD" "$CODEX_SKILLS_ROOT/krineon"
```

The default location is `~/.codex/skills/krineon`; the command respects a
custom `CODEX_HOME` and leaves an existing installation untouched. Start a new
Codex session from the target workspace after installing.

Invoke it in the Codex prompt:

```text
$krineon Audit this checkout under the attached program rules. Source review
and bounded local tests only; no live-target testing.
```

Codex follows symlinked skill directories, so the bundled scripts, references,
and templates remain available. The root Codex agent uses native collaboration
tools while Krineon's durable queue enforces task ownership, dependencies, and
independent replay; see the [Codex runtime adapter](references/codex.md). See the
[official Codex skill documentation](https://developers.openai.com/codex/skills).

### Start with only the program rules

Paste or attach the program guidelines and scope, identify the target checkout
if available, and request a campaign. State whether bounded testing in an owned
local environment is authorized. The agent preserves the input verbatim,
extracts review candidates, selects a research profile, pins the checkout,
inventories available tools, creates the launch plan, and queues the campaign.

If the rules identify one unambiguous public source repository, the agent can
acquire and pin it during setup. Otherwise it records the ambiguity instead of
guessing. It asks for input only when choosing would change the asset,
authority, credentials, or material cost.

When local testing is not authorized, source analysis can still begin, but
dynamic execution stays disabled. Local authorization never grants permission
for production, shared-system, account, wallet, or testnet interaction.

Separate scope text is optional when scope is already part of the guidelines.
The intake records its decisions and unresolved items in
`onboarding.json`, keeps the original text in `PROGRAM_GUIDELINES.md` and
`PROGRAM_SCOPE.md`, and writes their SHA-256 digests into the records. If the
repository or commit is not unambiguous, the setup task receives explicit
`pending-source-repository` or `pending-pin` values instead of a guess. See
[references/program-intake.md](references/program-intake.md).

### What the agent sets up

The coordinator records authorization, pins source and runtime artifacts,
creates the campaign plan and durable task queue, freezes bounded test
components, and proves the coordinator's evidence gate before scaling out.
Worker registration, task claims, lease renewal, and result submission are
handled by the agents. See
[orchestration](references/orchestration.md) and
[tool-assisted analysis](references/tool-assisted-analysis.md) for the internal
workflow.

The bundled Z3 example is generic mathematics, not target analysis. Target-bound
solver specifications identify an exact pinned-source fragment, expression,
and extraction method; the solver reads and hashes that fragment. Unbound
generic output remains experimental and creates no validation task.

Raw differential evidence is stored under `tools/static/RUN_ID/`; normalized
leads are in `tools/static-leads.json`. Each executed disagreement becomes an
`evidence-lead-validation` queue task that carries the campaign commit,
commands, observations, and evidence paths. Running ingestion twice does not
duplicate a task. No witness writes to the findings registry.

For Next.js, React, and Node targets, use a production adapter rather than a
development server or an ad hoc request. The adapter hashes the lockfile,
runtime, compiler probes, environment, generated bundles, declared surface
evidence, and deployment files, then launches and exercises that exact
artifact. See [framework adapters](references/framework-adapters.md) and the
[HTTP/protocol harness](references/http-protocol-harness.md). The latter
preserves duplicate headers and raw framing, models separate roles and tenants,
and supports stateful, concurrent, redirect, WebSocket, streaming, and
proxy/framework/origin differential replay.

The framework-analysis pipeline reads the resulting route, middleware,
prerender, build, and server-reference manifests; structurally indexes source,
generated, and vendored JavaScript; follows directive and module boundaries;
and reverse-maps source facts into shipped bundles. It emits concrete
production experiments with controls, not vulnerability verdicts. See
[framework production analysis](references/framework-analysis.md).

JavaScript targets can use persistent Node workers and runtime-native
V8/Istanbul coverage without target-written edge hooks. Browser precise
coverage from the Chromium runner and server coverage are remapped through
source maps and classified across Next.js server, edge, and client bundles.
Built-in semantic generators cover JSON, URLs, headers, multipart, RSC, Server
Actions, and manifests. See
[JavaScript coverage and generation](references/javascript-coverage-generation.md).

Every campaign includes `third_party/manifest.json`. The coordinator pins exact
dependencies selected by the target's lockfile, build graph, generated bundle,
or runtime linkage when they expose a high-value parser, native, lifetime,
callback, sandbox, or code-loading boundary.

Workers receive detached copies under `KRINEON_THIRD_PARTY/`, backed by the
campaign's shared Git object stores. This permits independent builds and
instrumentation without duplicating full repositories or mutating another
agent's dependency checkout. Dependency bugs may be chained with target bugs,
but the report must separately establish target integration, exact version,
attacker reachability, and program scope. See
[references/dependencies.md](references/dependencies.md).

Review `campaign.json` and `AUTHORIZATION.md` before running dynamic tests.
Agent task packets are written to `tasks/`, grouped into waves in
`launch-plan.json`, and materialized in the durable `orchestration.db` queue.
The launch plan remains reviewable configuration; the SQLite queue is the
operational source of truth.

The first worker may register after setup. A second worker is refused until
`gate-self-test` proves that coordinator re-execution rejects an intentionally
false runtime claim. After that, `auto` capacity grows with distinct active runtime-agent
identities registered by the adapter. It can run four, eight, or more workers
at once when the runtime safely exposes those slots and independent tasks are
ready. An explicit positive integer remains available as a hard safety ceiling.
Neither form assigns headcount to a strategy: all workers claim from the same
priority and dependency queue, and the coordinator continuously splits useful
missing links and backfills free slots.

Workers register stable identities and atomically claim only dependency-ready
tasks. A claim creates a per-worker workspace under `worktrees/`; when
the campaign includes a Git checkout, that workspace is a detached Git worktree
at the pinned revision. Claims carry renewable leases and task
timeouts. Expired leases are recovered, attempt budgets are enforced, and
submissions are deduplicated by caller-supplied idempotency keys.

When Krineon runs as a Codex or OMP skill, the root coordinator actively spawns
and backfills subagents through the runtime's collaboration tools. The portable
Python CLI remains model-vendor-neutral: Codex, OMP, Claude Code, OpenCode, CI
jobs, or human adapters connect spawned workers through
`claim`, `heartbeat`, and `submit`. This separation keeps process launch native
to each runtime while making dependency, identity, retry, cancellation,
timeout, budget, and result ingestion machine-enforced.

Finding-specific replay tasks exclude the recorded originator's worker and
immutable runtime-agent identities, including aliases registered later. A
reportable gate passes only after two different registered agents submit
hashed replay results. Later replay tasks also exclude earlier reviewer-agent
identities. The gate recomputes both artifact hashes and cross-checks the
accepted SQLite submissions, completed replay tasks, identity exclusions, and
replay JSON.

Ordinary completed tasks must follow `assets/task-result.template.json` and
record their searched surface, pinned source references, evidence, hypotheses,
next tasks, and first-principles provenance. Prose-only completion cannot
unlock dependent work.

The profile's replay-scheduler lane is also machine-bound: its result must list
one or more finding IDs in `taskResult.replayFindings`, and each must already
have two accepted, hashed, different-agent replays. Adversarial review and final
synthesis therefore cannot unlock merely because a replay was scheduled.

The coordinator uses repeated research rounds to keep incompatible routes alive
before composition, following `assets/research-round.template.json`.

Each round creates independent route-development tasks, a different-agent
adversarial task for every route, and a coordinator-only synthesis task.
Cross-pollination is rejected until both source routes have survived two fully
reviewed rounds. The synthesis result must compare strengths and gaps,
challenge the strongest current claims, redirect weak routes, and state whether
the coordinator will launch another round. “No findings” and failure of the
current routes cannot stop the campaign. Route results must propose fresh ideas;
sanity-checked intermediate bugs automatically produce dedicated composition
tasks that the synthesis task must await. A synthesis that requests another
round automatically creates a coordinator planning task; it remains incomplete
until the next round has actually been launched into the durable queue.

## Durable orchestration protocol

The agent manages queue creation, worker registration, dependency-ready claims,
lease renewal, result ingestion, cancellation, recovery, and independent replay.
These are internal operations, not manual setup steps. See
[references/orchestration.md](references/orchestration.md) for the worker
protocol and runtime bindings.

Each replay submission must link a `krineon-reality-runner` attestation. The
coordinator re-hashes the recipe, targets, and raw output and recomputes every
assertion. A different worker ID that merely submits `passed: true` is rejected.

Duplicate submissions are accepted only when the idempotency key, task, worker,
result digest, and outcome are identical; conflicting reuse fails. Recovery
releases expired worker leases, marks task timeouts, and blocks tasks whose
dependencies ended unsuccessfully. Coordinator or worker restarts do not erase
queue state or accepted submissions.

Profiles are Critical/RCE launch maps, not closed checklists. Workers add newly
exposed research branches to the queue. A blocked worker must identify the
missing link, blocking mechanism, reason, bypass hypotheses, alternate routes,
and cheapest discriminator. For self-resolvable technical blockers, Krineon
automatically creates a high-priority fresh-agent breakout task. Success
requeues the original lane and revives downstream work; another blocker
continues the diagnostic and bypass loop instead of ending the campaign.
Requeueing requires a new semantic mechanism fingerprint and evidence explaining
how it differs from the blocked mechanism; relabeling or mutating the same
approach is rejected. A generic retry cannot directly requeue a blocked task.

Krineon also maintains `approach-registry.json`, backed by durable SQLite
family-to-task bindings. Families are defined by security boundary, mechanism,
and invariant rather than task wording. New exploration claims minimize active
family load first and prior coverage second; raw priority and an approach
looking promising or suspicious cannot concentrate workers while another
family is runnable. Every redirect is recorded; see
[references/approach-families.md](references/approach-families.md).

See [references/blocker-resolution.md](references/blocker-resolution.md).

## Bounded dynamic testing

`scripts/dynamic_harness.py` executes owned local targets without a shell. It
supports one-input experiments, a deterministic smoke mutator, crash
deduplication, minimization, replay, and crash reproduction audits. It is not
the production zero-day fuzzer. Dynamic commands require
`authorization.confirmed: true`, an allowed environment, a pinned campaign
revision, and `source` or `local-lab` mode.

The agent selects file-input or stdin execution and pins the executable,
scripts, and data dependencies. Replay verifies those hashes and refuses to
silently substitute a changed target.

Each smoke seed is calibrated before the requested mutation iterations. A target or
wrapper can optionally write one coverage edge ID per line to the file named by
`KRINEON_COVERAGE_FILE`; `KRINEON_INPUT_FILE` names the current input. Inputs
that discover new edges join `dynamic/corpus/NAME/` and affect subsequent
mutations. Later fuzz runs can reload that corpus. The smoke runner does not
inject compiler instrumentation itself.

Use the external-fuzzer orchestrator for coverage-guided research. It injects
or verifies compiler instrumentation, operates pinned AFL++, libFuzzer, and
Fuzzilli engines, harvests source seeds, runs grammar/structured generators,
uses native parallel corpus sharing, forwards replay-confirmed crashes into the
triage store, and rebuilds AFL or LLVM coverage from the canonical corpus.

See [references/fuzzing.md](references/fuzzing.md) for AFL++ master/secondary
sync, libFuzzer fork workers, Fuzzilli jobs/REPRL, structured generation,
corpus provenance, crash forwarding, and coverage rebuilding.

The agent minimizes retained crashes, replays cases and crashes, checks
reproduction, and reviews triage before promotion.

Raw inputs, bounded stdout/stderr, coverage, results, and target configuration
are retained under `dynamic/runs/` and `dynamic/crashes/`. `regression` checks
that retained crashes still reproduce against their original pinned targets;
it performs no cross-version comparison. A crash or sanitizer report remains a
chain link until controls and escalation establish Critical/RCE impact.

Crash saving performs first-fault classification, separates read, write,
execute, lifetime, bounds, concurrency, and crash-only evidence, and assigns a
normalized stack-cluster ID. A sanitizer label never receives a controllability
score. Control remains `unverified` until a challenge-response run proves
chosen bytes or a chosen PC, repeated fresh-process stability, enforcing
controls, and allocation generation identity for a UAF claim.
`dynamic/triage/index.json` is refreshed as the corpus grows,
so distinct sanitizer reports sharing one underlying stack remain grouped even
when their exact crash fingerprints differ. Completed tasks can return these
clusters, invariant contradictions, and verified primitives through
`taskResult.researchLeads`. The coordinator deduplicates and ranks these leads
by machine-evidence grade, not claimed severity, automatically queues the next
stated experiment, and attaches reviewed triage to candidate findings.

The reality runner and primitive verifier attach that evidence. The candidate
gate rejects a crash-backed write or PC lead while
its primitive remains unverified. No automated verdict is machine-eligible to establish Critical impact;
the existing real-terminal, production-equivalent, and replay gates still
apply.

See [references/reality-evidence.md](references/reality-evidence.md) for the
recipe, observation, and independent-replay contracts.

## Frozen-corpus rediscovery measurement

Lane descriptions are hypotheses until they rediscover a hidden target-owned
oracle. `scripts/rediscovery_benchmark.py` freezes a local corpus and target
artifacts, stores only the hash of evaluator-held target-test/invariant
oracles, executes a local search command, and records seconds and hours to first
rediscovery plus recall. The oracle identities must not be shared with search
workers.

Before that metric exists, launch-plan lane efficacy is explicitly marked
`documentation-only`; running a lane is an experiment, not evidence that it
works. See
[references/rediscovery-benchmark.md](references/rediscovery-benchmark.md).

The POSIX runner enforces wall-clock, CPU, optional address-space, input, and
captured-output limits and performs best-effort process-group cleanup. These
are resource controls, **not a security sandbox**; use a disposable VM or
container for unsafe targets. Escaped process groups, target-written files,
and network access are not contained by this module.

## Chrome/V8 zero-day research profile

Krineon includes a purpose-built `chrome-v8` profile for authorized engine and
browser research. Its dependency-aware tasks cover JIT compiler invariants, GC
and backing-store lifetime, WebAssembly, V8 Sandbox boundaries, structured and
differential fuzzing, primitive escalation, sandbox-enabled Chromium
reachability, independent replay, adversarial review, and disclosure synthesis.

The agent registers exact release, ASan, and debug `d8` binaries, including their
runtime data dependencies and GN arguments, audits their identities, and runs
cross-build comparisons and owned-page browser replays.

The adapter verifies artifact hashes and delegates execution to the bounded
dynamic runner. Its dependency-free direct-CDP browser lane copies and hashes
an owned page, launches positive and control cases in separate fresh Chromium
profiles, blocks off-origin requests, and retains screenshots, browser events,
logs, final URLs, binary identity, and Linux renderer sandbox evidence. It
refuses sandbox-disabling and internal V8 flags. Results remain leads until
their impact is established. Final promotion requires minimization, release
relevance, this owned-page replay, and a machine-verified independent reviewer. See
[references/chrome-v8.md](references/chrome-v8.md) and
[agents/chrome-v8-agent.md](agents/chrome-v8-agent.md).

## Workflow

```text
scope and authorization
        |
        v
exact-version inventory and tool probe
        |
        v
wave 1: boundary map | sink-first trace | state/lifecycle | dependency boundaries
        |
        v
wave 2: chain composition | acquisition | primitive escalation | stock deployment
        |
        v
candidate registry and falsification
        |
        v
wave 3: bounded real terminal | controls | independent clean replay
        |
        v
executable source-to-sink path proof | recomputed observations | zero assumptions
        |
        v
evidence gate -> report package -> coordinated disclosure
```

## Project layout

```text
SKILL.md                         Portable agent skill instructions (Codex/OMP)
agents/openai.yaml               Codex skill UI metadata (not required by OMP)
scripts/research_harness.py      Campaign, registry, gates, lint, hashes
                                and durable task orchestration
scripts/path_proof.py            Exhaustive path, condition, contradiction,
                                executable evidence, and replay audit
scripts/reality_runner.py        Fresh-process baseline/control/positive runner
scripts/reality_evidence.py      Raw-output assertion and attestation validator
scripts/primitive_verifier.py    Chosen-byte/PC, allocation, and stability gate
scripts/rediscovery_benchmark.py Frozen-corpus blind rediscovery timing and recall
scripts/component_freeze.py      ASan/UBSan component build and artifact freeze
scripts/differential_witness.py  Same-input two-consumer disagreement recorder
scripts/search_score.py          Edge/stack/rediscovery scoring and ablation
scripts/framework_adapter.py     Next.js, React, and Node production build,
                                launch, exercise, and artifact freeze
scripts/framework_analysis_pipeline.py
                                Route/runtime/source-to-bundle hypothesis mapper
scripts/http_protocol_harness.py Stateful raw HTTP/WebSocket and differential
                                protocol replay
scripts/js_coverage_harness.py  Persistent Node execution and native JS coverage
scripts/js_persistent_worker.mjs Reusable module worker for many inputs
scripts/js_coverage_remap.mjs    V8/Istanbul and source-map coverage merger
scripts/structured_input_generator.py
                                Semantic framework representation generator
scripts/campaign_bootstrap.py    Program-rules intake, profile selection,
                                source pinning, planning, and queue setup
scripts/dynamic_harness.py       Bounded execution, fuzzing, and crash replay
scripts/crash_triage.py          First-fault classification, verified primitive
                                linkage, and cross-corpus stack clustering
scripts/chromium_replay.py       Direct-CDP owned-page runner and sandbox evidence
scripts/fuzzer_orchestrator.py   AFL++, libFuzzer, and Fuzzilli campaign adapter
scripts/chrome_v8_harness.py     Pinned d8 registry and cross-build matrices
scripts/tool_probe.py            Local static-tool capability inventory
scripts/static_analysis_pipeline.py
                                Differential execution, retained provenance,
                                and durable lead-task ingestion
scripts/z3_boundary_solver.py    Generic or pinned-source-bound constraint models
examples/z3/                     Generic solver-format examples
profiles/chrome-v8.json          Chrome/V8 dependency-aware research lanes
profiles/critical-rce.json       Default first-principles chain lanes
profiles/approach-families.json  Semantic boundary, mechanism, and invariant catalog
agents/chrome-v8-agent.md        Chrome/V8 worker evidence contract
references/methodology.md        End-to-end research method
references/program-intake.md     Rules-only campaign bootstrap and authority
references/orchestration.md      Multi-agent waves and handoffs
references/critical-rce.md       Critical/RCE promotion and discovery contract
references/chrome-v8.md          V8 build, fuzzing, triage, and promotion flow
references/blocker-resolution.md Dynamic exploration and unblock protocol
references/approach-families.md  Coverage accounting and convergence redirection
references/dependencies.md       Pinned dependencies and cross-library chains
references/tool-assisted-analysis.md
references/framework-adapters.md Production surface and artifact adapter schema
references/framework-analysis.md Runtime hypothesis and bundle-mapping schema
references/http-protocol-harness.md Raw protocol and stateful sequence schema
references/javascript-coverage-generation.md
                                Persistent JS coverage and generator schema
references/evidence-gates.md
references/false-positive-control.md
references/pre-filing.md
references/reporting.md
references/safety.md
assets/campaign.template.json
assets/finding.template.json
assets/agent-handoff.template.md
assets/research-round.template.json
assets/framework-analysis.template.json
tests/test_research_harness.py
tests/test_dynamic_harness.py
tests/test_chrome_v8_harness.py
tests/test_critical_rce_contract.py
tests/test_static_analysis_pipeline.py
```

## Core principles

- Start from security boundaries and sinks, not vulnerability buzzwords.
- Search for producer/consumer disagreement, omitted identity, stale ownership,
  validation-order gaps, non-injective encodings, and incomplete fixes.
- Use independent agents for discovery and falsification.
- Keep blocked routes. Negative knowledge prevents repeated dead ends.
- Prefer a smaller, honest report to a larger claim built on assumptions.
- Static analysis narrows the search; exact runtime evidence decides the claim.

## Safety boundary

Use only targets and environments the researcher owns or is explicitly
authorized to assess. Do not test production users, access third-party data,
degrade shared services, move funds not owned by the researcher, or publish
embargoed findings. See [references/safety.md](references/safety.md).
