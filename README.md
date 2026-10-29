# Krineon

Krineon is a multi-agent, evidence-driven Critical/RCE research harness and
durable cooperative task coordinator. It packages the methodology used across
source-code campaigns that produced multiple confirmed remote-code-execution
chains. Its central lesson is that finding a primitive is only the beginning.
Krineon follows the pinned code from attacker-controlled ingress through a
violated invariant and useful primitive to a stock execution or
program-defined Critical terminal, then requires controls and independent
replay.

Krineon does not hunt by reading changelogs, mining advisories, walking Git
history, or comparing the target with patched, earlier, later, or internet-
discovered source. Discovery is first-principles analysis of one pinned tree,
its checked-in artifacts, exact-revision builds, and runtime behavior.

The harness is intentionally target-neutral. It supports local source audits,
owned lab environments, testnets, and program-authorized systems. It does not
automate exploitation of third-party production targets.

Development builds and development servers may be used to discover and explain
a primitive, but Krineon will not promote or package them as findings. The
candidate gate requires the primary terminal to execute in a supported
production-equivalent, release-build, or authorized production configuration,
with explicit evidence that neither a development server nor development build
was used.

## Recommended agent

The harness is portable, but it works best with Codex because the orchestration
workflow maps directly to Codex collaboration tools. For long, adversarial
campaigns, use **GPT-5.6 Sol with `max` reasoning**. Other models and coding
agents can run the Python harness and follow the shared methodology, but their
subagent, permission, and skill-loading interfaces may require adapters.

## Analysis coverage

Krineon combines complementary analysis tools rather than treating any single
graph or query engine as authoritative:

- **Trailmark** rapidly maps one pinned revision's repository structure, entry
  points, call graphs, and privileged sinks. Krineon does not use its diff mode.
- **Tree-sitter** provides syntax-aware censuses and precise ordering checks
  without matching comments or strings as code.
- **Joern** builds a code property graph for bounded reachability, data-flow,
  dominance, and missing-validation questions.
- **Z3** solves implementation-matched constraints for integer boundaries,
  parser and serializer disagreements, non-injective encodings, cache-key
  collisions, and authorization-state combinations.

Together, these tools broaden coverage and help generate concrete test inputs.
Their output remains a lead or model result until manual source review and a
controlled runtime differential confirm the security claim. Krineon now runs
the tools rather than merely detecting them: `static_analysis_pipeline.py`
retains each command and raw output, normalizes the results, and creates
idempotent provenance-bound validation tasks in `orchestration.db`. Run
`scripts/tool_probe.py` first to record which optional tools are available. The
probe does not install or modify them.

## Quick start

### Start with only the program rules

Save the program guidelines and scope in one Markdown or text file. Krineon
preserves that input verbatim, extracts review candidates, selects an installed
research profile, pins a supplied Git checkout, inventories available tools,
creates the launch plan, and queues the campaign:

```bash
cd krineon

python3 scripts/campaign_bootstrap.py ../campaigns/example \
  --guidelines program-rules.md \
  --scope program-scope.md \
  --checkout ../target-checkout \
  --confirm-authorization
```

If the rules contain one unambiguous public source repository, Krineon can
acquire and pin it as part of setup:

```bash
python3 scripts/campaign_bootstrap.py ../campaigns/example \
  --guidelines program-rules.md --clone --confirm-authorization
```

Omit `--confirm-authorization` when the selected asset still needs review. The
campaign and durable queue are still created, but local dynamic execution is
disabled. `--confirm-authorization` covers source review and bounded testing in
the recorded owned environment only. It never converts a public program page
into permission for production, shared-system, account, wallet, or testnet
interaction.

The separate `--scope` file is optional when scope is already part of the
guidelines. The intake records its decisions and unresolved items in
`onboarding.json`, keeps the original text in `PROGRAM_GUIDELINES.md` and
`PROGRAM_SCOPE.md`, and writes their SHA-256 digests into the records. If the
repository or commit is not unambiguous, the setup task receives explicit
`pending-source-repository` or `pending-pin` values instead of a guess. See
[references/program-intake.md](references/program-intake.md).

When Krineon is used through Codex, Claude Code, or OpenCode, the researcher can
simply paste or attach the program rules and request a campaign. The agent
performs this intake, resolves routine public-source details, and starts the
queued source-analysis work. It asks for input only when choosing would change
the asset, authority, credentials, or material cost.

### Manual campaign setup

```bash
cd krineon

python3 scripts/research_harness.py init ../campaigns/example \
  --target example-project \
  --repo https://github.com/example/project \
  --checkout ../target-checkout \
  --commit 0123456789abcdef \
  --mode source

python3 scripts/research_harness.py plan ../campaigns/example \
  --max-concurrency auto --lease-seconds 900 \
  --task-timeout-seconds 7200 --max-attempts 2
python3 scripts/tool_probe.py --output ../campaigns/example/tools/tool-probe.json
python3 scripts/research_harness.py queue ../campaigns/example
python3 scripts/static_analysis_pipeline.py run ../campaigns/example \
  --language javascript --ingest
python3 scripts/research_harness.py worker-register ../campaigns/example worker-a \
  --agent codex:session-a --role originator
python3 scripts/research_harness.py claim ../campaigns/example worker-a --json
python3 scripts/research_harness.py orchestration-status ../campaigns/example
python3 scripts/research_harness.py status ../campaigns/example
```

For an implementation-derived integer boundary, add a Z3 specification. The
solver emits decimal, hexadecimal, big-endian, and little-endian testcase
payloads alongside the retained model:

```bash
python3 scripts/static_analysis_pipeline.py run ../campaigns/example \
  --language javascript \
  --z3-spec examples/z3/u32-truncates-to-zero.json --ingest
```

Raw analyzer evidence is stored under `tools/static/RUN_ID/`; normalized leads
are in `tools/static-leads.json`. Each lead becomes a
`static-lead-validation` queue task that carries the campaign commit, tool,
query, command output, and evidence paths. Running ingestion twice does not
duplicate a task. No static lead writes to the findings registry.

Every campaign includes `third_party/manifest.json`. Pin exact dependencies
selected by the target's lockfile, build graph, generated bundle, or runtime
linkage when they expose a high-value parser, native, lifetime, callback,
sandbox, or code-loading boundary:

```bash
python3 scripts/research_harness.py dependency-add ../campaigns/example library-name \
  --repo https://github.com/example/library \
  --commit EXACT_LOCK_RESOLVED_REVISION \
  --relationship runtime \
  --scope-status supporting-context \
  --lock-evidence package-lock.json:120 \
  --reason "Target input reaches this library before the native sink"

python3 scripts/research_harness.py dependency-status ../campaigns/example
```

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

`auto` capacity grows with the number of distinct active runtime-agent
identities registered by the adapter. It can run four, eight, or more workers
at once when the runtime safely exposes those slots and independent tasks are
ready. An explicit positive integer remains available as a hard safety ceiling.
Neither form assigns headcount to a strategy: all workers claim from the same
priority and dependency queue, and the coordinator continuously splits useful
missing links and backfills free slots.

Then invoke the skill with a concrete authorization boundary, for example:

```text
Use $krineon to audit the pinned local checkout in
../target. This is an authorized source-code and local-lab campaign. Read the
campaign's AUTHORIZATION.md, keep the root agent as coordinator, launch Wave 1
with complementary agents, and do not perform live-target testing.
```

Workers register stable identities and atomically claim only dependency-ready
tasks. A claim creates a per-worker workspace under `worktrees/`; when
`--checkout` points to a Git repository, that workspace is a detached Git
worktree at the pinned revision. Claims carry renewable leases and task
timeouts. Expired leases are recovered, attempt budgets are enforced, and
submissions are deduplicated by caller-supplied idempotency keys.

When Krineon runs as a Codex or compatible agent skill, the root coordinator
actively spawns and backfills subagents through the runtime's collaboration
tools. The portable Python CLI remains model-vendor-neutral: Codex, Claude
Code, OpenCode, CI jobs, or human adapters connect spawned workers through
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

Use repeated research rounds to keep incompatible routes alive before
composition:

```bash
python3 scripts/research_harness.py round-plan CAMPAIGN root-worker \
  --plan assets/research-round.template.json
```

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

```bash
# One-time campaign queue and worker registration
python3 scripts/research_harness.py queue CAMPAIGN
python3 scripts/research_harness.py worker-register CAMPAIGN worker-a \
  --agent codex:session-a --role originator

# Worker loop
python3 scripts/research_harness.py claim CAMPAIGN worker-a --json
python3 scripts/research_harness.py heartbeat CAMPAIGN worker-a TASK_ID \
  --lease-token LEASE_TOKEN
python3 scripts/research_harness.py submit CAMPAIGN worker-a TASK_ID \
  --lease-token LEASE_TOKEN --result result.json \
  --idempotency-key TASK_ID-attempt-1

# Coordinator operations
python3 scripts/research_harness.py cancel CAMPAIGN TASK_ID --reason "superseded"
python3 scripts/research_harness.py retry CAMPAIGN TASK_ID --reason "worker failed"
python3 scripts/research_harness.py recover CAMPAIGN

# Machine-enforced independent replay
python3 scripts/research_harness.py register CAMPAIGN F001 \
  --title "Candidate" --lane cross-lane-chain-composition --originator worker-a
python3 scripts/research_harness.py schedule-replay CAMPAIGN F001
```

`submit` accepts the same idempotency key repeatedly only when the task,
worker, result digest, and outcome are identical. A conflicting reuse fails.
`recover` releases expired worker leases, marks task timeouts, and blocks tasks
whose dependencies ended unsuccessfully. Coordinator or worker restarts do not
erase queue state or accepted submissions.

Profiles are Critical/RCE launch maps, not closed checklists. Workers add newly
exposed research branches with `task-add`. A blocked worker must identify the
missing link, blocking mechanism, reason, bypass hypotheses, alternate routes,
and cheapest discriminator. For self-resolvable technical blockers, Krineon
automatically creates a high-priority fresh-agent breakout task. Success
requeues the original lane and revives downstream work; another blocker
continues the diagnostic and bypass loop instead of ending the campaign.
Requeueing requires a new semantic mechanism fingerprint and evidence explaining
how it differs from the blocked mechanism; relabeling or mutating the same
approach is rejected. The generic `retry` command cannot directly requeue a
blocked task.

Krineon also maintains `approach-registry.json`, backed by durable SQLite
family-to-task bindings. Families are defined by security boundary, mechanism,
and invariant rather than task wording. New exploration claims minimize active
family load first and prior coverage second; raw priority and an approach
looking promising or suspicious cannot concentrate workers while another
family is runnable. Every redirect is recorded. Inspect the registry
with `approach-status`; see
[references/approach-families.md](references/approach-families.md).

```bash
python3 scripts/research_harness.py task-add CAMPAIGN adjacent-path-01 \
  --title "Adjacent state transition" --lane open-ended-expansion \
  --approach-family representation-parser \
  --objective "Test the sibling consumer" \
  --success-criterion "Confirm or disprove it with runtime evidence"

python3 scripts/research_harness.py schedule-unblock CAMPAIGN BLOCKED_TASK \
  --title "Recover observability" \
  --strategy "Derive a release-visible discriminator" \
  --success-criterion "Resume the original release-build experiment"
```

See [references/blocker-resolution.md](references/blocker-resolution.md).

## Bounded dynamic testing

`scripts/dynamic_harness.py` executes owned local targets without a shell. It
supports one-input experiments, a deterministic smoke mutator, crash
deduplication, minimization, replay, and crash reproduction audits. It is not
the production zero-day fuzzer. Dynamic commands require
`authorization.confirmed: true`, an allowed environment, a pinned campaign
revision, and `source` or `local-lab` mode.

Run a file-input target or smoke-test its input plumbing:

```bash
python3 scripts/dynamic_harness.py run ../campaigns/example \
  --input-file seeds/valid.bin --name parser --input-mode file \
  --cwd /path/to/target --target-artifact /path/to/parser \
  -- /path/to/parser '{input}'

python3 scripts/dynamic_harness.py fuzz ../campaigns/example \
  --seed-file seeds/valid.bin --iterations 10000 --rng-seed 1 \
  --name parser --input-mode file --cwd /path/to/target \
  --target-artifact /path/to/parser -- /path/to/parser '{input}'
```

Repeat `--target-artifact` for scripts and data dependencies. The executable is
also pinned automatically. Replay verifies those hashes and refuses to
silently substitute a changed target. For stdin targets, omit `--input-mode`
and `{input}`.

Each smoke seed is calibrated before the requested mutation iterations. A target or
wrapper can optionally write one coverage edge ID per line to the file named by
`KRINEON_COVERAGE_FILE`; `KRINEON_INPUT_FILE` names the current input. Inputs
that discover new edges join `dynamic/corpus/NAME/` and affect subsequent
mutations. Later fuzz runs reload that corpus unless `--no-load-corpus` is set.
The smoke runner does not inject compiler instrumentation itself.

Use the external-fuzzer orchestrator for coverage-guided research. It injects
or verifies compiler instrumentation, operates pinned AFL++, libFuzzer, and
Fuzzilli engines, harvests source seeds, runs grammar/structured generators,
uses native parallel corpus sharing, forwards replay-confirmed crashes into the
triage store, and rebuilds AFL or LLVM coverage from the canonical corpus:

```bash
python3 scripts/fuzzer_orchestrator.py register CAMPAIGN parser \
  --engine libfuzzer --target /owned/out/parser_fuzzer --revision REVISION
python3 scripts/fuzzer_orchestrator.py instrument CAMPAIGN parser \
  --kind libfuzzer-clang \
  --build-command-json '["ninja","-C","out","parser_fuzzer"]'
python3 scripts/fuzzer_orchestrator.py seed-harvest CAMPAIGN parser \
  --source /owned/source/tests --extension .bin
python3 scripts/fuzzer_orchestrator.py launch CAMPAIGN parser \
  --workers 16 --duration-seconds 21600 --forward-crashes
python3 scripts/fuzzer_orchestrator.py coverage-rebuild CAMPAIGN parser \
  --mode afl-showmap --tool /owned/afl/bin/afl-showmap
```

See [references/fuzzing.md](references/fuzzing.md) for AFL++ master/secondary
sync, libFuzzer fork workers, Fuzzilli jobs/REPRL, structured generation,
corpus provenance, crash forwarding, and coverage rebuilding.

Crash and reproduction workflow:

```bash
python3 scripts/dynamic_harness.py minimize CAMPAIGN CRASH_ID
python3 scripts/dynamic_harness.py replay crash CAMPAIGN CRASH_ID --minimized
python3 scripts/dynamic_harness.py replay case CAMPAIGN RUN_ID 0
python3 scripts/dynamic_harness.py regression CAMPAIGN
python3 scripts/dynamic_harness.py triage CAMPAIGN --crash-id CRASH_ID --json
```

Raw inputs, bounded stdout/stderr, coverage, results, and target configuration
are retained under `dynamic/runs/` and `dynamic/crashes/`. `regression` checks
that retained crashes still reproduce against their original pinned targets;
it performs no cross-version comparison. A crash or sanitizer report remains a
chain link until controls and escalation establish Critical/RCE impact.

Crash saving now automatically performs first-fault classification, separates
read, write, execute, lifetime, bounds, concurrency, and crash-only evidence,
calculates a conservative controllability score, and assigns a normalized
stack-cluster ID. `dynamic/triage/index.json` is refreshed as the corpus grows,
so distinct sanitizer reports sharing one underlying stack remain grouped even
when their exact crash fingerprints differ. Attach reviewed triage to a
finding with:

```bash
python3 scripts/dynamic_harness.py triage CAMPAIGN \
  --crash-id CRASH_ID --finding-id F001 \
  --reviewed-by worker-review --review-note "Interpretation and next experiment"
```

The candidate gate verifies the linked crash IDs, triage files, stack clusters,
and machine verdicts. A crash-only verdict requires an explicit override
reason. No automated verdict is machine-eligible to establish Critical impact;
the existing real-terminal, production-equivalent, and replay gates still
apply.

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

```bash
python3 scripts/research_harness.py init ../campaigns/v8 \
  --profile chrome-v8 --target v8 \
  --repo https://chromium.googlesource.com/v8/v8 \
  --checkout ../v8 --commit V8_COMMIT --mode local-lab
python3 scripts/research_harness.py plan ../campaigns/v8 --max-concurrency auto
python3 scripts/research_harness.py queue ../campaigns/v8
```

Register exact release, ASan, and debug `d8` binaries, including their runtime
data dependencies and GN arguments:

```bash
python3 scripts/chrome_v8_harness.py register-build ../campaigns/v8 release \
  --kind d8 --role release --revision V8_COMMIT \
  --binary ../v8/out/release/d8 \
  --gn-args-file ../v8/out/release/args.gn
python3 scripts/chrome_v8_harness.py audit ../campaigns/v8
python3 scripts/chrome_v8_harness.py matrix ../campaigns/v8 \
  --testcase testcase.js

python3 scripts/chrome_v8_harness.py browser-replay ../campaigns/v8 \
  --build chrome-release --page-dir ./owned-page \
  --entry index.html --control-entry control.html
```

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
machine-audited source-to-sink path proof | every branch | zero assumptions
        |
        v
evidence gate -> report package -> coordinated disclosure
```

## Project layout

```text
SKILL.md                         Codex operating instructions
agents/openai.yaml               Skill UI metadata
scripts/research_harness.py      Campaign, registry, gates, lint, hashes
                                and durable task orchestration
scripts/path_proof.py            Exhaustive path, condition, contradiction,
                                evidence, and independent-review audit
scripts/campaign_bootstrap.py    Program-rules intake, profile selection,
                                source pinning, planning, and queue setup
scripts/dynamic_harness.py       Bounded execution, fuzzing, and crash replay
scripts/crash_triage.py          First-fault classification, controllability
                                scoring, and cross-corpus stack clustering
scripts/chromium_replay.py       Direct-CDP owned-page runner and sandbox evidence
scripts/fuzzer_orchestrator.py   AFL++, libFuzzer, and Fuzzilli campaign adapter
scripts/chrome_v8_harness.py     Pinned d8 registry and cross-build matrices
scripts/tool_probe.py            Local static-tool capability inventory
scripts/static_analysis_pipeline.py
                                Analyzer execution, retained provenance, and
                                durable lead-task ingestion
scripts/tree_sitter_census.py    Syntax-aware ingress, guard, and sink census
scripts/z3_boundary_solver.py    Concrete integer-boundary testcase generator
queries/joern/                   Runnable CPG reachability and guard queries
examples/z3/                     Source-derived solver-spec examples
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
references/evidence-gates.md
references/false-positive-control.md
references/pre-filing.md
references/reporting.md
references/safety.md
assets/campaign.template.json
assets/finding.template.json
assets/agent-handoff.template.md
assets/research-round.template.json
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
