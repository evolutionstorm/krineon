---
name: krineon
description: Run authorized, aggressive multi-agent source audits that build complete Critical/RCE chains from first principles and validate them safely. Use for full source campaigns; do not use changelogs, history, patched-version or internet patch diffs for discovery, and do not invoke for unapproved live testing.
---

# Krineon Security Research

Run an evidence-driven campaign against code and systems the user is authorized
to test. Krineon has one objective: derive a complete Critical/RCE chain from
the pinned code, prove every link, and reproduce a bounded real terminal. A
crash, primitive, lower-severity bug, or denial of service is retained only as
a possible link; Krineon does not package it as a finding. Read
[references/critical-rce.md](references/critical-rce.md) for the promotion bar.

## Start from program rules

When the user supplies bounty-program guidelines and scope, treat that as the
campaign intake. Preserve the text verbatim, bootstrap the campaign, resolve a
unique public source repository and exact revision when possible, generate the
tool inventory, and queue the research plan. Do not ask the user for routine
values that can be derived from the rules or checkout.

```bash
python3 scripts/campaign_bootstrap.py CAMPAIGN_DIR \
  --guidelines PROGRAM_RULES.md --scope PROGRAM_SCOPE.md \
  --checkout LOCAL_CHECKOUT \
  --confirm-authorization
```

Omit `--scope` when scope is already included in the guidelines.

If no checkout was supplied, use `--clone` only when the rules identify one
unambiguous public repository. Otherwise let the coordinator resolve the
recorded intake item. Read
[references/program-intake.md](references/program-intake.md) for selection and
authorization rules. The retained program text remains authoritative; parser
output is only a candidate inventory.

After bootstrap, register the current coordinator identity, claim and complete
`coordinator-setup`, then launch complementary workers through the durable
queue when the user requested a full campaign. Resolve repository acquisition,
revision pinning, builds, and static source mapping inside that setup task so
research begins without another routine handoff. Do not infer live, testnet,
account, wallet, or shared-system permission from a public program page.
Require asset-specific authorization before those actions. Ask the user only
when a real ambiguity would choose a different asset, broaden authority,
require credentials, or incur meaningful cost.

## Start safely

Before dynamic testing, record the target, exact revision, authorization,
program scope, exclusions, allowed environment, and stopping conditions. Read
[references/safety.md](references/safety.md) when any test touches a live
service, testnet, browser profile, wallet, external account, or shared system.

Initialize a campaign with:

```bash
python3 scripts/research_harness.py init CAMPAIGN_DIR \
  --target TARGET --repo REPOSITORY --checkout LOCAL_CHECKOUT \
  --commit REVISION --mode source
python3 scripts/research_harness.py plan CAMPAIGN_DIR \
  --max-concurrency auto --lease-seconds 900 --task-timeout-seconds 7200
python3 scripts/research_harness.py queue CAMPAIGN_DIR
python3 scripts/tool_probe.py --output CAMPAIGN_DIR/tools/tool-probe.json
python3 scripts/static_analysis_pipeline.py run CAMPAIGN_DIR \
  --language TARGET_LANGUAGE --ingest
```

The static pipeline actually invokes available Trailmark, Tree-sitter, and
Joern analyzers, retains every command and raw output under
`tools/static/RUN_ID/`, and converts normalized leads into idempotent
`static-lead-validation` tasks in the durable queue. Add one or more
`--z3-spec` files when a source-derived numeric constraint is available. A
static hit or satisfiable model is never a finding: the generated task requires
manual source confirmation and a stock-build runtime discriminator.

## Campaign workflow

1. Confirm scope and pin exact source and runtime artifacts.
2. Map entry points, trust boundaries, state owners, execution/native sinks,
   and code-loading authority directly from the pinned tree.
3. Derive high-leverage dependency revisions from the target's lockfiles,
   manifests, generated bundles, build graph, or runtime linkage. Pin selected
   sources in the campaign's mandatory `third_party/` directory and audit
   target-to-library boundaries. Read
   [references/dependencies.md](references/dependencies.md).
4. Launch the maximum safe number of complementary discovery agents and keep
   dependency-ready slots occupied. Read
   [references/orchestration.md](references/orchestration.md).
5. Execute Trailmark, Tree-sitter, Joern, and source-derived Z3 constraints
   through the static pipeline. Feed every normalized lead into the durable
   validation queue with run, commit, command, and artifact provenance; do not
   let leads terminate as prose. Use targeted source search and runtime
   instrumentation as complementary assistants. Read
   [references/tool-assisted-analysis.md](references/tool-assisted-analysis.md).
6. Register every hypothesis, including blocked and disproved routes. Avoid
   silently recycling rejected ideas under new names.
   Treat profile lanes as starting axes, create focused runtime tasks for new
   branches, and use the structured blocker-resolution loop in
   [references/blocker-resolution.md](references/blocker-resolution.md).
7. Promote only a complete Critical/RCE chain with a stock or supported ingress,
   no application-authored unsafe sink, a harmless real terminal, baseline and
   negative controls, independent replay, and execution against a supported
   production-equivalent or release build. Before candidate promotion, require
   a machine-audited source-to-sink proof that enumerates every conditional,
   gives the concrete attacker mechanism for each branch outcome, contains no
   unresolved assumptions or contradictions, and is reviewed by a different
   identity. Development servers and development builds are lead-generation
   environments only. Read
   [references/false-positive-control.md](references/false-positive-control.md)
   and [references/evidence-gates.md](references/evidence-gates.md).
8. Only after the chain is complete, check scope, current official documentation,
   upstream tests, eligibility, and duplicate risk. Never use that filing review
   to mine fixes or diff patched code. Read [references/pre-filing.md](references/pre-filing.md).
9. Write a root-cause-first report with measured impact and explicit
   preconditions. Read [references/reporting.md](references/reporting.md).

## Operational multi-agent rule

When collaboration tools are available and the user authorized a full
campaign, keep the root agent as coordinator and use every safe worker slot
exposed by the runtime. Four or more workers may run concurrently whenever
capacity and independent work permit. Do not reserve or prescribe any number
of agents for a lane, strategy, or methodology. Profiles seed a shared task
queue; they are not staffing plans. Each eligible worker atomically claims the
highest-priority ready task only after semantic family load and prior coverage
have been balanced. Split promising missing links into non-overlapping dynamic
tasks without concentrating workers in that family, merge or cancel stale
work, and backfill every slot as evidence changes. Candidate-specific
validation must be assigned to an agent that did not originate the hypothesis.

Do not treat `launch-plan.json` as proof that orchestration occurred. Register
each runtime identity, atomically claim a dependency-ready task, run it in the
returned isolated workspace, renew long operations, and submit a JSON result
through the lease:

```bash
python3 scripts/research_harness.py worker-register CAMPAIGN_DIR worker-a \
  --agent codex:session-a --role originator
python3 scripts/research_harness.py claim CAMPAIGN_DIR worker-a --json
python3 scripts/research_harness.py heartbeat CAMPAIGN_DIR worker-a TASK_ID \
  --lease-token TOKEN
python3 scripts/research_harness.py submit CAMPAIGN_DIR worker-a TASK_ID \
  --lease-token TOKEN --result result.json \
  --idempotency-key TASK_ID-attempt-1
```

The SQLite coordinator enforces dependencies, concurrency, attempt and time
budgets, cancellation, leases, and recovery after worker or coordinator
failure. A local checkout produces detached per-attempt Git worktrees. Without
one, the worker still receives a separate directory and assignment manifest.

For independent validation, register the finding with `--originator`, run
`schedule-replay` twice, and let two different registered runtime agents claim
the tasks. The scheduler excludes the originator, its aliases, and agents that
already reviewed the finding. The reportable gate requires two accepted replay
artifacts with distinct reviewer-agent identities whose originator, reviewer,
digest, and finding ID agree. A prose assertion or manually set Boolean does
not pass this gate.

Normal completion must follow the task-result template copied into the claimed
workspace. Missing searched surfaces, pinned source references, evidence, or
first-principles provenance cannot unlock downstream tasks.
Replay-scheduler tasks additionally require `taskResult.replayFindings`; every
listed finding must already pass the independent replay verifier before the
profile can advance to adversarial review and synthesis.

Keep at least three genuinely incompatible routes alive through repeated
research rounds when the source surface permits it. Launch a round with
`round-plan` and a plan based on `assets/research-round.template.json`. Routes
must use distinct semantic families and reciprocal incompatibility records.
The scheduler uses different agents for route development in one round, pairs
every route with a different-agent adversarial review, and reserves round
synthesis for the coordinator. Do not cross-pollinate routes until each has
completed two development and adversarial-review rounds. After every synthesis,
the root coordinator must challenge the current conclusions, redirect weak
routes, retain incompatible alternatives, and launch the next justified round.
Failed current approaches and “no findings” are not stop conditions. Every
route-development result must retain fresh ideas and any intermediate bugs plus
chain hypotheses. A sanity-passed intermediate bug automatically creates a
fresh-agent composition task and delays synthesis until that task completes.
The coordinator may stop rounds only for an explicit user stop, missing
authorization, exhausted campaign budget, or an unsafe/out-of-scope boundary.
When synthesis requests another round, Krineon creates a durable coordinator
planning task. That task cannot complete until `round-plan` has actually
created the next round's development, adversarial, and synthesis tasks.

Maintain the semantic approach-family registry throughout the campaign. Every
task must bind to stable family IDs defined by security boundary, mechanism,
and invariant, never by similar wording. Check `approach-status` while agents
are active. The scheduler must balance active-agent load first and prior
coverage second, before considering task priority. A family may not dominate
because it appears promising, suspicious, exploitable, or familiar while a
runnable underexplored family exists. Do not defeat that balancing by renaming
the same method. Read
[references/approach-families.md](references/approach-families.md) for the
registry and redirection contract.

Do not launch subagents for a narrow review, a single factual check, or when
their tasks would overlap materially.

## Open-ended exploration and persistence

Do not constrain a campaign to the examples or lanes known when it started.
Within the recorded authorization, follow newly discovered call edges, sibling
implementations, state transitions, platform variants, and cross-lane
compositions. Use `task-add` to make those branches durable and assignable.
Select one or more existing semantic families with `--approach-family`; create
a new family only for a materially different boundary, mechanism, or invariant.

When a lane cannot progress, do not stop at “the attack failed.” Identify the
exact missing chain link, blocking guard or mechanism, why current assumptions
cannot cross it, source-derived bypass hypotheses, alternative routes to the
same boundary, and the cheapest discriminating experiment. A self-resolvable
technical blocker automatically creates a high-priority fresh-agent breakout
task; successful breakout resumes the original lane, while a new blocker
continues the loop. Retire only the exact route that evidence falsifies, then
search adjacent producers, consumers, representations, platforms, primitives,
and sinks. Never treat missing authorization, safety controls, or campaign
budgets as technical obstacles to route around, and never inflate a real
falsification into a claim.

Reopen a blocked route only when retained evidence establishes a genuinely new
mechanism. Blocker results carry a semantic mechanism fingerprint; successful
unblock results must provide a different fingerprint, explain the mechanism
change, and cite enabling evidence. New inputs, names, or wording for the same
mechanism do not qualify. The generic `retry` command refuses blocked tasks;
reopening must pass through the unblock evidence gate.

## Non-negotiable evidence rules

- Pin source links to the tested commit and recheck every method and line.
- Distinguish source inference, static-tool output, and runtime proof.
- Treat static tools as leads and cross-checks, not exploit evidence.
- Prove an unauthorized outcome before using words such as "bypass."
- Use a three-case truth table: working baseline, enforcing negative control,
  and attack case differing only in the disputed condition.
- Prefer stock builds, supported configuration, real protocol values, and
  actual harmless effects over synthetic callbacks or modified harness state.
- Never issue a finding whose primary terminal exists only in a development
  environment, development build, hot-reload server, test server, fixture
  server, preview-only runtime, or debug-only path. Reproduce it in a supported
  production-equivalent or release build first.
- Separate the root cause from downstream gadgets and deployment
  preconditions.
- Measure reliability as `N/M` across fresh processes when races, allocator
  state, ASLR, scheduling, or retries affect the result.
- Preserve raw evidence, commands, hashes, environment metadata, cleanup, and
  negative results.
- Record analysis provenance. Candidate gates fail if discovery used changelogs,
  advisories, git history or blame, historical commits, patched-version
  comparisons, or internet-derived patch diffs.
- Do not promote reasoning prose directly. Record the exact source-to-sink
  steps, every conditional on that path, the concrete attacker-selected outcome
  and runtime evidence for each condition, falsification controls, and an empty
  assumptions list in the linked path proof. A different identity must resolve
  all contradiction challenges before the candidate gate can pass.

## Bounded dynamic validation

After confirming authorization, use `scripts/dynamic_harness.py` for bounded
single-input replay and deterministic smoke mutation in owned `source` and
`local-lab` targets. Do not present its byte mutator as coverage-guided
zero-day fuzzing. For sustained fuzzing, read
[references/fuzzing.md](references/fuzzing.md) and use
`scripts/fuzzer_orchestrator.py` with pinned AFL++, libFuzzer, or Fuzzilli
artifacts and verified instrumentation.

```bash
python3 scripts/dynamic_harness.py fuzz CAMPAIGN_DIR \
  --seed-file SEED --iterations 10000 --rng-seed 1 \
  --name TARGET_NAME --input-mode file --cwd TARGET_DIR \
  --target-artifact TARGET_BINARY -- TARGET_BINARY '{input}'
python3 scripts/dynamic_harness.py minimize CAMPAIGN_DIR CRASH_ID
python3 scripts/dynamic_harness.py replay crash CAMPAIGN_DIR CRASH_ID --minimized
python3 scripts/dynamic_harness.py regression CAMPAIGN_DIR
python3 scripts/dynamic_harness.py triage CAMPAIGN_DIR --crash-id CRASH_ID --json
```

Every saved crash is automatically classified by first fault, access direction,
normalized stack cluster, and evidence-based controllability. The triager emits
an automated exploitability verdict with explicit limitations under
`dynamic/crashes/CRASH_ID/triage.json` and maintains cross-corpus clusters in
`dynamic/triage/index.json`. Use `triage --finding-id F001 --reviewed-by ID
--review-note NOTE` to attach one reviewed verdict to the candidate gate. A
score prioritizes escalation work; it never proves attacker control, RCE,
production reachability, or filing eligibility.

For coverage feedback, a target or wrapper writes one edge ID per line to
`KRINEON_COVERAGE_FILE`. New-coverage inputs persist in the target corpus and
are loaded by later runs. The POSIX resource limits and process-group cleanup
are not a security sandbox; use a disposable VM or container for unsafe code.
`regression` verifies reproduction against the original pinned target. Krineon
does not require or use a patched-version comparison.

External fuzzer workflow:

```bash
python3 scripts/fuzzer_orchestrator.py register CAMPAIGN PROFILE \
  --engine libfuzzer --target TARGET --revision REVISION
python3 scripts/fuzzer_orchestrator.py instrument CAMPAIGN PROFILE \
  --kind libfuzzer-clang --build-command-json '["ninja","-C","out","target"]'
python3 scripts/fuzzer_orchestrator.py seed-harvest CAMPAIGN PROFILE \
  --source SOURCE_TESTS
python3 scripts/fuzzer_orchestrator.py launch CAMPAIGN PROFILE \
  --workers 16 --duration-seconds 21600 --forward-crashes
```

Use native engine parallelism and corpus exchange. Rebuild AFL or LLVM coverage
from the retained canonical corpus after material growth. Only replay-confirmed
external crash artifacts may enter the first-fault triage and evidence gates.

## Chrome/V8 campaigns

When the target is Chrome or V8, initialize with `--profile chrome-v8` and read
[references/chrome-v8.md](references/chrome-v8.md). Give every worker
[agents/chrome-v8-agent.md](agents/chrome-v8-agent.md) together with its claimed
task packet.

Do not use the generic mutation loop as a substitute for structured JavaScript
generation. Operate Fuzzilli through `fuzzer_orchestrator.py`; use V8's
checked-in fuzzers, FuzzTest, or libFuzzer where appropriate while Krineon owns
revisions, task identity, instrumentation evidence, corpus/crash paths, result
ingestion, coverage rebuilds, and independent replay. Pin the fuzzer separately
from V8.

Register release, ASan, and debug `d8` builds before triage:

```bash
python3 scripts/chrome_v8_harness.py register-build CAMPAIGN release \
  --kind d8 --role release --revision V8_COMMIT --binary D8
python3 scripts/chrome_v8_harness.py audit CAMPAIGN
python3 scripts/chrome_v8_harness.py matrix CAMPAIGN --testcase CASE.js
python3 scripts/chrome_v8_harness.py browser-replay CAMPAIGN \
  --build chrome-release --page-dir OWNED_PAGE \
  --entry index.html --control-entry control.html
```

Keep these evidence levels distinct:

- a fuzzer anomaly or differential is a lead;
- a debug assertion is not automatically security relevant;
- a reproducible sanitizer or release memory-safety failure is an engine
  candidate after first-fault analysis;
- an owned-page full-Chromium replay establishes web reachability;
- renderer compromise is not a sandbox escape;
- a sandbox-escape claim requires a separate sandbox-boundary proof.

Internal flags and diagnostic instrumentation may aid diagnosis but must be
removed or explicitly classified before the web-reachability gate. Run browser validation
only against an owned local origin in a disposable environment, never against
third-party sites or a personal browser profile.

Use the direct-CDP runner for the final owned-page replay. It must retain a
positive and negative-control case in separate fresh processes, block external
requests, and record renderer sandbox evidence. Do not substitute a manual
browser observation or infer sandbox status only from the absence of
`--no-sandbox`. A linked replay passes the candidate evidence check only when
the retained machine record is promotion-ready and a named reviewer explains
what boundary it does and does not prove.

## Harness commands

```bash
python3 scripts/research_harness.py orchestration-status CAMPAIGN_DIR
python3 scripts/research_harness.py recover CAMPAIGN_DIR
python3 scripts/research_harness.py cancel CAMPAIGN_DIR TASK_ID --reason REASON
python3 scripts/research_harness.py retry CAMPAIGN_DIR TASK_ID --reason REASON
python3 scripts/research_harness.py status CAMPAIGN_DIR
python3 scripts/research_harness.py register CAMPAIGN_DIR F001 \
  --title "Candidate title" --lane cross-lane-chain-composition \
  --originator worker-a
python3 scripts/path_proof.py init CAMPAIGN_DIR F001
python3 scripts/path_proof.py audit CAMPAIGN_DIR F001 --update-gate --json
python3 scripts/research_harness.py schedule-replay CAMPAIGN_DIR F001
python3 scripts/research_harness.py gate CAMPAIGN_DIR F001 --level reportable
python3 scripts/research_harness.py hash CAMPAIGN_DIR
python3 scripts/research_harness.py lint CAMPAIGN_DIR
```

As a skill, Krineon's root coordinator actively launches and backfills
subagents with the runtime's collaboration tools. Its Python scheduler remains
model-vendor-neutral; Codex, Claude Code, OpenCode, CI jobs, and human adapters
connect those workers through the shared protocol. Krineon does not
autonomously attack third-party targets or submit reports. Dynamic execution is
limited to explicitly authorized environments, and external actions remain
subject to the user's authorization and program rules.
