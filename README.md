# Krineon

Krineon is a multi-agent, evidence-driven vulnerability-research harness and
durable cooperative task coordinator. It packages the methodology used across
source-code campaigns that produced
multiple confirmed remote-code-execution chains and several high-severity
findings. Its central lesson is that finding a primitive is only the beginning.
A bounty-grade result needs a supported ingress, a violated security boundary,
a realistic carrier, concrete impact, controls, independent replay, and
accurate scope and prior-art analysis.

The harness is intentionally target-neutral. It supports local source audits,
owned lab environments, testnets, and program-authorized systems. It does not
automate exploitation of third-party production targets.

## Recommended agent

The harness is portable, but it works best with Codex because the orchestration
workflow maps directly to Codex collaboration tools. For long, adversarial
campaigns, use **GPT-5.6 Sol with `max` reasoning**. Other models and coding
agents can run the Python harness and follow the shared methodology, but their
subagent, permission, and skill-loading interfaces may require adapters.

## Analysis coverage

Krineon combines complementary analysis tools rather than treating any single
graph or query engine as authoritative:

- **Trailmark** rapidly maps repository structure, entry points, call graphs,
  and security-relevant changes between revisions.
- **Tree-sitter** provides syntax-aware censuses and precise ordering checks
  without matching comments or strings as code.
- **Joern** builds a code property graph for bounded reachability, data-flow,
  dominance, and missing-validation questions.
- **Z3** solves implementation-matched constraints for integer boundaries,
  parser and serializer disagreements, non-injective encodings, cache-key
  collisions, and authorization-state combinations.

Together, these tools broaden coverage and help generate concrete test inputs.
Their output remains a lead or model result until manual source review and a
controlled runtime differential confirm the security claim. Run
`scripts/tool_probe.py` to record which optional tools are available. The probe
does not install or modify them.

## Quick start

```bash
cd krineon

python3 scripts/tool_probe.py --output ../campaigns/example/tools/tool-probe.json

python3 scripts/research_harness.py init ../campaigns/example \
  --target example-project \
  --repo https://github.com/example/project \
  --checkout ../target-checkout \
  --commit 0123456789abcdef \
  --mode source

python3 scripts/research_harness.py plan ../campaigns/example \
  --max-concurrency 3 --lease-seconds 900 \
  --task-timeout-seconds 7200 --max-attempts 2
python3 scripts/research_harness.py queue ../campaigns/example
python3 scripts/research_harness.py worker-register ../campaigns/example worker-a \
  --agent codex:session-a --role originator
python3 scripts/research_harness.py claim ../campaigns/example worker-a --json
python3 scripts/research_harness.py orchestration-status ../campaigns/example
python3 scripts/research_harness.py status ../campaigns/example
```

Review `campaign.json` and `AUTHORIZATION.md` before running dynamic tests.
Agent task packets are written to `tasks/`, grouped into waves in
`launch-plan.json`, and materialized in the durable `orchestration.db` queue.
The launch plan remains reviewable configuration; the SQLite queue is the
operational source of truth.

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

Krineon does not start model processes itself. Codex, Claude Code, OpenCode,
CI jobs, or human workers act as scheduler clients by calling `claim`,
`heartbeat`, and `submit`. This keeps model-runtime adapters small while making
dependency, identity, retry, cancellation, timeout, budget, and result-ingestion
rules operational and machine-enforced.

Finding-specific replay tasks exclude the recorded originator. A reportable
gate passes only when a different registered reviewer submits a hashed replay
result with matching originator, reviewer, and finding identities. The gate
recomputes the artifact hash and cross-checks the accepted SQLite submission,
completed replay task, excluded-originator list, and replay JSON payload.

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
  --title "Candidate" --lane protocol-differential --originator worker-a
python3 scripts/research_harness.py schedule-replay CAMPAIGN F001
```

`submit` accepts the same idempotency key repeatedly only when the task,
worker, result digest, and outcome are identical. A conflicting reuse fails.
`recover` releases expired worker leases, marks task timeouts, and blocks tasks
whose dependencies ended unsuccessfully. Coordinator or worker restarts do not
erase queue state or accepted submissions.

## Workflow

```text
scope and authorization
        |
        v
exact-version inventory and tool probe
        |
        v
wave 1: boundary map | sink-first trace | state/lifecycle audit
        |
        v
wave 2: protocol differential | variant/patch audit | configuration matrix
        |
        v
candidate registry and falsification
        |
        v
wave 3: independent replay | controls | prior art and scope
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
scripts/tool_probe.py            Local static-tool capability inventory
references/methodology.md        End-to-end research method
references/orchestration.md      Multi-agent waves and handoffs
references/tool-assisted-analysis.md
references/evidence-gates.md
references/pre-filing.md
references/reporting.md
references/safety.md
assets/campaign.template.json
assets/finding.template.json
assets/agent-handoff.template.md
tests/test_research_harness.py
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
