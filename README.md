# Krineon

Krineon is a multi-agent, evidence-driven vulnerability-research harness that
packages the methodology used across source-code campaigns that produced
multiple confirmed remote-code-execution chains and several high-severity
findings. Its central lesson is that finding a primitive is only the beginning.
A bounty-grade result
needs a supported ingress, a violated security boundary, a realistic carrier,
concrete impact, controls, independent replay, and accurate scope and prior-art
analysis.

The harness is intentionally target-neutral. It supports local source audits,
owned lab environments, testnets, and program-authorized systems. It does not
automate exploitation of third-party production targets.

## Recommended agent

The harness is portable, but it works best with Codex because the orchestration
workflow maps directly to Codex collaboration tools. For long, adversarial
campaigns, use **GPT-6.1 Sol with `max` reasoning**. Other models and coding
agents can run the Python harness and follow the shared methodology, but their
subagent, permission, and skill-loading interfaces may require adapters.

## Quick start

```bash
cd krineon

python3 scripts/tool_probe.py --output ../campaigns/example/tools/tool-probe.json

python3 scripts/research_harness.py init ../campaigns/example \
  --target example-project \
  --repo https://github.com/example/project \
  --commit 0123456789abcdef \
  --mode source

python3 scripts/research_harness.py plan ../campaigns/example
python3 scripts/research_harness.py status ../campaigns/example
```

Review `campaign.json` and `AUTHORIZATION.md` before running dynamic tests.
Agent task packets are written to `tasks/`, grouped into waves in
`launch-plan.json`.

Then invoke the skill with a concrete authorization boundary, for example:

```text
Use $krineon to audit the pinned local checkout in
../target. This is an authorized source-code and local-lab campaign. Read the
campaign's AUTHORIZATION.md, keep the root agent as coordinator, launch Wave 1
with complementary agents, and do not perform live-target testing.
```

The coordinator reads one wave from `launch-plan.json`, gives each worker its
corresponding file in `tasks/`, waits for all non-overlapping lanes, reconciles
their registry entries, and only then launches the next wave. A candidate's
clean replay must go to an agent that did not originate it.

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
