---
name: krineon
description: Coordinate authorized source-code vulnerability campaigns with multiple agents, static-analysis assistance, runtime validation, evidence gates, and submission-ready reporting. Use for full security research campaigns; do not invoke for a narrow code review or unapproved live-target testing.
---

# Krineon Security Research

Run an evidence-driven campaign against code and systems the user is authorized
to test. The objective is not to generate many speculative findings. The
objective is to converge on a small number of independently reproducible,
scope-eligible security boundary violations.

## Start safely

Before dynamic testing, record the target, exact revision, authorization,
program scope, exclusions, allowed environment, and stopping conditions. Read
[references/safety.md](references/safety.md) when any test touches a live
service, testnet, browser profile, wallet, external account, or shared system.

Initialize a campaign with:

```bash
python3 scripts/research_harness.py init CAMPAIGN_DIR \
  --target TARGET --repo REPOSITORY --commit REVISION --mode source
python3 scripts/research_harness.py plan CAMPAIGN_DIR
python3 scripts/tool_probe.py --output CAMPAIGN_DIR/tools/tool-probe.json
```

## Campaign workflow

1. Confirm scope and pin exact source and runtime artifacts.
2. Map entry points, trust boundaries, security promises, state owners, and
   privileged sinks before proposing exploits.
3. Launch discovery agents in complementary lanes, not duplicate free-form
   searches. Read [references/orchestration.md](references/orchestration.md).
4. Use Tree-sitter, Joern, Trailmark, targeted search, history, and runtime
   instrumentation as assistants. Read
   [references/tool-assisted-analysis.md](references/tool-assisted-analysis.md).
5. Register every hypothesis, including blocked and disproved routes. Avoid
   silently recycling rejected ideas under new names.
6. Promote a candidate only after baseline, negative, and positive controls,
   concrete impact, exact-version evidence, and an independent replay. Read
   [references/evidence-gates.md](references/evidence-gates.md).
7. Check official documentation, upstream tests, prior advisories, patches,
   scope, eligibility, and current release status before filing. Read
   [references/pre-filing.md](references/pre-filing.md).
8. Write a root-cause-first report with measured impact and explicit
   preconditions. Read [references/reporting.md](references/reporting.md).

## Multi-agent rule

When collaboration tools are available and the user authorized a full
campaign, keep the root agent as coordinator and run at most the environment's
safe concurrency limit. Prefer three complementary workers per wave: boundary
mapping, sink-first tracing, and state/lifecycle analysis. Candidate-specific
validation must be assigned to an agent that did not originate the hypothesis.

Do not launch subagents for a narrow review, a single factual check, or when
their tasks would overlap materially.

## Non-negotiable evidence rules

- Pin source links to the tested commit and recheck every method and line.
- Distinguish source inference, static-tool output, and runtime proof.
- Treat static tools as leads and cross-checks, not exploit evidence.
- Prove an unauthorized outcome before using words such as "bypass."
- Use a three-case truth table: working baseline, enforcing negative control,
  and attack case differing only in the disputed condition.
- Prefer stock builds, supported configuration, real protocol values, and
  actual harmless effects over synthetic callbacks or patched harness state.
- Separate the root cause from downstream gadgets and deployment
  preconditions.
- Measure reliability as `N/M` across fresh processes when races, allocator
  state, ASLR, scheduling, or retries affect the result.
- Preserve raw evidence, commands, hashes, environment metadata, cleanup, and
  negative results.
- Never claim a current patch status, version range, CVE relationship, or
  documentation guarantee without checking primary sources on the filing day.

## Harness commands

```bash
python3 scripts/research_harness.py status CAMPAIGN_DIR
python3 scripts/research_harness.py register CAMPAIGN_DIR F001 \
  --title "Candidate title" --lane protocol-differential
python3 scripts/research_harness.py gate CAMPAIGN_DIR F001 --level reportable
python3 scripts/research_harness.py hash CAMPAIGN_DIR
python3 scripts/research_harness.py lint CAMPAIGN_DIR
```

The harness does not attack targets or submit reports. It creates isolated task
packets, maintains the registry, evaluates evidence gates, and hashes retained
artifacts. External actions remain subject to the user's authorization and the
program rules.
