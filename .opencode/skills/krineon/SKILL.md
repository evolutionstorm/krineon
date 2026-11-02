---
name: krineon
description: Coordinate authorized Critical/RCE source research and High/Critical web application audits with independent workers, signed execution, evidence gates, and replay. Use for full campaigns against pinned source, owned labs, or explicitly authorized web environments; not for unapproved live testing or availability attacks.
compatibility: opencode
---

# Krineon for OpenCode

Read and follow [the canonical Krineon skill](../../../SKILL.md). Resolve every
script, asset, example, profile, query, and reference path from the repository
root containing that file, not from this adapter directory.

Read and follow the canonical skill, then read
`../../../references/opencode.md`. For a `web-app` campaign, also read
`../../../references/web-app.md` before creating tasks or target traffic.

The canonical skill contains the OpenCode `task`-tool orchestration rules and
the durable worker protocol. The primary agent owns web authorization, secrets,
browser state, MCP dispatch, shared budgets, cleanup, and coordinator replay.
Workers receive only redacted contracts and propose experiments. Task
completion alone is not evidence of a valid submission. OpenCode tool or MCP
permission is not campaign authorization.
