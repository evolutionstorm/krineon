# OpenCode runtime adapter

Use this adapter when Krineon runs in OpenCode. OpenCode supplies model
sessions and tools; Krineon's campaign database, signed web contract, budget,
and evidence remain authoritative.

## Load and resolve the skill

Load the skill with `@krineon` or the native `skill` tool. OpenCode discovers
project skills at `.opencode/skills/<name>/SKILL.md` and global skills at
`~/.config/opencode/skills/<name>/SKILL.md`. Resolve Krineon scripts, assets,
profiles, and references from the physical canonical skill root, not the target
checkout or `.opencode/skills/krineon/` adapter directory.

The primary OpenCode agent is the coordinator. It reads
`references/web-app.md` for a web campaign before it creates tasks. Runtime
permission to use `bash`, MCP, or an external directory does not authorize
target traffic.

## Web campaign ownership

The coordinator alone owns these private or authoritative resources:

- the unredacted program intake and authorization review;
- the secret store and literal credentials;
- browser profiles, cookies, local storage, and interactive login state;
- private Burp MCP arguments and returned bodies;
- workflow signatures, the shared budget, cleanup stack, and cancellation;
- controlled HTTP, CDP, Burp, callback, and replay dispatch; and
- final coordinator re-execution and finding promotion.

Do not place those resources in a child prompt, child workspace, task result,
or model-visible evidence. OpenCode MCP authentication storage is transport
configuration, not a Krineon secret broker or campaign authorization record.

## Worker use

Use `explore` for read-only source or retained-artifact analysis. Use `general`
only when the worker must write campaign artifacts or run an authorized local,
credential-free fixture. Every worker receives fresh context, so pass:

- absolute canonical skill, campaign, and claimed-workspace paths;
- the exact task and immutable OpenCode child-session or task identifier;
- redacted scope, rules, actor labels, resource ownership, and stop conditions;
- the evidence contract and output template; and
- explicit notice that it cannot dispatch authenticated target traffic.

Workers may search the blackboard, inspect redacted requests, develop source
hypotheses, prepare bounded workflows, challenge controls, and review retained
observations. They submit proposals to the durable queue. A task result does
not authorize execution and cannot unlock dependencies until the result is
accepted by Krineon.

Use one immutable OpenCode child-session identifier per Krineon worker. A
resumed child preserves identity. Independent review requires a fresh child
that did not originate or previously review the finding. Do not register
multiple worker names for one child session.

## Browser and MCP capabilities

Do not assume OpenCode has a browser, Playwright, Burp, or any other MCP
server. Inspect the tools exposed in the active session. Add a capability fact
only after that exact tool or MCP schema is observed. A browser lane may use a
locally measured Chrome/CDP capability or an already-enabled Playwright MCP.
Burp remains subject to `references/burp-mcp.md`.

Keep authenticated execution in the primary coordinator even when a child
could technically call the same MCP tool. Give workers only redacted hashes and
bounded metadata. Tool availability can activate context; it never broadens
origins, identities, actions, effects, budgets, or program scope.

## Recovery

If an OpenCode child stops, reconcile the durable lease before reassigning the
task. Revoke any in-flight dispatch capability, inspect cleanup state, and
recover only from retained campaign evidence. Conversation or task history is
not the source of truth.
