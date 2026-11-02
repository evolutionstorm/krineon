# OMP runtime adapter

Use this adapter when Krineon runs in OMP (Oh My Pi). Invoke
`/skill:krineon` and read supporting files through `skill://krineon/...`.
Resolve executable scripts from the physical skill directory recorded by OMP.

The top-level OMP session is the Krineon coordinator. Read
`skill://krineon/references/web-app.md` before starting a web campaign. OMP
tool approval and MCP availability do not authorize target traffic.

## Web campaign ownership

Keep these resources in the coordinator session and private campaign plane:

- literal credentials and the secret store;
- browser profiles, cookies, storage, and interactive login state;
- unredacted captures and private Burp MCP arguments or responses;
- signed workflow and authorization records;
- the process-shared request budget, cleanup stack, and cancellation state;
- HTTP, browser, Burp, callback, and replay dispatch; and
- coordinator re-execution and promotion decisions.

OMP children can receive proxy tools that reuse parent MCP connections. That
technical inheritance is not campaign authorization. Do not give a research worker an
authenticated browser, Burp send, or other target-dispatch tool merely because
OMP exposes it. Workers receive redacted artifacts and propose exact
experiments; the coordinator validates and dispatches them through Krineon's
signed broker.

## Worker use

OMP child sessions do not inherit the coordinator conversation. Put shared,
non-secret context in the task batch's `context` or a read-only `local://`
artifact. Each task must contain:

- absolute skill, campaign, and claimed-workspace paths;
- the pinned target or deployment epoch;
- redacted authorization boundaries, actor/resource labels, and exclusions;
- the evidence contract, output path, and stop conditions; and
- an explicit prohibition on direct authenticated target traffic.

The child registers with the durable queue using its real `PI_SESSION_ID`,
claims work, runs in the claimed workspace, heartbeats long tasks, writes the
result file, and submits it before returning. A yielded OMP result or
`agent://` artifact is only a notification.

Use `task` or `task.batch` within actual OMP capacity. Reuse a parked agent
through `agent://` for a follow-up when identity continuity is required. A
fresh independent reviewer needs a different OMP session and Krineon worker
identity. Never create independence by renaming one session.

## Browser and MCP capabilities

OMP's built-in browser can satisfy a browser-runtime lane only after the
coordinator verifies that it controls an owned Chrome/CDP session and records
the measured `runtime.browser-cdp` capability. An existing Playwright MCP may
instead record `mcp.playwright`. An existing Burp MCP follows
`skill://krineon/references/burp-mcp.md`.

Let Chrome generate browser context. Do not copy browser-only headers into raw
HTTP. Keep login and target traffic coordinator-owned; workers analyze
redacted, content-addressed observations.

## Cancellation and recovery

Stopping an OMP process does not update Krineon's lease. Cancel or requeue the
durable task, revoke dispatch authority, verify cleanup, and then backfill the
slot. In headless mode, keep asynchronous workers alive only for the reviewed
campaign duration and stop them when the shared budget or authorization
expires.
