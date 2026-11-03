# Krineon

Krineon coordinates authorized source and web application research. Source,
native, browser, and sandbox campaigns search for complete Critical
vulnerabilities, remote code execution (RCE), sandbox escapes, and zero-days.
Web-application campaigns additionally accept independently reproduced,
program-eligible High-severity security invariant violations.

For shipped binaries, generated bundles, JavaScript or Electron packages, and
other artifacts that source alone cannot explain, Krineon can consume evidence
from an existing local REA installation. It binds the evidence to unchanged
artifact and tool hashes, preserves REA coverage and unknowns, and turns the
result into source-versus-artifact hypotheses rather than findings.

## Requirements

Install these core components:

- Git
- Python 3.10 or later
- OpenSSL
- PyYAML for strict `krineon-web` Markdown metadata parsing
- Codex, OpenCode, or OMP (Oh My Pi)
- The target source code or a repository URL
- A disposable local environment for dynamic testing, when needed

Krineon works best with Codex and GPT-5.6 Sol at `max` reasoning effort.
Program rules and scope intake are optional for source-only campaigns. A
`web-app` campaign requires a versioned application contract and remains
offline until authorization is explicitly confirmed.

### Helper tools for maximum coverage

Krineon does not install helper tools. Install the tools that apply to the
target before starting a campaign. Run `scripts/tool_probe.py` to inventory
the supported analysis tools that Krineon can detect automatically.

| Tool | What it adds | Use it for |
| --- | --- | --- |
| ripgrep (`rg`) | Fast source and artifact search | Every source campaign |
| Tree-sitter CLI and Python modules | Syntax-aware source structure and candidate extraction | Multi-language source analysis |
| Trailmark | Single-revision structure, entrypoint, and data-flow assistance | Supported source languages |
| Joern (`joern`, `joern-parse`, `joern-scan`) | Code property graphs and cross-function reachability | C, C++, Java, JavaScript, and other supported languages |
| Z3 CLI and Python module | Concrete inputs for source-bound arithmetic and constraint models | Parsers, integer boundaries, state machines, and protocol checks |
| cppcheck | Additional C and C++ diagnostics | Native targets |
| Semgrep or OpenGrep | Fast structural rules and target-specific pattern checks | Source reconnaissance |
| CodeQL CLI | Deeper cross-file data-flow queries | Languages and builds supported by CodeQL |
| REA | Evidence from shipped binaries, generated bundles, Electron packages, and other artifacts | Source-versus-artifact differentials |

When Trailmark, Joern, Z3, or cppcheck is available and applicable, Krineon's
static pipeline runs it and retains its provenance. A tool match remains a
hypothesis until a controlled runtime experiment validates it.

### Build, runtime, and fuzzing helpers

| Tool | What it adds | Use it for |
| --- | --- | --- |
| Docker | Reproducible production builds, isolated services, and disposable test environments | Framework, service, and multi-component campaigns |
| Clang and LLVM | ASan, UBSan, libFuzzer, sanitizer coverage, symbolization, and coverage reports | Native code and browser engines |
| CMake and Ninja | Fast reproducible native builds | C and C++ targets |
| AFL++ (`afl-fuzz`, `afl-showmap`) | Parallel coverage-guided fuzzing and corpus measurement | Instrumented native parsers and protocol targets |
| Fuzzilli and Swift | JavaScript engine generation and REPRL execution | V8 and JavaScript engines |
| `llvm-profdata` and `llvm-cov` | Coverage merging and source-level coverage gaps | LLVM-instrumented targets |
| LLDB or GDB | Independent crash, lifetime, and control-flow observations | Native exploitability verification |
| `minidump_stackwalk` | Stable stack recovery from minidumps | Chromium and crash-reporting targets |
| Node.js and a lockfile-aware package manager | Production JavaScript builds and persistent test workers | React, Next.js, Node.js, and web tooling |
| Rust and Cargo | Reproducible Rust builds and sanitizer-compatible test targets | Rust projects |

For Chromium and V8, also install `depot_tools` (`gclient`, `gn`, and
`autoninja`), Ninja, Clang, `llvm-symbolizer`, a sandboxed Chrome or Chromium
binary, and Fuzzilli when JavaScript-engine fuzzing is in scope. On macOS,
install Xcode command-line tools, LLDB, `atos`, `codesign`, `lipo`, `otool`, and
`dwarfdump`.

### Web application helpers

| Tool | What it adds | Use it for |
| --- | --- | --- |
| Chrome or Chromium | Real browser sessions, CDP evidence, browser-generated headers, and client artifact collection | Authenticated and browser-only behavior |
| Playwright | Optional browser fixture and compatibility support | Owned browser test environments |
| Burp Suite MCP | Filtered proxy history, exact requests, and Repeater preparation | Authorized manual and agent-assisted web testing |
| Nuclei | Bounded supporting checks against broker-created, credential-free fixtures | Reviewed templates only |
| ffuf | Bounded candidate validation derived from observed routes | Approved endpoint discovery only |

Burp Suite MCP must already be enabled in Codex, OpenCode, or OMP. Krineon
does not install or configure Burp, bypass bot protection, or grant tools more
scope than the signed campaign contract.

## Supported hosts

Krineon supports these native 64-bit hosts:

- Linux on `x86_64` or `arm64`
- macOS on Apple Silicon (`arm64`)

Krineon normalizes the common `aarch64` and `armx64` aliases to the canonical
Apple architecture name, `arm64`.

On macOS, install Xcode and its command-line tools before you build native
targets. Krineon records Mach-O architecture evidence and validates Chromium's
Darwin Seatbelt sandbox without relying on Linux `/proc`. See
[macOS arm64 campaigns](references/macos-arm64.md).

## Start with Codex

### Load the skill in Codex

Run these commands once:

```bash
git clone https://github.com/evolutionstorm/krineon.git
cd krineon
mkdir -p "${CODEX_HOME:-$HOME/.codex}/skills"
ln -s "$PWD" "${CODEX_HOME:-$HOME/.codex}/skills/krineon"
```

If the destination already exists, remove or rename that installation before
you create the link. Start a new Codex session after installation.

Open the authorized target checkout:

```bash
cd /path/to/authorized-target
codex
```

Start the campaign with this prompt:

```text
$krineon Read PROGRAM_RULES.md and audit this pinned checkout for a complete
Critical, RCE, sandbox-escape, or zero-day chain. Use source review and bounded
tests in an owned local environment. Do not test live systems. Coordinate
independent agents and require machine-backed evidence before promotion.
```

The root Codex agent coordinates workers through the durable Krineon queue. For
details, see the [Codex runtime adapter](references/codex.md).

### Start with only the program rules

If you do not have a checkout, attach or paste the program rules and use this
prompt:

```text
$krineon Use the attached program rules as campaign intake. Resolve the
unambiguous in-scope public source repository and pin an exact revision. Begin
with source analysis. Ask before any action that requires credentials, cost,
live-system access, or a broader authorization boundary.
```

Krineon records an unresolved source or scope choice instead of guessing.

## Start with OpenCode

### Load the skill in OpenCode

For use from any authorized target checkout, install the skill globally:

```bash
git clone https://github.com/evolutionstorm/krineon.git
cd krineon
mkdir -p "$HOME/.config/opencode/skills"
ln -s "$PWD" "$HOME/.config/opencode/skills/krineon"
```

If the destination already exists, remove or rename that installation first.
Quit and restart OpenCode after installing or changing the skill; discovery and
configuration are loaded at startup.

The repository also includes `.opencode/skills/krineon/SKILL.md`, so OpenCode
can discover the skill automatically when started inside this checkout. Use
the global link above when working in a separate target checkout.

Open the authorized target:

```bash
cd /path/to/authorized-target
opencode
```

Start the campaign with this prompt:

```text
@krineon Read PROGRAM_RULES.md and audit this pinned checkout
for a complete Critical, RCE, sandbox-escape, or zero-day chain. Use source
review and bounded tests in an owned local environment. Do not test live
systems. Coordinate independent OpenCode tasks and require machine-backed
evidence before promotion.
```

The primary OpenCode agent remains the coordinator. It uses `task` workers and
the durable Krineon queue; a finished task is not a substitute for a submitted
result or independent replay. If the skill is not listed, verify its
frontmatter, the installation path, and that `permission.skill` does not deny
`krineon`.

For web campaigns, the primary OpenCode agent retains credentials, browser
state, MCP dispatch, budgets, and cleanup. Subagents receive redacted evidence
and propose experiments. See the
[OpenCode runtime adapter](references/opencode.md).

## Start with OMP

Run these commands once:

```bash
git clone https://github.com/evolutionstorm/krineon.git
cd krineon
mkdir -p "$HOME/.omp/agent/skills"
ln -s "$PWD" "$HOME/.omp/agent/skills/krineon"
omp read skill://krineon
```

Open the authorized target checkout and start OMP:

```bash
cd /path/to/authorized-target
omp
```

Start the campaign with this prompt:

```text
/skill:krineon Read PROGRAM_RULES.md and audit this pinned checkout for a
complete Critical, RCE, sandbox-escape, or zero-day chain. Use source review
and bounded tests in an owned local environment. Do not test live systems.
```

For a headless OMP campaign, configure `--wait-async` and an appropriate
`--max-time` value so the session retains active workers.

For web campaigns, the top-level OMP session retains credentials, browser
state, MCP dispatch, budgets, and cleanup. Task workers receive redacted
evidence and propose experiments. See the
[OMP runtime adapter](references/omp.md).

## Test a web application

Use Krineon only on applications and accounts that you own or are explicitly
authorized to test.

### Before you begin

Prepare the following information:

- The program rules and exact in-scope URL.
- Any documented request limits and prohibited actions.
- At least one owned test account; two are recommended for authorization or
  tenant-isolation testing.
- Disposable test records owned by those accounts.
- Optional redacted HTTP requests, HAR files, or Burp exports.
- Optionally, an already-enabled Burp Suite MCP connection exposed by Codex,
  OpenCode, or OMP. Keep Burp target approval enabled and use a dedicated
  project containing only authorized traffic.

Do not paste passwords, cookies, API keys, or bearer tokens into the prompt.
Krineon stores credentials through private references and keeps them out of
agent-visible evidence.

When program rules, exact origins, and verified owned-account details are all
available, Krineon activates owned full-test mode. The retained contract then
authorizes all bounded, in-scope methods and workflows on those accounts,
including state changes, uploads, browser actions, WebSockets, credential
lifecycle checks, cache/parser experiments, and small paired-concurrency tests.
Krineon does not pause for separate approval of each verb or hypothesis.
Its primary objective is novel, target-specific zero-day mechanism discovery.
It treats authentication and authorization as baseline coverage and one
possible chain family, keeping that family below roughly one fifth of active
exploration whenever producer-consumer, parser, workflow, cache, browser,
integration, storage, asynchronous, protocol, native, or execution-boundary
work is ready.

### Start the campaign

Open the authorized target in Codex, OpenCode, or OMP as described above.
Attach the program rules and optional request files, then invoke the client’s
skill form:

```text
Codex: $krineon Test this authorized web application under the supplied rules.
OpenCode: @krineon Test this authorized web application under the supplied rules.
OMP: /skill:krineon Test this authorized web application under the supplied rules.
```

Krineon creates an offline plan first, then binds the supplied rules and owned
accounts to an exact signed contract and immediately starts the eligible
research lanes. It automatically signs each bounded workflow and continues
through failed hypotheses without another user confirmation. It uses only
owned accounts and disposable data. Every candidate still requires an enforcing
negative control, authoritative readback, cleanup, and independent replay before
reporting.

### Verify the generated contract

The generated contract must contain:

- Only the intended origins, paths, and HTTP methods.
- The correct account, role, tenant, and resource ownership for each identity.
- Small request, time, concurrency, and data limits.
- Cleanup steps for every state-changing action.
- Stop conditions for third-party data, authentication ambiguity, bot
  challenges, unexpected effects, or exhausted limits.

If any item is missing or incorrect, Krineon must correct the contract before
traffic. Once the program rules and owned-account manifest agree, no further
per-experiment user approval is required.

### Run and verify the test

Krineon chooses controlled HTTP replay or real Chrome based on the behavior
being tested. It changes one relevant variable while keeping the target build,
account state, and test data stable.

A valid result must include all of the following:

1. A legitimate baseline that demonstrates the expected workflow.
2. An enforcing negative control that distinguishes the suspected mechanism.
3. A prohibited server-visible effect verified through authoritative readback.
4. Successful cleanup of every disposable change.
5. A fresh replay by a different reviewer identity with new credential
   bindings and rebuilt fixtures.

Treat missing telemetry, authentication uncertainty, challenge pages,
deployment changes, or cleanup failures as inconclusive. A status code,
scanner match, screenshot, or unusual response is not a finding by itself.

See [Web application campaigns](references/web-app.md) for the complete
contract, evidence, browser, business-logic, cache, and replay specifications.

## Update Krineon

Update the original Krineon clone used by the symbolic link:

```bash
git -C /path/to/krineon status --short
git -C /path/to/krineon pull --ff-only
```

Run the pull only when the status output is empty. If it shows local changes,
preserve or commit them before updating. The Codex, OpenCode, and OMP symbolic
links use the updated files automatically, so you do not need to reinstall the
skill. Restart the active client after the update so it reloads the skill.

Do not change Krineon versions during an active campaign. Record the current
revision with `git -C /path/to/krineon rev-parse HEAD`, finish or checkpoint the
campaign, and then update.

## What Krineon does

Krineon runs the following campaign:

1. Pins the source, runtime, build, and deployed artifact. It also records a
   supplied authorization boundary, but source-only analysis does not require
   an `AUTHORIZATION.md` file.
2. Builds one canonical architecture knowledge base for components, identities,
   resources, dependencies, entrypoints, trust boundaries, and generated
   artifacts. A hash-bound coverage ledger accounts for every production source
   file without treating file count as research depth.
3. Builds an evidence-linked semantic IR for attacker-controlled values,
   function-scoped def-use, aliases and property mutations, control candidates,
   cross-module calls, request representation changes, authority, ownership,
   lifetime, source maps, and runtime identity.
4. Moves campaigns through machine-enforced architecture, threat-model,
   planning, research, reconciliation, adversarial-review, production-critic,
   confirmation, replay, and reporting stages. Partial and blocked stages retain
   their exact reason.
5. Reconciles immutable source, runtime, browser, and fuzzing observations by
   mechanism and generates competing explanations. Runtime experiments require
   coordinator-owned baseline, enforcing-negative, positive, and automatic
   interpretation contracts.
6. Models each primitive as a typed capability and marks a connection feasible,
   unknown, or impossible. A chain exists only when one execution satisfies
   context, object generation, state, lifetime, ordering, deployment, and
   acquisition conditions together.
7. Treats login, cache priming, ownership transfer, worker reuse, allocation,
   release, reallocation, and victim reads as bounded, history-preserving state
   sequences. Browser and HTTP sessions are bound to exact actors, tenants,
   roles, and permission generations.
8. Launches independent research routes and prevents one approach family from
   consuming all worker capacity.
9. Promotes leads through observation, source-supported mechanism, runtime
   differential, verified primitive, compatible chain edge, and complete
   terminal. Every hypothesis receives an explicit disposition. Per-mechanism
   work limits and evidence expiry keep the active frontier bounded.
10. Rebuilds a versioned campaign-wide capability graph and assigns its
   highest-value missing-link experiment by boundary relevance, uncertainty,
   shared usefulness, and measured cost.
11. Activates lane context from measured source, tool, artifact, browser, MCP,
    and authorization capabilities. Missing capabilities keep a lane visible
    for planning without granting execution authority.
12. Compares evidence-bound fingerprints across independent observers and
    one-dimensional scope changes. Disagreements create controlled experiments,
    not version or vulnerability verdicts.
13. Requires separate adversarial and production-viability reviews. Reviewers
    receive role-isolated context without the originator's verdict, and source
    citations remain bound to exact revision, file, line, and snippet hashes.
14. Tests promising chains against supported release or production-equivalent
    builds in an owned environment.
15. Feeds coverage plateaus, invariant observations, and minimized stack
   clusters back into the next harness, grammar, or replay decision.
16. Requires coordinator-signed experiments, recomputed raw observations, an
   enforcing negative control, and fresh-process adversarial replay.
17. Produces a source-audit report package only when complete Critical/RCE
    impact is demonstrated. The separate web profile uses program-defined High
    or Critical impact and application-specific invariant gates.

The optional execution runtime binds each recipe to exact target hashes, an
exact container image digest, resource limits, an active external-agent session,
and primary plus separate-observer assertions. Arbitrary sandbox commands have no
network. Approved web traffic continues to use the signed HTTP or browser
broker rather than inheriting a worker's shell authority.

When a route fails, Krineon records the enforcing mechanism and creates a new
task only when the source supports a different bypass or composition. It does
not turn a crash, static-analysis match, or incomplete primitive into a finding.

## Research coverage

Krineon includes focused support for these targets and techniques:

- General source-code and dependency audits
- Authorized web applications with multi-identity HTTP workflows, typed
  security oracles, shared budgets, controlled CDP discovery, and admitted
  Nuclei templates
- Next.js, React, and Node.js production artifacts
- Raw HTTP, cache, authentication, routing, and protocol differentials
- Chrome and V8 release, sanitizer, debug, and owned-page browser replay
- Signed build provenance with live sanitizer and REPRL capability checks
- workerd GC, handle, reentry, cancellation, ArrayBuffer, and IoContext oracles
- Mandatory-when-available Trailmark, Joern, Z3, and cppcheck analysis
- Tree-sitter-assisted structural analysis
- AFL++, libFuzzer, and Fuzzilli campaigns
- V8, Istanbul, and source-map-aware JavaScript coverage
- First-fault crash clustering, minimization, and bounded replay
- Evidence-linked semantic IR and automatic runtime feedback
- Canonical architecture knowledge, production-source coverage, immutable
  observation reconciliation, production criticism, and hash-bound citations
- Role-isolated architect, researcher, reviewer, replayer, and reporter context
- Actor-, tenant-, role-, and permission-version-bound web sessions
- Offline per-task Docker recipes, correlated tool events, and immutable
  content-addressed runtime artifacts
- Fresh-agent runtime replay with a separate observer process
- Authenticated, loopback-only, read-only operator workbench
- Real-Chromium session discovery with browser-generated request context
- Broker-contained external Chromium journeys with declarative approved actions
- Offline identity, resource, lifecycle, and trust-representation mapping
- Business-rule coverage by actor, resource, action, and state
- Typed observation subscriptions with coordinator-reviewed experiment proposals
- Trust-tiered observation ancestry and poisoning-resistant policy separation
- Cost-aware independent verifier and heterogeneous per-role model routing
- Volatility-aware scheduling, persistent verified cleanup, owned OOB receipts,
  and provider/tool health telemetry

## Finding requirements

Krineon promotes a finding only when the retained evidence proves all of these
conditions:

- The tested source and runtime artifacts are pinned and hashed.
- An attacker controls the input at the real ingress.
- Every conditional between ingress and impact has a concrete, verified
  outcome.
- The chain runs against a supported release or production-equivalent build.
- The proof uses a harmless real terminal instead of a synthetic callback.
- For source/framework campaigns, the result does not depend on an
  application-authored unsafe sink. In the web profile, the application's own
  broken check or unsafe sink can be the defect.
- The positive case differs from the negative control only in the disputed
  condition.
- A different agent reproduces the result from the retained artifacts.
- The reviewer challenges both a hypothesis assumption and a possible observer
  failure using a different machine-checked assertion.
- The report states every deployment and attacker precondition.

Development servers, debug-only behavior, prose-only reasoning, and manually
asserted success values cannot pass the reportable gate.

State-changing web tasks declare durable resource leases for identity/session
refresh, owned objects, workflow instances, cache namespaces, browser profiles,
and receiver/callback correlation. Shared reads may coexist. Mutations are
serialized. A timeout, lost worker, or unverified cleanup blocks the affected
namespace until a coordinator records authoritative recovery evidence; a new
worker cannot infer recovery from lease expiry alone.

## Safety

Use Krineon only on source code, accounts, systems, and environments that you
own or are explicitly authorized to test. Runtime permission does not grant
campaign authorization.

Do not use Krineon to access third-party data, degrade a shared service, move
funds that you do not own, test production users, or publish embargoed findings.
Prefer disposable local virtual machines or containers for unsafe targets.

## Documentation

- [Skill instructions](SKILL.md)
- [Codex runtime adapter](references/codex.md)
- [OpenCode skill adapter](.opencode/skills/krineon/SKILL.md)
- [OpenCode runtime adapter](references/opencode.md)
- [OMP runtime adapter](references/omp.md)
- [Research methodology](references/methodology.md)
- [Critical/RCE promotion contract](references/critical-rce.md)
- [Orchestration and independent replay](references/orchestration.md)
- [Evidence gates](references/evidence-gates.md)
- [Semantic hypothesis experiments](references/semantic-experiments.md)
- [Semantic intermediate representation](references/semantic-ir.md)
- [Campaign architecture, evidence, review, and session intelligence](references/campaign-intelligence.md)
- [Event-driven swarm control, trust, routing, cleanup, and OOB verification](references/swarm-control.md)
- [REA shipped-artifact reverse-engineering evidence](references/rea.md)
- [Burp Suite MCP integration](references/burp-mcp.md)
- [Runtime fingerprint disagreements](references/fingerprint-disagreement.md)
- [Capability-conditioned lane activation](references/capability-lane-activation.md)
- [Runtime feedback loop](references/runtime-feedback.md)
- [Execution-boundary and typed chain reasoning](references/chain-reasoning.md)
- [Held-out multi-stage evaluation](references/multistage-evaluation.md)
- [Chrome and V8 campaigns](references/chrome-v8.md)
- [workerd native lifetime research](references/workerd-native.md)
- [Safety rules](references/safety.md)
