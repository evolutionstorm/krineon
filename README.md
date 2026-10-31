# Krineon

Krineon coordinates authorized source audits that search for complete Critical
vulnerabilities, remote code execution (RCE), sandbox escapes, and zero-days.

Krineon analyzes one pinned source tree from first principles. It does not use
changelogs, advisories, Git history, or patched-version comparisons to discover
bugs. It retains partial primitives as research leads, but it promotes a
finding only after a production-equivalent proof and independent replay.

Krineon's current semantic-discovery pilot focuses on one boundary: whether
Next.js authorization and production route execution resolve the same request
to the same resource. Support for building or exercising other targets does not
mean Krineon can yet derive equally strong oracles for them.

## Requirements

Install or provide the following components:

- Git
- Python 3.10 or later
- Codex, OpenCode, or OMP (Oh My Pi)
- The target source code or a repository URL
- A disposable local environment for dynamic testing, when needed

Krineon works best with Codex and GPT-5.6 Sol at `max` reasoning effort.
Program rules and scope intake are optional for source-only campaigns. Supply
them before any live, shared-system, account, wallet, or testnet action.

Krineon detects tools and does not install them automatically. When Trailmark,
Joern, Z3, or cppcheck is installed and compatible with the target, the static
pipeline must run it and retain the result. Tree-sitter, AFL++, libFuzzer, and
Fuzzilli add coverage when their target adapters apply.

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
Load the krineon skill. Read PROGRAM_RULES.md and audit this pinned checkout
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
2. Builds an evidence-linked semantic IR for attacker-controlled values,
   function-scoped def-use, aliases and property mutations, control candidates,
   cross-module calls, request representation changes, authority, ownership,
   lifetime, source maps, and runtime identity.
3. Derives competing explanations for the focused authorization-to-route
   boundary and runs only experiments with coordinator-owned baseline,
   enforcing-negative, positive, and automatic interpretation contracts.
4. Models each primitive as a typed capability and marks a connection feasible,
   unknown, or impossible. A chain exists only when one execution satisfies
   context, object generation, state, lifetime, ordering, deployment, and
   acquisition conditions together.
5. Treats login, cache priming, ownership transfer, worker reuse, allocation,
   release, reallocation, and victim reads as bounded, history-preserving state
   sequences.
6. Launches independent research routes and prevents one approach family from
   consuming all worker capacity.
7. Promotes leads through observation, source-supported mechanism, runtime
   differential, verified primitive, compatible chain edge, and complete
   terminal. Per-mechanism work limits and evidence expiry keep the active
   frontier bounded.
8. Rebuilds a versioned campaign-wide capability graph and assigns its
   highest-value missing-link experiment by boundary relevance, uncertainty,
   shared usefulness, and measured cost.
9. Tests promising chains against supported release or production-equivalent
   builds in an owned environment.
10. Feeds coverage plateaus, invariant observations, and minimized stack
   clusters back into the next harness, grammar, or replay decision.
11. Requires coordinator-signed experiments, recomputed raw observations, an
   enforcing negative control, and fresh-process adversarial replay.
12. Produces a report package only when the complete Critical/RCE impact is
   demonstrated.

When a route fails, Krineon records the enforcing mechanism and creates a new
task only when the source supports a different bypass or composition. It does
not turn a crash, static-analysis match, or incomplete primitive into a finding.

## Research coverage

Krineon includes focused support for these targets and techniques:

- General source-code and dependency audits
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

Static tools generate hypotheses. Runtime evidence decides whether a candidate
advances. Executable semantic models cover the Next.js
authorization-to-route-execution boundary and workerd native lifetime
boundaries; other entries in this list are execution adapters and analysis
aids.

## Finding requirements

Krineon promotes a finding only when the retained evidence proves all of these
conditions:

- The tested source and runtime artifacts are pinned and hashed.
- An attacker controls the input at the real ingress.
- Every conditional between ingress and impact has a concrete, verified
  outcome.
- The chain runs against a supported release or production-equivalent build.
- The proof uses a harmless real terminal instead of a synthetic callback.
- The result does not depend on an application-authored unsafe sink.
- The positive case differs from the negative control only in the disputed
  condition.
- A different agent reproduces the result from the retained artifacts.
- The reviewer challenges both a hypothesis assumption and a possible observer
  failure using a different machine-checked assertion.
- The report states every deployment and attacker precondition.

Development servers, debug-only behavior, prose-only reasoning, and manually
asserted success values cannot pass the reportable gate.

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
- [Research methodology](references/methodology.md)
- [Critical/RCE promotion contract](references/critical-rce.md)
- [Orchestration and independent replay](references/orchestration.md)
- [Evidence gates](references/evidence-gates.md)
- [Semantic hypothesis experiments](references/semantic-experiments.md)
- [Semantic intermediate representation](references/semantic-ir.md)
- [Runtime feedback loop](references/runtime-feedback.md)
- [Execution-boundary and typed chain reasoning](references/chain-reasoning.md)
- [Held-out multi-stage evaluation](references/multistage-evaluation.md)
- [Chrome and V8 campaigns](references/chrome-v8.md)
- [workerd native lifetime research](references/workerd-native.md)
- [Safety rules](references/safety.md)
