# Krineon

Krineon coordinates authorized, multi-agent source audits that search for
Critical vulnerabilities, remote code execution (RCE), sandbox escapes, and
zero-days.

Krineon analyzes one pinned source tree from first principles. It does not use
changelogs, advisories, Git history, or patched-version comparisons to discover
bugs. It retains partial primitives as research leads, but it promotes a
finding only after a production-equivalent proof and independent replay.

## Requirements

Install or provide the following components:

- Git
- Python 3
- Codex or OMP (Oh My Pi)
- The target source code or program scope
- The program rules and authorization boundary
- A disposable local environment for dynamic testing

Krineon works best with Codex and GPT-5.6 Sol at `max` reasoning effort.
Optional tools such as Tree-sitter, Joern, Trailmark, Z3, AFL++, libFuzzer, and
Fuzzilli improve coverage. Krineon detects available tools and does not install
them automatically.

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

## What Krineon does

Krineon runs the following campaign:

1. Records the authorization boundary and pins the source, runtime, build, and
   deployed artifact.
2. Maps attacker-controlled inputs, trust boundaries, state ownership,
   representation changes, native parsers, and execution authority.
3. Launches independent research routes and prevents one approach family from
   consuming all worker capacity.
4. Tracks blockers, primitives, negative results, and possible cross-library
   chains in a durable campaign registry.
5. Tests promising chains against supported release or production-equivalent
   builds in an owned environment.
6. Requires a baseline, an enforcing negative control, a positive case, and
   fresh-process independent replay.
7. Produces a report package only when the complete Critical/RCE impact is
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
- Tree-sitter, Joern, Trailmark, and Z3 assisted analysis
- AFL++, libFuzzer, and Fuzzilli campaigns
- V8, Istanbul, and source-map-aware JavaScript coverage
- First-fault crash clustering, minimization, and bounded replay

Static tools generate hypotheses. Runtime evidence decides whether a candidate
advances.

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
- [Research methodology](references/methodology.md)
- [Critical/RCE promotion contract](references/critical-rce.md)
- [Orchestration and independent replay](references/orchestration.md)
- [Evidence gates](references/evidence-gates.md)
- [Chrome and V8 campaigns](references/chrome-v8.md)
- [Safety rules](references/safety.md)
