# Krineon

Krineon coordinates authorized source and web application research that
searches for complete Critical vulnerabilities, remote code execution (RCE),
sandbox escapes, zero-days, and independently reproduced application security
invariant violations.

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
- PyYAML for strict `krineon-web` Markdown metadata parsing
- Codex, OpenCode, or OMP (Oh My Pi)
- The target source code or a repository URL
- A disposable local environment for dynamic testing, when needed

Krineon works best with Codex and GPT-5.6 Sol at `max` reasoning effort.
Program rules and scope intake are optional for source-only campaigns. A
`web-app` campaign requires a versioned application contract and remains
offline until authorization is explicitly confirmed.

## Start a web application campaign

Give Codex the program rules, an explicitly authorized application URL or web
contract, and secret references for owned identities. Do not paste credential
values into the prompt or campaign files. Start with this prompt:

```text
$krineon Create a web-app campaign from PROGRAM_RULES.md and the explicitly
authorized URL and owned identity references I supplied. Keep authorization
unconfirmed until the exact origins, paths, methods, rules date, environment
owner, expiration, effects, cleanup, and budgets are recorded. Produce an
offline plan first. Use signed workflows and the controlled broker for any
approved traffic. Do not test denial of service, perform infrastructure
reconnaissance, evade protections, or access third-party data.
```

## Test a web application

Use this workflow only for an application, accounts, tenants, and data that you
own or are explicitly authorized to test. Begin with two owned identities when
the application supports authorization or tenant-isolation testing. Create
disposable records for each identity and record the expected owner and allowed
actions before testing a cross-identity case.

The command-line workflow is fail-closed:

```bash
# Offline intake. This sends no target requests.
python3 scripts/campaign_bootstrap.py campaigns/web-demo \
  --profile web-app \
  --url https://app.example.test \
  --guidelines PROGRAM_RULES.md \
  --requests WEB_REQUESTS.md

# Store an owned credential by reference. This argument is the environment
# variable name, not the credential value.
python3 scripts/web_secret_store.py /private/path/krineon-secrets \
  --forbidden-root campaigns/web-demo \
  --put-reference secret://owned-user \
  --kind bearer \
  --env KRINEON_OWNED_USER_TOKEN

# Generate, complete, and apply the offline authorization review.
python3 scripts/web_contract.py prepare-review \
  campaigns/web-demo/web-campaign.json \
  --output campaigns/web-demo/web/authorization-review.json
python3 scripts/web_contract.py authorize campaigns/web-demo \
  campaigns/web-demo/web-campaign.json \
  campaigns/web-demo/web/authorization-review.json
```

Before authorization, inspect `web-campaign.json` and the redacted inputs under
`web/inputs/`. Record the exact origins, path prefixes, methods, identities,
tenants, effects, request limits, cleanup reserve, and stop conditions. The
secret store also supports a no-echo prompt or a regular, non-symlink secret
file with mode `0600`. The authorization is signed and bound to the exact
contract and retained rules hashes. Any later contract edit invalidates it.

Create one falsifiable experiment. Start from the workflow template, then
replace every placeholder. Include at least two competing explanations, change
one variable, bind every step to an owned resource, add executable controls and
oracles, and define cleanup for every write:

```bash
cp assets/web-workflow.template.json \
  campaigns/web-demo/web/approved-workflow.json

# Edit approved-workflow.json before continuing.
python3 scripts/web_workflow.py validate campaigns/web-demo \
  campaigns/web-demo/web-campaign.json \
  campaigns/web-demo/web/approved-workflow.json
python3 scripts/web_workflow.py approve campaigns/web-demo \
  campaigns/web-demo/web-campaign.json \
  campaigns/web-demo/web/approved-workflow.json
```

Run HTTP-only workflows through the controlled broker. It rechecks the signed
workflow, injects credentials at dispatch, enforces the shared budget, and
retains public and restricted evidence separately:

```bash
python3 scripts/web_execution_broker.py campaigns/web-demo \
  campaigns/web-demo/web-campaign.json \
  campaigns/web-demo/web/approved-workflow.json \
  --secret-store /private/path/krineon-secrets \
  --output campaigns/web-demo/evidence/web/http-run-01
```

Use real Chromium for browser-only behavior. Select one browser step from the
same signed workflow and use a fresh profile managed by the runner:

```bash
python3 scripts/web_cdp_runner.py campaigns/web-demo \
  campaigns/web-demo/web-campaign.json \
  campaigns/web-demo/web/approved-workflow.json \
  --step browser-step-id \
  --chromium /path/to/chrome-or-chromium \
  --secret-store /private/path/krineon-secrets \
  --output campaigns/web-demo/evidence/web/browser-run-01
```

Review the positive case, legitimate baseline, and enforcing negative control.
Treat missing telemetry, authentication ambiguity, bot challenges, deployment
drift, or cleanup failure as inconclusive. Do not promote a status-code-only
anomaly. A valid result must show the prohibited server-visible effect through
an authoritative readback.

Finally, rebuild the disposable fixtures and replay the minimized workflow
with a fresh reviewer identity and fresh credential bindings. Multi-step
business-logic findings must pass `web_sequence_evidence.py` with disjoint
machine evidence before promotion. HTTP and Chromium execution remain separate
explicit commands. Nuclei is an optional credential-free broker-replay adapter,
not part of default discovery. See the complete
[web application workflow](references/web-app.md).

Krineon can retain Markdown HTTP requests, HAR 1.2 files, Burp XML exports,
individual raw requests saved from Burp Repeater or Proxy, deployment notes,
and optional source as inputs. HTTP sequences and
typed invariant oracles are operational. The application-aware HTTP/1.1 broker,
byte-exact raw HTTP/1.1 transport, separate HTTP/2 adapter, and real
Chromium/CDP scenario harness share one atomic, revocable campaign budget.
Chromium child processes remain restricted to approved environments with
proved egress confinement. Nuclei never receives a target URL or credential:
the broker acquires an approved response, removes credentials, and exposes a
bounded loopback replay to a pinned, sandboxed Nuclei binary. Optional ffuf
support compiles small source-derived candidate lists; the broker, not ffuf,
dispatches them. Neither tool is required by business-logic research. See
[web application campaigns](references/web-app.md).

The web profile uses `scripts/web_hypothesis_loop.py` and
`scripts/web_oracles.py` to keep observed mechanisms, typed experiments,
three-valued outcomes, and exact scoped negatives in Krineon's shared durable
frontier.

Web chains use typed capabilities instead of free-form labels. Each capability
binds the actor and session, tenant, owned resource and owner, operation and
scope, lifetime and invalidation, provider and consumer process/origin/cache,
deployment epoch, prerequisites, measured effect, and evidence confidence.
Explicit context transitions are required; a matching capability name cannot
transfer authority across accounts, deployments, origins, or workflow states.

Business-logic campaigns additionally use `scripts/web_business_logic.py`,
`scripts/web_sequence_planner.py`, `scripts/web_composition_search.py`,
`scripts/web_sequence_executor.py`, `scripts/web_sequence_evidence.py`, and
`scripts/web_state_oracles.py`. They
compile explicit application rules into owned-fixture, multi-actor workflows;
search backward from one forbidden terminal instead of permuting captured
requests; execute only coordinator-signed operation contracts; and decide from
authoritative server or browser-network readback. Nuclei and single-request
identifier substitution provide leads but do not replace workflow discovery. See [web application
campaigns](references/web-app.md#business-logic-and-authorization-sequences).

Cache and representation-boundary campaigns use
`scripts/web_cache_research.py`, `scripts/web_deserialization_research.py`, and
`scripts/web_boundary_adapters.py`. These tools admit bounded experiments and
evaluate retained evidence. They do not provide a generic exploit mode or
perform target traffic. Cache claims require independent victim reuse and
proved shared-cache provenance. Deserialization claims require an observed
ingress, attacker acquisition, enforcing controls, and an owned nonpersistent
security effect. See [cache and deserialization research](references/web-app.md#cache-and-deserialization-research).

Before promotion, `scripts/web_evidence.py` validates the external deployment
epoch and `scripts/web_finding_gate.py` binds that evidence to the authorized
recipe, owned fixtures, semantic controls, independently observed effect,
cleanup, fresh replay, and reviewed artifact tiers. Black-box evidence can
prove an external authority violation without claiming an internal source root
cause. A changed stable deployment baseline expires the experiment. Krineon
keeps raw credentials in restricted private evidence, rejects leaks from the
reviewer package, and never publishes or submits a finding automatically.

The trusted importer preserves ordered headers, query order, request bodies,
and separate exact and semantic representations. It treats Markdown prose and
capture annotations as inert context. HAR and Burp captures require a reviewed
contract identity when they contain credentials. Literal bearer tokens,
cookies, and API keys move into a private secret store outside the campaign.
The importer writes separate redacted HAR, XML, or raw-request evidence, drops captured
responses, and never overwrites the researcher's original file. Workers see
only inert redacted request bundles. OpenAPI intake remains deferred and fails
closed instead of copying potentially credential-bearing input.

For evaluation, the coordinator can commit to an oracle set held outside the
campaign before any test runs. Krineon then scores only signed broker
observations against those hidden expected outcomes. The result reports exact
matches, rejected evidence, precision, and recall; it does not let workers
rewrite the answers after observing the target.

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
12. Produces a source-audit report package only when complete Critical/RCE
    impact is demonstrated. The separate web profile uses program-defined High
    or Critical impact and application-specific invariant gates.

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
- Real-Chromium session discovery with browser-generated request context
- Offline identity, resource, lifecycle, and trust-representation mapping
- Business-rule coverage by actor, resource, action, and state

For web campaigns, API extraction is a required discovery stage. First use a
legitimate real-Chromium journey to create
`client-artifact-manifest.json`. The manifest contains only artifacts Chrome
loaded from admitted origins and records referenced source maps without
probing them.
Then extract static and runtime operations and build the measured catalog:

```bash
scripts/web_js_api_extract.py \
  BROWSER_OUTPUT/client-artifact-manifest.json \
  --artifact-root BROWSER_OUTPUT \
  --output API_EXTRACTION.json
scripts/web_endpoint_catalog.py API_EXTRACTION.json \
  --output ENDPOINT_CATALOG.json
```

Literal URL strings remain hints. Bounded AST results remain source-supported
candidates. Only Chrome observations or independent replay raise confidence.
The catalog never claims to contain all APIs and does not authorize dispatch.
It reports unavailable chunks, source-map coverage, role differences,
unresolved expressions, blocked effects, and the next legitimate journey.

Map the catalog and other observed application behavior before creating broad
experiments:

```bash
scripts/web_surface_map.py --request-bundle REQUEST_BUNDLE.json \
  --browser-observation BROWSER_OBSERVATION.json \
  --endpoint-catalog ENDPOINT_CATALOG.json \
  --output SURFACE_MAP.json
scripts/web_workflow_model.py SURFACE_MAP.json --output WORKFLOW_MODEL.json
```

The browser runner uses real Chromium CDP and fresh profiles. Raw HTTP remains
an explicitly labelled client replay; it cannot impersonate Chrome by copying
User-Agent, client hints, or Fetch Metadata. Bot challenges pause the campaign
as environment-blocked rather than becoming a vulnerability or safe result.

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
