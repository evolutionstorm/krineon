# Web application campaigns

Use the `web-app` profile only for an application and environment that the
researcher is explicitly authorized to test. A URL, credential, request
capture, public bug-bounty page, or scanner configuration does not establish
that authority.

## Client runtime ownership

Read the active client adapter before creating tasks:

- `opencode.md` for OpenCode;
- `omp.md` for OMP; or
- `codex.md` for Codex.

The top-level client session remains the coordinator. It owns literal
credentials, authenticated browser state, private Burp arguments, signatures,
the shared budget, cleanup, target dispatch, and coordinator replay. Workers
receive redacted evidence and propose experiments. A child tool permission,
inherited MCP connection, or browser tool does not expand the web contract.

## Intake contract

The campaign authority is `web-campaign.json` (schema version 2). It records:

- exact origins, purposes, path ranges, exclusions, and methods;
- owner-approved identities, roles, tenants, sessions, and credential origins;
- secret references, never credential values;
- per-action request and response limits;
- shared request, byte, rate, concurrency, wall-clock, and cleanup budgets;
- shared response-decompression, redirect, WebSocket-frame, browser-event, and
  retained-storage budgets;
- read-only, disposable-write, sensitive, external-side-effect, and unknown
  effect policies;
- separate approval switches for redirects, browser navigation, WebSockets,
  uploads, state changes, cache mutation, bounded concurrency, callbacks,
  Nuclei, terminal execution, and credential refresh;
- program rules, rules date, environment owner, expiration, researcher
  headers, owned resource namespace, and stop conditions; and
- whether the campaign is first-principles or an explicit known-issue
  baseline.

`authorization.confirmed: false` permits offline planning only. The contract
validator permanently denies denial of service, resource
exhaustion, third-party data, real fund movement, persistence, uncontrolled
command execution, port scanning, host discovery, and bot-evasion effects.
Generated work cannot override these exclusions.

`authorization.ownedFullTesting.enabled: true` is the standing-authorization
mode for a retained program-rules file plus verified researcher-owned account
manifest. It enables all exact-origin methods and bounded operation classes
admitted by the contract. The coordinator automatically signs compatible
workflows and does not return to the user for each verb, lane, or fixture.
Permanent denials, target budgets, owned-resource bindings, cleanup, stop
conditions, and evidence gates remain enforced. External callbacks and HTTP
desynchronization remain unavailable unless their required exact callback or
isolated-topology authorization is present in the account manifest.

## Operational intake and approval

Bootstrap creates an unconfirmed contract, imports requests through the
trusted redaction boundary, and writes `web/offline-plan.json`. It performs
zero target requests:

```bash
python3 scripts/campaign_bootstrap.py campaigns/web-demo \
  --profile web-app \
  --url https://app.example.test \
  --guidelines PROGRAM_RULES.md \
  --requests WEB_REQUESTS.md
```

Use only an opaque `secret://` reference in the contract. Resolve its value
outside the campaign with a no-echo prompt, the name of an environment
variable, or an owner-restricted non-symlink file. This example passes the
variable name, not its value:

```bash
python3 scripts/web_secret_store.py /private/path/krineon-secrets \
  --forbidden-root campaigns/web-demo \
  --put-reference secret://owned-user \
  --kind bearer \
  --env KRINEON_OWNED_USER_TOKEN
```

Generate a review after intake. The generated file contains the exact contract
and program-rules hashes. A coordinator fills the reviewer, rules date,
authorization expiry, environment owner, fixture namespace, and sets each
check only after reviewing it:

```bash
python3 scripts/web_contract.py prepare-review \
  campaigns/web-demo/web-campaign.json \
  --output campaigns/web-demo/web/authorization-review.json
python3 scripts/web_contract.py authorize campaigns/web-demo \
  campaigns/web-demo/web-campaign.json \
  campaigns/web-demo/web/authorization-review.json
```

Authorization creates a signed record and executes no target traffic. Changing
the contract invalidates that record. The coordinator then validates and signs
the exact bounded workflow separately:

```bash
python3 scripts/web_workflow.py approve campaigns/web-demo \
  campaigns/web-demo/web-campaign.json \
  campaigns/web-demo/web/approved-workflow.json
```

Only the approved HTTP broker or real-Chromium CDP runner may execute the
workflow. Both recheck authorization, the signed workflow, identity bindings,
and the shared budget before dispatch. Nuclei remains separately selected and
limited to credential-free loopback replay. A surviving minimal sequence needs
a fresh reviewer identity, fresh credential bindings, rebuilt owned fixtures,
and full independent replay through `web_sequence_evidence.py`.

For an owned full-test campaign, retain a manifest based on
`assets/web-owned-accounts.template.json` inside the campaign and activate it
with `web_contract.py activate-owned-testing`. The manifest contains only
`secret://` references and reviewed ownership evidence, never password, cookie,
token, or API-key values. Bootstrap performs this activation automatically when
`--owned-accounts` is supplied with program guidelines and an exact web origin.
Once activated, the coordinator dispatches bounded experiments without another
user prompt and re-plans any lane that was previously planning-only.

An identity with `credentialRef: secret://user-a` must list the exact origin
IDs that may receive that credential. At execution time, the broker resolves
the reference from `KRINEON_SECRET_USER_A`. It does not copy credential values
into campaign, workflow, observation, or private request evidence.

Authenticated identities also declare a credential type, exact path ranges,
permitted HTTP or browser transports, expiry, and reviewed verification
evidence. Verification must come from an owner assertion, a reviewed low-impact
endpoint, or an interactive browser checkpoint. A role label or unsigned JWT
claim is not verification. Missing evidence, expiry, MFA, ambiguous login
state, or a session mutation produces `auth-inconclusive`; it is not evidence
of an authorization defect.

## Request import

The trusted importer accepts URL-only discovery or a Markdown bundle containing
one `yaml krineon-web` block and named `http` or `http2` fences. Metadata binds
every stable request ID to its identity, workflow, origin, purpose, effect,
owned resource, dependencies, and expected rule. Duplicate metadata keys,
ambiguous identities, undeclared hosts, and conflicting absolute URL and Host
authority fail intake.

Each imported request retains two records:

- an exact replay representation with ordered duplicate headers, raw request
  line, body bytes, and HTTP/2 pseudo-headers; and
- a semantic representation with method, path, ordered query fields, headers,
  body, resource, and action policy.

Neither representation silently replaces the other. A Markdown request that
did not preserve CRLF or binary encoding is marked non-byte-exact. Binary bodies
may use base64 metadata or a regular file under the request bundle's
`sidecars/` directory. Signed fields are immutable until an explicitly approved
re-signing adapter exists.

Markdown prose is inert and cannot authorize traffic, change exclusions, load
tools, or create tasks. Imported bundles are also inert until the coordinator
creates and signs a complete workflow. URL-only intake requires already
confirmed authorization. Multiple requests under one identity do not count as
cross-user coverage.

If the original contains a literal bearer token, cookie, or API key, the
trusted importer moves it to an explicitly supplied private secret store
outside the campaign and writes a separate redacted copy. It never overwrites
the original. Model-visible workspaces receive only the redacted Markdown and
inert bundle. The private store uses opaque secret versions and keyed
fingerprints; plain token hashes are not published. Same-UID processes are not
a confidentiality boundary, so worker isolation remains required.

HAR 1.2, Burp XML exports, and individual raw HTTP requests saved from Burp
Repeater or Proxy pass through the same trusted import boundary. Bootstrap
accepts the latter through `--burp-request`. Select the reviewed contract
identity and effect class for the capture. The importer
extracts recognized literal credentials to the private store, emits a separate
redacted HAR or XML copy, drops responses and descriptive fields, and produces
an inert request bundle. HAR is always marked non-byte-exact because it does
not retain a wire request. Base64 Burp HTTP/1.x requests and raw request files
retain exact redacted wire bytes; credential replacement is recorded as
non-byte-exact relative to the original. For origin-form request targets, the
`Host` header must select one exact authorized origin. Burp XML DTDs and
entities fail closed. OpenAPI intake remains deferred.

When the active Codex, OpenCode, or OMP session already exposes Burp Suite MCP,
follow [Burp Suite MCP](burp-mcp.md). The agent client owns the connection;
Krineon registers the advertised schemas and binds each admitted call to this
same contract and process-shared budget. MCP history and responses remain
untrusted intake and do not bypass workflow approval or independent replay.

## Workflow contract

Workers may import annotated Markdown requests, redacted HAR files, redacted
Burp exports, deployment notes, and optional source locations. An
import is evidence input, not approval. Imported Markdown becomes an unsigned,
incomplete workflow and cannot execute until the coordinator adds:

- at least two competing explanations;
- one changed variable;
- typed resources with expected owners;
- selected resources, permitted actions, observation origin, cache layer, and
  execution context;
- a maximum effect, bounded input, action count, timeout, cleanup plan, and a
  no-automatic-retry rule for every step;
- exact identity and session labels;
- executable baseline, enforcing-negative, and positive assertions;
- explicit required telemetry; and
- cleanup steps for every disposable write.

The coordinator validates the exact contract and signs the completed workflow.
Any later edit invalidates the signature.

## Adaptive hypothesis loop

`web_hypothesis_loop.py` converts observed behavior into ranked, falsifiable
experiments in the shared semantic IR, capability graph, and durable experiment
frontier. It does not create a second scheduler. Each experiment records the
invariant and its basis, attacker authority, owned fixtures and exact state,
competing explanations, causal variable or enumerated interaction, bounded
sequence, three control cases, observations, cleanup, replay prerequisites,
exact scope, and reopening conditions.

Derive the stable prerequisite version before signing a workflow:

```bash
scripts/web_hypothesis_loop.py derive-version CAMPAIGN HYPOTHESES.json
```

The version uses only reviewed deployment identity, workflow contract,
transport configuration, identity-capability version, and resource-fixture
version. It excludes credentials and does not change merely because a graph
score changes. Add that version to the signed workflow and typed oracle, then
admit the hypotheses:

```bash
scripts/web_hypothesis_loop.py plan CAMPAIGN HYPOTHESES.json
```

Candidates without a typed executable oracle remain visible in the planning
frontier. Executable contracts bind a registered runner, signed workflow,
actor and resource fixtures, `secret://` references, per-operation and shared
budgets, machine assertion, cleanup, evidence outputs, and independent replay.
They cannot select an arbitrary executable path.

Run the current HTTP experiment through the fixed controlled broker:

```bash
scripts/web_hypothesis_loop.py execute \
  CAMPAIGN FRONTIER_ID CAMPAIGN/evidence/web/EXPERIMENT_RUN
```

The result is one of `confirmed-disagreement`, `observed-preservation`, or
`inconclusive`. Authentication expiry, deployment drift, missing telemetry,
challenge blocking, inaccessible business state, and cleanup failure are
inconclusive. Preservation creates negative knowledge only for the exact
input, configuration, state, mechanism, and prerequisite version. After any
result, an unchanged graph can advance to the next eligible experiment.

## Controlled execution

The HTTP broker executes signed workflows sequentially. `web_policy.py`
validates the raw and normalized paths, exact origin, method, reviewed effect,
identity, and operation before dispatch. It resolves DNS immediately before
connection, connects only to a reviewed address, re-resolves and verifies the
peer, and keeps SNI and Host authority bound to the exact origin. Legitimate
CDN rotation remains possible inside the reviewed address policy. Redirects,
discovered origins, callbacks, and storage hosts remain candidates until the
contract independently admits them.

`web_budget.py` stores request, action, byte, evidence-storage, browser-event,
WebSocket, rate, concurrency, and lease state in one SQLite database shared by
processes. Reservations use atomic transactions. Pause, cancellation, wall
expiry, and lease expiry revoke outstanding dispatch capabilities. Adapters
poll cancellation and close their transport. A pause is never automatically
resumed.

The HTTP broker owns authentication
headers, cookies, request lengths, redirect behavior, timeouts, response-size
limits, redaction, cleanup, and one campaign-wide execution lease. All runs and
adapters share the atomic budget. The broker stores raw response material
only in permission-restricted private evidence; the signed observation contains
hashes, typed identities and resources, status, size, timing, and approved JSON
extractions.

Bearer and API-key headers are injected immediately before an admitted HTTP
request. Cookies, CSRF state, browser storage, and extracted variables remain
separate for each identity and session. Credential origins, paths, transports,
and expiry are checked again at dispatch. Browser credentials are applied only
to an admitted paused request or exact-origin cookie; Krineon never installs a
browser-global Authorization header. Redirects or origin changes lose
credentials unless a separately reviewed contract path admits them.

Credential refresh, OAuth refresh, and CSRF handling are separate operation
classes and authorization switches. They use a per-identity lease so workers
cannot rotate or invalidate one session concurrently. Request signing also has
a separate switch, but execution remains blocked until a reviewed
protocol-specific adapter exists; Krineon never falls back to a generic shell
hook. Generic shell-based login, MFA bypass, and personal browser profiles are
unsupported.

The oracle evaluator has three outcomes:

- `confirmed-invariant-disagreement` when both controls pass and secure
  behavior fails;
- `observed-invariant-preservation` when controls and secure behavior pass; or
- an inconclusive outcome when telemetry is missing or a control fails.

An anomalous status, page, timing, scanner match, screenshot, redirect,
reflected marker, or browser event is not a finding by itself. Oracles can
require an authenticated actor, tenant, object owner, selected resource,
permitted action, authoritative before-and-after state reads, business totals,
canary context, callback correlation, and browser security context. A
status-only positive assertion is rejected as insufficient evidence.

Extracted resource IDs, CSRF tokens, nonces, ETags, job IDs, pagination
cursors, and expiry values are bound to their producer request, identity,
tenant, origin, resource, and lifetime. Availability never makes an extracted
value transferable across tenants.

The browser scenario harness launches a separate fresh sandbox-enabled process
and profile for each attacker, victim, reviewer, headed, or headless run. It
records the pinned binary hash, browser and protocol versions, platform, flags,
negotiated CDP capabilities, network and Fetch events, target relationships,
DOM and accessibility hashes, console exceptions, bounded screenshots,
storage discovery, and service workers. It installs scope interception before
navigation and auto-attaches to new targets before resuming them. It never
attaches to a personal browser. Remote navigation remains blocked unless the
signed campaign selects `os-enforced-broker-only` containment, an explicit
loopback proxy, admitted origins, and retained evidence that direct egress and
out-of-broker DNS are blocked. Chrome then removes the implicit loopback bypass
and sends all target traffic through that broker while CDP independently
intercepts every request. A proxy, copied browser headers, or CDP interception
alone is insufficient. Loopback-owned application fixtures have real-Chromium
acceptance coverage; fake-CDP coverage is not treated as sufficient.

Browser steps may contain declarative `click`, `fill`, `select`, and
`wait-for-selector` actions. They cannot contain JavaScript. Fill and select
values are bounded literals or private `secret://` references. Every expected
network request names its exact origin, path prefix, method, effect class, and
maximum count in the signed workflow. Undeclared mutation is blocked, and a
declared request that never occurs fails the experiment. Disposable writes
still require a compensating cleanup step.

Use real Chromium CDP as the default browser-session and browser-only behavior
observer. Chrome generates its own User-Agent, client hints, Fetch Metadata,
Origin/Referer, cookies, navigation headers, TLS, and protocol behavior. A
copied User-Agent or copied browser headers are not a browser fingerprint and
must not be described as browser-equivalent.

Raw HTTP workflows are recorded as `http-client-replay`. They may retain
content negotiation, CSRF, signing, Origin, or Referer fields only from the
same owned browser session. Origin, Referer, CSRF, and request-signature fields
require a `headerContext` with the signed source observation and preserved
header names. User-Agent,
`Sec-CH-UA-*`, and `Sec-Fetch-*` impersonation is rejected. Every intentional
header change names its reason and control step.

When a challenge or interstitial is observed, including an HTTP 200 challenge
page, the broker records `environment-blocked`, pauses the shared budget, and
does not evaluate security oracles. Login or expired-session responses are
`auth-inconclusive`. Resume only with a new reviewed contract that records an
owner-approved staging environment, test-account policy, source-IP allowlist,
or researcher access path and a revalidated baseline. Researcher headers only
identify traffic. CAPTCHA solving, stealth plugins, rotating proxies,
challenge-token harvesting, and TLS or fingerprint impersonation are
prohibited.

The raw protocol harness can use the broker-backed transport while preserving
exact HTTP/1.1 bytes. It records that fidelity explicitly. HTTP/2 uses
`web_http2_adapter.py`, requires ALPN `h2`, and never silently downgrades or
merges HTTP/1.1 and HTTP/2 observations.

## Optional Nuclei and ffuf adapters

Nuclei is an optional response-analysis tool. Business-logic, authorization,
cache, and workflow research cannot depend on it. `nuclei_template_policy.py`
parses the complete YAML document, recursively expands reviewed local workflow
references, verifies content and expansion hashes, and calculates the request
bound. Tags, severity, signatures, and upstream ignore lists are not safety
evidence.

The first adapter admits only reviewed HTTP `GET`, `HEAD`, and `OPTIONS`
checks. It denies headless, JavaScript, code, file, network, DNS, WebSocket,
payload, race, fuzzing, flow, local-file, environment, external callback,
Interactsh, redirect, cookie-reuse, credential-header, unbounded expansion,
and state-changing behavior. Each manifest entry binds an origin ID, path
prefix, method, request and byte bounds, effect, and owned fixture namespace.
Agent-generated templates require a different reviewer and a successful owned
fixture run. First-principles profiles admit only generic invariants and
target-derived templates. CVE and public PoC templates require the separate
`known-issue-baseline` track and retain a known-issue or possible-duplicate
label.

`nuclei_adapter.py` probes the pinned binary's actual help and version output.
The run profile pins those outputs, the executable hash, manifest hash,
template commit, selected template hashes, and effective configuration. The
runner uses an empty private home and config directory and requires a
hash-pinned coordinator sandbox with retained loopback and denied-egress
evidence. Updates, downloads, cloud upload, AI generation, issue creation,
discovery integrations, OAST, redirects, retries, and ambient configuration
remain disabled.

Nuclei never receives the production target or credentials. The normal broker
uses the approved identity, charges the target request to the shared budget,
and creates a signed credential-free response fixture. Nuclei can connect only
to the ephemeral loopback replay. The replay enforces origin, route, namespace,
response-size, and runtime request-count bounds and records both broker and
loopback accounting. The deprecated `web_nuclei_adapter.py` command refuses
direct execution so it cannot bypass this path.

Scanner JSONL is size-bounded and sanitized before retention. Full requests,
responses, extracted values, credentials, and interaction data do not enter
the public observation. Retain the effective command, engine and template
provenance, admitted and rejected IDs, hashes, and redacted observations. A
match is only an observation. Replay every match through Krineon's HTTP broker
or CDP runner with an independent identity and application oracle before
promotion. A `critical` scanner label does not determine severity, and a
negative scan does not refute an application mechanism.

`ffuf_adapter.py` does not send traffic. It compiles a small list of concrete
candidates derived from observed client paths, route conventions, API schemas,
sibling operations, or unresolved symbolic segments. Each candidate retains
its rationale and evidence. Preflight includes candidates, retries, redirects,
calibration, and total requests. Recursion and automatic calibration are off
unless a reviewed exact bound permits calibration. The broker preserves the
legitimate request context and identity and stops on challenges or rate limits;
it does not alter fingerprints to evade protection. Imported results are
endpoint observations with soft-404, wildcard, login-shell, WAF, and content-
negotiation confounders. They require semantic workflow replay and never become
findings directly. Stop expanding when endpoint or workflow coverage no longer
improves.

## Required client API extraction

Run a legitimate real-Chromium journey for every available approved role and
tenant. The browser output includes `client-artifact-manifest.json` with the
scripts, modules, workers, service workers, and client manifests that Chrome
loaded from admitted origins. Artifacts are content-addressed and tied to one
deployment epoch. Referenced source maps are recorded but are not fetched
automatically.

```bash
scripts/web_js_api_extract.py \
  CAMPAIGN/evidence/web/browser/client-artifact-manifest.json \
  --artifact-root CAMPAIGN/evidence/web/browser \
  --output CAMPAIGN/web/api-extraction.json

scripts/web_endpoint_catalog.py CAMPAIGN/web/api-extraction.json \
  --output CAMPAIGN/web/endpoint-catalog.json
```

The extractor never evaluates bundle code. It combines literal hints, a
bounded call/expression AST, function- and block-scoped bindings, framework
module and call facts, source-map mapping, symbolic dynamic values, and CDP
initiator evidence. Reused local variable names do not leak across functions.
An unresolved overwrite remains unresolved instead of reviving an older value.
GraphQL operation names and JSON-RPC methods are extracted from request bodies,
so two operations using the same path and method remain distinct. Unknown calls
do not become endpoints. Query values and credential values do not enter the
model-visible catalog.

The catalog deduplicates by operation, not path alone, and keeps method,
GraphQL operation or persisted hash, RPC action, content type, actor, tenant,
and deployment epoch distinct. It records role differences, unavailable
chunks, unresolved expressions, blocked effects, coverage gaps, and the next
approved journey. A candidate remains non-dispatchable until its effect and
scope have been reviewed.

## Application behavior inventory

Build the offline surface and workflow models before broad dynamic testing:

```bash
scripts/web_surface_map.py \
  --request-bundle CAMPAIGN/web/request-bundle.json \
  --browser-observation CAMPAIGN/evidence/web/browser/browser-observation.json \
  --html OWNED_FIXTURE/index.html \
  --javascript OWNED_FIXTURE/app.js \
  --api-spec OWNED_FIXTURE/openapi.json \
  --endpoint-catalog CAMPAIGN/web/endpoint-catalog.json \
  --output CAMPAIGN/web/surface-map.json

scripts/web_workflow_model.py CAMPAIGN/web/surface-map.json \
  --output CAMPAIGN/web/workflow-model.json
```

Both commands are offline. API and GraphQL specifications are discovery hints,
not permission to execute every operation. The surface map connects identities,
resources, operations, and representations while retaining `observed`,
`owner-specified`, `source-supported`, or `hypothesized` confidence. The
workflow model records lifecycle prerequisites, invalidations, trust
boundaries, and attempted and unattempted actor × resource × action × state
cells. Ambiguous business rules become unresolved questions, not vulnerability
claims. No active GraphQL introspection, URL brute force, or directory
enumeration is required.

## Cache and deserialization research

Cache research begins with a measured cache layer and one disputed key
dimension. Validate a reviewed experiment, execute its workflow references only
through the controlled broker or CDP runner, and evaluate the retained
observations:

```bash
scripts/web_cache_research.py validate CAMPAIGN/web/cache-experiment.json
scripts/web_cache_research.py evaluate \
  CAMPAIGN/web/cache-experiment.json CAMPAIGN/evidence/web/cache-observations.json \
  --output CAMPAIGN/evidence/web/cache-result.json
```

Record the method, identity, cookies, partition signals, Age, Via, Vary, ETag,
timestamps, and response provenance. These headers corroborate a result; they
do not prove a shared cache key. Live mutation requires an isolated owned key
or exact owner approval for the shared effect. A random path or query marker is
not isolation because the cache may ignore it. Never broadly purge, evict,
target common routes, seek cached errors, or test availability loss.
Do not treat `Cache-Control: no-cache` as a purge or cleanup signal; verify the
owned entry's expiration or removal through the approved cache fixture.

For poisoning, establish a clean owned baseline, prime one bounded attacker
representation with a synthetic canary, and fetch the ordinary representation
through a fresh victim profile. The oracle requires victim reuse from an
application, reverse-proxy, or CDN cache plus an enforcing control and isolated
cleanup. The baseline must precede the prime and contain neither the canary nor
its security-relevant component digest. The evaluator compares named protected
components, not only whole-response hashes, so unrelated wrappers may vary
without hiding or manufacturing the disputed reuse. Browser memory or disk,
Cache API, service-worker state, reflection,
content negotiation, redirects, public content, generic shells, and stale
deployments do not satisfy it. A harmless marker is a primitive; prove RCE,
XSS, account compromise, or cross-tenant impact separately.

For deception, use a private synthetic canary owned by actor A. First prove
canonical authenticated retrieval and anonymous denial. Prime only under the
approved isolation contract, then retrieve the exact candidate as anonymous or
owned actor B in a fresh profile. The oracle requires the private canary itself,
not a page shell or redirect, and retains the causal mismatch between origin
resource identity and cache eligibility or key interpretation.

Deserialization research likewise starts from a real supported ingress and an
owned legitimate value:

```bash
scripts/web_deserialization_research.py validate CAMPAIGN/web/deserialization-experiment.json
scripts/web_deserialization_research.py generate \
  CAMPAIGN/web/deserialization-experiment.json CAMPAIGN/web/owned-baseline.json \
  --output CAMPAIGN/web/deserialization-cases.json
scripts/web_deserialization_research.py evaluate \
  CAMPAIGN/web/deserialization-experiment.json \
  CAMPAIGN/evidence/web/deserialization-observations.json \
  --output CAMPAIGN/evidence/web/deserialization-result.json
```

The generator changes small JSON structures and never evaluates the target
object. Retain the expected representation, integrity boundary, object type,
identity binding, consumer, every attacker-acquired coordinate, dependency and
configuration preconditions, and the invalid-signature control. Treat parsing,
object construction, unsafe type or authority selection, and an owned security
effect as separate evidence levels. Parser errors, stack traces, callbacks, and
rejected signatures are not execution proof. Generic gadget chains, shell
payloads, file writes, external callbacks, crashes, and resource exhaustion are
not default discovery modes.

The target workflow must also use `operationClass:
deserialization-experiment`, and the campaign contract must explicitly enable
`authorization.allowDeserializationExperiments`. HTTP desynchronization
workflows similarly require `operationClass: http-desynchronization` and
`authorization.allowHttpDesynchronization`; the admitted boundary contract is
an additional requirement, not a substitute for campaign authorization.

Use `scripts/web_boundary_adapters.py` to admit other target-specific boundary
experiments after the baseline is measured. Each contract needs an invariant,
at least two competing explanations, restricted effects, disposable fixtures,
an independent oracle, and cleanup. The adapters enforce browser proof for
CSRF and CORS, inert bounded files for upload, an approved owned receiver for
SSRF, identity-separated sessions for authorization, bounded GraphQL and
WebSocket operations, and scoped persistence checks. HTTP desynchronization is
off by default and requires explicit authorization for an isolated topology,
at most two connections, and a fixed byte bound. Raw HTTP support alone is not
permission to test shared transport framing.

## Business logic and authorization sequences

Compile only explicit application rules. A rule must be owner-specified,
source-supported, or established by a reviewed normal workflow. An unusual
response, hidden UI action, Nuclei match, or successful single-request object
substitution is a lead, not proof that a security rule was violated.

```bash
scripts/web_business_logic.py \
  CAMPAIGN/web/workflow-model.json CAMPAIGN/web/business-rules.json \
  --output CAMPAIGN/web/business-logic.json

scripts/web_sequence_planner.py \
  CAMPAIGN/web/approved-workflow.json CAMPAIGN/web/business-logic.json \
  --output CAMPAIGN/web/business-sequence-graph.json

scripts/web_composition_search.py \
  CAMPAIGN/web/business-sequence-graph.json CAMPAIGN/web/forbidden-goal.json \
  --output CAMPAIGN/web/forbidden-composition-frontier.json

scripts/web_sequence_executor.py \
  CAMPAIGN CAMPAIGN/web/forbidden-composition-frontier.json PLAN_ID counterfactual \
  --output CAMPAIGN/evidence/web/BUSINESS_RUN
```

`web_business_logic.py` provides pluggable domain oracles for object and
function authorization, tenant and parent binding, prerequisites, replay,
invalidation, server/client trust, asynchronous jobs, synthetic transaction
integrity, and separately approved bounded concurrency. Every rule binds an
owned fixture factory, independent readback, reversible cleanup hook, and
fixture version. Generic endpoint mutation is not a fixture contract.

`web_sequence_planner.py` builds one multi-actor state graph. Each operation
records the authenticated actor and any effective deputy actor, exact owned
resource and generation, authority binding, prerequisites, produced and
consumed values, invalidations, partial ordering, authoritative observations,
consistency window, cleanup, and cost. It joins steps only through concrete
IDs, tokens, versions, jobs, approvals, or replay-confirmed state transitions.
The position of a request in Markdown is only a sequencing hint.

`web_composition_search.py` does not permute captured requests. Start from the
smallest confirmed legitimate workflow and state its before and after evidence,
policy basis, and fixture epoch. Define one prohibited terminal effect and an
independent owned observer. The planner works backward from the final consumer,
works forward only through operations the attacker can actually attempt, and
joins paths only when the same concrete actor, tenant, resource, version,
generation, relationship, permission version, single-use value, and observation
epoch survive. It retains scoped refutations and incomplete frontiers rather
than treating a failed chain as a safe result.

Backward relevance resolves every typed prerequisite and consumed server value
to all compatible producers. It preserves actor transfer, resource binding,
value kind, version, relationship, and state constraints. A researcher does
not have to place the missing producer in `candidateOperationIds`; that field
can narrow an approved run but cannot make a valid dependency visible.

The initial local benchmark permits at most eight actions, two executions of a
reusable operation, and no concurrency unless the paired-concurrency family is
separately approved. Request count, polling, wall time, state-changing effects,
and frontier size are also explicit. These are bounded starting values, not a
claim that every defect fits eight steps. Continue a deeper search only from a
saved checkpoint whose hash is named by a reviewed budget extension.

The search uses backward relevance, semantic-state dominance, partial-order
reduction, and a resumable frontier. State identity preserves remaining
operation and request budgets, single-use consumption, permission versions,
resource generations, relationships, and security-relevant ordering. A final
response is not the terminal oracle. Re-read the protected state through the
approved independent observer and the signed state oracle.

Use these composition families as research questions, not presumed defects:

| Composition | Discovery question | Required control |
| --- | --- | --- |
| Approval then mutation | Does approval survive a change to the approved resource, recipient, or protected property? | Compare the same unmodified object and evaluate the changed binding against the documented rule. |
| Request then asynchronous consumption | Does a worker recheck authority and job ownership? | Use independent owner and unauthorized completion or readback identities. |
| Grant then revocation | Does a later consumer retain authority after revocation? | Bound propagation and distinguish durable grants from revoked authority. |
| Parent or tenant transition then use | Does a child, export, attachment, or job retain stale authority? | Verify ownership before and after the legitimate transition. |
| Delegated request then privileged deputy | Can attacker state redirect the deputy's resource or action? | Prove attacker influence; never insert deputy credentials to manufacture reachability. |
| Prepare or preview then commit | Does commit enforce the same object, totals, identity, and version? | Include a legitimate unchanged commit and a rejected mismatch control. |
| Invitation or share then lifecycle change | Does consumption enforce recipient, tenant, expiry, and cancellation? | Use only owned recipients and safe delivery. |
| One-time operation then alternate consumer | Can another permitted channel reuse the capability? | Independently read back the once-only effect and consumption state. |
| Independent weak primitives | Do compatible lower-impact observations produce new authority only together? | Show neither primitive alone reaches the terminal. |
| Paired concurrent steps | Can one approved pair violate a sequential invariant? | Use one disposable fixture, fixed attempts, explicit approval, and no load objective. |

Generate one targeted history change: omit one prerequisite, change one actor or
relationship, repeat one reusable operation, delay one consumption, use an
alternate consumer, or run one separately approved pair. Resolve dynamic values
from prior approved steps. Stop on unexpected effects, scope changes, or
ambiguous authentication. After execution, record confirmed transitions, scoped
refutations, unresolved prerequisites, and the highest-value next experiment.
Causal minimization may remove a step only while preserving the prohibited
effect, concrete ownership, timing, authentication, and state history. If a
single operation explains the effect, retain the narrower mechanism.

`web_sequence_executor.py` accepts only operation contracts that exactly match
the coordinator-signed workflow. It uses the fixed HTTP broker or registered
Chrome CDP runner. A DOM change or local planner variable cannot satisfy a
prerequisite. Cross-identity transfer of a job, token, or approval requires
evidence that the application permits that transfer. Invalidated values cannot
be consumed. An omitted prerequisite, stale authority, or replayed one-time
value can be attempted only in the counterfactual history and only when the
signed business rule names that exact reference. Unused exceptions make the
run inconclusive. Unknown consistency, missing readback, failed controls, or
failed cleanup produces `inconclusive`.

## Required sequence evidence and replay

Every forbidden-composition plan stores a `sequenceSpecification`, not merely
captured request order. It binds the sequence and prerequisite version;
verified actors, tenants, disposable fixtures, and initial authority; the
legitimate baseline and invariant basis; an independently observed goal
predicate; signed step guards, resources, partial order, and effect budgets;
value issuer, consumer, expiry, transfer, invalidation, and single-use status;
transition observations; reference expectations; implementation observations;
binding controls; competing explanations; primitive contributions; causal
witness; cleanup; and independent replay policy.

The histories are distinct:

- `legitimate` establishes the permitted workflow and controls;
- `disputed` contains the legitimate controls, minimal attacker sequence, and
  post-effect observer; and
- each `control-*` history removes or restores the exact disputed authority or
  state binding.

A prefix may contain a smaller valid issue. Record that issue separately and
state what each primitive contributes. Do not require every prefix to be
harmless merely to preserve a larger chain claim.

An actor has both a `sessionRefreshVersion` and an application
`permissionVersion`. They are not interchangeable. A reauthentication
operation must name the old and new session versions, preserve the permission
version, and retain evidence that it re-established the starting conditions.
The executor rejects a refresh that restores or changes application
permission.

A produced asynchronous job requires `asyncWait`. The signed operation records
an authoritative state observation, retained poll-attempt count, completion
predicate, maximum polls, and retry or consistency policy. The executor does
not treat a sleep as evidence. An unfinished, inaccessible, over-budget, or
unobserved job stops the history and produces an inconclusive result.

After the original and fresh replay executions, verify replay evidence:

```bash
scripts/web_sequence_evidence.py \
  ORIGINAL_SEQUENCE_SPEC.json ORIGINAL_SEQUENCE_RESULT.json \
  REPLAY_SEQUENCE_SPEC.json REPLAY_SEQUENCE_RESULT.json \
  REPLAY_ATTESTATION.json --evidence-root REPLAY_EVIDENCE_ROOT \
  --output INDEPENDENT_REPLAY.json
```

The reviewer must use a fresh identity, rebuild the disposable fixture with a
new generation, bind fresh credentials, retain the same application permission
version, execute the complete minimal causal history, and produce disjoint
machine evidence. The verifier rejects copied terminal responses,
pre-populated state, stale approvals, private evaluator-provided resources,
reused run identities, changed mechanisms, incomplete histories, and failed
cleanup. Record every necessary legitimate action by another owned actor and
all victim-interaction requirements.

Bounded concurrency is never simulated by sequential requests and is not a
load test. The fixed paired broker requires separate campaign approval, one
named disposable fixture, exactly two one-operation signed workflows, a
two-participant shared budget, synchronized dispatch, synchronized completion,
and cleanup only after both primary operations finish. Irreversible actions,
real funds, real inventory, more than one staged pair, and third-party
resources remain blocked.

## Typed capability composition

Use chain schema version 3 for web compositions. A capability label describes
an effect; it does not grant authority. Bind it to the exact actor/session,
tenant, resource and owner, operation and permitted scope, parameters, lifetime
and invalidation, provider and consumer process/origin/cache, deployment epoch
and configuration, acquisition prerequisites, measured effect, confidence, and
observed or hypothetical status.

An edge composes only when its concrete bindings agree. A change of principal,
tenant, process, origin, cache layer, or observation epoch requires a named,
evidenced context transition. Do not combine a capability observed in one
account, fixture generation, deployment, or workflow history with a consumer
from another merely because their type names match. Preserve an unmatched
observation as a primitive or hypothesis. Do not invent a bridging effect to
advance it.

The acceptance fixtures cover two complete examples: an exact cross-tenant
record-read chain and an exact shared-cache-to-browser-execution chain. The same
fixtures reject mismatched resource identities, epochs, and browser origins.

## Durable state and resource ownership

Every state-changing experiment declares durable scheduler resource leases.
Use a shared-read lease for observation only and an exclusive lease for
identity/session refresh, owned objects, workflow instances, cache namespaces,
browser profiles, and receiver/callback correlation. Conflicting mutations are
serialized independently of worker count. The shared network budget still
accounts for all retries, redirects, browser subrequests, bytes, evidence, and
cleanup.

Checkpoint authoritative state for the complete conflicting set before and
after effects. Worker loss, timeout, campaign expiry, or unverified cleanup
blocks that namespace. The scheduler does not resume the sequence or release
the resource based solely on time. An active coordinator must review recovery
evidence retained inside the campaign before clearing the block.

## Deployment evidence and finding gate

Create a deployment record from `assets/web-evidence.template.json` and
validate it with `scripts/web_evidence.py`. It binds exact scoped URLs,
observation times, TLS observations, deployment markers and their confidence,
client versions, a stable baseline, prerequisite version, owned identities and
fixtures, request/scenario hashes, provenance mode, cleanup, and artifact
retention policy.

Black-box evidence may prove an external security effect without knowing the
internal root cause. A response header or version string is not a source pin.
If stable baseline components drift, expire pending experiments and replay the
legitimate baseline before making a new claim. An independent replay proves
only the deployment epoch it actually observed.

Build a finding record from `assets/web-finding.template.json` and run
`scripts/web_finding_gate.py`. Promotion requires exact finding, experiment,
approval recipe, authorization contract, and epoch binding; the real attacker
starting authority and ingress; an explicit business rule; owned resources;
positive, negative, and counterfactual semantic controls; an independently
observed confidentiality, integrity, entitlement, cross-tenant, browser,
server, or program-defined effect; conditions and unknowns; fresh replay;
verified cleanup; and artifact hashes.

The web filing threshold is program-eligible **High or Critical** severity.
This exception applies only to the `web-app` profile; it does not lower the
Critical/RCE threshold for source, native, browser-engine, or sandbox
campaigns. Retain verified Medium and lower-severity observations as primitives
for possible chaining, but do not package them as reports by default. The gate
rejects any web finding whose program rating is not explicitly `High` or
`Critical`.

Store raw artifacts in encrypted restricted private evidence. The reviewer tier
contains only redacted synthetic data and is scanned for credential-like
material. Stop on unexpected third-party data. Krineon never publishes or
submits a finding automatically.

## Promotion and replay

The web profile does not inherit the source-only rule that an
application-authored broken check or unsafe sink is disqualifying. An
application's authorization, business-rule, cache, parser, callback, or tool
boundary can be the root cause.

A candidate must bind the signed workflow, signed broker observation, exact
contract hash, and exact budget snapshot. Krineon recomputes each oracle from
the retained observation. Reportable promotion additionally requires two
fresh replay workers whose immutable agent identities differ from the
originator and each other, with distinct run IDs and observation hashes.

## Blinded evaluation

Use blinded evaluation to measure whether a campaign finds and classifies
security-invariant disagreements without seeing the expected answers. The
evaluator keeps the held-out specification outside the campaign directory and
enrolls its hash before target execution. The specification identifies exact
workflow and oracle pairs and their expected three-way outcomes. Research
workers receive neither the file nor its contents.

The autonomous-discovery mode instead receives only authoritative owned-fixture
observations with actor, tenant, resource owner, visibility, action, and a
security-relevant digest. It derives the hypothesis, minimal three-observation
sequence, and oracle itself. Its signed record explicitly states that no
prepared hypothesis, workflow, or oracle was used. The evaluator scores stable
mechanism fingerprints held outside the campaign. This measures discovery; it
does not turn a runtime differential into a reportable finding.

Scoring accepts only signed workflows and signed broker observations whose
contract and exact budget snapshot are independently verified. It rejects
missing, altered, conflicting, or unsigned runs. The signed score records
true positives, false positives, false negatives, true negatives, precision,
recall, exact outcome agreement, and every rejected run. A blinded score is an
evaluation of the research system, not evidence that a target vulnerability is
reportable.

Stop on authorization expiry, scope ambiguity, unexpected third-party data,
an external side effect, inability to enforce a required containment rule, or
budget exhaustion. Never convert a blocked experiment into a best-effort scan.
