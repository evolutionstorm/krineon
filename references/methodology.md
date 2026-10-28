# Research Methodology

## Objective

Find violations of a security boundary, not merely unusual behavior. A useful
campaign connects five layers:

1. **Root cause:** the framework or library violates one of its own invariants.
2. **Ingress:** attacker-controlled data reaches that defect through a supported
   or realistically deployed interface.
3. **Carrier:** ordinary application or protocol data transports the malicious
   state without requiring an already vulnerable callback.
4. **Terminal:** the defect produces an independently meaningful effect such as
   unauthorized data access, policy mutation, cross-user integrity loss, or
   bounded code execution.
5. **Conditions:** every platform, version, configuration, ordering, memory,
   and interaction requirement is explicit and measured.

This decomposition prevents a strong primitive from being presented as a weak
deployment story, and prevents an impressive terminal from hiding an
application-authored vulnerability.

## Phase 0: freeze the target

Record before analysis:

- exact repository, commit, release, dependency lock, compiler, and runtime;
- program asset, severity floor, exclusions, and safe-harbor terms;
- supported deployment modes and defaults;
- authorization and test-data ownership;
- known advisories and recently changed security code;
- cleanup and stopping conditions.

Hash binaries and generated artifacts. Preserve the commands that produced
them. Do not describe a moving branch as the tested revision.

## Phase 1: model promises and boundaries

Inventory externally reachable entry points and write the promise each one is
supposed to enforce. Examples include:

- unauthenticated versus authenticated requests;
- public versus internal headers or protocol records;
- manifest-authorized versus arbitrary modules;
- tenant, route, project, build, account, or cache-key isolation;
- immutable versus mutable state;
- owner thread, request, process, or realm;
- parser success versus parser failure state;
- producer and consumer agreement on lengths and types.

Then enumerate privileged sinks: module loading, process execution, file and
network access, authorization decisions, cache writes, key use, native parser
entry, deserialization, memory copying, and lifecycle destruction.

The first useful artifact is a map from attacker-controlled entry points to
security promises and privileged sinks. Do not start by asking only for RCE.

## Phase 2: generate falsifiable hypotheses

Prioritize structural bug families that have repeatedly produced high-impact
results:

- producer and consumer parse the same value differently;
- validation occurs before a later merge, normalization, redirect, or decode;
- a key omits identity or has a non-injective encoding;
- state is process-global when ownership should be per project or request;
- case, locale, path, method, or header classification differs between layers;
- the success path enforces an invariant that an async or error path omits;
- discriminators or ownership metadata are committed before payload validation;
- pooled or recycled objects outlive their transaction, realm, or process;
- a patch covers one representation, transport, or branch but leaves a sibling;
- a public serializer emits values its paired decoder cannot represent safely;
- a generated or vendored runtime differs from the source reviewers normally
  inspect.

Write each hypothesis as:

> If input X crosses boundary Y, component A validates interpretation P while
> component B consumes interpretation Q, so attacker capability Z becomes
> possible. The hypothesis is false if control C behaves the same as the attack.

Assign a hypothesis a stable ID immediately. Preserve it when disproved.

## Phase 3: analyze in complementary lanes

Run separate lanes for:

- **boundary mapping:** ingress, provenance, identity, authorization, manifests;
- **sink-first tracing:** work backward from privileged operations;
- **state and lifecycle:** ownership, pooling, globals, async completion, errors;
- **protocol differential:** compare producer/consumer and layer classifications;
- **variant analysis:** patches, sibling functions, generated bundles, platforms;
- **deployment composition:** defaults, documentation, adapters, proxies, hosts;

Parallelism is useful only when the lanes produce different evidence. Three
agents repeating keyword searches is not a three-agent audit.

## Phase 4: build the proof ladder

Promote incrementally:

1. Source contradiction or invariant mismatch.
2. Minimal deterministic unit harness.
3. Unmodified component or production bundle.
4. Supported application fixture.
5. Real protocol ingress with attacker-controlled values.
6. Concrete harmless security effect.
7. Fresh-process reliability and independent replay.

At every step, identify which artificial mechanism was removed. A result that
requires patched source, forced sleeps, direct heap mutation, private build
inspection, or a test-only callback has not yet reached a production claim.

## Phase 5: construct differential controls

The minimum matrix is:

| Case | Security condition | Attacker input | Expected result |
| --- | --- | --- | --- |
| Baseline | normal supported path | benign | feature works |
| Negative control | enforcement present | exploit-shaped | effect blocked |
| Positive case | only disputed condition differs | same payload | effect occurs |

Add copied-value, wrong-ID, wrong-origin, clean-header, patched-version, and
restarted-process controls when relevant. The positive case should differ by
one fact that directly identifies the root cause.

For races and allocator-dependent behavior, report `N/M` across fresh
processes. A forced-schedule reproduction explains consequence; an unassisted
rate establishes reachability. Preserve both and label them separately.

## Phase 6: prove attacker acquisition

For every coordinate used by the exploit, record its origin:

- supplied by the attacker;
- public protocol output;
- reproducible from the public version;
- guessed with a measured search;
- obtained only by local build inspection;
- private or secret.

Remote acquisition is part of the exploit. A harness secret, locally scraped
manifest, or hard-coded address must not be described as remotely available.

## Phase 7: adversarial falsification

Assign a different agent to disprove the candidate. The agent should attempt:

- stock defaults and current stable/canary releases;
- removal of every suspicious fixture dependency;
- clean-process and copied-value controls;
- official documented patterns instead of researcher-created ones;
- prior-art and duplicate-root-cause matching;
- alternate explanations for every observed marker;
- direct measurement of the claimed unauthorized outcome;
- exact source-link and patch-status verification.

Promote only the narrowest claim that survives.

## Phase 8: package the result

Retain:

- exact commands and environment metadata;
- raw request, response, stdout, stderr, and exit status;
- source and binary hashes;
- baseline, negative, positive, and patched controls;
- cleanup and before/after state;
- a one-command local verifier where safe;
- a report whose title names root cause and consequence.

Do not substitute a synthetic marker for a real terminal when a harmless real
effect is available. For code execution, bounded commands such as `id`,
`whoami`, `uname`, or a timestamp are clearer than a harness-created boolean.
Never read credentials or third-party data merely to strengthen a proof.
