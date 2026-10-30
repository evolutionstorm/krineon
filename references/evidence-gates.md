# Evidence Gates

The harness has two mechanical gate levels. Human review remains mandatory.
These gates govern candidate findings and filing. They do not decide whether a
unique minimized stack, invariant break, or verified primitive is retained or
advanced as an internal research lead.

## Candidate gate

A candidate must have:

- authorization and scope confirmed;
- exact tested version pinned;
- framework- or library-owned root cause identified;
- attacker control established for the relevant value;
- a complete ingress, transformation, invariant, primitive, acquisition, sink,
  deployment, and terminal chain;
- stock/default or documented supported reachability;
- the primary terminal reproduced in a supported production-equivalent or
  release build, with development server and development build both false;
- no application-authored unsafe sink;
- a harmless real terminal rather than a synthetic callback;
- an `impactClass` of `rce` or `program-defined-critical`;
- first-principles provenance showing no changelog, advisory, Git-history,
  patched-version, or internet patch-diff discovery;
- a working baseline;
- an enforcing negative control;
- a positive case isolated to the disputed condition;
- concrete Critical/RCE impact, not a crash, DoS, lower-severity issue, or
  unexpected value;
- explicit preconditions and evidence paths.
- a machine-validated source-to-sink path proof. It must exactly enumerate the
  ordered transitions and every conditional on the chosen path, show concrete
  attacker control and observed evidence for every required branch outcome,
  contain zero unresolved assumptions, resolve every contradiction challenge,
  and bind every step and branch to an assertion recomputed from retained raw
  process output. The originator and reviewer must provide distinct machine
  attestations using fresh harness-generated challenges;
- reviewed automated triage when a sanitizer or crash artifact supports the
  chain. The gate verifies the crash identity, first-fault record, normalized
  stack cluster, and machine verdict against retained campaign artifacts.

This gate means “worth independent validation,” not “ready to file.”

The gate re-opens and validates
`evidence/path-proofs/FINDING_ID.json`; it does not trust the
`path_proof_complete` Boolean. Every cited proof artifact must exist under the
campaign `evidence/` tree. See
[false-positive-control.md](false-positive-control.md).

## Reportable gate

In addition to the candidate gate:

- reproduction is complete on an unmodified supported build;
- two different researcher or runtime-agent identities independently replayed
  it through fresh machine attestations, not by accepting or restating prose;
- official documentation and upstream tests were checked;
- current-version behavior was executed without mining or diffing patched code;
- any duplicate check happened only after independent chain validation;
- every source reference and quoted line was rechecked at the pinned commit;
- cleanup is verified and no secrets or third-party data are retained.

## Proof matrix

Use a table that makes the causal discriminator visible:

| Case | Input/provenance | Guard | Effect |
| --- | --- | --- | --- |
| Benign baseline | legitimate | allows | expected success |
| Enforcing control | exploit-shaped | blocks | no unauthorized effect |
| Attack | same payload, disputed condition only | bypassed or omitted | unauthorized effect |
| Invariant-restored control | copied or sanitized same-revision carrier | holds | no terminal |

The attack case and negative control should not differ in unrelated
configuration, data, timing, or application code.

## Impact requirements

Measure the effect a reviewer cares about:

- code execution: harmless real command output, process identity, or bounded
  file effect, with shell and environment prerequisites disclosed;
- program-defined Critical: exact owned-data effect plus the program rule that
  explicitly classifies it Critical;
- memory safety: unmodified-process reachability plus controlled consequence;
- cache or protocol poisoning: attacker prime followed by independent victim
  observation;
- cross-tenant or cross-project: distinct owners and the same shared state.

Do not infer RCE from a crash, arbitrary content from one marker, or cross-user
impact from same-user replay.

## Automated crash triage

Every dynamic crash has three separate identities:

- the exact crash fingerprint used for replay and input minimization;
- a normalized stack-cluster ID used to group related failures as the corpus
  grows; and
- a first-fault classification and, separately, verified primitive evidence.

The classifier distinguishes control-flow evidence, out-of-bounds read or
write, lifetime violations, double or invalid free, undefined behavior, data
races, null dereferences, bare signals, and abnormal exits. Those labels confer
no attacker control. `controlEvidence.status` remains `unverified` unless a
recomputable challenge run proves the exact consequence. The machine field
`machinePromotionEligible` must remain false.

When `dynamicTriage.required` is true, the candidate gate loads every referenced
`triage.json` and `dynamic/triage/index.json`, verifies crash and cluster IDs,
checks that the attached verdict matches the retained result, and requires a
named reviewer with notes. A `reject-crash-only` recommendation needs a
specific override reason. An unverified PC or write-oriented lead cannot
replace the real-terminal and production-reachability gates.

## Owned-page Chromium replay

When `browserReplay.required` is true, the candidate gate reads each linked
`chrome-v8/browser-replays/REPLAY_ID/replay.json` rather than trusting a prose
claim or screenshot. It requires the direct-CDP driver, a hashed registered
`sandboxed-chrome` build, a retained bounded site manifest, positive and
negative-control entries in different fresh processes and profiles, owned
final URLs, no off-origin request attempts, and machine-recorded renderer
sandbox evidence. The named reviewer must explain which boundary was proven.

`promotionReady` means the owned page and its control met this browser evidence
contract. It does not mean that a crash is exploitable, that renderer code
execution was achieved, or that the browser/OS sandbox was escaped. Those
claims still require their respective first-fault, terminal, acquisition, and
process-boundary evidence.

## External-fuzzer evidence

An AFL++, libFuzzer, or Fuzzilli artifact is not a candidate merely because the
engine put it in a crash directory. Preserve the pinned engine and target
hashes, verified instrumentation record, exact command, initial/final corpus
digests, worker topology, and crash origin. Forward it through the stock
`dynamic_harness.py run` replay. Only a replay that creates a Krineon crash ID
may enter automated first-fault triage.

Corpus size is not coverage. Retain an AFL `afl-showmap` union or LLVM
profile/`llvm-cov export` rebuild from the content-addressed canonical corpus.
Use missing coverage to redirect seed harvesting or structured generation; do
not use it as proof that unvisited code is safe.

## Reliability and environmental evidence

For probabilistic behavior, preserve:

- fresh process count and successes `N/M`;
- retry policy and timeout;
- ASLR, allocator, CPU, kernel, runtime, and container details;
- whether forced scheduling, debugger intervention, or heap grooming was used;
- unassisted and assisted results separately.

For large-resource triggers, record exact upload size, wire encoding, peak RSS,
virtual memory, disk use, elapsed time, and platform limits. A theoretical
integer wrap is not a realistic exploit until the resource conditions are
measured and compatible with a plausible deployment.

## Remote-acquisition checklist

For IDs, paths, addresses, build metadata, action references, manifests, or
module coordinates:

- show the public request that obtains them; or
- show deterministic agreement across independent builds of the public version;
- label any local inspection used by the harness;
- demonstrate the exploit does not read the target's private build output;
- provide a clean replay using only the public URL when remote exploitability is
  claimed.

## Artifact standard

Retain a self-contained evidence directory containing:

- `environment.json` with versions and hashes;
- `commands.log` or a deterministic run script;
- raw case outputs, not only summaries;
- `verification-results.json` with the matrix and conditions;
- source or binary inventories used for the claim;
- cleanup state;
- `SHA256SUMS` covering the report, instructions, PoC, and evidence.

Do not include credentials, tokens, real user data, absolute researcher paths,
or a technical report that the filing package does not reference.

## Failure conditions

Do not file when:

- the terminal exists only in a development server, development build,
  hot-reload path, test or fixture server, preview-only runtime, debug-only
  configuration, or developer tooling;
- impact requires an application-authored unsafe callback unrelated to the
  framework promise;
- only an undocumented insecure configuration enables the trigger, unless the
  vendor itself exposes and supports that configuration and it crosses a real
  boundary;
- the target version is stale and the current release is untested;
- the proof depends on private local build artifacts but claims remote attack;
- the result is only denial of service in a program that excludes it;
- the result is High, Medium, Low, crash-only, or a primitive without the full
  Critical/RCE chain;
- discovery used changelogs, advisory mining, Git history, patched-version
  comparisons, or internet-derived patch diffs;
- a post-validation duplicate check identifies the same disclosed root cause;
- the reproduction package cannot recreate the evidence it cites.
- the source-to-sink proof omits a branch, contains an unresolved assumption or
  contradiction, cites a missing artifact, or was self-reviewed.
