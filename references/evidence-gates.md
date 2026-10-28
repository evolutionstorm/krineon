# Evidence Gates

The harness has two mechanical gate levels. Human review remains mandatory.

## Candidate gate

A candidate must have:

- authorization and scope confirmed;
- exact tested version pinned;
- framework- or library-owned root cause identified;
- attacker control established for the relevant value;
- a working baseline;
- an enforcing negative control;
- a positive case isolated to the disputed condition;
- concrete security impact, not only a crash or unexpected value;
- explicit preconditions and evidence paths.

This gate means “worth independent validation,” not “ready to file.”

## Reportable gate

In addition to the candidate gate:

- reproduction is complete on an unmodified supported build;
- a different researcher or agent independently replayed it;
- official documentation and upstream tests were checked;
- prior advisories, issues, commits, and duplicate roots were checked;
- patch and current-release status were verified on the filing day;
- every source reference and quoted line was rechecked at the pinned commit;
- cleanup is verified and no secrets or third-party data are retained.

## Proof matrix

Use a table that makes the causal discriminator visible:

| Case | Input/provenance | Guard | Effect |
| --- | --- | --- | --- |
| Benign baseline | legitimate | allows | expected success |
| Enforcing control | exploit-shaped | blocks | no unauthorized effect |
| Attack | same payload, disputed condition only | bypassed or omitted | unauthorized effect |
| Patched/current control | same attack | fixed | no unauthorized effect |

The attack case and negative control should not differ in unrelated
configuration, data, timing, or application code.

## Impact requirements

Measure the effect a reviewer cares about:

- confidentiality: exact unauthorized data obtained;
- integrity: exact state, policy, identity, or content changed;
- authorization: actor before/after and forbidden operation completed;
- code execution: harmless real command output, process identity, or bounded
  file effect, with shell and environment prerequisites disclosed;
- memory safety: unmodified-process reachability plus controlled consequence;
- cache or protocol poisoning: attacker prime followed by independent victim
  observation;
- cross-tenant or cross-project: distinct owners and the same shared state.

Do not infer RCE from a crash, arbitrary content from one marker, or cross-user
impact from same-user replay.

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

- impact requires an application-authored unsafe callback unrelated to the
  framework promise;
- only an undocumented insecure configuration enables the trigger, unless the
  vendor itself exposes and supports that configuration and it crosses a real
  boundary;
- the target version is stale and the current release is untested;
- the proof depends on private local build artifacts but claims remote attack;
- the result is only denial of service in a program that excludes it;
- the same root cause is already patched, disclosed, or clearly reported;
- the reproduction package cannot recreate the evidence it cites.
