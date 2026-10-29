# Agent handoff: FINDING_ID

## Assignment

- Worker identity:
- Agent/runtime identity:
- Task ID and attempt:
- Lease token: retain locally; do not include in report artifacts
- Originator identity, if reviewing:
- Target and exact revision:
- Pinned dependencies and exact revisions:
- Target lock/build evidence selecting each dependency:
- Target-to-dependency boundaries examined:
- Authorization and environment:
- Primary question:
- In-scope files or interfaces:
- Prohibited actions:

## Current claim

- Impact class: RCE or program-defined Critical
- Attacker and starting privilege:
- Root cause:
- Registered approach family IDs:
- Boundary, mechanism, and invariant actually tested:
- Ingress:
- Transformations and carrier:
- Broken invariant:
- Useful primitive:
- Public acquisition:
- Execution or Critical sink:
- Terminal:
- Stock/supported deployment:
- Execution environment class (`production-equivalent`, `release-build`, or
  `supported-production`):
- Development server used for primary terminal: NO
- Development build used for primary terminal: NO
- Exact production/release command or entrypoint and retained evidence:
- Preconditions:

## Discovery provenance

- First-principles pinned-source analysis only:
- Changelog used: NO
- Git history or blame used: NO
- Advisory mining used: NO
- Patched-version comparison used: NO
- Internet patch diff used: NO

## Results

- Confirmed by execution:
- Source-confirmed:
- Source-inferred:
- Disproved:
- Crash IDs and exact fingerprints:
- First-fault class and access direction:
- Normalized stack-cluster ID:
- Controllability score and machine verdict:
- Human triage interpretation and limitations:
- Owned-page browser replay ID and record path:
- Positive/control fresh-process results:
- Final owned URL and blocked external requests:
- Renderer sandbox evidence and what boundary it proves:
- External fuzzer/profile and exact engine identity:
- Instrumentation or REPRL build record:
- Initial/final corpus digests and native worker topology:
- Replay-confirmed crash IDs:
- AFL/LLVM coverage rebuild record and remaining gaps:

## Controls

- Baseline:
- Negative:
- Positive:
- Same-revision invariant-restored:

## Source-to-sink path proof

- Proof record (`evidence/path-proofs/FINDING_ID.json`):
- Exact entry point and retained evidence:
- Exact sink and retained evidence:
- Ordered transitions completed:
- Every conditional on the selected path enumerated:
- Concrete attacker mechanism and observed outcome for every condition:
- Reviewed source ranges and hashes:
- Unresolved assumptions: MUST BE ZERO
- Contradiction challenges and resolutions:
- Falsification and negative-control artifacts:
- Originator identity:
- Independent path reviewer identity:
- `scripts/path_proof.py audit` result:

## Reproduction

```bash
# Exact commands
```

Artifacts:

- Raw output:
- Environment metadata:
- Hashes:
- Idempotency key for result submission:

## Remaining blockers

- Missing chain link:
- Guard or failure mechanism:
- Why the current assumptions are blocked:
- Retained evidence and attempted approaches:
- Source-derived bypass hypotheses:
- Alternative routes to the same Critical/RCE boundary:
- Blocked mechanism fingerprint:
- Genuinely new mechanism fingerprint and difference, if reopening:
- Cheapest discriminating experiment:
- Authority required (`none` or exact new authority):
- Can self-resolve within current authority:
- Falsification condition:

## Cleanup

- Processes stopped:
- Temporary files removed:
- External state restored:
