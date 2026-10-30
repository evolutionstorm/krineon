# False-positive control

Krineon treats a plausible explanation as a hypothesis, not a vulnerability.
No process can guarantee that a report is absolutely free of error, but Krineon
refuses candidate promotion until the claim survives a mechanical path audit
and independent human review.

## Required source-to-sink proof

Create one proof per registered finding:

```bash
python3 scripts/path_proof.py init CAMPAIGN F001
```

Complete `CAMPAIGN/evidence/path-proofs/F001.json`. The proof must contain:

1. The exact attacker-accessible entry point and exact security-relevant sink.
2. Every ordered source-to-sink transition, including the attacker-controlled
   value and a `machineEvidence` reference to a matched assertion in a retained
   Krineon reality attestation.
3. Every conditional statement on the selected path. For each condition,
   record its exact expression, required outcome, how the attacker causes that
   outcome, the concrete input or state, and a recomputable runtime assertion.
4. A function and source-range inventory. Retain and hash each reviewed source artifact
   and explicitly attest that every path condition was enumerated.
5. An empty `assumptions` array. An unresolved assumption is a blocker, not a
   field to explain away.
6. At least one contradiction challenge, its resolution, and retained
   evidence. Every challenge must end as `resolved-no-contradiction`; otherwise
   the claim remains blocked or is disproved.
7. Negative controls and checks for observations that would disprove the
   proposed path.
8. Originator and reviewer machine attestations produced from the same recipe
   and target hashes, but different fresh processes and random challenges.

File existence is not execution evidence. `path_proof.py` re-hashes the recipe,
targets, source snapshots, raw stdout and stderr, then recomputes every linked
assertion. The entry point must match the first step, the sink must match the
last step, and condition IDs must exactly equal the inventory.

## Audit and gate

Run the recipe once as the originator and again as the reviewer:

```bash
python3 scripts/reality_runner.py CAMPAIGN F001 \
  --recipe evidence/recipes/F001.json --worker-id worker-a --role originator
python3 scripts/reality_runner.py CAMPAIGN F001 \
  --recipe evidence/recipes/F001.json --worker-id worker-b --role reviewer
```

Link the two attestation paths and SHA-256 values in the proof, then audit it:

```bash
python3 scripts/path_proof.py audit CAMPAIGN F001 --update-gate --json
python3 scripts/research_harness.py gate CAMPAIGN F001 --level candidate --json
```

`path_proof_complete` is necessary but not sufficient. The candidate gate
loads the proof again and re-runs the validator. Manually changing the Boolean
cannot bypass missing conditions, artifacts, review identity, contradiction
resolution, or assumptions. It also resolves both identities through the
durable worker registry and rejects aliases that map to the same runtime-agent
identity.

## Reviewer procedure

The reviewer must independently re-derive the claim in this order:

1. Start at the stated public entry point and follow only edges supported by
   the pinned source.
2. At every branch, switch, exception edge, early return, permission check,
   parser state, feature gate, and platform gate, try to force the opposite
   outcome. Record the exact input or state that produces the claimed outcome.
3. Confirm that the value leaving each step is the value consumed by the next;
   reject name similarity, type similarity, or inferred aliasing as proof.
4. Search for sanitization, copying, canonicalization, revalidation, lifetime
   changes, privilege changes, and error handling between steps.
5. Replay the negative controls and look for any observation that contradicts
   attacker control, reachability, deployment feasibility, or impact.
6. Resolve every contradiction with retained evidence. If resolution requires
   “likely,” “normally,” “should,” an undocumented configuration, or an
   unobserved state, record a blocker and fail the audit.

Independent replay remains separately required for reportable promotion. The
path proof establishes internal consistency and complete branch reasoning; it
does not replace reproduction on the stock supported target.
