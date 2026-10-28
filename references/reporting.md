# Reporting Guide

## Title

Name the owning component, violated mechanism, and consequence:

> Component's X mismatch lets unauthenticated Y cross Z and perform impact

Avoid sensational severity labels, vague “bypass,” and downstream gadgets in
the title unless they are the root cause.

## Summary order

The first paragraphs should answer:

1. What invariant is violated?
2. Why is this framework- or library-owned rather than unsafe application code?
3. What attacker-controlled input reaches it through a supported path?
4. What concrete impact was executed?
5. What exact conditions limit the result?
6. Which current versions were tested?

Put the strongest independently verified fact early, such as a clean remote
replay, an unassisted success rate, or a stock-runtime command result.

## Recommended structure

1. Title and affected asset
2. Summary
3. Tested and inferred versions
4. Exact deployment conditions
5. Root cause with pinned source references
6. End-to-end attack path
7. Three-case truth table
8. Reproduction steps and expected output
9. Impact
10. Prior art and distinction
11. Recommended remediation
12. Safety, cleanup, and artifact hashes

## Claim labels

Use precise labels:

- **confirmed by execution** for observed runtime behavior;
- **source-confirmed** for a located code path not reached in the complete PoC;
- **source-inferred** for an affected version range;
- **conditional** for platform, memory, network, or configuration dependencies;
- **not claimed** for untested outcomes.

Never let an inferred variant read like part of the executed proof.

## Root-cause explanation

Show the exact producer/consumer or validation/use discrepancy with short code
excerpts and pinned links. Explain ordering and ownership, not only line numbers.
For vendored code, cite the compiled artifact the product actually ships and
the upstream source when both are relevant.

Separate:

- the violated invariant;
- the carrier that exposes it;
- the gadget chain used in the proof;
- the terminal effect;
- deployment preconditions.

A repair should address the invariant, not denylist proof-specific gadgets.

## Reproduction

Prefer:

```bash
unzip poc.zip
cd poc
sha256sum -c SHA256SUMS
./run.sh
```

If dependencies are required, pin them. State whether internet, Docker,
platform-specific runtimes, credentials, or large memory/disk are needed.
Include the exact expected discriminator, not pages of logs.

## Impact language

Describe the authority gained relative to the attacker starting point. For
example:

- unauthenticated request to server-process JavaScript execution;
- self-registered account to administrator-only policy mutation;
- tenant A input returned to tenant B;
- untrusted response restored as a framework-internal control header.

Use real harmless effects where possible. If command execution is demonstrated,
show bounded output such as process identity and time. Do not access real
credentials, customer data, or unrelated files.

## Remediation

Lead with the smallest fix owned by the recipient. Then add defense-in-depth:

- enforce the invariant at the trust boundary;
- bind state to route, build, tenant, project, or request identity;
- use non-overflowing and bounded representations;
- validate after every merge, redirect, decode, or normalization;
- close all sibling paths before exposing the new validator;
- add the positive and negative matrix as regression tests.

Avoid remediation lists that tell a downstream program only to patch somebody
else's library.

## Reviewer Q&A

Pre-answer only the objections that materially affect validity:

- Is the input supported and remotely obtainable?
- Is this intended behavior or documented trust?
- Is the sink application-authored?
- Does the current release reproduce?
- Is this the same root cause as a prior advisory?
- Are platform or hosting constraints explicit?
- Does the control isolate the claimed mechanism?

Do not bury the report under speculative variants or defensive essays.
