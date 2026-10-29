# Pre-Filing Review

Run this review on the day of submission.

## 1. Scope and eligibility

- Is the exact asset listed in scope?
- Is the affected component owned by the program, or is it an upstream project
  requiring separate disclosure?
- Is the weakness class eligible at the demonstrated severity?
- Are denial of service, unsafe configuration, social engineering, physical
  access, compromised credentials, or test-only code excluded?
- Does the proof use only authorized accounts, wallets, data, testnets, and
  infrastructure?

Quote the rule that supports eligibility. Do not assume a GitHub repository is
covered merely because a product vendors it.

This review begins only after a complete chain has passed independent replay.
It must not become a vulnerability-discovery or patch-diff phase.

## 2. Current-version validation

- Re-run on the latest stable release.
- State exact versions tested by execution.
- Re-pin links and line numbers whenever the tested commit changes.
- Do not diff the candidate against patched, later, earlier, canary, or
  internet-derived source. Test the selected current release on its own.

## 3. Intended behavior

Read primary documentation and tests for the pinned/current tested revision:

- official documentation and examples;
- threat model and security architecture;
- upstream regression and conformance tests;
- comments attached to the invariant;

If behavior is documented, identify the separate violated promise. If no such
promise exists, avoid presenting working-as-documented behavior as a bypass.

## 4. Post-validation duplicate risk

Only after the chain is complete, check titles and public descriptions for a
likely duplicate. Do not inspect patches, security commits, vulnerable-line
diffs, or prior PoCs to derive or extend the chain. Compare:

- root cause;
- input and parser path;
- affected endpoint or feature;
- bypass mechanism;
- consequence.

New variants with the same root and fix are usually duplicates. A new ingress
or stronger terminal helps only when the underlying security defect and
remediation are materially distinct.

## 5. Ownership

Identify who can close exposure immediately. A report to a downstream project
should lead with the downstream-owned trust boundary or configuration decision,
not a remediation list directed entirely at an upstream dependency.

Establish ownership from the current target's trust boundary and ability to
remove exposure. Do not frame the report as an incomplete-fix or patch-bypass
claim derived from history.

## 6. Realistic attack story

Answer in one paragraph:

- Who is the attacker?
- What access do they begin with?
- What public input do they control?
- What normal application action creates the carrier?
- Which framework-owned boundary is crossed?
- What exact unauthorized result occurs?
- Which deployment conditions are required?
- Which supported production-equivalent or release entrypoint reproduced it,
  and what evidence proves development server/build behavior was absent?

If the story needs “the application deliberately exposes a dangerous function”
or “the operator disables two safety limits,” expect the reviewer to treat it
as application or operator responsibility unless official product behavior
clearly contradicts that interpretation.

## 7. Severity

- Choose the CVSS version used by the program.
- Calculate with the official calculator.
- Explain each metric from demonstrated evidence.
- Put timing, environment, or build-coordinate preconditions in the correct
  metric rather than hiding them.
- Do not self-deflate with unrelated disclaimers, but do not ask for Critical
  when several uncommon conditions contradict near-universal exploitability.
- When uncertain, provide the vector and evidence and let the program score.

## 8. Package hygiene

- Extract the archive into a clean temporary directory.
- Follow the README exactly.
- Verify checksums.
- Confirm all referenced files exist.
- Remove local absolute paths, secrets, tokens, private URLs, stale reports, and
  unrelated research.
- Ensure the archive root matches the documented `cd` command.
- Make controls and expected output obvious.
- Include no destructive payload and no dependency on an unavailable service.

## 9. Reviewer simulation

Have an uninvolved reviewer answer:

- What is the root cause in one sentence?
- What single condition distinguishes attack from control?
- Can the reviewer reproduce without private researcher knowledge?
- Is the outcome meaningful without trusting a synthetic marker?
- What is the strongest reason to close as informative, duplicate, out of
  scope, or intended behavior?

Resolve those objections before filing, not after triage asks.
