# Runtime fingerprint disagreements

Use `scripts/fingerprint_disagreement.py` when two retained observers report
different facts about the same deployed component, or one observer reports a
different fact when exactly one request scope dimension changes.

The engine is an offline hypothesis generator. It does not probe targets, look
up known vulnerabilities, choose a preferred version, or promote findings.

## Evidence contract

Create one or more observation sets from
`assets/fingerprint-observations.template.json`. Every signal must name:

- one target and deployment epoch;
- an observer identity, kind, and independence family;
- the exact origin, hostname, port, route, method, actor, session, and known
  backend scope;
- one component property and a bounded scalar value; and
- campaign-relative evidence with a verified SHA-256 and selector.

Do not store raw cookies, bearer tokens, API keys, bodies, or credentials as
fingerprints. Prefer content hashes, build identifiers, generated asset roots,
protocol feature sets, parser decisions, runtime labels, and bounded behavior
classes.

## Output classes

`observer-conflict` means independent observer families disagree inside the
same exact scope. `same-scope-instability` means one observer family measured
more than one value in that scope. `scope-split` means different values were
retained while exactly one of origin, hostname, port, route, method, actor,
session, or backend changed within one deployment epoch.

All three remain planning-only. A conflict may be an observer bug, expected
content negotiation, personalization, deployment drift, or a real split
consumer. Run the emitted cheapest experiment before drawing conclusions.

## Security-oriented continuation

When a scope split survives its controls, compare one security-relevant
invariant across the cohorts:

- authorization and resource identity;
- normalization or parser decisions;
- cache partitioning and invalidation;
- middleware or policy enforcement;
- module, manifest, or generated-bundle identity; or
- ownership and lifetime behavior in the shipped runtime.

Change only the named scope dimension. Bind both observations to the same
deployment epoch and independently record content and backend identity. A
version disagreement alone is never a vulnerability.
