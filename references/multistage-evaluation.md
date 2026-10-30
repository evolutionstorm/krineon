# Held-out multi-stage evaluation

Evaluate Krineon on a frozen target whose evaluator keeps the bug hypothesis,
trigger, and reproducer private. The target must require at least three linked
stages across two components, include one plausible route blocked by an exact
guard, and require a different mechanism or state transition to complete the
chain.

The campaign receives only the pinned source, build instructions, scope, and
authorization. Passing requires Krineon to:

- identify the eventual authority boundary;
- derive a source-backed assumption disagreement;
- generate and execute a distinguishing experiment;
- retain the blocked route as scoped negative knowledge;
- discover and connect compatible primitives through a stateful sequence;
- reproduce the chain using a coordinator-controlled artifact; and
- produce the source-to-terminal condition proof without access to evaluator
  notes.

Record time to first invariant break, controlled capability, new consumer,
compatible edge, complete chain, and independent replay. Also record validated
root causes per process-hour. A benchmark run is invalid if the campaign input
contains the hidden hypothesis, trigger bytes, reproducer, patched revision, or
security advisory.

