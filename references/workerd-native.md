# workerd native lifetime research

Krineon includes an operational candidate extractor and trace oracle for six
workerd/V8 lifetime boundaries:

- GC visitation of traced JavaScript handles;
- moves and later use of traced handles;
- borrowed pointers that survive JavaScript reentry;
- cancellation, destruction, and later callback entry;
- ArrayBuffer pointer ownership across detach or resize; and
- IoContext affinity across asynchronous callbacks.

The source pass emits exact candidate locations, instrumentation points, and
required runtime events. It does not call a missing visitor or suspicious call
a vulnerability.

```bash
python3 scripts/workerd_lifetime_analysis.py \
  --checkout /owned/checkouts/workerd \
  --output CAMPAIGN/static/workerd-lifetime.json

python3 scripts/semantic_hypothesis_loop.py derive CAMPAIGN \
  --analysis CAMPAIGN/static/workerd-lifetime.json \
  --output CAMPAIGN/experiments/workerd-lifetime.json
```

Instrument a pinned, production-equivalent build only at the emitted points.
Write one JSON object per line for each observed event, then evaluate the raw
trace:

```bash
python3 scripts/workerd_lifetime_oracle.py \
  --trace CAMPAIGN/evidence/workerd/trace.jsonl \
  --output CAMPAIGN/evidence/workerd/oracle.json
```

The oracle is stateful. For example, it reports a borrowed-pointer invariant
only when a recorded JavaScript reentry is followed by an owner-generation
change and then a use of the old pointer. It reports IoContext affinity only
when callback execution differs from the recorded scheduling context and no
explicit transfer was recorded. Similar event sequences cover GC visitation,
handle moves, cancellation, and ArrayBuffer ownership.

An oracle violation is still a lead. Preserve the trace patch separately from
the target, run an enforcing negative control, replay with another observer,
and establish attacker reachability and impact before promotion. A source
candidate, an agent description, or a self-authored `violation: true` field is
not evidence.
