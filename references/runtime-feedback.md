# Runtime feedback loop

`scripts/runtime_feedback.py` turns retained runtime evidence into one bounded
next action. It consumes a semantic IR plus coverage, minimized crash, or
semantic-observation records.

The decision order is:

1. Minimize and independently replay a unique replay-confirmed crash.
2. Verify an executable security-oracle violation.
3. When coverage plateaus before a mapped consumer, change the harness or
   structured grammar to reach that consumer.
4. While measured edges continue to grow, continue bounded corpus growth.
5. If a semantic consumer has no telemetry, instrument it before scheduling an
   attack experiment.

The feedback record never authorizes promotion. It can add a deterministic
next task to the durable queue, but confirmation still requires coordinator
re-execution and independent review.

Native fuzz launches accept a campaign-relative semantic IR. When supplied,
the launcher reads the real nested plateau record and replay-confirmed,
minimized stack clusters, writes `runtime-feedback.json`, and queues the
selected next action. Use the no-ingest option only when you want to retain the
decision without changing the queue.

This closes the operational loop:

```text
execute
→ collect coverage, invariants, and stacks
→ deduplicate and minimize
→ identify the next unreached security consumer
→ change the harness or grammar
→ execute again
```

Coverage is a search signal. It does not establish attacker control,
authorization failure, memory controllability, or impact.
