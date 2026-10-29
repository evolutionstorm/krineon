# Semantic approach-family registry

Krineon classifies research by the security boundary, mechanism class, and
invariant being tested. It never infers novelty from titles, synonyms, or
different descriptions of the same experiment.

The canonical catalog is `profiles/approach-families.json`. Each family has:

- a stable ID;
- the security boundary it crosses;
- the mechanism class being examined;
- the invariant that would be violated; and
- an `exploration` flag distinguishing discovery work from coordination,
  replay, and reporting work.

`static-lead-generation` is a non-exploration infrastructure family. The
profile task runs the analyzers and populates the queue; each generated
validation task is rebound to the semantic security family inferred from the
lead, such as `execution-sink-backtrace`, `representation-parser`, or
`ingress-authority`. This prevents analyzer operation itself from inflating
coverage while still balancing the experiments it creates.

Every profile lane has an explicit mapping to one or more families. Every
runtime-added task must supply at least one registered family with
`--approach-family`. Automatic blocker tasks inherit the blocked task's
families and add `blocker-alternative-route`. Independent replay tasks use
`validation-replay`.

The durable SQLite tables are `approach_families` and
`task_approach_families`. The human-readable campaign snapshot is
`approach-registry.json`. Inspect it with:

```bash
python3 scripts/research_harness.py approach-status CAMPAIGN --json
```

## Dominance prevention and redirection

The scheduler counts distinct active runtime-agent identities per family and
tracks completed, blocked, failed, timed-out, and cancelled tasks as explored
coverage. For exploration tasks, `claim` orders eligible work by:

1. lowest active-agent load across the task's families;
2. lowest prior coverage across those families; and
3. ordinary task priority.

A multi-family task is charged the highest load of any family it uses, so an
unused secondary label cannot disguise continued concentration. A promising,
suspicious, familiar, or high-priority hypothesis does not override this
diversity order. Priority controls selection only among equally covered
families or when no alternative exploration family is runnable.

`claim` records each change from priority order as an
`approach-family-redirect` event with the original task, selected task,
dominated families, underexplored families, and both load measurements.
Coordination, replay, and synthesis families are excluded from discovery
balancing so required control work is not starved.

Do not evade balancing by inventing another label. Create a new family only
when its boundary, mechanism, or invariant is materially different. A new
testcase, file, platform, or wording inside the same mechanism remains in the
same family. A task may reference several families when it genuinely composes
them; that increases the load of each family and makes the convergence signal
conservative.

Registry balancing never overrides dependencies, worker exclusions,
authorization, safety stops, or campaign budgets.
