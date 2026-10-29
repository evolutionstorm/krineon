# Exploration and Blocker Resolution

Krineon profiles define starting search axes. They are not exhaustive testcase
lists, and completing every predeclared lane is not the definition of campaign
coverage. Workers should create focused tasks when evidence exposes a new
surface, composition, platform path, or falsifiable hypothesis that could fill
a missing link in a Critical/RCE chain. Do not schedule lower-severity report
work merely to keep a worker busy.

Authorization is the hard boundary. Curiosity, model confidence, and a high
potential severity do not authorize live-target access, third-party data,
service degradation, persistence, or a new asset.

Resolve blockers from the pinned source and exact-revision runtime. Do not use
changelogs, advisories, Git history, historical commits, patched versions, or
internet patch diffs as an unblocking shortcut.

## Expand a campaign at runtime

Add a task without regenerating or discarding the reviewed launch plan:

```bash
python3 scripts/research_harness.py task-add CAMPAIGN adjacent-path-01 \
  --title "Follow adjacent representation transition" \
  --lane open-ended-expansion \
  --objective "Determine whether the sibling lowering omits the same guard" \
  --success-criterion "Confirm or disprove the path with source and runtime evidence" \
  --depends-on jit-compiler-invariants \
  --priority 80
```

The task packet tells the worker to explore adjacent paths and preserve both
positive and negative knowledge. Dependencies, leases, retries, timeouts,
worker isolation, and result ingestion apply exactly as they do to profile
tasks.

## Submit a blocker

Use a blocked outcome only after bounded attempts produced evidence. The result
must contain:

```json
{
  "blocker": {
    "category": "missing-observability",
    "reason": "The production build exposes no discriminator for the state transition.",
    "blockedLink": "primitive-to-execution transition",
    "guardOrFailure": "the release build omits the state signal used by the diagnostic build",
    "mechanismFingerprint": "release-observability-v1",
    "whyBlocked": "the candidate state is indistinguishable from the negative control",
    "cheapestDiscriminator": "derive one release-visible output from the diagnostic state",
    "evidence": ["logs/release-control.txt"],
    "attempts": ["release replay", "ASan replay", "source-derived marker"],
    "nextExperiments": [
      "Use a diagnostic build to derive a release-visible discriminator",
      "Test the sibling consumer with an observable output"
    ],
    "bypassHypotheses": [
      "a sibling output path exposes the state without diagnostic instrumentation"
    ],
    "alternativeRoutes": [
      "reach the same execution boundary through the sibling consumer"
    ],
    "canSelfResolve": true,
    "authorityRequired": "none",
    "analysisProvenance": {
      "firstPrinciplesOnly": true,
      "changelogUsed": false,
      "gitHistoryUsed": false,
      "advisoryMiningUsed": false,
      "patchedVersionDiffUsed": false,
      "internetPatchDiffUsed": false
    }
  }
}
```

Categories should be concrete, such as missing build, missing observability,
nondeterminism, environmental mismatch, inaccessible state, tool failure,
coverage gap, unsupported precondition, or source-level falsification.

Do not use `blocked` to hide an assertion, guess, or unfinished search. Do not
claim an authorization blocker can be solved without explicit new authority.

For a self-resolvable technical blocker with `authorityRequired: "none"`, the
scheduler immediately creates a high-priority `automatic-blocker-breakout`
task and excludes the worker that reported the original blocker. The task is
seeded with the retained evidence, blocking mechanism, bypass hypotheses,
alternative routes, and cheapest discriminator. A second technical blocker
continues the same loop; it does not silently terminate the campaign.

## Schedule an unblock experiment

```bash
python3 scripts/research_harness.py schedule-unblock CAMPAIGN TASK_ID \
  --title "Recover release-state observability" \
  --strategy "Use a diagnostic build only to derive a release-visible control" \
  --success-criterion "Retain a discriminator usable by the original release lane" \
  --exclude-worker ORIGINAL_WORKER
```

The unblock task receives high priority and retains only the original task's
already-completed dependencies. If a task is merely transitively blocked,
schedule the unblock against each named root blocker instead. A successful
result must contain:

```json
{
  "taskResult": {
    "taskId": "unblock-TASK_ID-1",
    "summary": "Resolved the recorded observability blocker.",
    "conclusion": "The original task can resume with a retained discriminator.",
    "searchedSurface": ["pinned source and exact-revision diagnostic path"],
    "sourceReferences": ["src/example.cc:42"],
    "evidence": ["evidence/release-discriminator.json"],
    "hypotheses": [],
    "nextTasks": ["TASK_ID"],
    "replayFindings": [],
    "analysisProvenance": {
      "firstPrinciplesOnly": true,
      "changelogUsed": false,
      "gitHistoryUsed": false,
      "advisoryMiningUsed": false,
      "patchedVersionDiffUsed": false,
      "internetPatchDiffUsed": false
    }
  },
  "unblock": {
    "blockedTaskId": "TASK_ID",
    "blockerAddressed": true,
    "evidence": ["evidence/release-discriminator.json"],
    "resumeStrategy": "Replay the original matrix using the retained discriminator.",
    "newMechanism": {
      "fingerprint": "release-visible-discriminator-v2",
      "differsFrom": "release-observability-v1",
      "mechanism": "derive a discriminator from stock release output",
      "difference": "uses production output instead of the unavailable trace signal",
      "evidence": ["evidence/release-discriminator.json"]
    }
  }
}
```

Krineon verifies that the mechanism fingerprint changed before it requeues the
original task, extends its attempt budget when
needed, and revives downstream tasks that were blocked only by dependency
failure. If the unblock experiment finds another obstacle, submit that task as
blocked with a new diagnosis instead of falsely marking success. Krineon
schedules the next fresh-agent breakout automatically when it remains
self-resolvable. The generic `retry` command rejects blocked tasks, so a worker
cannot bypass the mechanism-evidence gate by manually requeueing the old path.

## Escalation ladder

For each obstacle, prefer the smallest experiment that distinguishes competing
explanations:

1. Verify the artifact, revision, command, environment, and expected baseline.
2. Add observation without changing the semantic path.
3. Compare sibling implementations, tiers, architectures, or supported builds.
4. Derive a new input or state sequence from source constraints.
5. Use a diagnostic build to understand the state, then return to an unmodified
   release or supported build for the security claim.
6. Explore an alternative path to the same security boundary.
7. If that exact mechanism is falsified, map which link failed and create a
   task for a different source-derived route to the same boundary.

The goal is a complete, justified Critical/RCE chain. A technical blocker ends
one hypothesis, not the campaign. Retire an exact route only when evidence
falsifies its required invariant or precondition, then continue with adjacent
producers, consumers, representations, platforms, or sinks. Stay conservative
about what the evidence proves. If only a lower-severity outcome survives,
preserve it as a falsification and keep searching for a different Critical/RCE
composition rather than preparing a lower-severity report.
