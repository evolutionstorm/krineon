# Capability-conditioned lane activation

Krineon activates worker context from measured capabilities rather than from a
static prompt containing every supported tool and research mode.

The activator reads the campaign, its selected profile, an optional
`tool_probe.py` inventory, optional explicit capability facts, the web campaign
contract, and an optional fingerprint-disagreement analysis. It then writes one
record per profile lane with:

- `eligible` or `planning-only` state;
- measured capabilities selected for the lane;
- missing capability requirements;
- minimal context packs and reference files;
- runtime-authority status; and
- a priority adjustment.

Missing tools or target evidence never prove that a mechanism is irrelevant.
The lane remains visible as `planning-only`, can analyze retained evidence, and
may design a bounded capability-acquisition experiment. It cannot pretend the
missing runtime, browser, fuzzer, MCP, artifact, or authorization exists.

## Explicit facts

Start from `assets/capability-facts.template.json`. A fact has this shape:

```json
{
  "id": "target.shipped-artifact",
  "state": "present",
  "provenance": {
    "trust": "source-supported",
    "basis": "build manifest binds the retained production bundle"
  }
}
```

Allowed states are `present`, `absent`, and `unknown`. Allowed trust labels are
`tool-measurement`, `source-supported`, `owner-specified`, and `inferred`.
Conflicting present and absent evidence resolves to unknown rather than silently
choosing a convenient capability. An `inferred` fact remains visible for
planning and prioritization, but cannot satisfy an execution requirement.

Useful explicit facts include `mcp.burp`, `mcp.playwright`, `mcp.rea`,
`target.shipped-artifact`, `target.instrumented-fuzz-target`, and
`target.libfuzzer-harness`. Add facts only after observing the capability. Tool
availability and target authorization are separate facts; neither implies the
other.

## Planning behavior

The default catalog is `profiles/lane-capabilities.json`. Profile base packs
remain small. Rules add only the references needed for a lane's measured
environment. REA, Burp MCP, browser, native fuzzing, and fingerprint follow-up
references are conditional.

`research_harness.py plan` writes `lane-activation.json`, adds activation state
to each task packet, and lowers planning-only priority without deleting the
lane. An explicit `--lane` selection still does not manufacture missing runtime
authority.
