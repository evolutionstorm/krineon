# Pinned dependency and cross-library research

Every campaign contains `third_party/manifest.json`. Use `third_party/` for
exact dependency revisions that the pinned target actually builds, bundles,
loads, or invokes. It is not a general mirror, vulnerability feed, or place to
download newer and older versions for diffing.

## Add a dependency

First derive the repository and revision from target-owned evidence such as a
lockfile, vendoring manifest, generated bundle, build graph, module inventory,
or runtime linkage record. Then pin it:

```bash
python3 scripts/research_harness.py dependency-add CAMPAIGN library-name \
  --repo https://github.com/example/library \
  --commit EXACT_LOCK_RESOLVED_REVISION \
  --relationship runtime \
  --scope-status supporting-context \
  --lock-evidence package-lock.json:120 \
  --reason "Public parser input crosses into this library before the native sink"
```

`--relationship` records whether the code is runtime, bundled, native, build,
optional, or transitive. `--scope-status` is a classification and never expands
program authorization. The command resolves the supplied revision to a full
object ID, refuses credential-bearing HTTP URLs, verifies a clean checkout,
and records provenance in the manifest.

Each claimed task receives the manifest as `KRINEON_DEPENDENCIES.json` and
detached dependency worktrees under `KRINEON_THIRD_PARTY/<name>/`. The Git
object store is shared with the campaign checkout, while each worker can build
or instrument its own worktree without modifying another worker's files.

## Select high-leverage dependencies

Do not clone every package. Prefer code that:

- directly consumes attacker-controlled bytes, objects, paths, messages, or
  handles;
- owns native parsing, allocation, deserialization, JIT, codec, cryptographic,
  IPC, sandbox, plugin, template, or module-loading boundaries;
- exports callbacks or mutable state that the target treats as trusted;
- establishes an invariant later consumed by target code, or consumes an
  invariant established by the target; or
- can turn an existing intermediate primitive into read, write, call, load,
  authority, sandbox escape, or execution capability.

Use multiple agents on distinct semantic boundaries. One agent traces the
target-to-dependency ingress, another works backward from dependency or target
sinks, another audits representation or lifetime invariants, and a fresh agent
composes retained intermediate bugs after adversarial review. Do not collapse
all dependency work into generic package scanning.

## Chain and ownership rules

A dependency bug can be a legitimate link when the supported target ships or
invokes that exact revision and target-controlled input reaches it. Prove:

1. the target's exact build selects the pinned dependency revision;
2. the claimed attacker reaches it through a supported target interface;
3. every cross-library transformation and guard;
4. the useful primitive and its compatibility with later target or dependency
   sinks; and
5. the complete stock-deployment terminal.

Do not assume an upstream bug is automatically eligible under the target's
program. Separate root-cause ownership, target integration impact, affected
artifact, and the program's scope. A dependency that is merely present but not
reachable does not support a target claim. Conversely, do not discard a chain
only because one or more links are in bundled or runtime library code.

Discovery remains first-principles. Audit only the target-selected dependency
revision. Do not consult dependency changelogs, advisories, issue history,
security patches, or diffs against other revisions to locate bugs or complete
the chain.
