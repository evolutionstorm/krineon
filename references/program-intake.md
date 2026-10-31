# Program-guidelines intake

Use this optional workflow when the researcher supplies program rules and scope
instead of, or in addition to, a prepared source campaign. Source-only analysis
does not require intake or an `AUTHORIZATION.md` file.

## Intake contract

1. Preserve the supplied text verbatim as `PROGRAM_GUIDELINES.md` and retain
   its SHA-256 digest in `onboarding.json`. When scope arrives separately,
   preserve it as `PROGRAM_SCOPE.md` with its own digest.
2. Treat extracted URLs, repositories, scope entries, exclusions, and profile
   choices as review candidates. The original rules remain authoritative.
3. Prefer an explicitly named repository. If the rules identify one unique
   public repository, use it. When multiple repositories could be the target,
   leave source acquisition unresolved instead of choosing silently.
4. Pin the exact Git revision from the acquired checkout. `pending-pin` permits
   setup and source acquisition but blocks the dynamic harness.
5. Queue the campaign so the coordinator can resolve intake items and begin
   source analysis. Source review may proceed while dynamic authorization or
   runtime setup remains unresolved.
6. Never infer authority for production, shared-system, account, wallet,
   testnet, or live-network interaction from the existence of a public bounty
   page. Confirm the exact asset, action, environment, and stopping conditions
   before such testing.

## One-command bootstrap

With an existing checkout:

```bash
python3 scripts/campaign_bootstrap.py CAMPAIGN \
  --guidelines PROGRAM_RULES.md --scope PROGRAM_SCOPE.md --checkout SOURCE \
  --confirm-authorization
```

The confirmation covers only source review and bounded local-owned testing.
It does not authorize live testing.

To let the bootstrap clone one uniquely identified public repository:

```bash
python3 scripts/campaign_bootstrap.py CAMPAIGN \
  --guidelines PROGRAM_RULES.md --clone --confirm-authorization
```

Without `--confirm-authorization`, the plan and durable queue are still
created, but dynamic execution stays disabled. Without a unique repository,
the setup task receives `pending-source-repository` and `pending-pin`; it must
resolve both before runtime work.

Pass `--authorization-record` only when a human-readable `AUTHORIZATION.md`
summary is useful. Structured authorization in `campaign.json`, not the
presence of that file, controls dynamic and live actions.

## Agent behavior

When program rules are pasted in chat, save them unchanged and run the intake
without asking routine setup questions. Resolve a public repository, commit,
tool inventory, and local build from primary sources when the rules make the
target unambiguous. Register the current agent as coordinator, claim
`coordinator-setup`, resolve any recorded intake items, and begin the queued
source-analysis waves. Ask the researcher only when an ambiguity would select
a different asset, broaden permitted actions, incur meaningful cost, or
require credentials or live-system authority.
