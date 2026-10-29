# Safety and Authorization

## Default boundary

Use this methodology only for:

- local source and binary analysis;
- owned disposable labs and accounts;
- explicitly authorized bug-bounty assets under their current rules;
- testnets or sandbox environments designated by the program.

Authorization is specific to assets and actions. Permission to review source is
not permission to exploit a live deployment. A terminal instruction such as
“keep testing” does not expand scope.

## Safe proof design

- Bind services to loopback unless remote access is required and authorized.
- Use randomized synthetic records owned by the researcher.
- Use bounded inputs and timeouts.
- Prefer read-only and reversible actions.
- Prove authorization impact using researcher-controlled identities.
- Prove code execution with harmless process identity, platform, timestamp, or
  a temporary file created and removed by the proof.
- Record cleanup and verify no process, listener, wallet approval, cloud
  resource, or temporary file remains.

## Live services

Before any live request, record:

- exact domain or contract in scope;
- allowed methods and rate;
- required researcher headers;
- account and data ownership;
- excluded classes and environments;
- stop conditions.

Do not evade bot protection, access controls, or rate limits unless the program
explicitly authorizes that exact test. Do not interact with other users' data.

## Memory-safety and RCE research

Use a disposable VM or container with resource limits. Start with sanitizers,
assertions, and deterministic harnesses. Move to uninstrumented stock builds
only after the trigger is bounded. Avoid uncontrolled shells, persistence,
network callbacks, credential access, or destructive commands.

`dynamic_harness.py` provides bounded local execution and evidence capture, not
a security sandbox. Its POSIX resource limits and best-effort process-group
cleanup do not contain escaped processes, target-written files, or network
access. Run unsafe targets inside a disposable VM or container, review raw
artifacts before sharing them, and use a fresh campaign/target pin for a fix.

When testing races or allocator corruption, cap attempts and monitor memory,
disk, CPU, process count, and listeners. Stop if the host becomes unstable or
the test escapes the owned environment.

## Browsers, extensions, and wallets

Use a disposable browser profile and wallet containing no valuable assets.
Use only researcher-controlled origins, extensions, snaps, accounts, and
tokens. Do not request real seed phrases, approvals, or signatures. Keep the
proof on testnets and revoke permissions afterward.

## Blockchain and consensus

Use local devnets or the program-designated testnet. Never test denial of
service, consensus interruption, or fund movement on mainnet. Use owned keys
and contracts. Cap gas and value, record transaction hashes, and clean up state
where the chain permits it.

## Stop immediately when

- a request reaches third-party or production data;
- the proof requires degrading a shared service;
- money, credentials, private keys, or customer data could be affected;
- the program rules are ambiguous about the planned action;
- the observed behavior exceeds the bounded effect;
- an embargo or coordinated-disclosure restriction prohibits the next step.

At that point, preserve the evidence, stop mutation, and ask the user or program
for direction.
