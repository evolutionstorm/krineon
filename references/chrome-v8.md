# Chrome/V8 Campaign Profile

The `chrome-v8` profile coordinates authorized source review, structured
fuzzing, crash triage, and local browser validation. It does not download or
modify V8, launch cloud instances, visit live targets, or turn a crash into an
exploit automatically.

Use checked-in V8/Chromium tests, DCHECK/ASSERT invariants, fuzz targets, and
fixtures from the pinned revision as discovery oracles. Do not mine later
regression tests, patch history, advisories, or fixed revisions. Preserve unique
minimized stack clusters and invariant breaks as research leads even before an
RCE chain exists; only filing promotion requires the complete chain.

Its lanes are deliberately non-exhaustive. The open-ended expansion lane and
`task-add` command capture new source-derived directions during a campaign.
Blocked paths use the evidence-driven `schedule-unblock` protocol described in
[blocker-resolution.md](blocker-resolution.md); a lane does not stop merely
because its first harness or assumption failed.

## Initialize the campaign

Pin an existing local V8 checkout and its exact revision:

```bash
python3 scripts/research_harness.py init CAMPAIGN \
  --profile chrome-v8 \
  --target v8 \
  --repo https://chromium.googlesource.com/v8/v8 \
  --checkout /owned/checkouts/v8 \
  --commit V8_COMMIT \
  --mode local-lab

python3 scripts/research_harness.py plan CAMPAIGN \
  --max-concurrency auto --lease-seconds 1800 \
  --task-timeout-seconds 21600 --max-attempts 2
python3 scripts/research_harness.py queue CAMPAIGN
```

Edit `AUTHORIZATION.md` and `campaign.json` before dynamic execution. Dynamic
commands refuse campaigns without `authorization.confirmed: true` and a named
allowed environment.

The official V8 build flow uses `gclient sync`, Linux build dependencies, and
`tools/dev/gm.py`; `d8` is V8's developer shell. Record the commands and GN
arguments actually used rather than assuming a named configuration implies a
specific set of mitigations or checks:

- <https://v8.dev/docs/build>
- <https://v8.dev/docs/d8>

## Register exact builds

Create at least three builds of the same pinned revision:

- `release`: closest practical engine behavior to production;
- `asan`: release-style build with AddressSanitizer;
- `debug`: checks and invariant diagnostics;
- optional `jitless`: a useful negative control, not a replacement for a
  source-level explanation;
- `sandboxed-chrome`: a full Chromium binary for the later browser lane.

Register the binary, its revision, GN args, runtime data files, and default
flags. Use `--flag=--value` for flags beginning with a dash.

```bash
python3 scripts/chrome_v8_harness.py register-build CAMPAIGN release \
  --kind d8 --role release --revision V8_COMMIT \
  --binary /owned/checkouts/v8/out/release/d8 \
  --gn-args-file /owned/checkouts/v8/out/release/args.gn \
  --artifact /owned/checkouts/v8/out/release/snapshot_blob.bin

python3 scripts/chrome_v8_harness.py audit CAMPAIGN --json
```

The audit recomputes hashes and fails if a registered artifact changed. It also
requires release, ASan, and debug `d8` roles. Registering sandboxed Chrome is
reported separately because an engine matrix is useful before a full browser
build exists.

## Run a bounded testcase matrix

```bash
python3 scripts/chrome_v8_harness.py matrix CAMPAIGN \
  --testcase testcase.js --timeout-ms 5000 --memory-mb 0
```

The adapter delegates each build to `dynamic_harness.py`. It retains stdout,
stderr, signals, sanitizer diagnostics, target hashes, and the testcase. An
address-space limit of zero is intentional for ASan because its shadow-memory
reservation is large. Run the worker inside a disposable VM; this is not a
security sandbox.

The matrix flags outcome or stdout disagreements and crashes as leads. It never
labels them vulnerabilities. Expected language-level nondeterminism, debug-only
assertions, OOM, timeouts, and allowed implementation differences must be
removed during triage.

Run the crash triager after a retained failure:

```bash
python3 scripts/dynamic_harness.py triage CAMPAIGN --crash-id CRASH_ID --json
```

It classifies the first fault and access direction and hashes normalized top
frames into a persistent cluster. It does not infer controllability. A write,
UAF, or apparent PC fault remains unverified until a challenge-response recipe
proves the exact chosen value, controls, fresh-process stability, and allocation
identity where claimed.

## Replay an owned page in sandboxed Chromium

Register a full Chromium binary built from the pinned revision, then provide a
small owned page directory containing a positive case and a negative control:

```bash
python3 scripts/chrome_v8_harness.py register-build CAMPAIGN chrome-release \
  --kind chrome --role sandboxed-chrome --revision CHROMIUM_COMMIT \
  --binary /owned/chromium/src/out/Release/chrome \
  --gn-args-file /owned/chromium/src/out/Release/args.gn

python3 scripts/chrome_v8_harness.py browser-replay CAMPAIGN \
  --build chrome-release \
  --page-dir /owned/reproducer \
  --entry index.html \
  --control-entry control.html \
  --success-expression 'globalThis.__KRINEON_REPLAY_RESULT__' \
  --expect-json true \
  --control-expect-json false
```

The runner uses the DevTools Protocol directly; Playwright is not required. It
copies and hashes the complete bounded page tree before serving it from an
ephemeral `127.0.0.1` origin. Each case gets a fresh Chromium process and
temporary profile. CDP Fetch interception blocks off-origin requests. The
runner captures console output, exceptions, network failures, the final URL,
a screenshot, bounded Chromium output, raw CDP events, binary identity, and
renderer process evidence.

The runner also routes non-loopback traffic to a dead loopback proxy and uses
resolver rules that exclude the owned origin. These are browser-layer controls,
not an OS network namespace. Keep the replay VM free of unrelated secrets and
use an external network sandbox as an additional control when the page exercises
WebRTC, native sockets, or another channel outside ordinary Fetch interception.

The command refuses `--no-sandbox`, `--disable-setuid-sandbox`, `--js-flags`,
and other final-proof shortcuts. On Linux, `promotionReady` additionally
requires every CDP-reported renderer PID to show `Seccomp=2` and
`NoNewPrivs=1` in `/proc`. Absence of a disabling flag alone is not treated as
proof that the sandbox was active. Other platforms need independently retained
sandbox evidence and therefore do not pass this Linux-specific automatic
check merely because the page result matched.

To attach the retained replay to a candidate:

```bash
python3 scripts/chrome_v8_harness.py browser-replay CAMPAIGN \
  --build chrome-release --page-dir /owned/reproducer \
  --entry index.html --control-entry control.html \
  --finding-id F001 --reviewed-by reviewer-b \
  --review-note 'The stock browser and negative control establish web reachability only.'
```

The candidate gate loads `chrome-v8/browser-replays/REPLAY_ID/replay.json` and
verifies the registered build role, retained site manifest, fresh profiles,
owned final URLs, positive and control results, network containment, sandbox
evidence, and reviewer attribution. A passing browser replay establishes web
reachability. It does not establish renderer code execution or a sandbox
escape by itself.

## Fuzzing workers

Use `scripts/fuzzer_orchestrator.py`; do not substitute
`dynamic_harness.py fuzz` for structured engine work. The latter is only a
deterministic smoke mutator.

Register the pinned Fuzzilli CLI and a REPRL-capable `d8`, attach exact build
evidence, harvest source-derived seeds, then launch native jobs:

```bash
python3 scripts/fuzzer_orchestrator.py register CAMPAIGN v8-fuzzilli \
  --engine fuzzilli --engine-binary /owned/fuzzilli/FuzzilliCli \
  --target /owned/v8/out/fuzzilli/d8 --revision FUZZILLI_AND_V8_REVISION \
  --preinstrumented-kind fuzzilli-reprl \
  --instrumentation-evidence /owned/v8/out/fuzzilli/args.gn

python3 scripts/fuzzer_orchestrator.py seed-harvest CAMPAIGN v8-fuzzilli \
  --source /owned/v8/test/mjsunit --extension .js

python3 scripts/fuzzer_orchestrator.py launch CAMPAIGN v8-fuzzilli \
  --workers 16 --duration-seconds 21600 --forward-crashes
```

The same orchestrator supports:

- Fuzzilli for coverage-guided, stateful JavaScript generation and JIT-focused
  sequences: <https://github.com/googleprojectzero/fuzzilli>
- V8's checked-in JS fuzzer and differential tooling under
  `tools/clusterfuzz/`.
- Chromium FuzzTest or libFuzzer targets for native parsers and component APIs.

Pin the fuzzer revision independently of the engine revision. Follow the
fuzzer's own target-build instructions, including any REPRL or coverage
instrumentation. Hash that evidence or run the instrument command so the
injected compiler environment is retained. Do not silently apply fuzzing-only
changes to a build later used as the production-behavior control.

Every fuzz worker must checkpoint its corpus and crash directory to persistent
storage. A Spot VM may disappear at any time. The orchestrator records command
arrays, revisions, initial/final corpus digests, worker topology, engine stats,
duration, deduplicated external crash IDs, replay-confirmed Krineon crash IDs,
and retained paths. Rebuild coverage with `coverage-rebuild`; do not infer
coverage from corpus size or depend on the target self-reporting edge names.

See [fuzzing.md](fuzzing.md) for instrumentation injection, AFL++
master/secondary sync, libFuzzer fork workers, structured generators, corpus
exchange, crash forwarding, and AFL/LLVM coverage rebuilding.

## Promotion gates

A lead advances in this order:

1. **Deterministic engine lead:** reproducible signal, sanitizer finding, or
   semantic differential with nondeterminism excluded.
2. **Minimized first fault:** the smallest practical testcase preserves the
   same root failure, and the earliest invalid state is explained.
3. **Release relevance:** not solely a DCHECK, resource exhaustion, unsupported
   internal intrinsic, or instrumented-shell artifact.
4. **Web reachability:** an owned local page reaches the behavior in full
   Chromium without internal-only V8 flags. Use the direct-CDP browser replay
   and retain a negative control in a second fresh process.
5. **Critical/RCE terminal:** the primitive reaches bounded real execution or
   another concrete impact that the program explicitly classifies Critical.
6. **Independent replay:** two registered workers with distinct runtime-agent
   identities rebuild or verify the pinned artifacts and reproduce the result
   in fresh processes.
7. **Sandbox claim, if any:** separately demonstrate the sandbox boundary. An
   engine memory-safety result normally establishes renderer compromise, not a
   browser sandbox escape.

Use Chromium's ASan guidance for instrumented full-browser builds and retain
whether the sandbox was enabled for each result:

<https://chromium.googlesource.com/chromium/src/+/HEAD/docs/asan.md>

## Cloud topology

Keep the coordinator, source checkout, build manifests, corpus, and crash store
on a persistent x86-64 workstation. Use disposable workers for fuzzing. Workers
claim Krineon tasks, use isolated worktrees, heartbeat long jobs, synchronize
corpora frequently, and submit results idempotently before shutdown.

Do not put cloud credentials, personal browser profiles, wallets, or unrelated
data in the research image. Expose no debugger, VNC, code-server, or SSH port
directly to the public internet.
