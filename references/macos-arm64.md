# macOS arm64 campaigns

Use this reference for native Apple Silicon campaigns. Krineon supports Darwin
`arm64` for source analysis, bounded process execution, external fuzzers,
Chrome/V8 build registration, testcase matrices, and owned-page Chromium
replay.

## Verify the host

Run these checks before campaign setup:

```bash
uname -m
xcode-select -p
python3 --version
```

The expected architecture is `arm64`. Krineon requires Python 3.10 or later.
Inputs named `aarch64`, `arm64e`, or `armx64` are normalized to `arm64` in
retained campaign evidence.
Install Xcode and its command-line tools before you build Chromium, V8, or
native sanitizer targets.

The tool inventory recognizes native macOS paths for Google Chrome and
Chromium. It also records `xcrun`, `lldb`, `atos`, `codesign`, `lipo`, `otool`,
and `dwarfdump` when available.

## Register native Chrome and V8 builds

On an Apple Silicon host, Krineon records `arm64` by default. Pass
`--architecture arm64` when you want an explicit assertion. Build registration
uses `lipo` and `file` output to retain Mach-O architecture evidence and rejects
a detected mismatch.

Typical native build artifacts are:

```text
/path/to/v8/out/Release/d8
/path/to/chromium/src/out/Release/Chromium.app/Contents/MacOS/Chromium
```

Chromium's native Apple Silicon build defaults to the host architecture. Add
`target_cpu = "arm64"` to `args.gn` when you need an explicit target or build
for arm64 from an Intel Mac. See the official
[Chromium arm64 documentation](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/mac_arm64.md)
and [macOS build instructions](https://chromium.googlesource.com/chromium/src/+/main/docs/mac_build_instructions.md).

Register the executable inside the `.app` bundle, not the bundle directory.
Krineon does not remove quarantine attributes, change signatures, or bypass
Gatekeeper. Prefer a locally built browser. If macOS blocks an owned downloaded
build, review the quarantine guidance in Chromium's documentation before you
change that artifact.

## Understand Darwin evidence

The bounded runner uses a fresh process session, wall-clock termination, output
caps, core-dump suppression, and CPU limits on Darwin. An address-space limit is
recorded as best effort because it is not a security boundary on macOS. Use an
owned disposable virtual machine for unsafe native targets.

macOS has no Linux `/proc` filesystem. For owned-page browser promotion,
Krineon instead retains these Seatbelt checks for every CDP-reported renderer:

- a `file-read-data` query for a randomized owned sentinel is denied;
- a `process-exec` query for `/bin/true` is denied; and
- the same sentinel file-read query succeeds for the browser process as a
  control.

The replay fails closed when `sandbox_check` is unavailable, a renderer cannot
be identified, a query errors, or the browser control does not succeed. These
checks establish that the renderer is confined by the active macOS Seatbelt
policy. They do not prove a sandbox escape or replace the separate impact gate.
For Chromium's sandbox design, see the official
[macOS sandbox documentation](https://chromium.googlesource.com/chromium/src/+/main/sandbox/mac/README.md).

## Preserve platform-specific results

Treat Intel, Apple Silicon, Linux, and simulator results as different evidence
rows. Record the host architecture, target architecture, macOS version, SDK,
Xcode, GN arguments, sanitizer configuration, executable hashes, and whether
Rosetta was involved. Do not infer native arm64 impact from an x86_64 process
running under Rosetta.
