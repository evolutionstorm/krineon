# Install Krineon helper tools

Krineon does not install third-party tools. Install only the tools needed for
the target, pin their versions for each campaign, and run the tool inventory
after installation:

```bash
scripts/tool_probe.py --json --output tool-inventory.json
```

Keep incompatible compiler and LLVM toolchains in separate directories or
containers. Record the executable hashes and effective versions in the
campaign. Do not replace a campaign tool with a moving release after evidence
has been collected.

## Install the base environment

On Ubuntu or Debian:

```bash
sudo apt update
sudo apt install -y \
  git openssl python3 python3-venv python3-pip pipx \
  curl unzip zip jq ripgrep \
  build-essential cmake ninja-build clang llvm lldb gdb \
  cppcheck z3 afl++ nodejs npm golang-go
```

On macOS with Homebrew:

```bash
brew install \
  git openssl python ripgrep jq \
  cmake ninja llvm lldb cppcheck z3 afl++ node go
```

Create a Krineon Python environment:

```bash
cd /path/to/krineon
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install \
  PyYAML tree-sitter tree-sitter-languages z3-solver playwright
```

Playwright is optional. Krineon's owned-page browser runner can communicate
with Chrome directly over CDP.

## Install source-analysis tools

### Tree-sitter

Install the CLI separately from its Python modules:

```bash
npm install --global tree-sitter-cli
tree-sitter --version
```

### Trailmark

Install Trailmark as an isolated Python tool:

```bash
pipx install trailmark
trailmark --version
```

For campaign reproducibility, replace the unversioned package with a reviewed
version pin.

### Joern

Download a pinned Joern release from the
[official repository](https://github.com/joernio/joern), extract it under the
research tools directory, and add its `joern-cli` directory to `PATH`. Verify:

```bash
joern --version
joern-parse --help
joern-scan --help
```

Do not use Joern's Git-diff facilities for first-principles campaigns.

### Fraunhofer AISEC CPG

Build a pinned AISEC CPG release with only the required language frontends.
Expose its standalone `cpg-neo4j` launcher on `PATH`. Follow the detailed
[AISEC CPG integration guide](aisec-cpg.md) and the
[official project](https://github.com/Fraunhofer-AISEC/cpg).

### Z3

The base packages install the Z3 CLI. Install the Python binding inside
Krineon's environment:

```bash
. .venv/bin/activate
python -m pip install z3-solver
z3 -version
```

### Semgrep and OpenGrep

Install Semgrep in an isolated environment:

```bash
pipx install semgrep
semgrep --version
```

Install a pinned OpenGrep release from the
[official repository](https://github.com/opengrep/opengrep), place `opengrep`
on `PATH`, and run `opengrep --version`.

### CodeQL

Download and extract a pinned CodeQL CLI bundle from the
[official releases](https://github.com/github/codeql-cli-binaries/releases).
Add the extracted directory to `PATH` and verify:

```bash
codeql version
```

Install the language query packs required by the target and retain their lock
files with the campaign.

### REA

Install REA through its
[official repository](https://github.com/morluto/rea) and provider
documentation. Put the resulting `rea` launcher on `PATH` and verify:

```bash
rea --version
```

REA remains an optional shipped-artifact assistant. Its decompiler output is
not a vulnerability verdict.

## Install language-specific analyzers

### SVF

SVF and the compiler that produces the target bitcode must use compatible LLVM
revisions. Build a reviewed SVF release in a dedicated directory:

```bash
git clone https://github.com/SVF-tools/SVF.git /opt/krineon-tools/svf
cd /opt/krineon-tools/svf
git checkout REVIEWED_SVF_TAG_OR_COMMIT
source ./build.sh
```

Add the directory containing `wpa` to `PATH`, then verify:

```bash
wpa --help
```

Use the same pinned Clang and LLVM revision to create `.ll` or `.bc` input.
Retain debug information and value names when possible.

### PhASAR

Build PhASAR against the LLVM revision selected for the target:

```bash
git clone --recurse-submodules \
  https://github.com/secure-software-engineering/phasar.git \
  /opt/krineon-tools/phasar
cd /opt/krineon-tools/phasar
git checkout REVIEWED_PHASAR_TAG_OR_COMMIT
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DPHASAR_LLVM_VERSION=SELECTED_LLVM_VERSION
cmake --build build --parallel
```

Add `build/tools/phasar-cli` to `PATH` and verify:

```bash
phasar-cli --help
```

PhASAR requires LLVM IR. Debug information materially improves precision and
result mapping.

### Pysa

Use a dedicated environment for Pyre and Pysa:

```bash
python3 -m venv /opt/krineon-tools/pysa-venv
. /opt/krineon-tools/pysa-venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install pyre-check fb-sapp
pyre --version
```

Initialize and review `.pyre_configuration`, search paths, taint models, and
rules inside the target before running the Krineon pipeline. Do not disable
model verification merely to obtain a clean-looking report.

### Infer Pulse

On macOS:

```bash
brew install infer
infer --version
```

On Linux, download a pinned binary release from
[Infer releases](https://github.com/facebook/infer/releases), extract it under
`/opt/krineon-tools`, add its `bin` directory to `PATH`, and verify
`infer --version`. Building Infer from source is possible but substantially
more expensive than using its release bundle.

### Go call graphs

Install the official `x/tools` command and then record the module version
embedded in the binary:

```bash
go install golang.org/x/tools/cmd/callgraph@latest
callgraph --help
go version -m "$(command -v callgraph)"
```

For a campaign, rebuild from an explicitly pinned `x/tools` version instead of
`latest` and retain the output of `go version -m`.

## Install native build and fuzzing tools

The base packages provide Clang, LLVM, CMake, Ninja, GDB or LLDB, cppcheck,
and AFL++. Install these additional tools only when the selected lane needs
them:

- [Docker Engine](https://docs.docker.com/engine/install/) for disposable
  production-equivalent services and builds.
- [Fuzzilli](https://github.com/googleprojectzero/fuzzilli) and Swift for V8
  REPRL campaigns.
- `llvm-profdata`, `llvm-cov`, and `llvm-symbolizer` from the same LLVM release
  used to build the target.
- `minidump_stackwalk` from a pinned Breakpad build for Chromium minidumps.
- Xcode command-line tools, LLDB, `atos`, `codesign`, `lipo`, `otool`, and
  `dwarfdump` for macOS targets.

For Chromium and V8, install a pinned
[`depot_tools`](https://chromium.googlesource.com/chromium/tools/depot_tools/)
checkout and expose `gclient`, `gn`, and `autoninja`. Keep depot_tools and the
target revision frozen for the evidence run.

## Install web-application tools

Install Chrome or Chromium from its official distribution. Use a disposable
profile for every campaign.

Burp Suite MCP must be installed and enabled in Burp and connected to Codex,
OpenCode, or OMP separately. Follow [Burp MCP integration](burp-mcp.md).
Krineon never reads browser credentials directly from disk.

Install supporting Go tools with reviewed version pins:

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
nuclei -version
ffuf -V
```

Replace `latest` with exact versions before a campaign evidence run. Nuclei and
ffuf remain bounded supporting adapters; their availability does not authorize
broad scanning.

## Verify the installation

From the Krineon repository:

```bash
scripts/tool_probe.py
scripts/tool_probe.py --json --output tool-inventory.json
```

Review unavailable and installed-but-unusable results. A tool is ready only
when its capability probe succeeds. Preserve `tool-inventory.json` with the
campaign so reviewers can distinguish missing coverage from a negative result.

