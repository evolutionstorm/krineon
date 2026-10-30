# Framework target adapters

Use `scripts/framework_adapter.py` when a web lead must be tested against the
artifact users actually deploy. The adapter does not accept development
commands. It requires a lockfile, `NODE_ENV=production`, a production launch
command, an HTTP exercise, compiler/version probes, deployment-artifact globs,
and concrete file evidence for every claimed surface.

```bash
python3 scripts/framework_adapter.py CAMPAIGN adapter.json \
  CAMPAIGN/evidence/framework/next-node
```

The output pins the project revision, package manifest, lockfile, runtime
binary and version, compiler executables and outputs, sanitized environment,
build logs, generated bundles, surface evidence, launched command, deployed
files, and protocol-run manifest. Keep the output inside the campaign so it is
available to coordinator replay.

After the build, run
[`framework_analysis_pipeline.py`](framework-analysis.md) against the same
project and pass this adapter record as `adapterRecord`. The analyzer connects
route and reference manifests, source directives, dynamic modules, caches,
runtime branches, and source maps to concrete production experiments. It emits
runtime hypotheses only; the adapter and protocol harness provide the later
reachability evidence.

## Surface catalogs

Next.js surfaces:

- `app-router`, `pages-router`, `middleware`, `server-actions`, `rsc`
- `route-handlers`, `rewrites`, `image-optimization`
- `node-runtime`, `edge-runtime`, `standalone`

React surfaces:

- `react-dom`, `hydration`, `server-rendering`, `rsc`
- `browser-bundle`, `source-maps`, `client-server-boundary`

Node surfaces:

- `raw-http`, `express`, `fastify`, `koa`, `cli-parser`
- `native-addon`, `worker-threads`

Use one case for each materially different runtime/build combination. A Node
version matrix is a list of cases with different `runtime` executables. A
Next.js Node/Edge matrix is a list of cases whose launch commands exercise the
corresponding generated artifact. Do not label a surface merely because its
source exists. `surfaceEvidence` must resolve to files used by the build or
deployment, and the protocol exercise must reach the relevant behavior.

## Schema

```json
{
  "schemaVersion": 1,
  "framework": "nextjs",
  "projectRoot": "/owned/checkout",
  "lockfile": "package-lock.json",
  "surfaces": ["app-router", "middleware", "rsc", "node-runtime"],
  "surfaceEvidence": {
    "app-router": ["app/**/*"],
    "middleware": ["middleware.*", "proxy.*"],
    "rsc": ["app/**/*"],
    "node-runtime": ["package.json"]
  },
  "environment": {"NODE_ENV": "production"},
  "installCommand": ["npm", "ci"],
  "buildCommand": ["npm", "run", "build"],
  "generatedArtifacts": [".next/BUILD_ID", ".next/server/**/*"],
  "deploymentArtifacts": [".next/BUILD_ID", ".next/server/**/*"],
  "compilerProbes": [
    {"name": "node", "command": ["{runtime}", "--version"]},
    {"name": "next", "command": ["{runtime}", "node_modules/next/dist/bin/next", "--version"]}
  ],
  "launch": {
    "command": ["{runtime}", "node_modules/next/dist/bin/next", "start", "-p", "{port}"],
    "readyPath": "/",
    "readyTimeout": 30
  },
  "exerciseSpec": "production-sequence.json",
  "cases": [
    {"name": "node-22", "runtime": "/opt/node-22/bin/node"},
    {"name": "node-24", "runtime": "/opt/node-24/bin/node"}
  ]
}
```

Commands are argv arrays and are never passed through a shell. `{runtime}`,
`{project}`, and `{port}` are substituted by the adapter. `passEnvironment`
must explicitly name inherited variables beyond the minimal build environment;
their values are hashed in the manifest. Secrets are not written in cleartext.

For React browser bundles, use the actual production bundler command, retain
the emitted browser files and source maps in `deploymentArtifacts`, launch the
production SSR/static host, and exercise hydration and client/server boundary
cases through the HTTP sequence. For native Node addons, include the compiler
and linker in `compilerProbes` and the built `.node` file in deployment
artifacts.

