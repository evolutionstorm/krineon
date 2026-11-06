# Application fixture broker

Krineon's application fixture broker runs a hash-pinned owned client, SDK,
service integration, or test application without exposing its credentials to
research workers. The historical `sdk_fixture_broker.py` entry point remains
available; `application_fixture_broker.py` is the provider-neutral name.

## Security boundary

The coordinator defines one schema-v2 fixture configuration. It identifies:

- the exact executable, arguments, working directory, and hashed artifacts;
- zero or more private `secret://` references, environment bindings, and
  optional prefix, length, or full-pattern validation;
- constant non-secret environment values;
- zero or more exact outbound host and port pairs;
- the line-delimited control protocol and readiness event;
- admitted operations, JSON fields and types, payload sizes, and call limits;
- total operation, proxy-connection, and transferred-byte budgets.

Workers receive a fixture ID and admitted operation names. They do not receive
credentials, the control token, an unrestricted shell, or permission to invent
new destinations or operations.

The broker:

- verifies every declared artifact before each start;
- requires every worktree file named by the command to be hash-pinned;
- resolves multiple secrets privately and redacts their literal and base64
  forms from retained evidence;
- exports an authenticated loopback-only control interface;
- forwards only payloads that satisfy the operation's field and type policy;
- routes standard proxy-aware clients through an exact CONNECT allowlist;
- supports explicit private or loopback endpoints only when the configuration
  sets `allowPrivate` for that exact host and port;
- records a hash-chained operation, process, and proxy transcript; and
- persists budgets across broker restarts.

The proxy is an application-level boundary. A fixture can bypass it if the
client ignores proxy environment variables or opens sockets itself. Therefore,
only admit coordinator-reviewed, hash-pinned fixture code. Use an operating
system network sandbox as an additional boundary for hostile or complex
clients.

## Fixture protocol

The child process writes one readiness event to stdout:

```text
KRINEON_RPC {"kind":"event","type":"ready"}
```

It then reads JSON objects from stdin. Each request contains an opaque `id`, an
`operation`, and only the fields admitted for that operation. It returns:

```text
KRINEON_RPC {"kind":"response","id":"...","ok":true,"result":{}}
```

The prefix, readiness-event name, and child shutdown operation are configurable.
`status`, `restart`, and `shutdown` are broker operations. All other admitted
`fixture` operations are forwarded unchanged after schema validation.

## Configure and run

Copy `assets/sdk-fixture-broker.template.json` and replace its paths, hashes,
secret bindings, endpoints, operations, and budgets. Import credentials once
with `web_secret_store.py`; never put secret literals in the fixture config.

Validate without resolving secrets or making a network request:

```text
scripts/application_fixture_broker.py validate /path/to/application-broker.json
```

Start the fixture:

```text
scripts/application_fixture_broker.py start /path/to/application-broker.json
```

Invoke an admitted operation with a complete JSON payload:

```text
scripts/application_fixture_broker.py control CONFIG owned-operation \
  --worker WORKER --payload-json '{"resourceId":"owned-1","input":{}}'
```

The generic control form works for any fixture. The old LaunchDarkly shorthand
flags remain available for schema-v1 configurations during migration.

## Schema-v1 compatibility

Existing `provider: launchdarkly-node` configurations continue to load. The
broker normalizes them into the universal internal model while retaining the
original documented LaunchDarkly endpoints, operation schemas, secret-key
format checks, and budgets. New fixtures should use schema version 2.

## Evidence and replay

Evidence is retained under
`evidence/application-fixtures/FIXTURE_ID/`:

- `manifest.json` binds the configuration, command artifacts, secret references
  and environment names, endpoints, operations, and budgets;
- `events.jsonl` is a hash-chained transcript;
- fixture stdout and stderr logs are redacted; and
- `budget-state.json` makes restarts unable to reset limits.

Independent replay must verify the same source artifacts, create fresh owned
fixtures where the application permits it, use a fresh worker identity, and
re-execute the minimal operation sequence. Re-reading an originator's response
is not independent replay.
