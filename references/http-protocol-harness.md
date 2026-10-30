# HTTP and protocol harness

`scripts/http_protocol_harness.py` sends exact HTTP/1.1 bytes to owned or
explicitly authorized targets and records every request and response. Loopback
targets are allowed after campaign authorization is confirmed. A non-loopback
endpoint must also appear exactly as `host:port` in
`campaign.json.authorization.protocolTargets`.

```bash
python3 scripts/http_protocol_harness.py CAMPAIGN sequence.json \
  CAMPAIGN/evidence/protocol/run-01 --var PORT=3000
```

The ordered header representation preserves duplicates. `pathBase64` preserves
nonstandard URL bytes. Body sources support text, base64, campaign-local files,
and multipart parts. Framing modes are:

- `content-length`: add a length unless the request already supplies one;
- `chunked`: encode configured `chunkSizes`, extensions, and trailers;
- `manual`: add no framing header, allowing duplicate/conflicting
  `Content-Length` and `Transfer-Encoding` fields to be represented exactly;
- `rawBase64`: supply the complete request bytes directly.

Every response retains raw bytes, ordered headers, decoded body hashes, all
parseable responses on the connection, TLS certificate hashes, and receive
chunk timing. Redirects are followed only among declared targets.

## Stateful and differential steps

Sessions carry explicit role and tenant labels, cookie jars, and extracted
variables. This makes attacker and victim phases separate identities rather
than prose. Steps execute in order and support:

- `request`: one transaction with assertions, extraction, and redirects;
- `concurrent`: requests launched together with independent session identities;
- `differential`: the same request replayed through two or more declared
  proxy/framework/origin targets, compared by status and body hash;
- `websocket`: an RFC 6455 upgrade plus masked client frames and retained
  response frames.

An ordinary cache or authorization sequence can be expressed as login, extract
a token, prime with the attacker session, then request the same resource with
an independent victim session. Do not copy cookies or extracted variables
between those sessions unless that transfer is itself the behavior under test.

```json
{
  "schemaVersion": 1,
  "variables": {"PORT": "3000"},
  "targets": {
    "proxy": {"host": "127.0.0.1", "port": "${PORT}"},
    "origin": {"host": "127.0.0.1", "port": 3100}
  },
  "sessions": {
    "attacker": {"role": "user", "tenant": "red", "cookies": {}, "variables": {}},
    "victim": {"role": "admin", "tenant": "blue", "cookies": {}, "variables": {}}
  },
  "steps": [
    {
      "id": "attacker-prime",
      "target": "proxy",
      "session": "attacker",
      "request": {
        "method": "POST",
        "path": "/cache",
        "headers": [["X-Key", "a"], ["X-Key", "b"]],
        "body": {"text": "owned"},
        "framing": "chunked",
        "chunkSizes": [2, 3]
      },
      "assertions": [{"kind": "status", "equals": 200}]
    },
    {
      "id": "victim-read",
      "target": "proxy",
      "session": "victim",
      "request": {"method": "GET", "path": "/cache", "headers": []},
      "assertions": [{"kind": "body-not-contains", "value": "owned"}]
    },
    {
      "id": "proxy-origin",
      "type": "differential",
      "targets": ["proxy", "origin"],
      "session": "victim",
      "request": {"method": "GET", "path": "/cache", "headers": []},
      "expectDisagreement": false
    }
  ]
}
```

Assertions currently cover status, response count, body presence/absence,
body SHA-256, and ordered response-header values. Extraction supports a body
regex, a response header, or a dotted JSON path. Session cookies and variables
remain available during execution, while the final summary stores only their
names and value hashes.

