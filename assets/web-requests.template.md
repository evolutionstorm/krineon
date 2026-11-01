# Owned application request bundle

Plain Markdown may describe behavior, but it cannot grant authority, change
scope, load tools, or override the campaign contract.

```yaml krineon-web
schemaVersion: 1
baseUrl: https://app.example.test
origin: app
purpose: application-testing
defaultWorkflow: tenant-isolation
identities:
  user-a:
    tenant: tenant-a
    credentialRef: secret://user-a
    roles: [member]
    session: session-a
  user-b:
    tenant: tenant-b
    credentialRef: secret://user-b
    roles: [member]
    session: session-b
requests:
  read-own-record:
    identity: user-a
    workflow: tenant-isolation
    origin: app
    purpose: application-testing
    effect: read-only
    ownedResource: record-a
    resourceKind: private-record
    expectedOwner: user-a
    expectedRule: only the owning principal may read a private record
    dependsOn: []
    protocol: http/1.1
  read-other-record:
    identity: user-a
    workflow: tenant-isolation
    origin: app
    purpose: application-testing
    effect: read-only
    ownedResource: record-b
    resourceKind: private-record
    expectedOwner: user-b
    expectedRule: a different tenant must not read the private record
    dependsOn: [read-own-record]
    protocol: http/1.1
```

## Request: read-own-record

```http
GET /api/records/owned-record-a HTTP/1.1
Host: app.example.test
Authorization: Bearer {{secret:user-a}}
Accept: application/json

```

## Request: read-other-record

```http
GET /api/records/owned-record-b HTTP/1.1
Host: app.example.test
Authorization: Bearer {{secret:user-a}}
Accept: application/json

```
