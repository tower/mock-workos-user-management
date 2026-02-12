# mock-workos-user-management

In-memory mock of the WorkOS User Management API for local development and testing. Point the `workos-go` SDK at it instead of the real API. No WorkOS account needed.

## Setup

```
cp seed.example.json seed.json  # add your test users, orgs, memberships
go run ./cmd/mock-workos-user-management --seed seed.json
```

Listens on `:8091` by default.

## Using with the WorkOS SDK

Set the `Endpoint` on the SDK clients to the mock server:

```go
umClient := &usermanagement.Client{
    APIKey:     "anything",
    Endpoint:   "http://localhost:8091",
    HTTPClient: http.DefaultClient,
    JSONEncode: json.Marshal,
}

orgClient := &organizations.Client{
    APIKey:     "anything",
    Endpoint:   "http://localhost:8091",
    HTTPClient: http.DefaultClient,
    JSONEncode: json.Marshal,
}
```

From there, `CreateUser`, `GetUser`, `AuthenticateWithPassword`, `CreateOrganization`, `CreateOrganizationMembership`, and `ListOrganizationMemberships` all work as normal. Authentication returns a real HMAC-SHA256 JWT with `sub`, `org_id`, and `sid` claims.

## Seed data

Pre-populate users, organizations, and memberships via a JSON file:

```json
{
  "users": [
    {"id": "user_01EXAMPLE", "email": "alice@dev.local", "password": "abc123", "email_verified": true}
  ],
  "organizations": [
    {"id": "org_01EXAMPLE", "name": "Dev Org"}
  ],
  "memberships": [
    {"user_id": "user_01EXAMPLE", "organization_id": "org_01EXAMPLE"}
  ]
}
```

Pass it with `--seed`:

```
go run ./cmd/mock-workos-user-management --seed seed.json
```

IDs are optional. They'll be generated if omitted. Passwords are bcrypt-hashed at load time.

## Config

| Flag | Env | Default |
|---|---|---|
| `--addr` | `MOCK_WORKOS_ADDR` | `:8091` |
| `--seed` | `MOCK_WORKOS_SEED` | (none) |
| `--signing-key` | `MOCK_WORKOS_SIGNING_KEY` | built-in dev key |

State lives in memory and resets on restart.
