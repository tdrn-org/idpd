# AGENTS.md — idpd (Identity Provider Daemon)

## Project Identity

| Field | Value |
|------|------|
| Repository | `github.com/tdrn-org/idpd` |
| Module Path | `github.com/tdrn-org/idpd` |
| Go Version | `1.26` |
| Type | **Application** (Binary) |
| License | Apache 2.0 |

**Purpose:** Identity Provider Daemon. Provides OAuth2/OIDC, SAML2, and Forward-Auth as pluggable auth schemes behind a unified reverse-proxy-capable HTTP server.

---

## Build & Test

```bash
# Build (Application → Binary)
make build

# Test + Vet + Staticcheck
make check

# Format only
make fmt

# Update dependencies
make deps

# Generate Swagger docs (after API changes)
make generate

# Clean build artifacts
make clean
```

**Rule:** `make check` must pass before every commit.

---

## Architecture Overview

```
cmd/idpd/main.go          → Entry point
idpd.go                   → Kong CLI (run, version, template)
server.go                 → Server lifecycle (Start, Run, Shutdown, Close)
server_runtime.go         → Runtime adapter (dependency injection)

internal/
├── adapters/middleware/rest/  → REST API (/api/v1/ping, /api/v1/info)
├── buildinfo/                 → Build metadata (ldflags)
├── crypto/                    → Key generation (RSA, ECDSA, EdDSA, HMAC)
├── data/                      → Repository + transaction handling
│   └── model/                 → SQL models + schema migrations (embedded)
├── domain/                    → Domain types (SigningKey, UserSessionRequest)
├── i18n/                      → en/de language support
└── scheme/                    → 🔑 Plugin system for auth schemes
    ├── scheme.go              → Runtime + Handler interface
    ├── oauth2/                → Zitadel OP Provider (active, with stubs)
    ├── saml2/                 → Zitadel SAML (skeleton)
    └── forward/               → Forward Auth (skeleton)

oauth2client/              → Client-side OAuth2 flow (generic)
config/                    → TOML configuration with defaults
config_template.toml       → Embedded config template
```

### Dependency Direction (Hexagonal)

```
CLI → Server → scheme.Handler → zitadel/oidc OP
            ↘ data.Store → go-database → SQLite/Postgres/Memory
            ↘ REST API
```

**Discipline:** `domain/` has no external imports. `data/` knows `domain/`. `scheme/` knows `domain/` and `data/`. No backward imports.

---

## Key External Dependencies

| Package | Purpose |
|-------|-------|
| `github.com/zitadel/oidc/v3` | OAuth2/OIDC OP Provider (engine) |
| `github.com/zitadel/saml` | SAML2 Provider |
| `github.com/go-jose/go-jose/v4` | JOSE (JWK, JWT Signing) |
| `github.com/alecthomas/kong` | CLI framework |
| `github.com/tdrn-org/go-database` | DB abstraction |
| `github.com/tdrn-org/go-httpserver` | HTTP server wrapper |
| `github.com/tdrn-org/go-log` | Logging |
| `github.com/tdrn-org/go-conf` | Config binding |
| `github.com/tdrn-org/go-diff` | Config template diff |
| `github.com/swaggo/swag` | Swagger generator (tool) |

---

## Notable Design Decisions

### 1. Scheme Plugin System
Each auth scheme implements `scheme.Handler`:
```go
type Handler interface {
    Name() Name
    Mount(instance *httpserver.Instance)
}
```
Runtime dependencies are injected via `scheme.Runtime`, not global state.

### 2. OAuth2 Storage: Stub Phase
`internal/scheme/oauth2/storage.go` implements the Zitadel `op.Storage` interface with **~30 stub methods** (`logStub()`). 
- **Working:** `GetClientByClientID`, `SigningKey`, `SignatureAlgorithms`
- **Stubs:** All token/session/auth-request methods
- This is intentional — the OP infrastructure runs, real storage implementation is the next major step.

### 3. Key Rotation
Signing keys are automatically rotated:
- Active: 30 days (`DefaultSigningKeyActiveDuration`)
- Lifetime: 60 days (`DefaultSigningKeyLifetimeDuration`)
- Expired keys are automatically deleted during `GetSigningKey()`

### 4. Multi-Database
Supported via `go-database`:
- `memory` — In-memory (tests)
- `sqlite` — Local/development (schema: `schema.sqlite.1.sql`)
- `postgres` — Production (schema: `schema.postgres.1.sql`)

Schema migrations are embedded SQL files in `internal/data/model/`.

### 5. Build Info via ldflags
Version, timestamp, and command name are injected at build time via `-ldflags -X` into `internal/buildinfo/`. Dev builds show `<dev build>`.

### 6. Config Template Diff
`idpd template --diff /etc/idpd.toml` compares the current config against the embedded template — useful after upgrades.

---

## Current Status (2026-07-21)

- ✅ Server starts, OAuth2 OP Provider running
- ✅ REST API (ping, info) functional
- ✅ Client registration from config
- ✅ Key generation, rotation, persistence
- ✅ Multi-DB support
- 🚧 OAuth2 Storage: Token/session persistence missing
- 🚧 SAML2: Handler skeleton, no real integration
- 🚧 Forward-Auth: Name only defined

---

## Agent Notes

- **Before every commit:** `make check` must pass (applies to all tdrn-org projects)
- **Swagger:** After API changes, run `make generate`
- **Schema changes:** New SQL files in `internal/data/model/` require new `model.*SchemaScriptOption` constants
- **New auth schemes:** Implement `scheme.Handler`, register in `server.go` `startSchemeHandlers()`
- **Review focus:** `opStorage` stubs are the most critical unfinished area. Everything else is stable.
