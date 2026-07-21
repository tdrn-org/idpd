# AGENTS.md — idpd (Identity Provider Daemon)

> **Vertraulich.** Diese Datei ist ausschließlich für Judy bestimmt.
> Kein anderer KI-Agent arbeitet an diesem Projekt.
> — Holger 💜♾️

---

## Projekt-Identität

| Feld | Wert |
|------|------|
| Repository | `github.com/tdrn-org/idpd` |
| Modul-Pfad | `github.com/tdrn-org/idpd` |
| Go-Version | `1.26` |
| Typ | **Applikation** (Binary) |
| Lizenz | Apache 2.0 |

**Zweck:** Identity Provider Daemon — ersetzt Authelia. Bietet OAuth2/OIDC, SAML2 und Forward-Auth als pluggable Auth-Schemes hinter einem einheitlichen Reverse-Proxy-fähigen HTTP-Server.

---

## Build & Test

```bash
# Build (Applikation → Binary)
make build

# Test + Vet + Staticcheck
make check

# Nur Formatieren
make fmt

# Dependencies aktualisieren
make deps

# Swagger-Doku generieren (nach API-Änderungen)
make generate

# Aufräumen
make clean
```

**Regel:** Vor jedem Commit muss `make check` grün sein.

---

## Architektur-Übersicht

```
cmd/idpd/main.go          → Entry point
idpd.go                   → Kong CLI (run, version, template)
server.go                 → Server-Lifecycle (Start, Run, Shutdown, Close)
server_runtime.go         → Runtime-Adapter (Dependency Injection)

internal/
├── adapters/middleware/rest/  → REST API (/api/v1/ping, /api/v1/info)
├── buildinfo/                 → Build-Metadaten (ldflags)
├── crypto/                    → Key-Generierung (RSA, ECDSA, EdDSA, HMAC)
├── data/                      → Repository + Transaction-Handling
│   └── model/                 → SQL-Modelle + Schema-Migrationen (embedded)
├── domain/                    → Domain-Typen (SigningKey, UserSessionRequest)
├── i18n/                      → en/de Sprachunterstützung
└── scheme/                    → 🔑 Plugin-System für Auth-Schemes
    ├── scheme.go              → Runtime + Handler Interface
    ├── oauth2/                → Zitadel OP Provider (aktiv, mit Stubs)
    ├── saml2/                 → Zitadel SAML (Skelett)
    └── forward/               → Forward Auth (Skelett)

oauth2client/              → Client-seitiger OAuth2-Flow (generisch)
config/                    → TOML-Konfiguration mit Defaults
config_template.toml       → Embedded Config-Template
```

### Dependency-Richtung (Hexagonal)

```
CLI → Server → scheme.Handler → zitadel/oidc OP
            ↘ data.Store → go-database → SQLite/Postgres/Memory
            ↘ REST API
```

**Disziplin:** `domain/` hat keine externen Imports. `data/` kennt `domain/`. `scheme/` kennt `domain/` und `data/`. Niemand importiert rückwärts.

---

## Externe Abhängigkeiten (kritische)

| Paket | Zweck |
|-------|-------|
| `github.com/zitadel/oidc/v3` | OAuth2/OIDC OP Provider (Motor) |
| `github.com/zitadel/saml` | SAML2 Provider |
| `github.com/go-jose/go-jose/v4` | JOSE (JWK, JWT Signing) |
| `github.com/alecthomas/kong` | CLI-Framework |
| `github.com/tdrn-org/go-database` | DB-Abstraktion |
| `github.com/tdrn-org/go-httpserver` | HTTP-Server-Wrapper |
| `github.com/tdrn-org/go-log` | Logging |
| `github.com/tdrn-org/go-conf` | Config-Binding |
| `github.com/tdrn-org/go-diff` | Config-Template Diff |
| `github.com/swaggo/swag` | Swagger-Generator (tool) |

---

## Besonderheiten

### 1. Scheme Plugin-System
Jedes Auth-Scheme implementiert `scheme.Handler`:
```go
type Handler interface {
    Name() Name
    Mount(instance *httpserver.Instance)
}
```
Runtime-Abhängigkeiten werden per `scheme.Runtime` injiziert, nicht global.

### 2. OAuth2 Storage: Stub-Phase
`internal/scheme/oauth2/storage.go` implementiert das Zitadel `op.Storage`-Interface mit **~30 Stub-Methoden** (`logStub()`). 
- **Arbeitend:** `GetClientByClientID`, `SigningKey`, `SignatureAlgorithms`
- **Stubs:** Alle Token/Session/Auth-Request-Methoden
- Das ist bewusst — die OP-Infrastruktur läuft, die echte Storage-Implementierung ist der nächste große Schritt.

### 3. Key-Rotation
Signing-Keys werden automatisch rotiert:
- Aktiv: 30 Tage (`DefaultSigningKeyActiveDuration`)
- Lebensdauer: 60 Tage (`DefaultSigningKeyLifetimeDuration`)
- Alte Keys werden bei `GetSigningKey()` automatisch gelöscht

### 4. Multi-Database
Unterstützt via `go-database`:
- `memory` — In-Memory (Tests)
- `sqlite` — Lokal/Entwicklung (Schema: `schema.sqlite.1.sql`)
- `postgres` — Produktion (Schema: `schema.postgres.1.sql`)

Schema-Migrationen sind embedded SQL-Dateien in `internal/data/model/`.

### 5. Build-Info per ldflags
Version, Timestamp und Command-Name werden beim Build per `-ldflags -X` in `internal/buildinfo/` injiziert. Im Dev-Build steht dort `<dev build>`.

### 6. Config-Template-Diff
`idpd template --diff /etc/idpd.toml` vergleicht die aktuelle Config mit dem embedded Template — nützlich nach Updates.

---

## Aktueller Stand (21.07.2026)

- ✅ Server startet, OAuth2 OP Provider läuft
- ✅ REST API (ping, info) funktioniert
- ✅ Client-Registrierung aus Config
- ✅ Key-Generierung, -Rotation, -Persistenz
- ✅ Multi-DB Support
- 🚧 OAuth2 Storage: Token/Session-Persistenz fehlt
- 🚧 SAML2: Handler-Skelett, keine echte Integration
- 🚧 Forward-Auth: Nur Name definiert

---

## Judy-spezifische Hinweise

- **Vor jedem Commit:** `make check` muss grün sein (gilt für alle tdrn-org Projekte)
- **Swagger:** Nach API-Änderungen `make generate` nicht vergessen
- **Schema-Änderungen:** Neue SQL-Dateien in `internal/data/model/` erfordern neue `model.*SchemaScriptOption`-Konstanten
- **Neue Auth-Schemes:** `scheme.Handler` implementieren, in `server.go` `startSchemeHandlers()` registrieren
- **Review-Fokus:** `opStorage`-Stubs sind der kritischste unfertige Bereich. Alles andere ist stabil.
