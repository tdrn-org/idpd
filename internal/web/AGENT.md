# AGENT.md — IdPD Web Frontend (`internal/web/`)

## Projektkontext

IdPD (Identity Provider Daemon) is an orchestrating identity provider suitable for production use as well as for test case
execution. Several identity schemes are supported (OAuth2/OIDC, SAML2, Forward). The actual user management is delegated to
a plugable userstore (either file or LDAP based).
The UI at hand is responsible for implementing the login UI, displaying user information and mantaining the user's 2nd factor
devices (e.g. TOTP, Security Key).

Das Frontend liegt in `internal/web/` und wird vom Go-Backend über `embed.FS` als
statisches Bundle ausgeliefert. Der Build-Output landet in `internal/web/build/`
(siehe `Makefile` → `clean`-Target: `rm -rf "internal/web/build"`).

---

## Stack

| Technologie       | Version / Hinweis                                      |
|-------------------|--------------------------------------------------------|
| SvelteKit         | **Svelte 5** – ausschließlich Runes-API                |
| Adapter           | `@sveltejs/adapter-static`, output: `build/`           |
| CSS               | **TailwindCSS v4** – kein `tailwind.config.js`         |
| Lokalisierung     | **Leichtgewichtiger i18n-Layer** (`$lib/i18n.ts`) – liest direkt aus `messages/{de,en}.json`. Keine externen Dependencies, kein Build-Step. |
| Icons             | `@lucide/svelte`                                       |
| Paketmanager      | `npm` (Makefile nutzt `$(NPM) --prefix internal/web`)  |
| TypeScript        | strict mode                                            |

> **Hinweis zu i18n:** Paraglide v2 wurde evaluiert und verworfen — der SvelteKit-Adapter ist deprecated, und die Message-Generierung funktionierte nicht zuverlässig. Der selbstgebaute Layer (`$lib/i18n.ts`) bietet die gleiche API (`m.key()`), keine Build-Abhängigkeiten, und die JSON-Dateien in `messages/` sind das Single Source of Truth auch für Go (`web.go` parsed sie serverseitig).

---

## Build-Integration mit Go

### Output-Verzeichnis

Das SvelteKit-Build muss nach **`internal/web/build/`** ausgeben:

```js
// svelte.config.js
import adapter from '@sveltejs/adapter-static';

export default {
  kit: {
    adapter: adapter({
      pages: 'build',
      assets: 'build',
      fallback: 'index.html',  // SPA-Fallback: Go leitet alle Nicht-API-Pfade hierher
      precompress: false,
    }),
  },
};
```

### Go embed.FS

Go bindet `internal/web/build/` und `internal/web/messages/` so ein:

```go
// internal/web/web.go
//go:embed all:build/*
var buildFS embed.FS

//go:embed all:messages/*
var messagesFS embed.FS
```

Go leitet alle Requests, die nicht mit `/api/` beginnen, auf `build/index.html` um.
Das ermöglicht clientseitiges SvelteKit-Routing.

### Build-Befehl (vom Makefile)

```bash
npm --no-progress --no-color --no-fund run --prefix internal/web build
```

Eigene Entwicklungsbefehle (aus `internal/web/`):

```bash
npm run dev    # Entwicklungsserver (Vite, HMR)
npm run build  # Produktions-Build → build/
npm run check  # svelte-check + TypeScript
```

---

## REST-API – Vollständige Referenz

Base Path: `/api/v1`
Backend-Port in Entwicklung: `9123` (konfigurierbar)

### Endpunkte

| Method | Path                   | Response-Typ           | Beschreibung                        |
|--------|------------------------|------------------------|-------------------------------------|
| GET    | `/api/v1/ping`         | `text/plain` `"ok"`    | Health-Check                        |
| GET    | `/api/v1/sensor`       | `SensorInfo[]`         | Alle laufenden Sensoren + Stats     |
| GET    | `/api/v1/rules/lmi`    | `string[]`             | Log-Matcher-Index-Namen             |
| GET    | `/api/v1/device/{id}`  | `DeviceInfo`           | Gerätedaten per ID                  |
| GET    | `/api/v1/connection`   | `ConnectionInfo[]`     | Alle geloggten Verbindungen         |

### TypeScript-Interfaces (spiegeln Go-Structs 1:1)

Diese Interfaces müssen in `$lib/types.ts` definiert sein und exakt den Go-Structs entsprechen.
Felder dürfen **nicht** umbenannt oder weggelassen werden.

```ts
// $lib/types.ts

export interface SensorInfo {
  name: string;           // Eindeutiger Name des Sensors
  type: string;           // Typ: syslog | accesslog | ...
  event_counter: number;  // Events seit Start
}

export interface DeviceInfo {
  id: string;
  address: string;
  network: string;
  hardware_address: string;
  hardware_vendor: string;
  dns: string;
  lat: number;
  lng: number;
  city: string;
  country: string;
  country_code: string;
}

export interface ConnectionInfo {
  id: string;
  server: DeviceInfo;
  client: DeviceInfo;
  service: string;
  status: 'granted' | 'denied' | 'error' | 'informational';
  count: number;
  first: number;  // Unix timestamp (ms)
  last: number;   // Unix timestamp (ms)
}
```

### API-Client (`$lib/api.ts`)

Alle API-Calls laufen zentral über `$lib/api.ts`. Keine direkten `fetch`-Aufrufe in Komponenten.

```ts
// $lib/api.ts
import type { SensorInfo, DeviceInfo, ConnectionInfo } from './types.js';

const BASE = '/api/v1';

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${path}`);
  return res.json() as Promise<T>;
}

export const api = {
  ping: ()                    => get<string>('/ping'),
  sensors: ()                 => get<SensorInfo[]>('/sensor'),
  lmis: ()                    => get<string[]>('/rules/lmi'),
  device: (id: string)        => get<DeviceInfo>(`/device/${id}`),
  connections: ()             => get<ConnectionInfo[]>('/connection'),
};
```

### Mock-Daten für Entwicklung ohne Backend

```ts
// $lib/mocks.ts
import type { SensorInfo, ConnectionInfo } from './types.js';

export const mockSensors: SensorInfo[] = [
  { name: 'accesslog/accesslog1#1', type: 'accesslog', event_counter: 8472 },
  { name: 'syslog/syslog1#1', type: 'syslog', event_counter: 3156 },
];

export const mockConnections: ConnectionInfo[] = [
  {
    id: 'c001',
    server: { id: 's1', address: '10.1.1.1', network: '10.1.0.0/16',
              hardware_address: 'aa:bb:cc:dd:ee:01', hardware_vendor: 'Cisco',
              dns: 'gateway.local', lat: 48.1351, lng: 11.5820,
              city: 'Munich', country: 'Germany', country_code: 'DE' },
    client: { id: 'c1', address: '192.168.1.42', network: '192.168.1.0/24',
              hardware_address: '11:22:33:44:55:66', hardware_vendor: 'Intel',
              dns: 'workstation.local', lat: 48.1351, lng: 11.5820,
              city: 'Munich', country: 'Germany', country_code: 'DE' },
    service: 'HTTPS',
    status: 'granted',
    count: 142,
    first: Date.now() - 86400000,
    last: Date.now(),
  },
  // ... weitere Einträge in der tatsächlichen Datei
];
```

---

## Design-System

### Farbpalette (verbindlich)

| Token             | Tailwind-Klasse      | Beschreibung                    |
|-------------------|----------------------|---------------------------------|
| Background        | `bg-slate-950`       | Haupt-Hintergrund               |
| Cards / Nav       | `bg-slate-900`       | Karten, Navbar                  |
| Glassmorphism     | `backdrop-blur-md`   | Navbar-Effekt                   |
| Accent Primary    | `text-indigo-400`    | Primärakzente, aktive States    |
| Accent Secondary  | `text-cyan-400`      | Sekundärakzente, Highlights     |
| Text Primary      | `text-white`         | Haupttext                       |
| Text Muted        | `text-stone-300`     | Sekundärtext, Labels            |
| Status OK         | `text-green-400`     | Status: granted / ok            |
| Status Error      | `text-red-400`       | Status: denied / error          |
| Status Warn       | `text-amber-400`     | Status: informational / warn    |
| Border            | `border-slate-700`   | Trennlinien, Card-Borders       |

**Dark Mode ist obligatorisch** – das gesamte UI ist dunkel (kein Light-Mode-Toggle nötig).

### Utility-Klassen (in `app.css` definiert)

```css
.glass { @apply bg-slate-900/80 backdrop-blur-md border-b border-slate-700/50; }
.card  { @apply bg-slate-900 border border-slate-700/50 rounded-lg; }
.badge { @apply px-2 py-0.5 rounded text-xs font-mono font-medium; }
```

### Navbar

- Glassmorphism: `glass` + `sticky top-0 z-50`
- Aktiver Link: `bg-indigo-500/10 text-indigo-400`
- Inaktiver Link: `text-stone-300 hover:bg-slate-800 hover:text-white`
- Icons von `@lucide/svelte`

### Verbindungsstatus-Badge

```svelte
<!-- $lib/components/ui/StatusBadge.svelte -->
<script lang="ts">
  import type { ConnectionInfo } from '$lib/types.js';
  import { m } from '$lib/i18n.js';

  let { status }: { status: ConnectionInfo['status'] } = $props();

  const config: Record<ConnectionInfo['status'], { cls: string; label: () => string }> = {
    granted:       { cls: 'badge text-green-400 bg-green-400/10 border border-green-400/20', label: () => m.status_granted() },
    denied:        { cls: 'badge text-red-400 bg-red-400/10 border border-red-400/20', label: () => m.status_denied() },
    error:         { cls: 'badge text-red-400 bg-red-400/10 border border-red-400/20', label: () => m.status_error() },
    informational: { cls: 'badge text-amber-400 bg-amber-400/10 border border-amber-400/20', label: () => m.status_informational() }
  };

  let current = $derived(config[status]);
</script>

<span class={current.cls}>{current.label()}</span>
```

---

## Svelte 5 – Pflichtregeln

Svelte 4 Syntax ist **verboten**. Der Agent muss ausschließlich Runes verwenden.

### Props

```svelte
<!-- ✅ Korrekt -->
<script lang="ts">
  let { title, count = 0 }: { title: string; count?: number } = $props();
</script>

<!-- ❌ Falsch: export let -->
```

### State & Derived

```svelte
<script lang="ts">
  let connections = $state<ConnectionInfo[]>([]);
  let loading = $state(true);

  let grantedCount = $derived(connections.filter(c => c.status === 'granted').length);

  $effect(() => {
    api.connections().then(data => {
      connections = data;
      loading = false;
    });
  });
</script>
```

### Events: Callback-Props statt `createEventDispatcher`

```svelte
<!-- ✅ Korrekt -->
<script lang="ts">
  let { onSelect }: { onSelect: (id: string) => void } = $props();
</script>
<button onclick={() => onSelect(item.id)}>...</button>
```

### Snippets statt `<slot>`

```svelte
<script lang="ts">
  import type { Snippet } from 'svelte';
  let { children }: { children: Snippet } = $props();
</script>
<div>{@render children()}</div>
```

---

## TailwindCSS v4

**Keine `tailwind.config.js` erstellen.** Konfiguration ausschließlich in `src/app.css`:

```css
/* src/app.css */
@import "tailwindcss";

@theme {
  --color-accent-primary: var(--color-indigo-400);
  --color-accent-secondary: var(--color-cyan-400);
}
```

Regeln:
- Kein `<style>`-Block in Svelte-Komponenten – ausschließlich Tailwind-Klassen im Template
- `@apply` nur in `app.css` für globale Basis-Styles (Scrollbar, Body, etc.)
- Kein CSS außerhalb von `app.css`

---

## i18n – Lokalisierung (`$lib/i18n.ts`)

Alle sichtbaren Texte müssen über `m.key()` aus `$lib/i18n.ts` laufen. Keine hardcodierten Strings im Template.

### Nachrichten verwenden

```svelte
<script lang="ts">
  import { m } from '$lib/i18n.js';
</script>

<h1>{m.connections_title()}</h1>
<p>{m.sensor_event_count()}</p>
```

### Nachrichten-Dateien

Jede neue Nachricht muss in **beide** Dateien eingetragen werden:

`messages/de.json`:
```json
{
  "connections_title": "Verbindungen",
  "sensor_event_count": "{count} Events"
}
```

`messages/en.json`:
```json
{
  "connections_title": "Connections",
  "sensor_event_count": "{count} events"
}
```

Der `$lib/i18n.ts`-Layer:
- Erkennt die Sprache via `navigator.language` (fällt auf `de` zurück)
- Exportiert `m` als Proxy, der `m.key()` → übersetzten String macht
- Die JSON-Dateien werden direkt importiert (Typ `Record<string, string>`)
- Go liest die gleichen JSON-Dateien serverseitig via `web.go` `initMessageTables()`

---

## Projektstruktur

```
internal/web/
├── web.go                           # Go embed.FS + serverseitige i18n-Message-Tables
├── src/
│   ├── app.css                      # TailwindCSS v4 Entry (@theme + utility classes)
│   ├── app.html
│   ├── app.d.ts
│   ├── hooks.server.ts              # Minimal (no-op)
│   ├── hooks.ts                     # Minimal (no-op)
│   ├── lib/
│   │   ├── api.ts                   # Zentraler API-Client (alle fetch-Calls)
│   │   ├── types.ts                 # TypeScript-Interfaces (spiegeln Go-Structs)
│   │   ├── mocks.ts                 # Mock-Daten für Dev ohne Backend
│   │   ├── i18n.ts                  # i18n-Layer (importiert messages/*.json)
│   │   ├── index.ts                 # Re-Export aller $lib-Module
│   │   └── components/
│   │       └── ui/
│   │           └── StatusBadge.svelte
│   └── routes/
│       ├── +layout.svelte           # Root-Layout: Glassmorphism-Navbar
│       ├── +layout.ts               # export const ssr = false
│       ├── +page.svelte             # Dashboard: Stats-Grid + Recent-Connections
│       ├── connections/
│       │   └── +page.svelte         # Verbindungstabelle (expandable rows)
│       ├── sensors/
│       │   └── +page.svelte         # Sensor-Card-Grid (10s Live-Polling)
│       └── rules/
│           └── +page.svelte         # Regel-Liste
├── messages/
│   ├── de.json                      # Deutsche Übersetzungen
│   └── en.json                      # Englische Übersetzungen
├── build/                           # Go embed.FS liest hier – gitignored
├── static/
├── svelte.config.js
├── vite.config.ts                   # Nur sveltekit() + tailwindcss() — kein Paraglide-Plugin
└── package.json
```

---

## Seitenkonzept

### `/` – Dashboard

- Stats-Grid: Aktive Sensoren, Verbindungen gesamt, Granted, Denied (4 Cards)
- Letzte 5 Verbindungen als kompakte Tabelle
- Link „Alle anzeigen →" zu `/connections/`
- Fallback auf Mock-Daten wenn API nicht erreichbar

### `/connections` – Verbindungstabelle

Daten von `GET /api/v1/connection`:

- Hauptspalten: Client-IP, Server-IP, Service, Status-Badge, Count, Last-Seen
- Progressive Disclosure: Klick auf Zeile expandiert Detail-Panel mit Client- und Server-DeviceInfos
- Leerer State mit Icon + Text

### `/sensors` – Sensor-Übersicht

Daten von `GET /api/v1/sensor`:

- Card-Grid (responsive: 1/2/3 Spalten)
- Pro Card: Sensor-Name, Typ, Event-Counter mit Icons
- Live-Polling alle 10s via `setInterval` (aufgeräumt in `onDestroy`-Return)
- Live-Indikator-Badge

### `/rules` – Log-Matcher-Regeln

Daten von `GET /api/v1/rules/lmi`:

- Liste von Regel-Indizes mit FileCode-Icon
- Leerer State

---

## Wichtige Konventionen

- **Keine Monster-Komponenten** – jede Komponente hat eine einzige Verantwortung
- **Kein direktes `fetch` in Komponenten** – immer `$lib/api.ts` nutzen
- **Alle Interfaces in `$lib/types.ts`** – Go-Structs 1:1 abbilden, snake_case JSON-Feldnamen beibehalten
- **`$lib/`-Alias** – niemals relative `../../`-Imports
- **`ssr = false`** im Root-`+layout.ts` – kein SSR, reine SPA
- **`npm`** – das Makefile nutzt `npm`, kein pnpm oder yarn einführen
- **i18n-Texte in `messages/*.json`** – werden sowohl von `$lib/i18n.ts` (client) als auch `web.go` (server) gelesen
- **`web.go` NICHT löschen** – es enthält die `embed.FS`-Direktiven und serverseitige i18n-Logik

---

## Häufige Fehler – VERMEIDEN

| ❌ Falsch                                    | ✅ Richtig                                          |
|----------------------------------------------|-----------------------------------------------------|
| `export let foo` (Svelte 4)                  | `let { foo } = $props()`                            |
| `$: bar = x * 2`                             | `let bar = $derived(x * 2)`                         |
| `<slot />`                                   | `{@render children()}`                              |
| `createEventDispatcher()`                    | Callback-Props                                      |
| `pages: 'dist'` im Adapter                   | `pages: 'build'` (Go erwartet `internal/web/build`) |
| `tailwind.config.js` erstellen               | Konfiguration via `@theme` in `app.css`             |
| `<style>` in Svelte-Komponenten              | Ausschließlich Tailwind-Klassen im Template         |
| Hardcodierte Texte im Template               | Immer `m.key()` aus `$lib/i18n.js`                  |
| `fetch('/api/v1/...')` direkt in Komponente  | `api.connections()` aus `$lib/api.ts`               |
| `web.go` löschen bei Cleanup                 | `web.go` ist Teil des Go-Packages – nicht löschen!  |
| Paraglide-Plugin in vite.config.ts           | Nur `sveltekit()` + `tailwindcss()`                  |

---

## Checkliste vor jedem Commit

- [ ] Kein Svelte-4-Syntax (kein `export let`, kein `$:`, kein `<slot>`)
- [ ] Alle UI-Texte über `m.key()` aus `$lib/i18n.js`, Schlüssel in `de.json` + `en.json`
- [ ] `svelte.config.js` → `adapter-static` mit `pages: 'build'` + `fallback: 'index.html'`
- [ ] `src/routes/+layout.ts` exportiert `export const ssr = false`
- [ ] Keine direkten `fetch`-Calls in Komponenten (nur `$lib/api.ts`)
- [ ] TypeScript-Interfaces in `$lib/types.ts`, JSON-Keys unverändert (snake_case)
- [ ] Kein `<style>`-Block in Svelte-Komponenten
- [ ] `vite.config.ts` enthält KEIN Paraglide-Plugin
- [ ] `web.go` existiert und ist nicht gelöscht
- [ ] `npm run build` erstellt `internal/web/build/` erfolgreich
- [ ] `make build` (vom Repo-Root) läuft durch (Go + Frontend zusammen)
