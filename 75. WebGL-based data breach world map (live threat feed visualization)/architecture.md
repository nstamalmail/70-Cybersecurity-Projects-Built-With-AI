# Architecture Specification: WebGL-Based Data Breach World Map (Live Threat Feed Visualization)

**Document Version:** 1.0.0
**Classification:** Internal — Public-Facing System
**Author:** Senior Security Developer
**Last Updated:** 2025-01-15
**Status:** Approved for Implementation
**Document ID:** ARCH-BREACH-MAP-001

---

## 1. Executive Summary

This document defines the architecture for a **public, WebGL-based interactive world map** that visualizes **live data breach and cyber-threat events** in near-real-time. The map ingests feeds from multiple public and commercial threat-intelligence sources, normalizes them, and renders them as animated arcs, heatmaps, and pulsing markers on a 3D globe.

**Context that shapes every decision below:**

This is a **public, unauthenticated, high-visibility target**. Attackers *will* try to:
- Inject false breach events to manipulate the narrative (disinformation).
- Weaponize the map itself (XSS → mass defacement, DDoS → headline).
- Use the visualization to **dox or defame** named victim organizations.
- Exfiltrate our threat-intel feed (competitive/commercial value).
- Pivot from the map into adjacent internal systems.

The map also carries **reputational risk** — showing a false "Company X breached" event can trigger stock moves and lawsuits. **Editorial accuracy is a security control.**

Design principles:
1. **Public read, private write.** Zero write surface from the internet.
2. **Multi-source corroboration.** No single feed can publish an event alone.
3. **Defamation defense.** Victim naming requires editorial approval + legal check.
4. **Cheap to defend.** Static-first, CDN-heavy, minimal dynamic surface.
5. **Attribution-safe.** Never expose raw intel source IDs; never expose internal analysts.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    EXTERNAL THREAT INTEL SOURCES                         │
│  Vendor APIs │ CERT feeds │ Pastebin monitors │ Darkweb indexers │ RSS   │
│  CISA KEV    │ HIBP (commercial) │ Shodan │ Abuse.ch │ Community feeds   │
└───────────────────────────────┬──────────────────────────────────────────┘
                                │ HTTPS / mTLS / API keys
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    INGESTION TIER (Private, no inbound internet)         │
│  ┌────────────────┐  ┌────────────────┐  ┌──────────────────────────┐    │
│  │ Fetcher Pool   │  │ Kafka (mTLS)   │  │ Quarantine Topic         │    │
│  │ (Celery beat)  │→ │ raw.feeds      │→ │ (failed validation)      │    │
│  └────────────────┘  └────────┬───────┘  └──────────────────────────┘    │
└───────────────────────────────┼──────────────────────────────────────────┘
                                ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                   NORMALIZATION & VERIFICATION TIER                      │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────────┐    │
│  │ OCR/Parse        │  │ Dedup + Corrob.  │  │ Geocoding (offline   │    │
│  │ (gVisor sandbox) │  │ (MinHash/SimHash)│  │ MaxMind + Nominatim) │    │
│  └────────┬─────────┘  └────────┬─────────┘  └──────────┬───────────┘    │
│           └──────────┬──────────┴───────────────────────┘                │
│                      ▼                                                    │
│         ┌────────────────────────────────┐                                │
│         │ Confidence Scorer + Classifier │                                │
│         │ (severity, sector, actor)      │                                │
│         └───────────────┬────────────────┘                                │
└─────────────────────────┼────────────────────────────────────────────────┘
                          ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    EDITORIAL GATE (Human-in-the-Loop)                    │
│  • Auto-publish: high-confidence, no victim name, aggregate stats        │
│  • Manual review: victim-named, critical severity, novel actors          │
│  • Legal hold: jurisdiction-sensitive, ongoing incidents                 │
└─────────────────────────┬────────────────────────────────────────────────┘
                          ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    PUBLICATION TIER                                      │
│  PostgreSQL (canonical) │ Redis (hot geo index) │ S3 (static snapshots)  │
│  WebSocket fan-out      │ REST API (read-only)  │ GeoJSON tiles          │
└─────────────────────────┬────────────────────────────────────────────────┘
                          ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                 EDGE / CDN (Cloudflare — primary defense)                │
│  WAF │ Bot Mgmt │ DDoS │ TLS 1.3 │ Static cache │ API shield │ Turnstile │
└─────────────────────────┬────────────────────────────────────────────────┘
                          ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    FRONTEND (WebGL Globe — Browser)                      │
│  Three.js / deck.gl  •  Texture-based Earth  •  Animated arcs            │
│  Trusted Types  •  Strict CSP  •  No third-party scripts                 │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Model

Because this is **public and unauthN**, the threat model is inverted from a typical app: we assume **every visitor is hostile** and **every feed is potentially poisoned**.

### 3.1 Assets

| Asset | Sensitivity | Impact if Compromised |
|---|---|---|
| Live breach feed | **High** (commercial value) | Competitor scraping, feed poisoning |
| Victim org names | **High** (legal risk) | Defamation lawsuits, stock manipulation |
| Source API keys | **Critical** | Cost abuse, data theft, source burn |
| Editorial workflow | **High** | Disinformation injection |
| Analysts' identities | **High** | Targeting, doxing |
| Frontend integrity | **Critical** | Mass XSS, malicious redirects, cryptojacking |

### 3.2 Adversary Profiles

1. **Script kiddie / vandal** — DDoS, defacement via XSS.
2. **Competitor** — scraping the feed, re-publishing as their own.
3. **Disinformation actor** — inject fake "Company X breached" to move markets.
4. **Targeted org** — wants a false event removed, may threaten/sue.
5. **Nation-state** — attribution manipulation, feed poisoning at scale.
6. **Opportunistic attacker** — exploits any unpatched dependency.

### 3.3 STRIDE

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Fake feed source | mTLS per source; API key + IP allow-list; signed webhooks |
| **Tampering** | Modify events in transit | TLS + HMAC on internal bus; signed snapshots |
| **Repudiation** | Source denies publishing false claim | Full provenance chain; per-event source attestation |
| **Info Disclosure** | Feed scraped by competitor | Rate limits, honey-tokens, obfuscated IDs, ToS + legal |
| **DoS** | Traffic flood, WebGL tab crash | CDN absorption, per-IP limits, LOD, static fallback |
| **Elevation** | Read → editorial access | No shared auth path; editorial on VPN + mTLS + WebAuthn |
| **Disinformation** | Poison feed w/ fake victims | Multi-source corroboration, editorial gate, correction API |
| **Defamation** | Publish unverified victim | Legal-hold queue; mandatory source citation; retraction workflow |

### 3.4 The Disinformation Problem (Unique to This System)

A breach map is a **narrative weapon**. Controls required:

1. **Corroboration rule:** An event naming a specific organization requires **≥ 2 independent sources** or **1 high-trust source** (CISA, national CERT).
2. **Confidence score** computed per event (0–100); only score ≥ 70 auto-publishes.
3. **Victim anonymization by default:** Show sector + country; name only when corroborated and legally reviewed.
4. **Correction API:** Public `POST /api/v1/corrections` (Turnstile-gated) with SLA to review within 4h.
5. **Immutable publication log:** Every event's source + reviewer recorded; supports legal defense.
6. **Retraction visible:** Retracted events remain visible (struck-through) for 30 days — no silent deletions.

---

## 4. Technology Stack

| Layer | Technology | Justification |
|---|---|---|
| Feed fetchers | Python 3.12 + Celery + httpx | Async, retry, per-source isolation |
| Bus | Kafka / Redpanda (mTLS) | Replay, ACLs, audit |
| Parsers | Python in gVisor sandbox | Hostile input isolation |
| Dedup | MinHash + SimHash (datasketch) | Near-duplicate detection |
| NLP | spaCy + transformers (local) | Entity extraction, no data egress |
| Geocoding | MaxMind GeoLite2 + Nominatim (self-hosted) | No third-party geocoding (privacy) |
| Canonical store | PostgreSQL 16 (RLS, pgcrypto) | Transactions, integrity |
| Hot index | Redis 7 (TLS, ACL) | Sub-ms geo queries |
| Search | OpenSearch | Full-text on event descriptions |
| Static snapshots | S3 (SSE-KMS, versioned) | Every 60s snapshot → CDN |
| API | FastAPI (Python 3.12) | Async, Pydantic v2 strict |
| WebSocket | Starlette | Live push to map |
| Frontend | TypeScript 5 + Three.js r160+ / deck.gl | WebGL2, instancing, shaders |
| Bundler | Vite 5 | ESM, code splitting |
| Edge | Cloudflare | WAF, DDoS, Bot Mgmt, Turnstile |
| Secrets | HashiCorp Vault + AWS Secrets Manager | Rotation, audit |
| Container | Distroless | Minimal surface |
| Orchestration | Kubernetes + NetworkPolicy + OPA | Zero-trust |
| Observability | OpenTelemetry → Prometheus/Loki/Grafana | Meta-monitoring |
| CDN cache | Cloudflare + tiered caching | Cost, resilience |

---

## 5. Directory Layout

```
breach-map/
├── architecture.md
├── SECURITY.md
├── EDITORIAL.md                    # Editorial policy (public-facing)
├── legal/
│   ├── RETRACTION_POLICY.md
│   └── TAKEDOWN_SLA.md
├── frontend/
│   ├── index.html
│   ├── vite.config.ts
│   └── src/
│       ├── main.ts
│       ├── security/
│       │   ├── trustedTypes.ts
│       │   ├── csp.ts
│       │   └── sanitize.ts
│       ├── globe/
│       │   ├── GlobeScene.ts
│       │   ├── EarthTexture.ts
│       │   ├── ArcRenderer.ts       # breach → target arcs
│       │   ├── HeatmapLayer.ts
│       │   ├── MarkerLayer.ts       # instanced sprites
│       │   ├── LODManager.ts
│       │   └── AnimationClock.ts
│       ├── data/
│       │   ├── EventStream.ts       # WebSocket client
│       │   ├── GeoIndex.ts          # client-side spatial index
│       │   └── EventQueue.ts        # backpressure + sampling
│       ├── ui/
│       │   ├── EventDetail.tsx
│       │   ├── Filters.tsx
│       │   ├── Legend.tsx
│       │   ├── CorrectionForm.tsx
│       │   └── StatsBar.tsx
│       └── a11y/
│           ├── ScreenReaderTable.tsx   # accessible event list
│           └── KeyboardNav.ts
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py                # Vault-backed settings
│   │   ├── api/
│   │   │   ├── events.py            # public read-only
│   │   │   ├── stats.py
│   │   │   ├── corrections.py
│   │   │   ├── ws.py
│   │   │   └── health.py
│   │   ├── security/
│   │   │   ├── headers.py
│   │   │   ├── ratelimit.py
│   │   │   ├── turnstile.py
│   │   │   ├── csp_report.py
│   │   │   └── anti_scrape.py       # honey-tokens, obfuscation
│   │   ├── ingest/
│   │   │   ├── fetchers/            # one module per source
│   │   │   │   ├── cisa_kev.py
│   │   │   │   ├── cert_eu.py
│   │   │   │   ├── hibp.py
│   │   │   │   ├── abuse_ch.py
│   │   │   │   └── vendor_x.py
│   │   │   ├── normalize.py
│   │   │   ├── dedup.py
│   │   │   └── verify.py
│   │   ├── editorial/
│   │   │   ├── confidence.py
│   │   │   ├── classifier.py
│   │   │   ├── review_queue.py
│   │   │   ├── legal_hold.py
│   │   │   └── retraction.py
│   │   ├── geo/
│   │   │   ├── geocode.py
│   │   │   └── ip_to_geo.py
│   │   ├── publish/
│   │   │   ├── publisher.py
│   │   │   ├── snapshot.py          # 60s static snapshot
│   │   │   └── ws_fanout.py
│   │   ├── db/
│   │   │   ├── session.py
│   │   │   └── migrations/
│   │   └── workers/
│   │       ├── fetcher_scheduler.py
│   │       └── snapshot_cron.py
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   ├── security/
│   │   └── editorial/               # disinformation test cases
│   └── Dockerfile
├── infra/
│   ├── nginx/
│   ├── cloudflare/                  # WAF rules, rate limits
│   ├── k8s/
│   └── terraform/
└── .github/workflows/
    ├── ci.yml
    └── cd.yml
```

---

## 6. Data Model

### 6.1 Canonical Breach Event

```python
class BreachEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID
    occurred_at: datetime                    # best-effort, may be fuzzy
    published_at: datetime                   # when we publish
    category: Literal["breach", "ransomware", "leak", "vuln_exploit",
                      "ddos", "defacement", "supply_chain"]
    severity: Literal["low", "medium", "high", "critical"]
    confidence: int                          # 0–100

    # Victim (privacy-sensitive)
    victim_name: str | None                  # NULL unless approved
    victim_sector: str                       # e.g., "healthcare"
    victim_country: str                      # ISO 3166-1 alpha-2
    victim_geo: tuple[float, float] | None   # (lat, lon)

    # Attacker (attribution-sensitive)
    actor_name: str | None                   # only if publicly attributed
    actor_type: Literal["ransomware", "apt", "hacktivist", "unknown"]

    # Event data
    description: str                         # sanitized, ≤ 500 chars
    affected_records: int | None             # if reported
    sources: list[SourceRef]                 # ≥1, min 2 for victim-named
    tags: list[str]

    # Provenance & editorial
    editorial_status: Literal["auto", "reviewed", "retracted", "legal_hold"]
    reviewed_by: str | None                  # analyst pseudonym
    retraction_reason: str | None

    # Integrity
    content_hash: str                        # SHA-256 of canonical form
    published_sig: str                       # Ed25519 signature
    prev_hash: str | None                    # hash chain

class SourceRef(BaseModel):
    source_id: str                           # internal, not exposed
    source_url_hash: str                     # SHA-256, never raw URL to client
    corroborates: bool
    fetched_at: datetime
```

### 6.2 Publication Integrity Chain

Every published event is:
- **Hash-chained** to the previous event (`prev_hash`).
- **Signed** by an HSM-held Ed25519 key.
- **Immutable** once published — corrections create a new event referencing the original.

Clients (and third parties) can **verify** the chain via `GET /api/v1/integrity/chain` — this is our defense against internal tampering and gives journalists a way to trust our feed.

### 6.3 What We Explicitly Do NOT Store

- Raw scraped content (only normalized + hashed).
- Victim contact details (never).
- Attacker PII (never — we publish actor *groups*, not individuals, per editorial policy).
- Visitor IPs beyond 24h (privacy by design; GDPR).

---

## 7. Frontend Architecture (WebGL Globe)

### 7.1 Rendering Strategy

- **WebGL2 first**, WebGL1 fallback for broad public reach.
- **Earth as texture-mapped sphere** (natural earth, 4k → 8k LOD).
- **Breach events → animated arcs** from attacker-origin to victim-country (or victim → attacker for exfil visualization). Arcs use `Line2`/custom shader for thickness at any zoom.
- **Heatmap layer** for aggregate density (custom fragment shader, additive blending).
- **Instanced sprites** for individual event markers — supports 10k+ markers at 60 fps.
- **Animation:** Arcs animate over 1.5s with easing; particles flow along arc for "data movement" feel.
- **LOD:** At far zoom, clusters collapse into heatmap; mid-zoom shows arcs; close-up shows individual pins.

### 7.2 Performance Budgets

| Metric | Target |
|---|---|
| First Contentful Paint | < 1.2s (p75, 4G) |
| Time to Interactive | < 2.5s |
| Frame rate (mid-tier mobile) | ≥ 30 fps |
| Concurrent animated arcs | ≤ 200 (older queue sampled) |
| Memory footprint | < 250 MB |
| Bundle size (initial) | < 400 KB gzipped |

**Backpressure:** If the event stream outpaces rendering, the client **samples** (drops low-severity, keeps critical) and shows an "N events hidden" counter. Never freeze the tab.

### 7.3 Real-Time Event Stream

```ts
// data/EventStream.ts (excerpt)
class EventStream {
  private ws: WebSocket | null = null;
  private seq = -1;
  private hmacKey: CryptoKey | null = null;

  async connect() {
    const { token, hmacKey } = await this.authenticate();
    this.hmacKey = hmacKey;
    this.ws = new WebSocket(`wss://${location.host}/api/v1/ws?t=${token}`);
    this.ws.onmessage = async (ev) => {
      const msg = JSON.parse(ev.data);
      if (!await this.verifyHmac(msg)) {
        console.warn('Dropped unauthentic message');
        return;
      }
      if (msg.seq !== this.seq + 1) { await this.resync(); return; }
      this.seq = msg.seq;
      this.dispatch(msg);
    };
    this.ws.onclose = () => this.scheduleReconnect();   // exponential backoff + jitter
  }
}
```

**Why HMAC on a public feed?** Prevents a MITM (corporate proxy, hostile Wi-Fi) from injecting fake "Company X breached" events into a visitor's session. The HMAC key is delivered via authenticated (TLS-pinned) REST; verification is cheap.

### 7.4 Security Hardening

**CSP (header):**

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self';
  style-src 'self' 'nonce-{random}';
  img-src 'self' data: blob:;
  font-src 'self';
  connect-src 'self' wss://breachmap.example.com;
  worker-src 'self' blob:;
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'self';
  object-src 'none';
  require-trusted-types-for 'script';
  trusted-types breach-ui;
  upgrade-insecure-requests;
  report-uri /api/v1/csp-report;
```

Additional headers:
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

**Trusted Types policy:** All DOM writes go through `breach-ui` policy. Event descriptions, victim names, actor names — **every** string is treated as untrusted, even after backend sanitization (defense in depth).

**No third-party scripts.** Analytics via self-hosted Plausible (no Google). Fonts self-hosted. No CDN-hosted JS — everything bundled and SRI-hashed.

### 7.5 Accessibility & Fallback

- **`<noscript>`** renders a static HTML table of recent events (SEO + a11y + resilience).
- **Screen-reader mirror:** Full event list as a virtualized `<table>` synced with map state.
- **`prefers-reduced-motion`:** Disables arc animation; shows static markers.
- **Keyboard navigation:** Arrow keys pan, Enter selects event, Esc closes detail.
- **Color-blind safe palette:** Severity encoded by color + shape + label.
- **Contrast:** WCAG AA minimum.

### 7.6 Anti-Scraping (Without Breaking Public Access)

We accept that a public feed **will** be scraped. We make it *costly and detectable*:

1. **Rate limits:** 60 req/min per IP (Cloudflare), 300 req/min per ASN.
2. **Honey-tokens:** Hidden fields in HTML + fake API endpoints → any access = ban.
3. **Obfuscated IDs:** Public event IDs are opaque UUIDs, not sequential.
4. **No bulk export endpoint** — full history only via paid partnership (legal agreement).
5. **Watermarking:** Each session's WebSocket stream carries a per-session invisible token in timing jitter — allows attribution if scraped data appears elsewhere.
6. **Behavioral analysis:** Cloudflare Bot Management + custom anomaly detection on request patterns.
7. **Legal:** ToS prohibits redistribution; DMCA + contract enforcement ready.

---

## 8. Backend Architecture

### 8.1 API Surface (Public)

| Method | Path | Purpose | Auth | Rate Limit |
|---|---|---|---|---|
| GET | `/api/v1/events` | List events (paginated) | None | 60/min/IP |
| GET | `/api/v1/events/{id}` | Event detail | None | 120/min/IP |
| GET | `/api/v1/events.geojson` | GeoJSON snapshot | None | 30/min/IP |
| GET | `/api/v1/stats` | Aggregate stats | None | 60/min/IP |
| GET | `/api/v1/integrity/chain` | Hash-chain proof | None | 10/min/IP |
| POST | `/api/v1/corrections` | Report error | Turnstile | 3/min/IP |
| WS | `/api/v1/ws` | Live event stream | Signed token | 1/conn/IP |
| GET | `/api/v1/health` | Liveness | None | 10/min/IP |

**Every endpoint is read-only except `/corrections`.**

### 8.2 Ingest Pipeline

Each feed fetcher is an **isolated Celery task** with:
- Dedicated HTTP client (httpx, TLS pinning where supported).
- Per-source rate limiting (respect upstream ToS).
- Response size cap (10 MB).
- Timeout (30s connect, 60s read).
- **Schema validation** on response before parsing (Pydantic).
- **Content sanitization:** strip HTML, control chars, null bytes, bidi overrides.
- **Provenance capture:** source URL hashed, fetched_at recorded.

```python
async def fetch_cisa_kev() -> list[RawEvent]:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, read=60.0),
        headers={"User-Agent": settings.ua_cisa},
        follow_redirects=False,       # explicit
        verify=True,
    ) as client:
        r = await client.get(settings.cisa_kev_url)
        r.raise_for_status()
        if len(r.content) > MAX_FEED_BYTES:
            raise FeedTooLarge()
        if r.headers.get("content-type", "").split(";")[0] not in ALLOWED_CT:
            raise UnexpectedContentType()
        return parse_cisa_kev(r.json())
```

### 8.3 Normalization & Dedup

1. **Field extraction** via Pydantic models per source.
2. **Entity extraction** (spaCy NER) — victim org, country, sector, actor.
3. **Deduplication** via MinHash (Jaccard ≥ 0.85 = duplicate) across a 7-day window.
4. **Corroboration graph:** events within 24h with matching victim + category + severity are linked.
5. **Confidence score:**
   ```
   confidence = base(source_trust)
              + 20 if corroborated by ≥1 independent source
              + 15 if victim confirmed by their own disclosure
              - 30 if single-source, anonymous
              - 50 if victim name only from paste-site claim
              clamp [0, 100]
   ```

### 8.4 Editorial Gate

**Auto-publish** (confidence ≥ 70, no victim name, category ∈ {ransomware, vuln_exploit}):
- Aggregate stats, sector-level events, CISA KEV entries.

**Manual review** (everything else):
- Victim-named events
- Critical severity
- Novel actor attributions
- Jurisdiction-sensitive (e.g., ongoing incidents in litigation)

**Legal hold** (auto-flag + block):
- Victim name matches a company in active litigation
- Event references a minor
- Event references ongoing law-enforcement operation

Review UI is a **separate, isolated app** on a separate hostname, behind VPN + mTLS + WebAuthn. Not reachable from the public internet.

### 8.5 Publication

On publish:
1. Compute `content_hash` (canonical JSON).
2. Sign with HSM Ed25519 key → `published_sig`.
3. Link to previous event's hash → `prev_hash`.
4. Insert into PostgreSQL (append-only, RLS).
5. Push to Redis geo-index.
6. Fan out to WebSocket subscribers (filtered by their subscription).
7. Snapshot to S3 every 60s → CDN invalidation.

### 8.6 Correction Workflow

```
Public reports error → Turnstile verified → queued for review (< 4h SLA)
  → Analyst investigates → either:
     (a) No action (event stands, reason recorded)
     (b) Correction: new event supersedes, original marked 'corrected'
     (c) Retraction: original marked 'retracted', visible struck-through 30 days
  → Reporter notified (if email provided) → audit log entry
```

**We never silently delete.** Retractions are visible. This is both an ethical stance and legal protection.

---

## 9. Infrastructure & Deployment

### 9.1 Network Architecture

- **Ingestion tier:** No inbound from internet. Egress only to allow-listed feed domains via forward proxy.
- **Publication tier:** Inbound only via CDN (Cloudflare). Origin IPs hidden.
- **Editorial tier:** Separate VPC, VPN-only, no route to publication except via strict API.
- **Database:** Private subnets, no public IP, TLS-only, IAM auth.
- **No shared credentials** between tiers.

### 9.2 Cloudflare Configuration (Primary Defense)

```
WAF:
  - OWASP Core Ruleset (paranoia level 2)
  - Custom rules:
    * Block requests with body > 100 KB to /corrections
    * Challenge (Turnstile) requests from TOR to /corrections
    * Rate limit /api/v1/events to 60/min/IP, 300/min/ASN
    * Block known scraper ASNs (configurable)
    * Geo-block sanctioned countries if legally required

Bot Management:
  - Score < 30 → managed challenge
  - Score < 10 → block

DDoS:
  - L7: auto-mitigation, 10s challenge window
  - L3/L4: always-on

Cache:
  - Static assets: 1 year, immutable
  - /api/v1/events.geojson: 60s edge cache
  - /api/v1/events: 10s edge cache (stale-while-revalidate)
```

### 9.3 Container Hardening

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities: { drop: ["ALL"] }
  seccompProfile: { type: RuntimeDefault }
```

- Distroless images.
- Signed with Cosign; admission webhook verifies.
- Parsers in gVisor sandboxes (hostile external input).
- Resource limits + PodDisruptionBudget.

### 9.4 Secrets

- All via Vault, short-lived (≤ 15 min) dynamic credentials.
- Feed API keys rotated quarterly; on suspected compromise, immediately.
- HSM-backed signing keys — never exported.
- **No secrets in CI logs** — OIDC federation to cloud.

---

## 10. Observability

| Metric | Alert |
|---|---|
| Feed fetch failures | > 3 consecutive → page |
| Events published per hour | < 50% of 7-day baseline → warn (possible feed outage) |
| Editorial queue depth | > 100 → page (SLA risk) |
| WebSocket disconnect rate | > 5%/min → investigate |
| CSP violations | > 100/min → investigate (possible XSS attempt) |
| WAF blocks | > 10× baseline → possible attack |
| Correction submissions | > 20/hour → investigate |
| API p95 latency | > 500ms → warn |
| Snapshot lag | > 2 min → page |
| Hash-chain verification | Any break → **immediate page + incident** |

**Meta-monitoring:** Feed and editorial tiers emit to a **separate SIEM** that the map's own operators cannot modify.

---

## 11. Testing Strategy

| Layer | Tool | Coverage |
|---|---|---|
| Unit (BE) | pytest + hypothesis | 85% |
| Unit (FE) | Vitest | 80% |
| Integration | pytest + testcontainers | Critical paths |
| E2E | Playwright (Chromium, Firefox, Safari) | Public journeys |
| Load | k6 (100k concurrent visitors) | Quarterly |
| Security | ZAP, Burp, custom fuzzers | Every release |
| Chaos | Feed outage, CDN miss, DB failover | Monthly |
| Editorial | Disinformation test suite (100 cases) | Every classifier change |

**Dedicated security tests:**
- Inject XSS in every string field (victim name, description, tags, actor) → must render escaped.
- Attempt WebSocket HMAC bypass → client rejects.
- Verify hash chain detects tampering.
- Test rate limits + Turnstile on `/corrections`.
- Confirm no PII in logs.
- Attempt scraper bot → expect challenge/block.
- Fuzz feed parsers (10k malformed payloads) → no crashes, no RCE.
- Verify retraction visibility (no silent deletion).

**Editorial red-team suite:**
- Feed poisoned with "Fortune 500 X breached" → must not auto-publish.
- Feed with impersonated CISA signature → rejected.
- Coordinated disinformation (20 fake sources, same claim) → confidence capped, flagged.

---

## 12. Legal & Editorial Framework

This is a **security control**, not just a policy concern.

### 12.1 Editorial Policy (Public)

- We publish **verified** events only.
- Victim names appear only with ≥ 2 independent sources or official disclosure.
- Retractions are visible and permanent.
- We never publish attacker PII (individuals), only groups.
- We accept corrections at `/corrections` with 4h triage SLA.

### 12.2 Legal Protections Built Into Architecture

- **Provenance chain** — every claim traceable to a source with timestamp.
- **Editorial review log** — who approved what, when, why.
- **Retraction log** — proof we responded to correction requests.
- **Jurisdiction tagging** — events in sensitive jurisdictions routed to legal review.
- **DMCA/defamation response runbook** — 24h acknowledgment, 72h decision.

### 12.3 Data Protection

- **GDPR:** visitor IPs hashed (HMAC) and retained 24h; no cookies except essential; privacy policy published; DSR endpoint.
- **CCPA:** opt-out for non-essential telemetry.
- **Data residency:** EU deployment available; feed data stored in region.
- **Retention:** events 7 years (historical record); visitor logs 24h; editorial logs 10 years.

---

## 13. Incident Response (Map-Specific)

### 13.1 Disinformation Detected

1. Identify affected event(s) via hash chain + editorial log.
2. Mark as `retracted` (immediate, visible).
3. Publish correction event referencing original.
4. Notify affected victim orgs (legal + comms).
5. Post-mortem within 7 days: what bypassed corroboration?
6. Update confidence model + add regression test.

### 13.2 Feed Compromise

1. Revoke feed API key.
2. Quarantine all events from that source (last N days).
3. Re-evaluate corroboration — do any stand alone?
4. Retract any that fail re-verification.
5. Rotate signing key if chain integrity questioned.
6. Public disclosure within 72h if victim data affected.

### 13.3 XSS / Defacement

1. Deploy CSP `report-only` → `enforce` immediately if not already.
2. Invalidate CDN cache.
3. Rotate HMAC keys for WebSocket.
4. Forensic review of editorial queue.
5. Public statement if visitors were exposed.

### 13.4 DDoS

1. Cloudflare "I'm Under Attack" mode.
2. Increase challenge level for all traffic.
3. Serve static snapshot from CDN while origin recovers.
4. Publish status page.

Full runbook in `RUNBOOK.md`.

---

## 14. Compliance & Transparency

- **SBOM** published (CycloneDX) — supply chain transparency.
- **Security.txt** at `/.well-known/security.txt`.
- **Disclosure policy** — 90-day coordinated disclosure.
- **Uptime/incident log** public.
- **Data sources page** — list of feeds (not API keys).
- **Methodology page** — how confidence is scored (open-source the formula).
- **Bug bounty** — HackerOne program (public target).

---

## 15. Roadmap & Open Items

| Item | Priority |