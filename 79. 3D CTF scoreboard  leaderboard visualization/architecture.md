# Architecture Specification: 3D CTF Scoreboard / Leaderboard Visualization

**Document Version:** 1.0.0
**Classification:** Internal — Public-Facing During Events
**Author:** Senior Security Developer
**Last Updated:** 2025-01-15
**Status:** Approved for Implementation
**Document ID:** ARCH-CTF-3D-001

---

## 1. Executive Summary

This document defines the architecture for a **WebGL-based 3D scoreboard and leaderboard visualization** for Capture-The-Flag (CTF) competitions — both internal (corporate red-team exercises) and public (conference/community events). The system renders live scoring as an animated 3D scene: bar/race charts, team "ships" progressing through puzzle nodes, and dynamic rank changes with cinematic transitions suitable for projection on a big screen.

**Context that shapes every decision:**

A CTF scoreboard is a **high-visibility, adversarial audience** target. The audience is *literally* a room full of hackers. Simultaneously:

1. **Live event, zero downtime tolerance.** A scoreboard that freezes mid-competition is a public failure. Availability is a headline.
2. **Integrity of scores is everything.** If scores can be tampered with — even briefly — the entire competition is void.
3. **Live public-facing during events.** Attack surface is exposed and probed continuously.
4. **Sensitive data flows through it.** Team names, player handles, sometimes corporate identities (internal CTFs), and *in some cases* flags (must never leak).
5. **Projection on a big screen.** Everything rendered is visible to hundreds of people — a single XSS is a public defacement.
6. **The scoreboard is a trusted oracle.** Teams make decisions based on what they see. Falsified rankings cause real competitive damage.
7. **Speed is theatrical.** Frame drops during a rank change kill the moment. Performance is a *feature*, not a metric.

**Design principles:**

1. **Scores are computed by the CTF platform, not the scoreboard.** The scoreboard is a **renderer**, not an authority. It never accepts score submissions directly from contestants.
2. **The scoreboard is read-only from the CTF platform.** One-way data flow; compromise of the scoreboard cannot affect the competition.
3. **The scoreboard is a Tier-0 asset during events.** Harden like it's production, because during an event it *is* production.
4. **Public display = public security.** Treat everything as if a competitor is trying to XSS the projection screen.
5. **Graceful degradation is mandatory.** If WebGL fails on the projector, fall back to a 2D chart in under 500ms.
6. **Never leak flags, hashes, or solve internals.** The scoreboard shows aggregates; specific flag content never crosses the boundary.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    CTF CHALLENGE PLATFORM (Authoritative)                │
│  • Flag submission service  • Solve validation  • Score computation      │
│  • Team management          • Challenge deployment                       │
│  ⚠ Separate system — scoreboard NEVER writes to it                       │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │ Push: signed score events (webhook/mTLS)
                               │ Pull: read-only REST (signed)
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    SCOREBOARD INGESTION (Read-Only)                      │
│  • Signature verification (Ed25519, from CTF platform HSM)               │
│  • Schema validation (Pydantic strict)                                   │
│  • Deduplication (idempotency by event_id)                               │
│  • Append-only event log (hash-chained)                                  │
│  • Score recomputation (verify against source)                           │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    STATE TIER                                            │
│  PostgreSQL (teams, challenges, solves, scores — append-only)            │
│  Redis (hot leaderboard, pub/sub for WS fan-out)                         │
│  S3 (event archive, snapshots, WORM audit)                               │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    SCOREBOARD API (FastAPI / Python 3.12)                │
│  • Read-only REST (public)  • WebSocket (live deltas)                    │
│  • Public metrics endpoint  • Health endpoint                            │
│  • No write endpoints — ever                                             │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    EDGE / CDN (Cloudflare — primary defense during event)│
│  • WAF (aggressive during event)  • Bot Mgmt  • DDoS L3/L4/L7            │
│  • Static asset caching  • Rate limits                                   │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│              PUBLIC 3D SCOREBOARD (WebGL — display + browser)            │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Three.js scene  •  Bar race / nodes / ships  •  Big-screen mode   │  │
│  │  Trusted Types  •  Strict CSP  •  HMAC WS  •  2D fallback          │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    ADMIN / OPERATOR CONSOLE (Restricted)                 │
│  • Manual score corrections (with audit)  • Announcement overlays        │
│  • Theme/scene selection  • Emergency 2D mode switch                     │
│  ⚠ Separate hostname, mTLS, IP allow-list, no public route               │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Model

### 3.1 Assets

| Asset | Sensitivity | Impact if Compromised |
|---|---|---|
| Score integrity | **Critical** | Competition voided, reputation destroyed |
| Team/player identity (internal CTFs) | **High** (PII) | Doxing, targeting |
| Challenge metadata (names, categories) | **Medium** | No direct impact; hints leak |
| Flag values or flag hashes | **Critical** | Competition trivialized |
| Live event state | **High** | Disruption during competition |
| Display projection integrity | **High** | Public defacement |
| CTF platform credentials | **Critical** | Full competition compromise |
| Admin console | **Critical** | Score manipulation, defacement |

### 3.2 Adversary Profiles

1. **Competitor (sophisticated)** — probing during the event, looking for score tampering, info leak, DoS.
2. **Script kiddie spectator** — casual probing, XSS attempts, bot traffic.
3. **Griefer** — wants to disrupt the event, cause chaos.
4. **Disgruntled ex-participant** — targeted attack, may have partial knowledge.
5. **Opportunistic attacker** — exploiting dependencies, misconfig.
6. **Insider (event staff)** — malicious or accidental score manipulation.
7. **Automated scanners** — background noise, must not distract.

### 3.3 STRIDE

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Fake score events | Ed25519 signature from CTF platform; mTLS |
| **Tampering** | Modify scores in transit/at rest | Signatures, hash chain, append-only storage |
| **Repudiation** | "I didn't submit that solve" | Full event log, platform is authority |
| **Info Disclosure** | Flag/hash leak via scoreboard | Strict field allow-list; no flag content ever crosses boundary |
| **DoS** | WS flood, REST flood | CDN, rate limits, concurrency caps |
| **Elevation** | Viewer → operator | Separate hostnames, mTLS, OPA |
| **Defacement** | XSS on projection | CSP, Trusted Types, sanitize all strings |
| **Score suppression** | Blocked WebSocket so team can't see | HMAC, seq numbers, resync via REST |
| **Replay** | Replay old score events | Idempotency by event_id; monotonic sequence |
| **Timing side-channel** | Infer solves from update timing | Batch updates (200ms windows) |

### 3.4 The Score Integrity Problem

**The scoreboard is not authoritative.** It has one job: **render the truth the CTF platform publishes.** Controls:

1. **Signed events.** Every score event arrives with an Ed25519 signature from the CTF platform's HSM. Invalid signature → dropped, not rendered.
2. **Hash chain.** Local event log is hash-chained; any tampering detectable.
3. **Monotonic sequence.** Events carry `seq` from the platform; gaps trigger resync, not interpolation.
4. **Idempotent ingestion.** Duplicate `event_id` → ignored.
5. **Recomputation.** Optionally recompute score locally from raw solves and compare — mismatch = alert + hide.

**If we cannot verify, we do not display.** A frozen "verifying" state is better than a wrong score.

### 3.5 The Flag Leak Problem

The scoreboard **must never** display or transmit:
- Flag values.
- Flag hashes.
- Challenge solution internals.
- Per-solve timing that could fingerprint flag formats.

**Field allow-list** (the *only* fields that cross the boundary):

```python
class ScoreEventField(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID
    team_id: str                    # public-safe identifier
    team_name: str                  # sanitized
    challenge_id: str
    challenge_name: str             # sanitized
    challenge_category: str
    challenge_points: int
    solved_at: datetime             # rounded to 1s for timing side-channel defense
    sequence: int
    signature: str                  # Ed25519
```

**Nothing else.** No flag, no hash, no filesystem paths, no solver identity unless the platform explicitly provides it.

---

## 4. Technology Stack

| Layer | Technology | Justification |
|---|---|---|
| CTF platform (external) | Existing (CTFd, custom, etc.) | Authority |
| Ingest | FastAPI + Pydantic v2 strict | Fast, typed |
| Message bus | NATS / Redis Streams (mTLS) | Low-latency, ordering |
| DB | PostgreSQL 16 | Transactions, append-only |
| Cache / pub-sub | Redis 7 (TLS, ACL) | Hot state, WS fan-out |
| Object store | S3 (SSE-KMS, versioned, Object Lock) | Event archive (WORM) |
| API | FastAPI (Python 3.12) | Async, typed |
| WS | Starlette + `wsproto` | Per-message auth |
| Task queue | Celery + Redis (TLS) | Snapshots, reports |
| Frontend | TypeScript 5 (strict) + Three.js r160+ | WebGL2, instancing |
| Bundler | Vite 5 | ESM, code splitting |
| Charts | Custom Three.js bar race | Full control, no 3rd party |
| Fallback | D3 or plain SVG 2D chart | For no-WebGL |
| Signing | Ed25519 (HSM-backed, both ends) | Event authenticity |
| Auth | OIDC + WebAuthn (admins) | Phishing-resistant |
| Secrets | HashiCorp Vault | Dynamic creds |
| Container | Distroless | Minimal surface |
| Orchestration | Kubernetes + OPA + NetworkPolicy | Zero-trust |
| Observability | OTel → Prometheus/Loki/Grafana + SIEM | Full-stack |
| CDN/Edge | Cloudflare | WAF, DDoS, TLS 1.3 |

---

## 5. Directory Layout

```
ctf-scoreboard-3d/
├── architecture.md
├── SECURITY.md
├── RUNBOOK.md                       # event-day procedures
├── EVENT_CHECKLIST.md
├── frontend/
│   ├── index.html
│   ├── vite.config.ts
│   └── src/
│       ├── main.tsx
│       ├── security/
│       │   ├── trustedTypes.ts
│       │   ├── csp.ts
│       │   └── sanitize.ts
│       ├── scene/
│       │   ├── SceneManager.ts
│       │   ├── BarRace.ts            # 3D bar race chart
│       │   ├── NodeGraph.ts          # challenge-node map
│       │   ├── ShipRace.ts           # optional "ship" theme
│       │   ├── RankTransitions.ts    # animated rank changes
│       │   ├── Announcements.ts      # overlay for events
│       │   └── BigScreenMode.ts      # projector-optimized layout
│       ├── data/
│       │   ├── EventStream.ts        # WS client w/ HMAC verify
│       │   ├── LeaderboardState.ts   # server-authoritative mirror
│       │   └── Resync.ts             # gap detection + resync
│       ├── ui/
│       │   ├── ScoreTable.tsx
│       │   ├── TeamDetail.tsx
│       │   ├── ChallengeList.tsx
│       │   ├── Clock.tsx             # event timer
│       │   └── AnnouncementBanner.tsx
│       ├── fallback/
│       │   └── TwoDLeaderboard.tsx   # no-WebGL equivalent
│       └── a11y/
│           ├── ScreenReaderMirror.tsx
│           └── KeyboardNav.ts
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py                 # Vault-backed
│   │   ├── api/
│   │   │   ├── leaderboard.py        # read-only
│   │   │   ├── challenges.py         # read-only
│   │   │   ├── teams.py              # read-only
│   │   │   ├── events.py             # public event log
│   │   │   ├── health.py
│   │   │   └── ws.py
│   │   ├── ingest/
│   │   │   ├── webhook.py            # signed score events
│   │   │   ├── verify.py             # Ed25519 verification
│   │   │   ├── dedup.py              # idempotency
│   │   │   ├── chain.py              # hash chain
│   │   │   └── recompute.py          # score recomputation
│   │   ├── state/
│   │   │   ├── leaderboard.py        # server-authoritative
│   │   │   ├── snapshot.py           # periodic snapshots
│   │   │   └── pubsub.py             # WS fan-out
│   │   ├── security/
│   │   │   ├── authn.py
│   │   │   ├── authz.py
│   │   │   ├── headers.py
│   │   │   ├── ratelimit.py
│   │   │   ├── ws_hmac.py
│   │   │   └── sanitize.py           # team names, etc.
│   │   ├── admin/
│   │   │   ├── corrections.py        # manual score fix (audited)
│   │   │   ├── announcements.py
│   │   │   └── kill_switch.py
│   │   ├── audit/
│   │   │   ├── emitter.py
│   │   │   └── worm_sink.py
│   │   └── db/
│   │       ├── session.py
│   │       └── migrations/
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   ├── security/
│   │   ├── load/                     # event-day simulation
│   │   └── chaos/                    # mid-event failure drills
│   └── Dockerfile
├── admin-console/                    # separate app, restricted
│   └── ...
├── infra/
│   ├── nginx/
│   ├── cloudflare/
│   ├── k8s/
│   │   ├── networkpolicy.yaml
│   │   ├── opa-policies/
│   │   └── pdb.yaml
│   ├── terraform/
│   └── vault/
└── .github/workflows/
    ├── ci.yml
    └── cd.yml
```

---

## 6. Data Model

### 6.1 Ingested Score Event (Append-Only)

```python
class ScoreEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: UUID
    sequence: int                    # monotonic from platform
    team_id: str
    team_name: str                   # sanitized
    challenge_id: str
    challenge_name: str
    challenge_category: str
    challenge_points: int
    solved_at: datetime              # rounded to 1s
    signature: str                   # Ed25519 by CTF platform

    # Local
    received_at: datetime
    chain_prev_hash: str
    chain_hash: str                  # sha256(prev || canonical(event))
    verify_status: Literal["verified", "rejected"]
```

**Storage is append-only.** No updates, no deletes. Corrections come as new events from the platform.

### 6.2 Leaderboard (Derived)

```python
class TeamScore(BaseModel):
    team_id: str
    team_name: str
    total_points: int
    solves: list[str]                # challenge_ids
    last_solve_at: datetime | None
    rank: int
    rank_prev: int | None            # for animated transitions
    rank_changed_at: datetime | None
```

**Derived state** is recomputed from the event log on every snapshot; not authoritative source of truth. If derived state and event log diverge → alert.

### 6.3 Challenge (Read-Only from Platform)

```python
class ChallengePublic(BaseModel):
    challenge_id: str
    name: str
    category: str
    points: int
    solves_count: int
    first_blood_team: str | None     # team_id
    release_time: datetime
    # NO flags, NO hashes, NO descriptions beyond safe public text
```

### 6.4 What Never Crosses the Boundary

- Flag values or hashes.
- Challenge source code or files.
- Per-solve timings more precise than 1 second.
- IP addresses of solvers.
- Submission attempts (only successful solves).
- Admin notes or internal challenge metadata.
- Any PII beyond team display name.

**Enforced by strict Pydantic models + CI test that fails if fields are added.**

---

## 7. Frontend Architecture (3D Visualization)

### 7.1 Visualization Modes

Multiple scene types, selectable by event organizer:

1. **Bar Race** — horizontal bars, animated rank swaps (classic race chart in 3D).
2. **Node Graph** — challenges as 3D nodes, teams as particles flowing to solved nodes.
3. **Ship Race** — thematic; teams as "ships" progressing along a course.
4. **Hex Grid** — teams as hexes on a board, color-coded by category strength.
5. **Big-Screen Mode** — top 10 teams, oversized fonts, animated transitions, sponsor banner.

**All modes share the same data contract.** Scene switching does not change backend.

### 7.2 Rendering Strategy

- **WebGL2 required** for 3D modes; WebGL1 falls back to 2D chart.
- **Instanced meshes** for team bars/nodes — handles 500+ teams at 60 fps.
- **GPU-side animations** via shader uniforms; CPU only updates data buffers.
- **Rank transitions:** 1.2s easing curve, particle trail effect on rank gain.
- **Announcements overlay:** separate DOM layer (not WebGL) for accessibility and dynamic content.
- **Projection mode:** 4K target, larger fonts, higher contrast, reduced motion optional.

### 7.3 Performance Budgets

| Metric | Target |
|---|---|
| First Contentful Paint | < 1s (big screen, wired) |
| WebSocket → visual update | < 250ms |
| Rank transition | 1.2s, no dropped frames |
| Sustained FPS (4K projection) | ≥ 60 |
| Concurrent teams rendered | 500+ |
| Frame time during rank swap | < 16ms |

**Backpressure:** If the client can't keep up, drop intermediate deltas but **never drop the final state** — always converge to authoritative snapshot.

### 7.4 WebSocket Protocol (HMAC-Verified)

```ts
type ClientMsg =
  | { type: 'subscribe'; channels: ('leaderboard' | 'announcements')[] }
  | { type: 'resync'; since_seq: number }
  | { type: 'ping' };

type ServerMsg =
  | { type: 'hello'; sessionId: string; hmacKeyId: string }
  | { type: 'snapshot'; seq: number; teams: TeamScore[]; challenges: ChallengePublic[] }
  | { type: 'delta'; seq: number; changes: Delta[] }
  | { type: 'announcement'; text: string; severity: 'info' | 'warning' | 'urgent' }
  | { type: 'error'; code: string };

// Every server message includes: hmac = HMAC-SHA256(payload || seq || sessionId)
```

**Client verifies HMAC before applying.** MITM (hostile Wi-Fi at a conference, malicious proxy) cannot inject fake scores.

**Sequence integrity:** Client tracks `seq`; gaps → resync via REST. Missing deltas are never silently ignored.

### 7.5 Trusted Types & XSS Prevention

**Team names, challenge names, announcements** — all attacker-influenced (competitors choose team names) — must be treated as hostile.

```ts
// security/trustedTypes.ts
if (window.trustedTypes) {
  trustedTypes.createPolicy('ctf-ui', {
    createHTML: () => { throw new Error('HTML creation forbidden'); },
    createScriptURL: (s) => { throw new Error('Script creation forbidden'); },
  });
}
```

**No `innerHTML`. Ever.** Team names rendered via `textContent` or React's safe rendering. CSP `require-trusted-types-for 'script'` enforces this at the browser.

**Sanitization pipeline (defense in depth):**

```python
# backend/app/security/sanitize.py
import unicodedata
import re

CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
BIDI_CHARS = re.compile(r"[\u202a-\u202e\u2066-\u2069]")
ZERO_WIDTH = re.compile(r"[\u200b-\u200f\u2060\ufeff]")

def sanitize_display_name(s: str, max_len: int = 60) -> str:
    # Normalize
    s = unicodedata.normalize("NFC", s)
    # Strip control + bidi + zero-width
    s = CONTROL_CHARS.sub("", s)
    s = BIDI_CHARS.sub("", s)
    s = ZERO_WIDTH.sub("", s)
    # Collapse whitespace
    s = re.sub(r"\s+", " ", s).strip()
    # Length cap
    if len(s) > max_len:
        s = s[:max_len]
    # Reject empty
    if not s:
        s = "[unnamed]"
    return s
```

**Bidi override defense** is critical — a team named `Alice‮evil` can visually reorder text on the projection, impersonating others. Bidi chars are stripped at ingest.

### 7.6 Security Hardening (Frontend)

**CSP (header):**

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self';
  style-src 'self' 'nonce-{random}';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self' wss://scoreboard.example.com;
  worker-src 'self';
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'none';
  object-src 'none';
  require-trusted-types-for 'script';
  trusted-types ctf-ui;
  upgrade-insecure-requests;
  report-uri /api/v1/csp-report;
```

Additional headers:
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store
```

### 7.7 2D Fallback (Mandatory)

If WebGL2 unavailable (old projector, restricted browser, GPU crash):

- **Auto-detect** at boot; fallback in < 500ms.
- **Equivalent content:** leaderboard table, rank changes highlighted, announcements.
- **No feature loss** for core functionality (scores, ranks, timer).
- **Manual override** in UI ("Switch to 2D mode") for reliability during events.

### 7.8 Accessibility

- **Screen-reader mirror:** Semantic table, ARIA live regions for rank changes.
- **Keyboard:** Full navigation, no mouse required.
- **High contrast mode** for projection.
- **Font scaling** to 200%.
- **`prefers-reduced-motion`:** disables transitions, keeps updates.
- **Color-blind palette:** team colors + shape/pattern differentiation.

---

## 8. Backend Architecture

### 8.1 API Surface (Read-Only Public)

| Method | Path | Purpose | Auth | Rate Limit |
|---|---|---|---|---|
| GET | `/api/v1/leaderboard` | Current standings | None | 60/min/IP |
| GET | `/api/v1/leaderboard/events` | Event log (paginated) | None | 60/min/IP |
| GET | `/api/v1/teams/{id}` | Team detail | None | 120/min/IP |
| GET | `/api/v1/challenges` | Challenge list + solve counts | None | 60/min/IP |
| GET | `/api/v1/announcements` | Current announcements | None | 60/min/IP |
| GET | `/api/v1/health` | Liveness | None | 10/min/IP |
| GET | `/api/v1/metrics` | Public metrics | None | 10/min/IP |
| WS | `/api/v1/ws` | Live stream | None (HMAC on messages) | 5/conn/IP |

**No write endpoints on the public API.** Admin console is a separate hostname with its own API surface.

### 8.2 Ingest Webhook (from CTF platform)

```python
@router.post("/internal/v1/score-events", dependencies=[Depends(verify_mtls)])
async def ingest_score_event(
    request: Request,
    body: ScoreEvent,
    _sig: None = Depends(verify_platform_signature),
):
    # Idempotency
    if await event_store.exists(body.event_id):
        return {"ok": True, "duplicate": True}

    # Sequence check
    last = await event_store.last_sequence()
    if body.sequence <= last:
        audit.warn("ingest.out_of_order", seq=body.sequence, last=last)
        return {"ok": True, "out_of_order": True}

    # Chain
    prev_hash = await event_store.head_hash()
    chain_hash = sha256(prev_hash + canonical(body))

    # Persist (append-only)
    await event_store.append(ScoreEvent(
        **body.model_dump(),
        received_at=utcnow(),
        chain_prev_hash=prev_hash,
        chain_hash=chain_hash,
        verify_status="verified",
    ))

    # Recompute leaderboard
    await leaderboard.apply(body)

    # Publish to WS fan-out
    await pubsub.publish("leaderboard.delta", leaderboard.delta_for(body))

    # Audit
    audit.emit("score.ingested", event_id=body.event_id,
               team_id=body.team_id, challenge_id=body.challenge_id)
    return {"ok": True}
```

**Properties:**
- **mTLS + Ed25519 signature** — only the CTF platform can publish.
- **Idempotent** — duplicate events ignored.
- **Monotonic sequence** — out-of-order events logged, not applied (platform will retry).
- **Hash chain** — tamper-evident.
- **No write path from public internet** — endpoint on internal network only.

### 8.3 Leaderboard State (Server-Authoritative)

The leaderboard is **derived** from the event log:

```python
class LeaderboardState:
    def __init__(self) -> None:
        self.teams: dict[str, TeamScore] = {}
        self.challenges: dict[str, ChallengeState] = {}

    def apply(self, event: ScoreEvent) -> Delta:
        team = self.teams.setdefault(event.team_id, TeamScore(
            team_id=event.team_id,
            team_name=event.team_name,
            total_points=0,
            solves=[],
            last_solve_at=None,
            rank=0,
            rank_prev=None,
            rank_changed_at=None,
        ))
        if event.challenge_id in team.solves:
            # Already solved — ignore (defensive)
            return Delta.empty()
        team.solves.append(event.challenge_id)
        team.total_points += event.challenge_points
        team.last_solve_at = event.solved_at

        old_ranks = {t.team_id: t.rank for t in self.teams.values()}
        self._recompute_ranks()
        return self._diff(old_ranks)

    def _recompute_ranks(self) -> None:
        # Sort by points desc, then by last_solve_at asc (earlier = better)
        ordered = sorted(
            self.teams.values(),
            key=lambda t: (-t.total_points, t.last_solve_at or datetime.max),
        )
        for i, t in enumerate(ordered, start=1):
            if t.rank != i:
                t.rank_prev = t.rank
                t.rank_changed_at = utcnow()
            t.rank = i
```

**Tie-breaking rule** (documented publicly): points descending, then earlier last-solve wins. Deterministic, auditable.

### 8.4 Snapshots

Every 5 seconds, the current leaderboard is snapshotted to:
- **S3** (for post-event archive, immutable).
- **Redis** (for fast new-client bootstrap).

New clients fetch snapshot + subscribe to deltas from that sequence. Prevents replay of the entire event history.

### 8.5 WebSocket Handler

```python
@router.websocket("/api/v1/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    session_id = uuid4().hex
    hmac_key = derive_ws_key(session_id)          # per-session key

    try:
        # Send hello with session ID (client uses for HMAC verification)
        await send_signed(ws, hmac_key, session_id, {
            "type": "hello", "sessionId": session_id,
        })

        # Initial snapshot
        snapshot = await leaderboard.snapshot()
        seq = snapshot.seq
        await send_signed(ws, hmac_key, session_id, {
            "type": "snapshot", "seq": seq, **snapshot.to_public(),
        })

        # Subscribe to deltas
        async for delta in pubsub.subscribe("leaderboard.delta"):
            seq += 1
            await send_signed(ws, hmac_key, session_id, {
                "type": "delta", "seq": seq, **delta.to_public(),
            })

    except WebSocketDisconnect:
        audit.debug("ws.disconnect", session_id=session_id)
    finally:
        await pubsub.unsubscribe(...)
```

```python
async def send_signed(ws, key, session_id, payload: dict) -> None:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    sig = hmac_sha256(key, f"{payload.get('seq', 0)}|{session_id}|{body}".encode())
    await ws.send_text(json.dumps({**payload, "hmac": sig.hex()}))
```

**Properties:**
- **Per-session HMAC key** — unique to each WS connection.
- **Signed payloads** — MITM cannot inject or modify.
- **Sequence numbers** — client detects gaps; resyncs.
- **Rate-limited** at edge (5 connections per IP).

### 8.6 Admin Console (Separate Hostname)

`admin.scoreboard.example.com` — isolated, restricted.

- **Auth:** OIDC + WebAuthn (mandatory MFA).
- **Network:** mTLS + corporate VPN + IP allow-list.
- **Capabilities:**
  - **Announcements:** overlay messages on all displays.
  - **Manual score corrections:** creates a new event with `correction_reason`, requires second approver.
  - **Scene selection:** switch visualization mode.
  - **Emergency 2D mode:** force all clients to 2D fallback.
  - **Kill switch:** freeze all updates (displays "PAUSED — REVIEW IN PROGRESS").
- **All actions hash-chained + audited.** Corrections visible in public event log.

### 8.7 Audit Logging

Every privileged action:

```json
{
  "ts": "2025-01-15T14:32:11Z",
  "actor": {"sub": "user:admin1", "roles": ["event_operator"], "mfa_ns": 1705329131123000000},
  "action": "score.correction",
  "resource": {"team_id": "team-42", "challenge_id": "web-3"},
  "outcome": "applied",
  "reason": "Platform bug — duplicate solve reported",
  "approver_2": "user:admin2",
  "prev_hash": "sha256:...",
  "signature": "ed25519:..."
}
```

- **Hash-chained, signed, WORM.**
- Corrections **visible in public event log** — transparency preserves trust.

---

## 9. Infrastructure & Deployment

### 9.1 Event-Day Hardening

During live events:

- **WAF paranoia level raised** to 3 (from 2).
- **Rate limits tightened** (public API 60/min → 30/min per IP).
- **Bot management aggressive** — most bots challenged.
- **Static asset caching** maximized to reduce origin load.
- **Autoscaling minimum** raised to handle 10× traffic.
- **On-call SRE** staffed with direct line to event organizers.
- **Rollback plan ready** — previous version can be redeployed in < 2 min.
- **Freeze deploys** during competition window (exception: emergency security patch).

### 9.2 Network Architecture

- **Ingest endpoint** on internal network only; reachable only from CTF platform.
- **Public API** on DMZ behind Cloudflare.
- **Admin console** on separate VPC, VPN-only, no public route.
- **Database** private subnet, TLS-only, IAM auth.
- **No shared credentials** between tiers.

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

- Distroless base.
- Cosign-signed images; admission webhook verifies.
- Resource limits + HPA.

### 9.4 Secrets

- Vault dynamic creds.
- Ed25519 signing keys in HSM — never exported.
- WS HMAC keys derived per-session from rotating master.
- CI/CD via OIDC federation.

### 9.5 High Availability

- **Multi-AZ** active-active for read paths.
- **Database:** primary + synchronous replica in separate AZ.
- **Redis:** cluster mode with replicas.
- **WebSocket fan-out:** Redis pub/sub with sticky routing OR a dedicated pub/sub tier (NATS).
- **Degraded mode:** if pub/sub fails, clients poll REST every 2s.

---

## 10. Observability

| Metric | Alert |
|---|---|
| Ingest signature failures | any → **page** |
| Hash chain break | any → **page + freeze** |
| Score recomputation mismatch | any → **page + hide affected scores** |
| WS disconnect rate | > 10%/min → investigate |
| API p95 latency | > 300ms → warn |
| WS → visual latency | > 500ms → warn |
| Leaderboard state divergence | any → **page** |
| CSP violations | > 50/min → investigate |
| WAF blocks | > 10× baseline → investigate |
| Public API rate-limit hits | > 100/min → investigate |
| Frame drops on display | > 5% → warn |

**Meta-monitoring:** Audit logs streamed to a separate SIEM the scoreboard operators cannot modify.

---

## 11. Testing Strategy

| Layer | Tool | Coverage |
|---|---|---|
| Unit (BE) | pytest + hypothesis | 90% |
| Unit (FE) | Vitest | 85% |
| Integration | pytest + testcontainers | Critical paths |
| E2E | Playwright (Chromium, Firefox, Safari) | Every scene mode |
| Load | k6 (50k concurrent WS, 5k solves/sec) | Every release |
| Security | ZAP, Burp, custom fuzzers | Every release |
| Chaos | WS partition, DB failover, pub/sub outage | Monthly |
| Visual | Snapshot tests per scene | Every release |
| Event simulation | Full mock event (teams solving, rank swaps) | Before every event |

**Dedicated security tests:**
- Attempt to send unsigned score event → rejected.
- Attempt to send from non-platform source → mTLS reject.
- Replay old event_id → idempotent, ignored.
- Out-of-order sequence → logged, not applied.
- Tamper with hash chain → detected, freeze.
- XSS via team name (all payloads) → escaped.
- Bidi override in team name → stripped.
- Zero-width chars in team name → stripped.
- Extremely long team name → truncated.
- XSS via challenge name → escaped.
- XSS via announcement → escaped.
- IDOR on team detail → no private data exposed.
- Rate limit bypass via headers → ineffective.
- WS injection attempt → HMAC verify fails client-side.
- Flag fields never appear in any API response (contract test).

**Event-day dry run (mandatory before every event):**
- Full mock competition with 100 teams, 50 challenges, 5000 solves.
- Rank swap stress test.
- WebSocket disconnect/reconnect storm.
- Display fallback trigger.
- Kill switch test.

---

## 12. Compliance & Ethics

- **Public display of team names** — competitors consent via registration.
- **Internal CTF** — participant names may be PII; access controlled.
- **GDPR:** minimal data (team name, handle, score); retention policy documented.
- **Event archive** — retained per organizer policy; deletable on request.
- **Transparency:** public event log; corrections visible; tie-breaking rules published.
- **Accessibility:** WCAG 2.2 AA mandatory; screen-reader parity for 2D fallback.
- **Ethics:** no hidden scoring, no algorithmic advantage to sponsors, no per-team timing leaks beyond 1s precision.

Full policy in `RUNBOOK.md`.

---

## 13. Incident Response (During Event)

### 13.1 Score Integrity Suspected

1. **Kill switch** — freeze updates, display "PAUSED — REVIEW IN PROGRESS."
2. Cross-check event log against CTF platform.
3. Contact platform admins directly (out-of-band).
4. If compromised: roll back to last verified snapshot; re-ingest from platform.
5. Announce to participants (transparency).
6. Post-event: full forensic review.

### 13.2 Defacement / XSS

1. Deploy CSP `report-only` → `enforce` (already enforced; verify).
2. Invalidate CDN.
3. Rotate WS HMAC keys.
4. Review ingest for malicious team names; sanitize + re-render.
5. Public statement.

### 13.3 DoS

1. Cloudflare "I'm Under Attack" mode.
2. Raise challenge level.
3. Serve static snapshot from CDN while origin recovers.
4. If WS unavailable, force 2D polling mode.

### 13.4 Platform Compromise (CTF Side)

1. **Kill switch** scoreboard.
2. Notify event organizers.
3. Do not ingest further events.
4. Preserve all local logs.
5. Await platform recovery + re-verification.

Full runbook in `RUNBOOK.md`.

---

## 14. Event-Day Checklist

Pre-event (T-24h):
- [ ] Load test passed at expected peak + 3×
- [ ] WAF paranoia level raised
- [ ] Autoscaling minimums raised
- [ ] On-call rotation confirmed
- [ ] Rollback plan rehearsed
- [ ] Display hardware tested (projector, resolution, color)
- [ ] 2D fallback verified
- [ ] Backup internet path verified

Event start (T-0):
- [ ] Health checks green
- [ ] WS latency < 250ms
- [ ] Snapshot cadence confirmed
- [ ] First solves flow through
- [ ] Display rendering 60 fps

During event:
- [ ] Monitor ingest signature failures
- [ ] Monitor leaderboard divergence
- [ ] Announcements flow correctly
- [ ] No unexpected rate-limit storms

Post-event:
- [ ] Final archive to S3 (WORM)
- [ ] Winner certificate generation
- [ ] Incident review if any
- [ ] WAF settings restored
- [ ] Autoscaling minimums restored

Full checklist in `EVENT_CHECKLIST.md`.

---

## 15. Roadmap & Open Items

| Item | Priority | Rationale |
|---|---|---|
| Multi-event concurrent mode | P2 | Multiple CTFs sharing platform |
| Historical event replay | P2 | Post-event analysis |
| Sponsor integration (safe) | P3 | Branding without XSS risk |
| WebGPU renderer path | P3 | 10× throughput; spec stabilizing |
| Federated scoreboard (cross-org) | P4 | Trust framework needed |
| Quantum-resistant signing | P3 | HSM vendor readiness |
| Public API keys for researchers | P3 | Scraping control |
| Stream overlay integration | P2 | Twitch/YouTube for remote viewers |

---

## 16. References

- OWASP ASVS v4.0.3 — Level 2
- OWASP Top 10 (2021)
- OWASP WebSocket Security Cheat Sheet
- NIST SP 800-53 Rev. 5 — Moderate baseline
- NIST SP 800-61r3 — Incident Handling
- W3C Trusted Types, CSP Level 3
- W3C WCAG 2.2 AA
- Khronos glTF 2.0 / WebGL 2.0 Specification
- CTFd documentation (platform reference)
- SLSA v1.0 — Build Level 3
- RFC 8032 — Ed25519
- Unicode UAX #9 — Bidi algorithm (for override defense)

---

**Approval:** Requires sign-off from **Security Lead**, **CTF Platform Owner**, and **Event Organizer** before production. Changes to **ingest signature scheme**, **field allow-list**, or **admin correction workflow** require re-review by all three.

**Review cadence:** Before every event (mandatory), plus quarterly, or upon: (a) incident, (b) platform change, (c) new scene mode, (d) rule change.

**Contact:** `ctf-scoreboard-security@example.com` — PGP key in `SECURITY.md`.

**Non-negotiables:**
- The scoreboard is read-only from the CTF platform. It never writes back.
- Every score event is signed. Unsigned = dropped.
- Flags, hashes, and solver IPs never cross the boundary.
- Team names are treated as hostile. Bidi and zero-width stripped.
- WS messages are HMAC-signed per session. MITM cannot inject.
- A 2D fallback exists and is tested before every event.
- Corrections are public and hash-chained. No silent score changes.
- Kill switch is one API call. Rehearsed before every event.
- The display never crashes. Degrades gracefully. Always converges to truth.