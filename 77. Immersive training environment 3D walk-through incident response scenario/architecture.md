# Architecture Specification: Immersive Training Environment — 3D Walk-Through Incident Response Scenario

**Document Version:** 1.0.0
**Classification:** Internal — Restricted (Training Content is Sensitive)
**Author:** Senior Security Developer
**Last Updated:** 2025-01-15
**Status:** Approved for Implementation
**Document ID:** ARCH-IR-TRAIN-3D-001

---

## 1. Executive Summary

This document defines the architecture for an **immersive, browser-based 3D training environment** where security and IT staff **walk through incident response (IR) scenarios** in first-person or third-person view. Trainees navigate a simulated data center / office / cloud-console, inspect compromised hosts, respond to alerts, and make decisions that branch the scenario.

**Why this system is unusual, and why the security bar is high:**

1. **The content itself is sensitive.** Scenarios encode real TTPs, real IOC patterns, and often mirror **actual past incidents** (with details altered). A leak of the training content leaks defensive playbooks and can reveal what we *don't* detect.
2. **Trainees are high-value accounts.** SOC analysts, IR leads, and executives. Compromising a training session = credential theft from privileged users on a shared platform.
3. **The environment is a shared multi-tenant sandbox.** One trainee's session must be cryptographically isolated from another's.
4. **It renders untrusted 3D content.** Scenario assets (GLB, textures, animations, voice-over) come from authors, contractors, and vendors — a supply-chain surface.
5. **It records trainee behavior.** Decision logs, timings, mistakes — sensitive HR-adjacent data requiring strict access control and retention policy.
6. **It integrates with real systems.** SSO, HR (rostering), LMS (SCORM/xAPI), and sometimes real SOAR/EDR for "hybrid" scenarios — an obvious pivot point into production.

**Design principles:**

1. **The training environment never touches production.** Hard network isolation; scenarios that reference production are redacted/simulated.
2. **Trainee sessions are cryptographically isolated.** Per-session keys; no shared state.
3. **Scenario content is signed and versioned.** Authors sign; platform verifies.
4. **Trainee telemetry is PII-adjacent.** Encrypted, access-controlled, retention-bounded.
5. **The system assumes a hostile trainee.** Trainees are security professionals — they will probe, break, and try to exfiltrate the scenario.
6. **Realism is a security requirement.** The simulation is only valuable if it feels real; the platform must not leak its own internals through errors, timing, or asset names.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     CLIENT (Browser — WebGL2 / WebXR)                    │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Three.js Scene  •  First/third-person controls  •  React UI       │  │
│  │  Trusted Types  •  Strict CSP  •  Per-session key  •  WASM crypto  │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                              │ HTTPS / WSS (per-session E2E-optional)    │
└──────────────────────────────┼───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                 EDGE / CDN (Cloudflare — WAF, DDoS, TLS 1.3)             │
│  • Bot Mgmt  • Geo-fence (optional)  • Static scenario asset caching     │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    IDENTITY & ACCESS TIER                                │
│  OIDC (Okta/Entra) + WebAuthn (mandatory)  •  RBAC  •  Session binding   │
│  SCIM for provisioning  •  Device posture check (optional, MDM signal)   │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                APPLICATION TIER (Python 3.12 / FastAPI)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Scenario     │  │ Session      │  │ Decision     │  │ Scoring &    │  │
│  │ Service      │  │ Orchestrator │  │ Engine       │  │ Analytics    │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                 │                 │                 │          │
│  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────┴───────┐  ┌──────┴───────┐  │
│  │ Telemetry    │  │ WebSocket    │  │ Audit        │  │ Instructor   │  │
│  │ Recorder     │  │ Fan-out      │  │ Emitter      │  │ Console API  │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                     SANDBOX / SIMULATION TIER                            │
│  • Simulated network services (mock DNS, mock EDR, mock SIEM)            │
│  • Per-session isolated containers (gVisor / Firecracker)                │
│  • No route to production — enforced at network policy + egress proxy    │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        DATA TIER (Encrypted)                             │
│  PostgreSQL (scenarios, sessions, decisions)  •  Redis (hot state)       │
│  S3 (assets, recordings — SSE-KMS, Object Lock for audit)  •  OpenSearch │
│  Vault (secrets)  •  HSM (signing, per-session keys)  •  OTel → SIEM     │
└──────────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    INTEGRATIONS (Strictly Bounded)                       │
│  HRIS (roster, read-only)  •  LMS (xAPI, write-only)  •  SOAR (sandbox)  │
│  Calendar (scheduling)  •  Email (invites)  •  SIEM (audit sink only)    │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Model

### 3.1 Assets

| Asset | Sensitivity | Impact if Compromised |
|---|---|---|
| Scenario content (TTPs, IOCs) | **Critical** | Reveals defensive gaps |
| Trainee decision logs | **High** | HR/performance data, PII |
| Session recordings (3D, audio, screen) | **High** | PII, biometric-adjacent (voice, gait) |
| SSO/OIDC tokens (privileged users) | **Critical** | ATO into corporate IdP |
| Scenario signing keys | **Critical** | Malicious scenario injection |
| Instructor console | **Critical** | Manipulate training, harvest trainees |
| Simulation containers | **Medium** | Pivot attempt (must fail) |
| Integration credentials (SOAR, LMS) | **High** | Lateral movement |

### 3.2 Adversary Profiles

1. **Curious trainee** — probes for shortcuts, tries to see "answers," explores hidden content.
2. **Malicious insider** — a trainee exfiltrating scenario content (competitor, future employer).
3. **External attacker** — targets the platform to harvest privileged credentials.
4. **Supply-chain attacker** — compromises a scenario author / asset vendor.
5. **Cheating trainee** — modifies client to fake performance scores.
6. **Opportunistic attacker** — dependency exploit, XSS.
7. **Nation-state** — sophisticated targeting of a training platform to map our IR playbooks.

### 3.3 STRIDE

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Impersonate trainee/instructor | OIDC + WebAuthn, session binding, mTLS for instructors |
| **Tampering** | Modify scenario, decisions, score | Signed scenarios, server-side decision log, HMAC WS |
| **Repudiation** | Trainee denies actions | Full telemetry recording, hash-chained decisions |
| **Info Disclosure** | Scenario leak, cross-session spillover | Per-session isolation, egress controls, DLP on scenario assets |
| **DoS** | Session flood, WebGL tab crash | CDN, per-user concurrency cap, LOD, graceful fallback |
| **Elevation** | Trainee → instructor via IDOR | RLS, per-object authz, separate hostnames |
| **Content injection** | Malicious GLB / voice-over | Signed assets, sanitization pipeline, allow-list extensions |
| **Cheating** | Client-side score manipulation | Server-authoritative scoring, behavioral signals |
| **Pivot** | From sandbox to production | Air-gap, no shared creds, egress allow-list |
| **Deanonymization** | Recordings re-identified | Encryption at rest, per-session KMS keys, retention policy |

### 3.4 The "Hostile Trainee" Assumption

The people using this system are the ones who are *paid* to break systems. Design accordingly:

- **Assume the client is fully compromised.** All decisions scored server-side; client is a rendering terminal.
- **Assume scenario content will be extracted.** Watermark every asset (visible or steganographic). Log every asset fetch with session ID. Legal + DLP coverage.
- **Assume the WS will be reverse-engineered.** Server never trusts client-reported state; every decision is replayed server-side.
- **Assume integration boundaries will be probed.** SOAR adapter runs against a *simulated* SOAR, not the real one — unless explicitly "live fire" mode, which is gated by multi-party approval.

---

## 4. Technology Stack

| Layer | Technology | Justification |
|---|---|---|
| Frontend 3D | Three.js r160+, WebXR (optional) | WebGL2, VR headset support |
| Frontend UI | React 18 + TypeScript 5 (strict) | Ecosystem, type safety |
| Bundler | Vite 5 | ESM, HMR, code splitting |
| Physics | Rapier (WASM) | Fast, deterministic for scoring |
| Audio | Web Audio API + spatial | Positional voice-over |
| Backend | FastAPI (Python 3.12) | Async, Pydantic v2 strict |
| WS | Starlette + `wsproto` | Native async, per-message auth |
| Task queue | Celery + Redis (TLS) | Async scoring, recording finalize |
| DB | PostgreSQL 16 (RLS) | Transactions, per-tenant isolation |
| Cache | Redis 7 (TLS, ACL) | Live session state |
| Object store | S3 (SSE-KMS, versioned, Object Lock) | Recordings, assets, audit |
| Search | OpenSearch | Scenario search, decision analytics |
| Simulation | Firecracker microVMs + gVisor | Strong isolation for mock services |
| Asset pipeline | gltf-transform, libvips | Sanitization, re-encode |
| Auth | OIDC (Okta/Entra) + WebAuthn | Phishing-resistant MFA |
| Secrets | HashiCorp Vault | Dynamic creds, short TTL |
| Signing | AWS KMS / HSM (Ed25519) | Scenario + session signing |
| Container | Distroless | Minimal surface |
| Orchestration | Kubernetes + OPA + NetworkPolicy | Zero-trust |
| Observability | OpenTelemetry → Prometheus/Loki/Grafana | Full-stack |
| CDN/Edge | Cloudflare | WAF, DDoS, TLS 1.3 |

---

## 5. Directory Layout

```
ir-training-3d/
├── architecture.md
├── SECURITY.md
├── SCENARIO_AUTHORING.md            # for content authors
├── PRIVACY.md                        # trainee data handling
├── RUNBOOK.md
├── frontend/
│   ├── index.html
│   ├── vite.config.ts
│   └── src/
│       ├── main.tsx
│       ├── security/
│       │   ├── trustedTypes.ts
│       │   ├── csp.ts
│       │   ├── sessionKey.ts        # per-session crypto
│       │   └── sanitize.ts
│       ├── scene/
│       │   ├── SceneManager.ts
│       │   ├── EnvironmentLoader.ts # safe GLB loader
│       │   ├── PlayerController.ts  # first/third person
│       │   ├── Interaction.ts       # inspect, use, respond
│       │   ├── Terminal.tsx         # in-world console UI
│       │   ├── NpcAgent.ts          # scripted actors
│       │   └── Audio.ts             # spatial voice-over
│       ├── simulation/
│       │   ├── ScenarioRuntime.ts   # client mirror (server-authoritative)
│       │   ├── DecisionClient.ts    # sends decisions to server
│       │   └── BranchState.ts       # renders server-confirmed state
│       ├── ui/
│       │   ├── Hud.tsx
│       │   ├── Objectives.tsx
│       │   ├── Notes.tsx            # trainee notebook
│       │   ├── Debrief.tsx          # post-scenario review
│       │   └── Watermark.tsx        # visible + invisible session watermark
│       └── a11y/
│           ├── ScreenReaderMirror.tsx
│           └── KeyboardNav.ts
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py                 # Vault-backed
│   │   ├── api/
│   │   │   ├── scenarios.py
│   │   │   ├── sessions.py
│   │   │   ├── decisions.py
│   │   │   ├── scoring.py
│   │   │   ├── recordings.py
│   │   │   ├── instructor.py         # separate hostname
│   │   │   └── ws.py
│   │   ├── security/
│   │   │   ├── authn.py              # OIDC + WebAuthn
│   │   │   ├── authz.py              # ABAC
│   │   │   ├── session_key.py        # per-session key derivation
│   │   │   ├── headers.py
│   │   │   ├── ratelimit.py
│   │   │   ├── csrf.py
│   │   │   ├── watermark.py          # invisible asset watermarking
│   │   │   └── dlp.py                # scenario asset access monitor
│   │   ├── scenarios/
│   │   │   ├── loader.py
│   │   │   ├── verifier.py           # signature verification
│   │   │   ├── validator.py          # structural validation
│   │   │   └── versioning.py
│   │   ├── sessions/
│   │   │   ├── orchestrator.py       # lifecycle
│   │   │   ├── isolation.py          # per-session sandbox
│   │   │   ├── snapshot.py           # periodic state save
│   │   │   └── reaper.py             # timeout/cleanup
│   │   ├── decisions/
│   │   │   ├── engine.py             # server-authoritative
│   │   │   ├── log.py                # hash-chained
│   │   │   └── replay.py             # forensic replay
│   │   ├── scoring/
│   │   │   ├── rubric.py             # per-scenario
│   │   │   ├── compute.py
│   │   │   └── anti_cheat.py         # behavioral signals
│   │   ├── telemetry/
│   │   │   ├── recorder.py           # 3D events, decisions, timings
│   │   │   └── export.py             # to LMS via xAPI
│   │   ├── simulation/
│   │   │   ├── mock_edr.py
│   │   │   ├── mock_siem.py
│   │   │   ├── mock_dns.py
│   │   │   └── adapter.py            # routes to sandbox
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
│   │   ├── scenarios/                # 100+ scenario validation corpus
│   │   └── anti_cheat/
│   └── Dockerfile
├── scenarios/                        # authored content (signed)
│   ├── _schema/
│   ├── ransomware-finance-v3/
│   ├── apt-exfil-healthcare-v2/
│   └── insider-threat-rnd-v1/
├── infra/
│   ├── nginx/
│   ├── k8s/
│   │   ├── networkpolicy.yaml
│   │   ├── sandbox-isolation.yaml
│   │   └── opa-policies/
│   ├── terraform/
│   └── vault/
└── .github/workflows/
    ├── ci.yml
    └── cd.yml
```

---

## 6. Data Model

### 6.1 Scenario

Scenarios are **authored artifacts**, signed like code.

```python
class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: UUID
    slug: str                          # e.g., "ransomware-finance-v3"
    version: int
    title: str
    description: str
    difficulty: Literal["intro", "intermediate", "advanced", "expert"]
    duration_minutes: int
    target_roles: list[str]            # ["soc_analyst", "ir_lead"]
    tags: list[str]

    # Content
    environment: EnvironmentSpec       # 3D world, assets
    script: ScenarioScript             # branching logic, triggers
    rubric: Rubric                     # scoring rules
    assets: list[AssetRef]             # sanitized, watermarked GLBs, audio

    # Provenance
    author_id: str
    reviewed_by: list[str]
    approved_at: datetime
    content_hash: str                  # SHA-256 canonical
    signature: str                     # Ed25519, HSM-signed

    # Classification
    sensitivity: Literal["public", "internal", "confidential", "restricted"]
    redaction_notes: str | None        # what was altered from real incident
```

**Signature verification is mandatory.** The runtime refuses to load an unsigned scenario.

### 6.2 Session

```python
class TrainingSession(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    session_id: UUID
    trainee_id: str                    # from OIDC sub
    scenario_id: UUID
    scenario_version: int
    scenario_hash: str                 # pin to exact content

    started_at: datetime
    ended_at: datetime | None
    status: Literal["active", "paused", "completed", "abandoned", "terminated"]

    # Isolation
    sandbox_id: str                    # Firecracker VM ID
    session_key_id: str                # KMS key alias, unique per session
    watermark_token: str               # embedded in assets

    # Telemetry
    decision_log_hash: str             # chain head
    recording_s3_key: str | None
    recording_finalized: bool

    # Scoring
    score: int | None
    rubric_breakdown: dict[str, int] | None
    anti_cheat_flags: list[str]
```

### 6.3 Decision (Hash-Chained)

Every trainee decision is recorded immutably — server-side, never client-reported.

```python
class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    decision_id: UUID
    session_id: UUID
    sequence: int                      # monotonic per session
    timestamp: datetime
    actor: str                         # trainee_id (or "npc" / "system")

    action: str                        # allow-listed verb
    target: str | None                 # in-world object
    parameters: dict[str, str]         # allow-listed keys only
    context_hash: str                  # hash of world state at decision time

    outcome: str                       # scenario-defined
    time_since_objective_start_ms: int

    # Integrity
    prev_hash: str
    signature: str                     # Ed25519 with session key
```

**Hash chain:** each decision includes hash of previous → tampering detectable. On session end, chain head is signed and stored in WORM.

### 6.4 Telemetry (Trainee Behavior)

```python
class TelemetryEvent(BaseModel):
    session_id: UUID
    ts: datetime
    kind: Literal["move", "look", "interact", "terminal_input", "voice",
                  "objective_start", "objective_complete", "hint_request",
                  "assistance_request", "idle"]
    payload: dict                      # structured, PII-minimized
    # No screen recording by default; opt-in, disclosed, retention-bounded
```

**Privacy stance:**
- **No always-on screen recording.** Optional per-scenario, disclosed on entry, requires explicit consent.
- **No biometric analysis** by default (gait, voice stress) — feature-flagged, requires Works Council / legal review.
- **Telemetry encrypted per-session** with session KMS key.
- **Retention:** 90 days by default; extended only for incidents/investigations with documented reason.

---

## 7. Frontend Architecture (Immersive 3D)

### 7.1 Rendering

- **WebGL2 required**, WebGL1 not supported (this is a training tool, not consumer).
- **WebXR optional** for VR headsets (Quest, Index) — same code, feature-detected.
- **Scene budget:** ≤ 500k triangles, ≤ 4k textures on desktop; LOD halves on mobile/VR.
- **60 fps target** at 1440p desktop; 72/90 fps in VR (comfort-critical).
- **Rendering modes:**
  - First-person (WASD + mouse look).
  - Third-person (orbit + follow).
  - "Over-the-shoulder terminal" — sit at a virtual workstation to run commands.

### 7.2 Simulation Model — Server Authoritative

The client **renders** state. The server **owns** state.

```
┌─────────────┐    decision    ┌──────────────┐   validated   ┌──────────────┐
│  Trainee    │───────────────►│  Decision    │──────────────►│  Scenario    │
│  (client)   │                │  Engine      │               │  Runtime     │
│             │◄───────────────│  (server)    │◄──────────────│  (server)    │
└─────────────┘  state delta   └──────────────┘   new state   └──────────────┘
```

**Rules:**
- Client **never** applies a decision outcome locally first.
- Client sends **intent**, waits for server-confirmed delta.
- Latency is hidden with local prediction for *movement* only (never for scored actions).
- Server logs every intent — including rejected ones. Rejected intents are anti-cheat signals.

```ts
// simulation/DecisionClient.ts (excerpt)
async decide(action: Action): Promise<void> {
  const reqId = crypto.randomUUID();
  const env = { action, target: action.target, params: action.params, reqId,
                clientTs: performance.now() };
  this.pending.set(reqId, env);
  this.ws.send(JSON.stringify({ type: 'decision', ...env }));

  const resp = await this.awaitResponse(reqId, 5000);
  if (!resp.ok) {
    // server rejected — do NOT apply locally
    this.ui.showError(resp.reason);
    this.telemetry.record('decision.rejected', { reqId, reason: resp.reason });
    return;
  }
  this.scenarioRuntime.applyDelta(resp.delta);
}
```

### 7.3 WebSocket Protocol

```ts
type ClientMsg =
  | { type: 'auth'; token: string; nonce: string }
  | { type: 'decision'; action: string; target?: string;
      params: Record<string, string>; reqId: string; clientTs: number }
  | { type: 'hint.request'; objective: string }
  | { type: 'assistance.request'; message: string }   // to instructor
  | { type: 'pause' | 'resume' | 'quit' }
  | { type: 'ping' };

type ServerMsg =
  | { type: 'auth.ok'; sessionId: string; expiresAt: number; watermark: string }
  | { type: 'state'; seq: number; snapshot: WorldState; hmac: string }
  | { type: 'delta'; seq: number; delta: WorldDelta; hmac: string }
  | { type: 'decision.ack'; reqId: string; ok: boolean; delta?: WorldDelta;
      reason?: string }
  | { type: 'objective.update'; objective: ObjectiveState }
  | { type: 'instructor.message'; text: string; from: string }
  | { type: 'error'; code: string };

type ServerMsg = ServerMsg & { seq: number };
```

**Per-message HMAC** over `(seq || payload || sessionId)` — client verifies before applying. Prevents MITM (hostile Wi-Fi, malicious proxy) from injecting fake state.

### 7.4 Per-Session Key & Watermarking

Every session is bound to a **unique KMS-derived key** and a **unique watermark token** embedded in scenario assets served to that session.

- **Key derivation:** `HKDF(master_key, salt=session_id)` → used for HMAC of WS messages and encryption of session-specific assets.
- **Watermarking:** visible (subtle, corner) + invisible (LSB steganography in textures). Any leaked screenshot/recording → forensic attribution to session + trainee.

```python
def derive_session_key(session_id: UUID) -> bytes:
    return hkdf(
        master=secrets.kms.get("session-master"),
        salt=session_id.bytes,
        info=b"ws-hmac-v1",
        length=32,
    )
```

### 7.5 Security Hardening (Frontend)

**CSP (header):**

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'wasm-unsafe-eval';
  style-src 'self' 'nonce-{random}';
  img-src 'self' data: blob:;
  media-src 'self' blob:;
  font-src 'self';
  connect-src 'self' wss://training.example.com;
  worker-src 'self' blob:;
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'none';
  object-src 'none';
  require-trusted-types-for 'script';
  trusted-types training-ui;
  upgrade-insecure-requests;
  report-uri /api/v1/csp-report;
```

Additional headers:
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(self), geolocation=(), usb=(), serial=(), xr-spatial-tracking=(self)
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store
```

**`no-store` is mandatory** — training content must not persist in browser cache on shared workstations.

### 7.6 Accessibility

- **Screen-reader mode:** Full textual walkthrough of the scenario as a branching narrative; equivalent scoring path. This is a legal requirement, not optional.
- **Keyboard-only navigation.**
- **`prefers-reduced-motion`:** disables head-bob, camera smoothing, flash effects.
- **Color-blind palette** for status indicators.
- **Subtitles** for all voice-over; transcript download post-session.

---

## 8. Backend Architecture

### 8.1 API Surface

| Method | Path | Purpose | Auth | Rate Limit |
|---|---|---|---|---|
| GET | `/api/v1/scenarios` | List (trainee's allowed scenarios) | OIDC | 60/min |
| GET | `/api/v1/scenarios/{slug}` | Metadata (no script content) | OIDC | 60/min |
| POST | `/api/v1/sessions` | Start session | OIDC + WebAuthn | 5/min |
| GET | `/api/v1/sessions/{id}` | Session state | OIDC (owner) | 120/min |
| POST | `/api/v1/sessions/{id}/pause` | Pause | OIDC + CSRF | 30/min |
| POST | `/api/v1/sessions/{id}/end` | End | OIDC + CSRF | 30/min |
| GET | `/api/v1/sessions/{id}/debrief` | Post-scenario report | OIDC (owner) | 30/min |
| GET | `/api/v1/sessions/{id}/recording` | Signed URL (opt-in) | OIDC (owner+instructor) | 10/min |
| WS | `/api/v1/ws` | Live session | OIDC + per-msg HMAC | 1/session |
| **Instructor** (separate hostname) | | | | |
| GET | `/instructor/v1/sessions` | Live sessions list | OIDC + role + mTLS | 60/min |
| POST | `/instructor/v1/sessions/{id}/intervene` | Send message, inject event | OIDC + role + mTLS | 30/min |
| POST | `/instructor/v1/sessions/{id}/terminate` | Force end | OIDC + role + mTLS | 10/min |

**Separate hostnames:** `training.example.com` (trainee), `instructor.training.example.com` (instructor), `admin.training.example.com` (admin). Different TLS certs, different cookie domains, different WAF policies.

### 8.2 Session Orchestration

On session start:

1. Verify trainee's OIDC token + WebAuthn step-up.
2. Verify scenario signature against trusted HSM key.
3. Verify scenario version pinning (trainee's org policy may forbid outdated).
4. Provision **Firecracker microVM** for simulated services (mock EDR, SIEM, DNS).
5. Generate per-session KMS key + watermark token.
6. Watermark assets on the fly → signed URLs (5-min TTL).
7. Return session manifest (WS URL, session token, watermark).
8. Emit audit event + start telemetry recording.

On session end:

1. Finalize decision log; sign chain head; write to WORM (S3 Object Lock).
2. Finalize recording (if enabled); encrypt with session KMS key.
3. Compute score server-side using rubric.
4. Export to LMS via xAPI (only fields LMS needs).
5. Destroy sandbox VM, invalidate session key, expire assets.
6. Emit audit event.

### 8.3 Decision Engine (Server-Authoritative)

```python
async def process_decision(session: TrainingSession, msg: DecisionMsg) -> DecisionAck:
    # 1. Reject if session not active
    if session.status != "active":
        return DecisionAck(req_id=msg.req_id, ok=False, reason="session_inactive")

    # 2. Validate against scenario allow-list
    scenario = await scenario_store.get(session.scenario_id, session.scenario_version)
    if msg.action not in scenario.script.allowed_actions:
        audit.warn("decision.disallowed_action", session_id=session.id,
                   action=msg.action)
        return DecisionAck(req_id=msg.req_id, ok=False, reason="invalid_action")

    # 3. Rate limit per session (prevent brute-forcing the branching tree)
    if not await ratelimit.decision(session.id):
        return DecisionAck(req_id=msg.req_id, ok=False, reason="rate_limited")

    # 4. Evaluate in the scenario runtime
    world = await runtime.get_world(session.id)
    outcome, delta = scenario.script.evaluate(world, msg)

    # 5. Persist decision to hash chain (before applying)
    prev = await decision_log.head(session.id)
    decision = Decision(
        decision_id=uuid4(),
        session_id=session.id,
        sequence=prev.sequence + 1 if prev else 1,
        timestamp=utcnow(),
        actor=session.trainee_id,
        action=msg.action,
        target=msg.target,
        parameters=msg.params,
        context_hash=hash_world(world),
        outcome=outcome,
        time_since_objective_start_ms=world.objective_elapsed_ms,
        prev_hash=prev.chain_hash if prev else "GENESIS",
        signature=signer.sign(prev.chain_hash if prev else "GENESIS",
                              session.session_key_id),
    )
    await decision_log.append(decision)

    # 6. Apply delta to world
    await runtime.apply(session.id, delta)

    # 7. Return ack + delta
    return DecisionAck(req_id=msg.req_id, ok=True, delta=delta)
```

**Anti-cheat properties:**
- Client cannot "skip" decisions — every action is recorded.
- Replay attacks (same `reqId`) are idempotent by `reqId` lookup.
- Impossible-to-reach states are detected (delta rules reject).
- Timing anomalies flagged (decisions faster than humanly possible).
- Behavioral signals (unusual action distribution) → flagged for review, not auto-fail.

### 8.4 Simulation Sandbox (Per-Session Firecracker)

Each session gets an isolated microVM running mock services:

- **Mock EDR** — returns scripted host telemetry.
- **Mock SIEM** — searchable log dataset for the scenario.
- **Mock DNS** — resolves scripted domains, logs lookups.
- **Mock ticketing** — for "open a ticket" steps.
- **Mock firewall** — for "block this IP" steps.

**Isolation guarantees:**
- **No network route to production.** Enforced at NetworkPolicy + egress proxy with domain allow-list.
- **No shared credentials** between sandbox and any production system.
- **Mock services are read-mostly** — no real actions possible even if the trainee exploits them.
- **Ephemeral** — VM destroyed on session end; no persistence.
- **Resource-capped** — CPU/memory/disk limits prevent noisy-neighbor and crypto-mining abuse.

**"Live fire" mode (exception path):** Some advanced scenarios may want to run against real (but isolated) staging SOAR/EDR. This requires:
- Multi-party approval (security + training lead).
- Dedicated staging environment, not production.
- Time-boxed (≤ 4h).
- Full packet capture for review.

### 8.5 Scenario Signing & Delivery

- **Authors sign scenarios** with their HSM-backed key.
- **Platform verifies** against a trust store of approved author keys.
- **Content hash pinned** at session start; runtime loads only that hash.
- **Assets delivered via signed URLs** with 5-min TTL; watermarking applied per-session on the fly (or pre-watermarked variants for scale).
- **No caching** — `Cache-Control: no-store` on all scenario asset responses.

### 8.6 Instructor Console

Separate application, separate hostname, separate auth path.

- **Roles:** `instructor`, `senior_instructor`, `admin`.
- **Access:** OIDC + WebAuthn + mTLS + IP allow-list (corporate VPN only).
- **Capabilities:**
  - View live sessions (state, telemetry timeline).
  - Send messages to trainees (never modify scored decisions).
  - Inject scenario events ("the CEO calls you now") — allow-listed injections only.
  - Terminate sessions (audit-logged).
- **Restrictions:**
  - Cannot modify decision log.
  - Cannot alter scores.
  - Cannot view other instructors' sessions without explicit share.
- **All actions hash-chained** to the same WORM store as trainee decisions.

### 8.7 Audit Logging

Every privileged action → structured audit record:

```json
{
  "ts": "2025-01-15T14:32:11Z",
  "actor": {"sub": "user:alice", "roles": ["instructor"], "mfa_ns": 1705329131123000000},
  "action": "instructor.intervene",
  "resource": {"type": "session", "id": "sess_01HXXX", "trainee": "user:bob"},
  "outcome": "delivered",
  "ip_hash": "sha256:...",
  "session_id": "sess_01HXXX",
  "prev_hash": "sha256:...",
  "signature": "ed25519:..."
}
```

- **Hash chain** + **Ed25519 signature** + **S3 Object Lock (WORM)** — 7-year retention.
- **Streamed to SIEM** in real time — the training platform monitors itself.

---

## 9. Infrastructure & Deployment

### 9.1 Network Architecture

- **Three separate trust zones:** trainee-facing, instructor-facing, sandbox.
- **No shared VPC** between training platform and production systems.
- **Egress allow-list** — the only outbound traffic is to OIDC, LMS, email, HRIS (read-only), and audit sink.
- **No inbound from monitored networks.**
- **Service mesh** (Istio/Linkerd) with mTLS between all tiers, SPIFFE identities.
- **Kubernetes NetworkPolicy** — default-deny, explicit allow.

### 9.2 Container Hardening

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65532
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities: { drop: ["ALL"] }
  seccompProfile: { type: RuntimeDefault }
```

- Distroless base for app services.
- **Firecracker** for per-session sandboxes (stronger than containers for hostile trainee workload).
- **gVisor** for asset decoders/parsers (defense-in-depth).
- Cosign-signed images; admission webhook verifies signature + SBOM.

### 9.3 Secrets

- All via Vault, dynamic, short-lived (≤ 15 min).
- HSM-backed signing keys for scenarios + sessions.
- Per-session KMS keys — never exported, destroyed on session end.
- CI/CD via OIDC federation to cloud — zero long-lived credentials.

### 9.4 Resilience

- **Multi-AZ** deployment; sessions pinned to a zone but resumable elsewhere via snapshot.
- **Graceful degradation:** If WebGL unavailable → text-mode fallback (equivalent scoring).
- **Session resume:** Periodic snapshots to S3; interrupted sessions resume within 15 min.
- **Kill switch:** Single command disables all session creation and terminates active sessions (e.g., during a platform compromise).

---

## 10. Observability & Meta-Monitoring

| Metric | Alert |
|---|---|
| Session start failures | > 5% → warn |
| Decision rejection rate | > 10% → investigate (possible cheating) |
| WS disconnect rate | > 5%/min → investigate |
| Instructor interventions | > 20/session → review |
| Scenario signature failures | any → **page** |
| Watermark mismatch (detected leak) | any → **page + legal** |
| Firecracker VM failures | > 2% → warn |
| Egress proxy denies | > 10/min → investigate |
| CSP violations | > 50/min → investigate |
| Recording storage growth | > 10% week-over-week → review |

**Meta-monitoring:** The platform's own audit and telemetry stream to a **separate SIEM** that platform operators cannot modify — this protects against a compromised admin.

---

## 11. Testing Strategy

| Layer | Tool | Coverage |
|---|---|---|
| Unit (BE) | pytest + hypothesis | 90% |
| Unit (FE) | Vitest | 85% |
| Integration | pytest + testcontainers | Critical paths |
| E2E | Playwright (Chromium, Firefox, Safari, WebXR emulated) | Every scenario |
| Load | k6 (500 concurrent sessions) | Quarterly |
| Security | ZAP, Burp, custom fuzzers | Every release |
| Fuzz | GLB, audio, scenario JSON, WS | Every release |
| Chaos | Firecracker kill, WS partition, SSO outage | Monthly |
| Content | 100+ scenario validation corpus | Every scenario change |
| Anti-cheat | Red-team attempts to fake scores | Quarterly |

**Dedicated security tests:**
- Attempt to load unsigned scenario → refused.
- Attempt to resume another trainee's session (IDOR) → 404.
- Attempt to modify decision log → hash-chain break detected.
- Attempt to exfiltrate scenario via screenshot → watermark recovers session ID.
- Inject XSS in scenario title, NPC dialogue, instructor message → escaped.
- Attempt sandbox escape (Firecracker) → fails, alert fired.
- Attempt to reach production from sandbox → egress denied, alert fired.
- Replay decisions after session end → rejected.
- Rapid-fire decisions (bot) → rate-limited + flagged.
- Cross-tenant access attempts → RLS denies.

---

## 12. Privacy & Compliance

Trainee data is **PII-adjacent** and often **HR-adjacent** — treat it with maximum care.

- **Legal basis:** Legitimate interest (training) + consent (recording).
- **Data minimization:** Only record what's needed for scoring and pedagogical improvement.
- **No always-on screen recording.** Opt-in per scenario, disclosed on entry.
- **No biometric analysis** by default — feature-flagged, requires Works Council (EU) / legal review.
- **Retention:**
  - Telemetry: 90 days.
  - Recordings: 30 days (or per policy), encrypted with per-session key.
  - Scores/debriefs: per HR policy (typically 2 years).
  - Audit logs: 7 years (WORM).
- **Right to access:** Trainee can export their own data.
- **Right to erasure:** Supported for telemetry/recordings (audit logs exempt as legal record).
- **Cross-border:** Regional deployments; no cross-region transfer of trainee data without explicit consent.
- **Works Council:** If EU employees, consultation before enabling behavioral analytics.
- **Access control:** Trainee sees own data. Instructor sees own sessions. Admin sees aggregates. HR access requires documented reason + audit.

Full policy in `PRIVACY.md`.

---

## 13. Incident Response (Training Platform Itself)

### 13.1 Scenario Content Leak Suspected

1. Query asset-fetch audit by scenario + session.
2. Cross-reference watermark tokens with suspicious access patterns.
3. Revoke trainee's access pending investigation.
4. Rotate scenario signature key; re-sign + redistribute.
5. Legal notify (IP theft, contract breach).
6. Post-mortem → strengthen DLP + watermarking.

### 13.2 Malicious Scenario Detected

1. Immediately disable scenario across platform.
2. Revoke author's signing key.
3. Forensically analyze scenario (isolated environment).
4. Notify all trainees who ran it; check their environments.
5. Post-mortem → strengthen author verification.

### 13.3 Platform Compromise

1. **Kill switch:** terminate all sessions; disable session creation.
2. **Isolate:** remove from network at K8s level; revoke certs.
3. **Rotate:** all WebAuthn sessions, OIDC tokens, mTLS certs, KMS keys.
4. **Preserve:** snapshot pods, memory, WORM audit logs.
5. **Assess:** meta-SIEM timeline; check hash chains.
6. **Notify:** CISO, legal, potentially regulators (72h GDPR if PII exposed).
7. **Rebuild:** from signed images + IaC. No in-place recovery.

### 13.4 Trainee Misconduct (Cheating, Harassment)

1. Preserve decision log + telemetry.
2. Notify training lead + HR (documented process).
3. Anti-cheat flags reviewed by human (never auto-fail).
4. Trainee may contest; process documented.

Full runbook in `RUNBOOK.md`.

---

## 14. Scenario Authoring Security

Scenario authors are a **trusted but not infinitely trusted** population.

- **Authors are onboarded** with background check + NDA + signed AUP.
- **Authors have HSM-backed signing keys** — unique per author, revocable.
- **Every scenario is peer-reviewed** before approval (two-person rule).
- **Content is redacted** — real incidents must be altered; redaction notes stored with scenario.
- **IOC realism:** Authors may use real IOCs (from public threat intel), never internal ones.
- **PII:** No real names, no real customer data, ever.
- **Asset sources:** Only from approved asset vendors; license tracked.
- **Author tooling** runs in a **separate, hardened environment** (no internet, no production access).

Full authoring guide in `SCENARIO_AUTHORING.md`.

---

## 15. Roadmap & Open Items

| Item | Priority | Rationale |
|---|---|---|
| WebXR / VR mode (full) | P1 | Higher immersion; pilot with Quest 3 |
| Multi-trainee cooperative scenarios | P2 | Team training; requires sharded world state |
| AI-driven NPCs (LLM) | P3 | Realism; jailbreak risk, prompt-injection defense needed |
| Live-fire integration (staging SOAR) | P2 | High realism; strict approval workflow |
| Voice-over recording (trainee) | P3 | Debrief richness; consent + retention critical |
| Behavior analytics for skill assessment | P3 | Requires Works Council consultation |
| Quantum-resistant signatures | P3 | HSM vendor readiness 2025-2026 |
| Offline / air-gapped deployment | P2 | Classified environments; needs deployment redesign |
| Federated scenarios (cross-org) | P4 | Requires trust framework |

---

## 16. References

- OWASP ASVS v4.0.3 — Level 3 (privileged users, sensitive content)
- OWASP Top 10 (2021)
- NIST SP 800-53 Rev. 5 — Moderate baseline + AU, AC, SC
- NIST SP 800-61r3 — Incident Handling
- NIST SP 800-207 — Zero Trust Architecture
- MITRE ATT&CK — scenario realism
- MITRE D3FEND — defensive coverage
- Khronos glTF 2.0 Specification
- W3C WebXR Device API
- xAPI (Experience API) 1.0.3 — LMS integration
- SCORM 2004 4th Ed. — legacy LMS
- GDPR Art. 5, 6, 9, 13, 17, 22, 35 — DPIA required for behavioral analytics
- SLSA v1.0 — Build Level 3
- Firecracker microVM documentation
- gVisor security model

---

**Approval:** This document requires sign-off from the **CISO**, **Training Director**, **Legal/Privacy**, and **Head of Security Architecture** before production. Changes to **scenario signing**, **sandbox isolation**, **trainee telemetry scope**, or **live-fire mode** require re-review by all four.

**Review cadence:** Quarterly, or upon: (a) scenario content leak, (b) privacy regulation change, (c) new integration, (d) new scenario sensitivity class, (e) Works Council consultation.

**Contact:** `ir-training-architecture@example.com` — PGP key in `SECURITY.md`.

**Non-negotiables:**
- Scenarios are signed. Always.
- Trainee sessions are cryptographically isolated.
- Sandbox has zero path to production. Ever.
- The server owns state; the client only renders.
- Every trainee action is hash-chained and auditable.
- Trainee data is minimized, encrypted, and retention-bounded.
- "Live fire" requires multi-party approval and is time-boxed.
- Real incidents are redacted before becoming scenarios.