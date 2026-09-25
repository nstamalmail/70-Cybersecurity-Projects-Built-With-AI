# Architecture Specification: WebXR Security Awareness Training Module

**Document Version:** 1.0.0
**Classification:** Internal — Company-Wide Deployment
**Author:** Senior Security Developer
**Last Updated:** 2025-01-15
**Status:** Approved for Implementation
**Document ID:** ARCH-WEBXR-SAT-001

---

## 1. Executive Summary

This document defines the architecture for a **WebXR-based security awareness training (SAT) module** delivered to the **entire workforce** — from executives to interns — through a browser or VR headset. Unlike a specialist IR simulator, this platform targets **non-technical users** with short, immersive scenarios covering phishing, social engineering, data handling, physical security, and incident reporting.

**Why this is a distinct security problem:**

1. **Massive user base, low technical literacy.** Thousands of employees, including those who will click *any* link. If the platform itself is compromised, we've taught the entire company the *wrong* lesson — and given an attacker a mass-delivery vector.
2. **Phishing simulation is dual-use.** The platform sends simulated phishing emails. If an attacker compromises it, they can send **real** phishing from a trusted internal tool. This is one of the highest-impact attack chains possible.
3. **WebXR expands the attack surface.** Headset browsers (Quest Browser, Wolvic, Pico), WebXR permissions (camera, hand tracking, spatial data, eye tracking), and motion sensors create novel privacy and safety concerns.
4. **Regulatory mandate.** Annual security awareness training is required by ISO 27001, SOC 2, PCI-DSS, HIPAA, NIS2, and most enterprise contracts. **Failure to deliver = compliance breach**, which makes availability a first-class security property.
5. **HR-adjacent data.** Completion status, quiz scores, phishing-click rates are HR-sensitive and, in some jurisdictions, **works-council-gated**.
6. **Immersive content affects people.** VR motion sickness, accessibility exclusion, and psychological impact (simulated harassment, simulated breach consequences) require safeguards that don't exist in typical web apps.

**Design principles:**

1. **The training platform is untrusted-by-default for phishing.** Phishing simulation is a *separate, hardened subsystem* with its own outbound controls — never inline with the training web app.
2. **Accessibility is a legal requirement, not a feature.** Every module works without WebXR, without 3D, and with screen readers. WCAG 2.2 AA minimum.
3. **No behavioral surveillance.** Completion data is minimal; no keystroke-level analytics on employees; no biometrics.
4. **VR is optional and safe.** Motion sickness mitigation, session caps, opt-out to 2D.
5. **Compliance is provable.** Every completion is signed, timestamped, and exportable to auditors.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    WORKFORCE CLIENTS                                     │
│  Desktop browsers  │  Mobile browsers  │  VR headsets (Quest/Pico/Index) │
│  (Chrome/Edge/FF/Safari) │ (iOS/Android) │ (WebXR-capable browsers)      │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │ HTTPS / WSS
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│              EDGE / CDN (Cloudflare — WAF, DDoS, Bot Mgmt, TLS 1.3)      │
│  • Static training asset cache  • Geo-routing  • Rate limits             │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    IDENTITY TIER                                         │
│  SSO (OIDC — corporate IdP)  •  WebAuthn (step-up for high-risk roles)   │
│  SCIM provisioning  •  Group → module mapping                            │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    TRAINING WEB APP (FastAPI / Python 3.12)              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Module       │  │ Progress &   │  │ Assessment   │  │ Completion   │  │
│  │ Catalog      │  │ Resume       │  │ (quiz)       │  │ Certificates │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ WebSocket    │  │ Accessibility│  │ i18n / l10n  │  │ Reporting    │  │
│  │ Session      │  │ Fallback     │  │              │  │ (HR / audit) │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    PHISHING SIMULATION SUBSYSTEM (ISOLATED)              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Campaign     │  │ Mail Relay   │  │ Landing Page │  │ Education    │  │
│  │ Scheduler    │  │ (own IP/dom.)│  │ Server       │  │ ("teachable  │  │
│  │              │  │              │  │              │  │  moment")    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘  │
│  ⚠ No shared credentials, no shared infra with training web app          │
│  ⚠ Outbound email send rate-limited, allow-listed recipients only        │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        DATA TIER                                         │
│  PostgreSQL (RLS, encrypted PII)  •  Redis (sessions)                    │
│  S3 (assets, certificates — SSE-KMS)  •  OpenSearch (reporting)          │
│  Vault (secrets)  •  HSM (completion signing)  •  OTel → SIEM            │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Model

### 3.1 Assets

| Asset | Sensitivity | Impact if Compromised |
|---|---|---|
| Employee roster + groups | **High** (PII) | Target list for real attacks |
| Phishing simulation engine | **Critical** | Attacker sends real phishing as us |
| Training module content | **Medium** | Phishing template leak → evasion |
| Completion records | **High** (HR/audit) | Compliance fraud, false attestation |
| Quiz answer keys | **Low-Medium** | Cheating (low impact) |
| Session tokens | **High** | Account takeover of any employee |
| VR telemetry (motion, spatial) | **High** (privacy) | Behavioral profiling, safety |
| SSO integration | **Critical** | ATO into corporate IdP |

### 3.2 Adversary Profiles

1. **Lazy employee** — clicks through, tries to skip, shares answers.
2. **Malicious insider** — wants to falsify completion, sabotage phishing metrics.
3. **External attacker** — targets the platform to harvest employee list or phishing engine.
4. **Nation-state** — wants to use our platform as a trusted phishing origin.
5. **Opportunistic** — dependency exploit, XSS on shared module.
6. **Curious researcher** — probes WebXR permissions, data collection.
7. **Works council / privacy regulator** — scrutinizes behavioral data collection.

### 3.3 STRIDE

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Forge completion records | HSM-signed certificates; server-side only |
| **Tampering** | Modify quiz answers, scores | Server-side scoring; answer keys never sent to client |
| **Repudiation** | "I never completed that" | Signed completion + audit trail |
| **Info Disclosure** | Employee roster leak | RLS, minimal PII, encrypted at rest |
| **DoS** | Campaign flood, mail relay abuse | Rate limits, allow-listed recipients, hard caps |
| **Elevation** | Employee → admin via IDOR | UUIDs, RLS, separate hostnames |
| **Phishing abuse** | Attacker sends real phishing from platform | Subsystem isolation, allow-list, out-of-band approval |
| **Privacy violation** | VR sensors collect more than needed | Sensor minimization, explicit consent, no recording |
| **Accessibility exclusion** | 3D-only path | 2D + screen-reader parity mandated |
| **Motion sickness** | VR comfort violation | Comfort defaults, session caps, opt-out |

### 3.4 The Phishing Simulation Problem

**This is the highest-risk component in the entire system.** A phishing simulator is, functionally, a phishing kit. Controls:

1. **Physical/logical isolation:** Runs in a dedicated VPC with **no shared credentials, no shared database, no shared Kubernetes cluster** with the training web app. Compromise of one does not grant the other.
2. **Recipient allow-list:** Every send is checked against the HR-sourced roster. **No external recipients, ever.**
3. **Domain separation:** Simulation uses a **dedicated, non-corporate domain** (e.g., `sat-simulation.example`) with SPF/DKIM/DMARC configured to prevent misuse and clearly documented in the AUP.
4. **Rate limiting:** Global cap (e.g., 5,000 emails/hour), per-campaign cap, per-recipient cap (1/day).
5. **Approval workflow:** Campaign creation requires **two-person approval** (SAT admin + security lead).
6. **Kill switch:** Single API call stops all in-flight campaigns and revokes mail relay credentials.
7. **No real credentials accepted:** Landing pages never store passwords entered by users — a common ethical failure.
8. **Education-first:** Landing page immediately teaches; no shaming; no automatic punitive action.
9. **Audit every send:** Immutable log of every recipient, template, timestamp, approver.
10. **Jurisdiction rules:** Campaigns respect local law (e.g., some EU works councils require notification before simulated phishing).

Full policy in `PHISHING_SIM_POLICY.md`.

---

## 4. Technology Stack

| Layer | Technology | Justification |
|---|---|---|
| Frontend 3D | Three.js r160+ with WebXR | Broad browser support, WebXR native |
| Frontend UI | React 18 + TypeScript 5 (strict) | Ecosystem, accessibility tooling |
| Bundler | Vite 5 | ESM, code splitting |
| Accessibility | axe-core, ARIA, RNIB-tested | WCAG 2.2 AA |
| i18n | i18next + ICU | Multi-language, RTL support |
| Backend | FastAPI (Python 3.12) | Async, Pydantic v2 strict |
| WS | Starlette + `wsproto` | Per-message auth |
| Task queue | Celery + Redis (TLS) | Async campaigns, reports |
| DB | PostgreSQL 16 (RLS) | Transactions, row-level security |
| Cache | Redis 7 (TLS, ACL) | Sessions, rate limits |
| Object store | S3 (SSE-KMS, versioned) | Assets, certificates |
| Search | OpenSearch | Reporting queries |
| Phishing subsystem | **Separate VPC + separate Postgres + separate credentials** | Blast-radius isolation |
| Mail relay | Dedicated IP + domain, SPF/DKIM/DMARC, DMARC `p=reject` | Anti-abuse |
| Auth | OIDC (corporate IdP) + WebAuthn (step-up) | SSO-first; MFA for admins |
| Secrets | HashiCorp Vault | Dynamic creds |
| Signing | AWS KMS / HSM (Ed25519) | Completion certificates |
| Container | Distroless | Minimal surface |
| Orchestration | Kubernetes + OPA + NetworkPolicy | Zero-trust |
| Observability | OTel → Prometheus/Loki/Grafana + SIEM | Full-stack |
| CDN/Edge | Cloudflare | WAF, DDoS, TLS 1.3 |

---

## 5. Directory Layout

```
webxr-sat/
├── architecture.md
├── SECURITY.md
├── PHISHING_SIM_POLICY.md
├── PRIVACY.md
├── ACCESSIBILITY.md
├── VR_SAFETY.md
├── frontend/
│   ├── index.html
│   ├── vite.config.ts
│   └── src/
│       ├── main.tsx
│       ├── security/
│       │   ├── trustedTypes.ts
│       │   ├── csp.ts
│       │   └── sanitize.ts
│       ├── xr/
│       │   ├── XRSession.ts           # WebXR entry/exit, capability detect
│       │   ├── ComfortSettings.ts     # snap-turn, vignette, seated mode
│       │   ├── MotionSickness.ts      # session cap, break prompts
│       │   ├── HandTracking.ts        # optional, opt-in, no recording
│       │   └── SpatialAudio.ts
│       ├── scene/
│       │   ├── SceneManager.ts
│       │   ├── EnvironmentLoader.ts   # safe GLB
│       │   ├── Avatars.ts             # non-PII avatars for scenarios
│       │   ├── Interaction.ts         # raycast, grab, use
│       │   └── Scenarios/
│       │       ├── PhishingEmail.tsx  # inspect suspicious email
│       │       ├── Tailgating.tsx     # physical security
│       │       ├── CleanDesk.tsx
│       │       ├── SocialEngCall.tsx
│       │       └── DataHandling.tsx
│       ├── ui/
│       │   ├── Hud.tsx                # flat overlay, always readable
│       │   ├── Quiz.tsx
│       │   ├── Progress.tsx
│       │   ├── Pause.tsx
│       │   ├── ReportButton.tsx       # "report this" — always reachable
│       │   └── Certificate.tsx
│       ├── fallback/
│       │   ├── TextMode.tsx           # full non-3D equivalent
│       │   └── ScreenReaderFlow.tsx
│       └── a11y/
│           ├── AriaLive.ts
│           ├── FocusManager.ts
│           └── RtlLayout.tsx
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py                  # Vault-backed
│   │   ├── api/
│   │   │   ├── modules.py
│   │   │   ├── progress.py
│   │   │   ├── quiz.py
│   │   │   ├── completion.py
│   │   │   ├── reporting.py           # HR/audit exports
│   │   │   └── ws.py
│   │   ├── security/
│   │   │   ├── authn.py               # OIDC
│   │   │   ├── authz.py               # ABAC
│   │   │   ├── headers.py
│   │   │   ├── ratelimit.py
│   │   │   ├── csrf.py
│   │   │   ├── signing.py             # certificate signing
│   │   │   └── privacy_guard.py       # enforces data minimization
│   │   ├── modules/
│   │   │   ├── catalog.py
│   │   │   ├── loader.py
│   │   │   ├── validator.py
│   │   │   └── versioning.py
│   │   ├── progress/
│   │   │   ├── tracker.py
│   │   │   ├── resume.py
│   │   │   └── completion.py          # signed certificates
│   │   ├── quiz/
│   │   │   ├── engine.py              # server-side scoring
│   │   │   ├── questions.py           # answer keys never leave server
│   │   │   └── randomization.py
│   │   ├── reporting/
│   │   │   ├── hr_export.py           # minimal fields
│   │   │   ├── audit_export.py
│   │   │   └── compliance.py          # ISO/SOC2/PCI evidence
│   │   ├── roster/
│   │   │   ├── scim.py                # from IdP
│   │   │   └── sync.py
│   │   └── db/
│   │       ├── session.py
│   │       └── migrations/
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   ├── security/
│   │   ├── a11y/                      # automated + manual
│   │   └── privacy/
│   └── Dockerfile
├── phishing-sim/                       # ISOLATED SUBSYSTEM
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   │   ├── campaigns.py           # CRUD, approval workflow
│   │   │   ├── send.py                # allow-listed recipients
│   │   │   ├── landing.py             # education pages
│   │   │   └── kill_switch.py
│   │   ├── security/
│   │   │   ├── approval.py            # two-person rule
│   │   │   ├── recipient_guard.py     # roster-only
│   │   │   ├── rate_limit.py
│   │   │   └── audit.py
│   │   ├── mailer/
│   │   │   ├── relay.py               # dedicated IP/domain
│   │   │   ├── spf_dkim_dmarc.py
│   │   │   └── template_render.py
│   │   └── db/
│   ├── tests/
│   └── Dockerfile
├── modules-content/                    # authored training modules
│   ├── _schema/
│   ├── phishing-basics-v2/
│   ├── social-engineering-v1/
│   ├── data-handling-v3/
│   └── physical-security-v1/
├── infra/
│   ├── nginx/
│   ├── cloudflare/
│   ├── k8s/
│   ├── terraform/
│   └── vault/
└── .github/workflows/
    ├── ci.yml
    └── cd.yml
```

---

## 6. Data Model

### 6.1 Employee & Roster

Minimal PII. Only what's needed for delivery and compliance.

```python
class Employee(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    employee_id: UUID                  # internal, not the HR ID
    idp_subject: str                   # OIDC sub — primary key
    display_name: str                  # for greeting only
    email: str                         # for invites
    department: str
    region: str                        # for jurisdiction rules (works council)
    manager_idp_subject: str | None
    required_modules: list[str]        # from group mapping
    locale: str                        # i18n
    accessibility_prefs: dict          # screen reader, reduced motion, etc.
    status: Literal["active", "leave", "terminated"]
```

**Explicitly NOT stored:**
- Personal phone numbers (not needed).
- Home address.
- Job title beyond department.
- Any biometric data.
- Performance reviews or unrelated HR data.

### 6.2 Module

Training modules are authored content, versioned and signed.

```python
class TrainingModule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    module_id: UUID
    slug: str                          # "phishing-basics-v2"
    version: int
    title: str                         # localized variants
    description: str
    duration_minutes: int
    target_groups: list[str]           # IdP groups
    required: bool
    cadence: Literal["onboarding", "annual", "quarterly", "ad_hoc"]

    # Content
    scenes: list[SceneSpec]            # 3D content
    text_fallback: TextSpec            # mandatory non-3D equivalent
    quiz: QuizSpec
    localization: dict[str, LocalizedContent]

    # Provenance
    author_id: str
    reviewed_by: list[str]
    approved_at: datetime
    content_hash: str
    signature: str                     # Ed25519, HSM
```

### 6.3 Progress & Completion

```python
class ProgressRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: UUID
    employee_id: UUID
    module_id: UUID
    module_version: int
    started_at: datetime
    completed_at: datetime | None
    status: Literal["not_started", "in_progress", "completed",
                    "failed", "expired"]
    score: int | None                  # if quiz
    attempts: int

    # Accessibility path used (for compliance evidence)
    delivery_mode: Literal["webxr_vr", "webxr_ar", "3d_2d", "text_only",
                           "screen_reader"]

    # Completion certificate
    certificate_id: UUID | None
    certificate_signature: str | None  # Ed25519, HSM
    certificate_issued_at: datetime | None
```

**Certificate is signed.** Auditors can verify a completion was issued by our HSM — prevents forgery.

### 6.4 Quiz (Answer Keys Server-Only)

```python
# Server-side model — NEVER serialized to client
class QuizQuestion(BaseModel):
    question_id: UUID
    text: str
    choices: list[Choice]
    correct_choice_id: UUID            # never sent to client
    rationale: str

# Client-facing model — correct answer stripped
class QuizQuestionPublic(BaseModel):
    question_id: UUID
    text: str
    choices: list[Choice]              # id + text only
```

**Server-side scoring only.** Client submits choice IDs; server returns score + rationale. Client never receives the answer key, even after submission (prevents replay to other sessions).

### 6.5 What We Do NOT Collect (Privacy by Design)

- **No keystroke timing.**
- **No mouse movement heatmaps.**
- **No gaze/eye tracking** (even if headset supports it — feature-flagged off).
- **No hand-tracking data retention** (used transiently for interaction, never stored).
- **No spatial mapping data.**
- **No camera feed retention** (AR mode uses camera transiently; no frames stored).
- **No microphone retention** (voice interactions processed locally or discarded).
- **No biometric analysis** (voice stress, gait, etc.).
- **No cross-context tracking** (this platform tracks only training; no analytics pixels, no third-party JS).

Full policy in `PRIVACY.md`.

---

## 7. Frontend Architecture (WebXR)

### 7.1 Delivery Modes (Parity Required)

Every module MUST be deliverable in **five modes** with equivalent learning outcomes and scoring:

1. **WebXR VR** — full immersive (headset).
2. **WebXR AR** — passthrough on supported devices (optional).
3. **3D 2D** — Three.js scene rendered in a browser window (mouse/keyboard).
4. **Text-only 2D** — pure HTML/CSS narrative with images.
5. **Screen-reader flow** — semantic HTML, ARIA live regions, keyboard-only.

**Rule:** A module cannot be published if any mode is missing. Enforced by CI (`modules-content/` validation).

### 7.2 WebXR Session Lifecycle

```ts
// xr/XRSession.ts (excerpt)
export async function enterVR(mode: 'vr' | 'ar' = 'vr'): Promise<XRSession> {
  if (!navigator.xr) throw new UnsupportedError();
  const supported = await navigator.xr.isSessionSupported(
    mode === 'vr' ? 'immersive-vr' : 'immersive-ar'
  );
  if (!supported) throw new UnsupportedError();

  const session = await navigator.xr.requestSession(
    mode === 'vr' ? 'immersive-vr' : 'immersive-ar',
    {
      requiredFeatures: ['local-floor'],
      optionalFeatures: ['bounded-floor', 'hand-tracking'],
      // Explicitly NOT requesting: eye-tracking, plane-detection,
      // anchors (unless module needs), camera-access (AR only, transient)
    }
  );

  session.addEventListener('end', onSessionEnd);
  return session;
}
```

**Permission minimization:** We request **only** what a module needs. Hand-tracking is optional and off by default. Eye-tracking is **never** requested. Camera access in AR is transient and never recorded.

### 7.3 Comfort & Safety (VR)

Mandatory for all VR modules:

- **Snap-turn** as default (smooth-turn optional).
- **Vignette during locomotion** (reduces vection-induced nausea).
- **Seated mode** available for all scenarios.
- **Teleport locomotion** as default (smooth locomotion optional, warned).
- **Session cap:** 20 minutes continuous VR; forced break prompt; module designed to fit.
- **Motion sickness check-in:** After 10 minutes, "How are you feeling?" with option to switch to 2D.
- **No flashing > 3 Hz** (photosensitive epilepsy).
- **Comfort settings persisted** per employee.
- **Never require standing** unless medically cleared and disclosed.

Full guidance in `VR_SAFETY.md`.

### 7.4 Scene & Content

- **Environment GLBs** are signed and served from the training CDN.
- **No user-generated content** in the 3D scene (no avatars of real people, no uploaded logos).
- **Fictional scenarios** — company names in scenarios are clearly fictional (e.g., "Acme Corp", not our actual customers).
- **No depictions of real incidents** without legal review.
- **NPC dialogue** is pre-authored, localized, subtitle-mandatory.
- **No LLM-generated content** in training scenes (avoids jailbreak + accuracy risk).

### 7.5 Accessibility (Mandatory)

- **Screen reader parity:** Every scene has a text equivalent that is *the same content*, not a degraded summary.
- **Keyboard navigation:** All interactions reachable without mouse/controller.
- **Subtitles** for all audio; **transcripts** downloadable.
- **High-contrast mode** toggle.
- **Font scaling** up to 200%.
- **RTL support** for Arabic/Hebrew locales.
- **Color-blind safe palette** for status indicators.
- **No audio-only** content.
- **Alternative to VR**: If an employee cannot use VR (medical, discomfort, no headset), the 3D 2D and text modes are equally valid completions.

Accessibility testing in `ACCESSIBILITY.md` includes manual screen-reader testing (NVDA, JAWS, VoiceOver) each release.

### 7.6 Security Hardening (Frontend)

**CSP (header):**

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self';
  style-src 'self' 'nonce-{random}';
  img-src 'self' data: blob:;
  media-src 'self' blob:;
  font-src 'self';
  connect-src 'self' wss://training.example.com;
  worker-src 'self' blob:;
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'self';
  object-src 'none';
  require-trusted-types-for 'script';
  trusted-types sat-ui;
  upgrade-insecure-requests;
  report-uri /api/v1/csp-report;
```

Additional headers:
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: camera=(self "https://training.example.com"),
                   microphone=(self),
                   geolocation=(),
                   usb=(),
                   xr-spatial-tracking=(self),
                   interest-cohort=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Cache-Control: no-store
```

`camera` and `microphone` are gated to our origin only. `xr-spatial-tracking` allowed (needed for WebXR) but no persistent storage. `interest-cohort=()` opts out of FLoC/Topics.

### 7.7 Trusted Types & Sanitization

All DOM writes through `sat-ui` policy. **No `innerHTML`.** Scenario dialogue, employee display names, quiz text — all rendered via `textContent` or React's safe rendering.

---

## 8. Backend Architecture

### 8.1 API Surface

| Method | Path | Purpose | Auth | Rate Limit |
|---|---|---|---|---|
| GET | `/api/v1/modules` | Modules for this employee | OIDC | 60/min |
| GET | `/api/v1/modules/{slug}` | Module metadata + assets manifest | OIDC | 60/min |
| POST | `/api/v1/progress/start` | Begin module | OIDC + CSRF | 30/min |
| POST | `/api/v1/progress/update` | Progress heartbeat | OIDC + CSRF | 300/min |
| POST | `/api/v1/progress/complete` | Complete module | OIDC + CSRF | 30/min |
| POST | `/api/v1/quiz/submit` | Submit quiz answers | OIDC + CSRF | 30/min |
| GET | `/api/v1/certificates/{id}` | Download signed cert | OIDC (owner) | 30/min |
| GET | `/api/v1/reporting/self` | Employee sees own records | OIDC | 30/min |
| WS | `/api/v1/ws` | Live session | OIDC | 2/session |
| **Admin** (separate hostname) | | | | |
| GET | `/admin/v1/employees` | Roster (aggregate) | OIDC + role + mTLS | 60/min |
| GET | `/admin/v1/reports/compliance` | Compliance exports | OIDC + role + mTLS | 10/min |
| POST | `/admin/v1/modules` | Publish module | OIDC + role + 2-person | 5/min |

**Separate hostnames:**
- `training.example.com` — employees.
- `admin.training.example.com` — SAT admins, mTLS + IP allow-list.
- `sim.example.com` — phishing simulation landing pages (isolated).

### 8.2 Progress Tracking (Minimal)

```python
class ProgressUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    module_id: UUID
    scene_id: str
    event: Literal["scene_enter", "scene_exit", "step_complete"]
    client_ts: int                      # for ordering only
```

**No free-form telemetry.** Only structured events with allow-listed types. This limits both data collection and attack surface.

```python
async def update_progress(employee: Employee, msg: ProgressUpdate) -> ProgressAck:
    record = await progress.get(employee.id, msg.module_id)
    if record.status == "completed":
        return ProgressAck(ok=True)     # idempotent

    # Server validates the transition
    if not is_valid_transition(record, msg):
        audit.warn("progress.invalid_transition", employee_id=employee.id)
        return ProgressAck(ok=False)

    await progress.apply(record, msg)
    return ProgressAck(ok=True, next_scene=compute_next(record))
```

**Server-authoritative progress.** The client can't claim completion without the full validated sequence.

### 8.3 Quiz Scoring (Server-Side Only)

```python
@router.post("/quiz/submit")
async def submit_quiz(
    employee: Employee,
    req: QuizSubmit,
    csrf: None = Depends(verify_csrf),
):
    module = await modules.get(req.module_id)
    quiz = await quiz_engine.load(module.quiz_id)

    # Randomization is per-session, seeded server-side
    session_quiz = await quiz_engine.session_quiz(employee.id, module.id)
    if req.attempt_token != session_quiz.attempt_token:
        raise HTTPException(400, "invalid attempt")

    score = 0
    results = []
    for answer in req.answers:
        q = session_quiz.get_question(answer.question_id)
        correct = answer.choice_id == q.correct_choice_id
        if correct:
            score += 1
        results.append({
            "question_id": q.question_id,
            "correct": correct,
            "rationale": q.rationale,      # disclosed after submission
        })

    passed = score >= session_quiz.passing_threshold
    await progress.record_attempt(employee.id, module.id, score, passed)

    if passed:
        cert = await certificates.issue(employee.id, module.id, score)
        return {"score": score, "passed": True,
                "certificate_id": cert.id, "results": results}

    return {"score": score, "passed": False,
            "results": results, "retake_after": "24h"}
```

**Properties:**
- Answer keys **never** sent to client.
- Attempt token prevents replaying a completed session's submissions.
- Rationale disclosed post-submission (teaching value).
- Certificate issued only server-side.
- Retake cooldown prevents brute-forcing (randomized questions).

### 8.4 Completion Certificates (Signed)

```python
class CompletionCertificate(BaseModel):
    certificate_id: UUID
    employee_id: UUID
    module_id: UUID
    module_version: int
    module_hash: str                    # exact content version
    score: int | None
    completed_at: datetime
    delivery_mode: str
    issuer: str                         # "webxr-sat@example.com"
    signature: str                      # Ed25519, HSM-backed
    verify_url: str                     # public verification endpoint
```

**Public verification:** `GET /api/v1/certificates/{id}/verify` — anyone with the cert ID can verify signature (no PII returned). Useful for auditors and cross-org.

### 8.5 Reporting (HR & Audit)

```python
# HR export — MINIMAL fields only
class HRReportRow(BaseModel):
    employee_id: UUID
    display_name: str
    department: str
    module_slug: str
    module_version: int
    status: str
    completed_at: datetime | None
    score: int | None

# Audit export — includes delivery mode + certificate signature
class AuditReportRow(HRReportRow):
    delivery_mode: str
    certificate_id: UUID | None
    certificate_signature: str | None
    content_hash: str
```

**Access control:**
- HR sees only completion status (not detailed quiz responses, not time-per-question).
- Auditor sees completion + certificate signatures (for evidence).
- No manager sees direct reports' *quiz answers* — only pass/fail.
- Exports are signed and watermarked (per-export token) for leak attribution.
- All export actions audited.

### 8.6 Phishing Simulation Subsystem (Isolated)

**Separate application, separate VPC, separate database, separate credentials.** No shared code beyond utility libraries (audited).

#### 8.6.1 Campaign Lifecycle

```
1. Draft campaign (SAT admin)
   - Choose template, target group, schedule
2. Peer review (second SAT admin)
3. Security lead approval (two-person rule enforced at DB level)
4. Recipient validation against roster
   - Reject any non-employee
   - Respect employee leave/terminated status
5. Schedule send (Celery beat)
6. Send (rate-limited, dedicated mail relay)
7. Landing page tracking (clicked, entered creds — but NEVER stored)
8. Education shown
9. Metrics aggregated
10. Campaign closed (auto after N days)
```

#### 8.6.2 Hard Controls

```python
# Recipient guard — allow-list enforced
async def validate_recipients(recipients: list[str]) -> list[str]:
    allowed = await roster.get_active_employee_emails()
    invalid = [r for r in recipients if r not in allowed]
    if invalid:
        audit.warn("phishing.invalid_recipients",
                   count=len(invalid), sample=invalid[:5])
        raise ForbiddenRecipients()
    return recipients

# Rate limits — global + per-campaign + per-recipient
RATE_LIMITS = {
    "global_per_hour": 5000,
    "per_campaign_per_hour": 1000,
    "per_recipient_per_day": 1,
}

# Kill switch
@router.post("/kill-switch", dependencies=[Depends(require_role("security_lead"))])
async def kill_switch():
    await campaigns.pause_all()
    await mail_relay.revoke_credentials()
    audit.emit("phishing.kill_switch", actor="security_lead")
    return {"status": "stopped"}
```

#### 8.6.3 Landing Pages (Education, Not Harvesting)

- **Never** store submitted credentials — even if user enters them (common failure mode).
- Show immediate education: "This was a simulated phishing test. Here's what to look for."
- Offer "Report this email" button teaching correct behavior.
- No shaming, no public leaderboards.
- Optional: automatically enroll clicked users in a short refresher module.

#### 8.6.4 Mail Relay (Anti-Abuse)

- **Dedicated sending domain** (e.g., `sat-simulation.example`), not corporate primary.
- SPF, DKIM, DMARC `p=reject` configured.
- **Dedicated sending IP(s)** with reputation monitoring.
- Outbound rate limited at SMTP level.
- **No external recipients** — checked at SMTP layer, not just app.
- **Abuse monitoring** — auto-pause if bounce rate > 5% or complaint rate > 0.1%.

#### 8.6.5 Jurisdiction Rules

- **EU:** Works council notification before first campaign in each country; campaigns respect local law.
- **Germany:** Consultation required; some scenarios may be prohibited.
- **France:** CNIL guidance followed.
- **California (US):** No punitive action based solely on simulation clicks.
- **All:** Employees can opt out of simulation campaigns (still must complete training) where legally required.

### 8.7 Audit Logging

Every privileged action → structured audit record:

```json
{
  "ts": "2025-01-15T14:32:11Z",
  "actor": {"sub": "user:admin1", "roles": ["sat_admin"], "mfa_ns": 1705329131123000000},
  "action": "phishing.campaign.approve",
  "resource": {"type": "campaign", "id": "camp_01HXXX", "target_group": "engineering"},
  "outcome": "approved",
  "approver_2": "user:admin2",
  "ip_hash": "sha256:...",
  "prev_hash": "sha256:...",
  "signature": "ed25519:..."
}
```

- **Hash-chained**, **signed**, **WORM** (S3 Object Lock), 7-year retention.
- Streamed to SIEM in real time.

---

## 9. Infrastructure & Deployment

### 9.1 Network Architecture

- **Two isolated VPCs:** training platform and phishing simulation.
- **No shared credentials** between them.
- **No route from phishing sim to training DB.**
- **Egress allow-list** for each VPC:
  - Training: OIDC, LMS, S3, Vault.
  - Phishing sim: **only** the mail relay's SMTP endpoint.
- **Kubernetes NetworkPolicy** — default-deny.
- **Service mesh** with mTLS between tiers.

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

- Distroless base.
- Cosign-signed images; admission webhook verifies.
- gVisor for asset decoding.
- Resource limits + HPA.

### 9.3 Secrets

- Vault dynamic creds, short-lived.
- **Separate Vault namespaces** for training and phishing sim.
- HSM-backed signing keys for certificates.
- Mail relay credentials rotated quarterly; on compromise, immediately.

### 9.4 Resilience

- **Multi-AZ**, active-active for read paths.
- **Degraded mode:** If WebXR fails, fall back to 3D 2D, then text mode.
- **Campaign pause:** If mail relay reports elevated bounces, auto-pause.
- **Kill switch:** One API call stops all phishing simulation activity.

---

## 10. Observability

| Metric | Alert |
|---|---|
| Module start failures | > 5% → warn |
| WS disconnect rate | > 5%/min → investigate |
| Quiz submission failures | > 2% → warn |
| Certificate signing failures | any → **page** |
| Phishing sim: bounces | > 5% → auto-pause |
| Phishing sim: complaints | > 0.1% → auto-pause + page |
| Recipient guard rejections | any → investigate |
| External recipient attempts | any → **page** (should be impossible) |
| CSP violations | > 50/min → investigate |
| VR session abandonment | > 30% mid-session → review comfort settings |
| Accessibility fallback usage | > 20% → investigate why |

**Meta-monitoring:** All audit logs streamed to a SIEM the SAT operators cannot modify.

---

## 11. Testing Strategy

| Layer | Tool | Coverage |
|---|---|---|
| Unit (BE) | pytest + hypothesis | 90% |
| Unit (FE) | Vitest | 85% |
| Integration | pytest + testcontainers | Critical paths |
| E2E | Playwright (Chromium, Firefox, Safari, WebXR emulated) | Every module |
| Accessibility | axe-core + manual NVDA/JAWS/VoiceOver | Every release |
| VR | Manual on Quest 3, Index, Pico | Every VR module |
| Load | k6 (10k concurrent) | Quarterly |
| Security | ZAP, Burp, custom fuzzers | Every release |
| Phishing sim | Isolated test environment + recipient allow-list test | Every campaign |
| Privacy | Data-flow audit against `PRIVACY.md` | Every release |
| Chaos | Mail relay failure, SSO outage, CDN miss | Monthly |

**Dedicated security tests:**
- Attempt to send phishing to non-employee → blocked.
- Attempt to bypass two-person approval → blocked.
- Attempt to access another employee's progress (IDOR) → 404.
- Attempt to extract quiz answer keys → not present in any response.
- Attempt XSS via scenario dialogue, employee display name, quiz text → escaped.
- Verify certificate signature verification endpoint works.
- Verify audit hash-chain detects tampering.
- Confirm no PII in logs.
- Confirm no camera/mic/eye-tracking data leaves the device.
- Verify VR session caps + break prompts fire.

**Accessibility tests (mandatory):**
- Full module completion with screen reader only.
- Full module completion with keyboard only.
- Color-blind simulation (deuteranopia, protanopia, tritanopia).
- 200% zoom usable.
- RTL layout renders correctly.

**Privacy tests:**
- Verify no third-party requests from frontend (network log).
- Verify no keystroke/mouse analytics.
- Verify camera/mic not requested unless AR/voice module.
- Verify Vault access pattern for PII columns.

---

## 12. Privacy & Compliance

- **Legal basis:** Employment (training requirement) + legitimate interest.
- **Works council:** Required consultation in EU before deploying phishing simulation and any behavioral metric.
- **Data minimization:** See §6.5 — what we do NOT collect.
- **Retention:**
  - Progress records: per HR policy (typically 2 years, or until training cycle ends).
  - Completion certificates: 7 years (audit).
  - Phishing sim campaign data: 12 months, aggregated.
  - Audit logs: 7 years (WORM).
  - VR session metadata: 30 days.
- **Right to access:** Employee can export their own records via self-service.
- **Right to erasure:** Supported for progress records on separation (audit logs exempt as legal record).
- **Cross-border:** Regional deployments; no transfer without legal basis.
- **Regulatory mapping:**
  - ISO 27001 A.6.3 (awareness training) — completion evidence.
  - SOC 2 CC1.4, CC2.2 — training records.
  - PCI-DSS 12.6 — security awareness program evidence.
  - HIPAA §164.308(a)(5) — workforce security awareness.
  - NIS2 Art. 20 — cyber hygiene training.
  - GDPR Art. 5, 6, 13, 17, 22, 35 — DPIA required for phishing sim.

Full policy in `PRIVACY.md`.

---

## 13. Incident Response (Training Platform Itself)

### 13.1 Phishing Simulation Abuse Detected

1. **Kill switch** immediately.
2. Query audit log for all campaigns sent in last 24h.
3. Verify recipient list — confirm no external addresses.
4. Contact email security team (outbound filtering may have flagged).
5. Notify employees if any real-looking phishing was sent.
6. Rotate mail relay credentials, DKIM keys.
7. Forensic review of `phishing-sim` VPC.
8. Post-mortem within 7 days.

### 13.2 Employee Data Leak

1. Identify scope (which columns, which employees).
2. Rotate Vault credentials.
3. Notify privacy office; 72h GDPR notification if required.
4. Provide self-service breach notice to employees.
5. Legal review for employment implications.

### 13.3 Certificate Forgery

1. Revoke compromised certificate IDs via CRL (published).
2. Rotate signing key.
3. Re-issue legitimate certificates.
4. Notify auditors of the incident + remediation.
5. Post-mortem → strengthen issuance controls.

### 13.4 Platform Compromise

1. **Kill switch** (both training + phishing sim).
2. Isolate VPCs; revoke certs.
3. Rotate all secrets, keys, sessions.
4. Preserve evidence (memory, logs).
5. Assess scope via SIEM.
6. Notify CISO, legal, privacy (72h GDPR if applicable).
7. Rebuild from signed images + IaC.

Full runbook in `RUNBOOK.md`.

---

## 14. Module Authoring Security

Authors create training modules (3D scenes, text, quizzes). Trusted but bounded.

- **Onboarding:** NDA + AUP + background check for direct employees; contract + DPA for vendors.
- **Signing keys:** HSM-backed, unique per author, revocable.
- **Peer review mandatory** (two-person rule before publish).
- **Content rules:**
  - No real customer names, logos, or PII.
  - No real incident details without legal review.
  - No real IOCs from internal sources.
  - No depictions of harassment, discrimination, or violence without DEI review.
  - No LLM-generated content in published modules.
- **Asset sources:** Approved vendors only; license tracked.
- **Author tooling** in a hardened environment (no internet, no prod access).
- **Localization:** Reviewed by native speakers; no machine translation for published content.

Full guidance in `ACCESSIBILITY.md` and authoring addendum.

---

## 15. Roadmap & Open Items

| Item | Priority | Rationale |
|---|---|---|
| WebXR AR passthrough modules | P2 | Higher immersion for physical security |
| Multi-language expansion (12 → 24) | P2 | Global workforce |
| Adaptive learning paths | P3 | Requires behavioral data (privacy review) |
| LLM-guided debrief | P3 | Prompt-injection defense required |
| Voice interaction in VR | P3 | Consent + retention critical |
| Offline/air-gapped deployment | P2 | Classified environments |
| Federated completion (cross-org) | P4 | Trust framework needed |
| Quantum-resistant certificate signatures | P3 | HSM vendor readiness 2025-2026 |
| Biometric feedback (optional) | P4 | Works council + ethics review |

---

## 16. References

- OWASP ASVS v4.0.3 — Level 2
- OWASP Top 10 (2021)
- OWASP File Upload Cheat Sheet
- OWASP WebSocket Security Cheat Sheet
- NIST SP 800-53 Rev. 5 — Moderate baseline
- NIST SP 800-50 — Building an IT Security Awareness Program
- NIST SP 800-61r3 — Incident Handling
- NIST SP 800-207 — Zero Trust Architecture
- W3C WebXR Device API
- W3C WCAG 2.2 AA
- ARIA Authoring Practices Guide
- Khronos glTF 2.0
- ISO 27001 A.6.3
- SOC 2 CC1.4, CC2.2
- PCI-DSS v4.0 §12.6
- HIPAA §164.308(a)(5)
- NIS2 Article 20
- GDPR Art. 5, 6, 13, 17, 22, 35
- ENISA Cybersecurity Awareness guidance
- SLSA v1.0 — Build Level 3

---

**Approval:** This document requires sign-off from **CISO**, **Head of People / HR**, **Privacy Officer**, **Accessibility Lead**, and **Head of Security Architecture** before production. Changes to **phishing simulation controls**, **privacy scope**, **accessibility parity**, or **certificate signing** require re-review by all five.

**Review cadence:** Quarterly, or upon: (a) phishing sim incident, (b) privacy regulation change, (c) accessibility complaint, (d) works council feedback, (e) new module class.

**Contact:** `sat-architecture@example.com` — PGP key in `SECURITY.md`.

**Non-negotiables:**
- Phishing simulation is isolated. Always.
- Recipients are allow-listed to employees only. Enforced at every layer.
- Two-person approval for every phishing campaign.
- No credential harvesting, ever — even in simulations.
- Answer keys never leave the server.
- Completion certificates are signed. Auditors can verify.
- Every module works without WebXR, without 3D, and with a screen reader.
- We collect the minimum data needed for compliance — nothing more.
- Works councils are consulted before behavioral data or simulation campaigns.
- A kill switch exists for every dangerous subsystem.