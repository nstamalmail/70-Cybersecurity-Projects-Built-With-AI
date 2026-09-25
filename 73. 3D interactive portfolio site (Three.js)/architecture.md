# Architecture Specification: 3D Interactive Portfolio Site

**Document Version:** 1.0.0
**Classification:** Internal
**Author:** Senior Security Developer
**Last Updated:** 2025-01-15
**Status:** Approved for Implementation

---

## 1. Executive Summary

This document defines the architecture for an **interactive 3D portfolio website** built with **Three.js** on the frontend and **Python (FastAPI)** on the backend. The system renders a WebGL-based 3D scene with interactive project showcases, contact functionality, and an administrative content pipeline.

Given the public-facing nature of the site and the WebGL attack surface, this architecture treats security as a **first-class, non-negotiable requirement** — not an afterthought. All design decisions are evaluated against OWASP Top 10 (2021), OWASP ASVS L2, and common WebGL/asset-pipeline threats.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                          CLIENT (Browser)                            │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  Static Frontend (Three.js + Vite)                             │  │
│  │  • WebGL Renderer  • GLTF/DRACO Loader  • UI Overlay (DOM)     │  │
│  │  • CSP-locked, SRI-verified bundles, no inline scripts         │  │
│  └────────────────────────────────────────────────────────────────┘  │
│                              │ HTTPS / WSS                           │
└──────────────────────────────┼───────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     EDGE / CDN (Cloudflare / CloudFront)             │
│  • TLS 1.3 termination   • WAF (OWASP ruleset)   • DDoS mitigation  │
│  • Bot management        • Static asset caching (immutable)          │
└──────────────────────────────┬───────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                 REVERSE PROXY (Nginx — hardened)                     │
│  • Rate limiting  • Request size caps  • Security headers            │
│  • Path normalization  • TLS re-encrypt to app tier                  │
└──────────────────────────────┬───────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                    APPLICATION TIER (Python 3.12)                    │
│  ┌──────────────────────┐  ┌──────────────────┐  ┌───────────────┐   │
│  │ FastAPI (API)        │  │ Celery Workers   │  │ Admin CLI     │   │
│  │ • Contact form       │  │ • GLB/GLTF scan  │  │ • Publish     │   │
│  │ • Analytics beacon   │  │ • Asset optimize │  │ • Rotate keys │   │
│  │ • Asset manifest     │  │ • Email dispatch │  │               │   │
│  └──────────┬───────────┘  └────────┬─────────┘  └───────┬───────┘   │
└─────────────┼───────────────────────┼────────────────────┼───────────┘
              ▼                       ▼                    ▼
┌──────────────────────────────────────────────────────────────────────┐
│                        DATA & INFRASTRUCTURE                         │
│  PostgreSQL (RLS) │ Redis (TLS, auth) │ S3 (SSE-KMS, versioned)      │
│  HashiCorp Vault (secrets) │ OpenTelemetry → SIEM                    │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Technology Stack

| Layer | Technology | Justification |
|---|---|---|
| Frontend 3D | Three.js r160+ | Mature, tree-shakeable, WebGL2 |
| Bundler | Vite 5 | ESM, code splitting, HMR |
| Language (FE) | TypeScript 5 (strict) | Type safety, DOM XSS prevention |
| Backend | FastAPI (Python 3.12) | Async, Pydantic v2 validation |
| ASGI Server | Uvicorn + Gunicorn | Battle-tested, non-root worker |
| Task Queue | Celery + Redis (TLS) | Async asset pipeline |
| Database | PostgreSQL 16 | Row-Level Security, JSONB |
| Object Store | S3-compatible (SSE-KMS) | Versioned, private-by-default |
| Secrets | HashiCorp Vault / AWS Secrets Manager | No secrets in env or repo |
| Container | Docker (distroless) | Minimal attack surface |
| Orchestration | Kubernetes (or Fly.io) | NetworkPolicy, PSP/PSA |
| Observability | OpenTelemetry, Prometheus, Loki | Structured audit trail |
| CDN / Edge | Cloudflare | WAF, bot mgmt, TLS 1.3 |

---

## 4. Directory Layout

```
portfolio-3d/
├── architecture.md
├── README.md
├── SECURITY.md
├── frontend/
│   ├── index.html
│   ├── vite.config.ts
│   ├── src/
│   │   ├── main.ts
│   │   ├── scene/                # Three.js scene graph
│   │   │   ├── SceneManager.ts
│   │   │   ├── CameraRig.ts
│   │   │   ├── Lighting.ts
│   │   │   └── PostProcessing.ts
│   │   ├── loaders/              # Asset loading w/ validation
│   │   │   ├── GLTFLoaderSafe.ts
│   │   │   └── AssetManifest.ts
│   │   ├── interactions/
│   │   │   ├── Raycaster.ts
│   │   │   └── HotspotManager.ts
│   │   ├── ui/                   # DOM overlay (accessible)
│   │   │   ├── Overlay.tsx
│   │   │   └── A11yFallback.ts
│   │   └── security/
│   │       ├── csp.ts
│   │       └── sanitize.ts
│   └── public/assets/            # Served from CDN, SRI-hashed
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py             # Pydantic Settings, no defaults for secrets
│   │   ├── api/
│   │   │   ├── contact.py
│   │   │   ├── analytics.py
│   │   │   └── manifest.py
│   │   ├── security/
│   │   │   ├── headers.py        # HSTS, CSP, COOP, COEP
│   │   │   ├── ratelimit.py
│   │   │   ├── csrf.py
│   │   │   └── captcha.py        # Turnstile verification
│   │   ├── models/               # Pydantic v2 strict models
│   │   ├── db/
│   │   │   ├── session.py
│   │   │   └── migrations/
│   │   └── workers/
│   │       ├── asset_scan.py     # GLB/GLTF sanitization
│   │       └── mailer.py
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   └── security/             # Dedicated security regression suite
│   └── Dockerfile
├── infra/
│   ├── nginx/nginx.conf
│   ├── k8s/
│   └── terraform/
└── .github/workflows/
    ├── ci.yml                    # SAST, SCA, secret scan
    └── cd.yml                    # SLSA L3 provenance
```

---

## 5. Frontend Architecture (Three.js)

### 5.1 Rendering Pipeline
- **WebGL2 first**, WebGL1 fallback for legacy; detect capabilities at boot.
- **Renderer config:** `antialias: true`, `powerPreference: "high-performance"`, `preserveDrawingBuffer: false` (prevents pixel readback abuse via `toDataURL`).
- **Post-processing** via `EffectComposer` (SSAO, bloom) — disabled on low-power devices via `navigator.hardwareConcurrency` + `WEBGL_debug_renderer_info` heuristics.

### 5.2 Asset Loading — **Critical Security Surface**
GLTF/GLB files are **untrusted input**. The loader MUST:

1. Validate MIME type (`model/gltf-binary`) **and** magic bytes (`glTF`).
2. Enforce a **max file size** (e.g., 25 MB) client-side *and* server-side.
3. Parse GLB header manually to reject:
   - Embedded scripts in `extras` fields.
   - External URI references (`http://`, `https://`, `file://`) — **only relative, allow-listed paths**.
   - Shader injection via `KHR_materials_*` custom extensions.
4. Only enable a **strict allow-list** of glTF extensions: `KHR_draco_mesh_compression`, `KHR_texture_basisu`, `KHR_mesh_quantization`.
5. Load via `fetch()` with `credentials: 'omit'` and `referrerPolicy: 'no-referrer'`.

```ts
// loaders/GLTFLoaderSafe.ts (excerpt)
const ALLOWED_EXT = new Set([
  'KHR_draco_mesh_compression',
  'KHR_texture_basisu',
  'KHR_mesh_quantization',
]);

export async function loadGLB(url: string, opts: LoadOptions) {
  if (!isAllowListedUrl(url)) throw new SecurityError('URL not allow-listed');
  const res = await fetch(url, { credentials: 'omit', referrerPolicy: 'no-referrer' });
  if (!res.ok) throw new LoadError(res.status);
  const buf = await res.arrayBuffer();
  if (buf.byteLength > opts.maxBytes) throw new SecurityError('Asset too large');
  const magic = new TextDecoder().decode(new Uint8Array(buf, 0, 4));
  if (magic !== 'glTF') throw new SecurityError('Invalid GLB magic');
  const loader = new GLTFLoader();
  const gltf = await loader.parseAsync(buf, '');
  validateExtensions(gltf, ALLOWED_EXT);
  return gltf;
}
```

### 5.3 Interaction Layer
- **Raycaster** for hotspot picking, throttled to `requestAnimationFrame`.
- No `eval`, no `new Function`, no dynamic `import()` of user-derived strings.
- All user-controlled text (project titles, descriptions) rendered via `textContent` — **never** `innerHTML`.

### 5.4 Accessibility & Fallback
- `<noscript>` renders a **static HTML portfolio** (SEO + a11y requirement).
- `prefers-reduced-motion` disables camera animation.
- Keyboard navigation for hotspots; ARIA labels synced with 3D focus state.
- Screen-reader-only DOM mirror of scene content.

### 5.5 Content Security Policy
Served as a **header** (not meta) from Nginx/CDN:

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'wasm-unsafe-eval' https://cdn.jsdelivr.net;
  style-src 'self';
  img-src 'self' data: blob:;
  font-src 'self';
  connect-src 'self' https://api.example.com;
  worker-src 'self';
  child-src 'none';
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'self';
  object-src 'none';
  require-trusted-types-for 'script';
  upgrade-insecure-requests;
```

> `'wasm-unsafe-eval'` is required **only** if Draco is WASM-decoded. Prefer `wasm-unsafe-eval` over `'unsafe-eval'`.

Additional headers:
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

---

## 6. Backend Architecture (Python / FastAPI)

### 6.1 API Surface

| Method | Path | Purpose | AuthN | Rate Limit |
|---|---|---|---|---|
| GET | `/api/v1/manifest` | Asset manifest (signed URLs) | None | 60/min/IP |
| POST | `/api/v1/contact` | Contact form submission | Turnstile + CSRF | 5/min/IP |
| POST | `/api/v1/analytics/event` | Privacy-preserving beacon | None | 120/min/IP |
| GET | `/api/v1/health` | Liveness | None | 10/min/IP |
| GET | `/api/v1/projects/{slug}` | Project metadata | None | 60/min/IP |
| POST | `/admin/v1/assets` | Upload 3D asset | mTLS + OIDC | 10/min/user |

### 6.2 Input Validation — Pydantic v2 (Strict Mode)

```python
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from typing import Annotated

class ContactRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: Annotated[str, Field(min_length=1, max_length=80, pattern=r"^[\w\s\.\-']+$")]
    email: EmailStr
    subject: Annotated[str, Field(min_length=1, max_length=120)]
    message: Annotated[str, Field(min_length=10, max_length=2000)]
    turnstile_token: Annotated[str, Field(min_length=20, max_length=4096)]
```

**Rules:**
- `extra="forbid"` — reject unknown fields (mass-assignment defense).
- Max length on every string — prevents ReDoS / DB bloat.
- Email via `EmailStr` (uses `email-validator`, no regex DoS).

### 6.3 Contact Endpoint (Hardened)

```python
@router.post("/contact", status_code=202)
async def submit_contact(
    payload: ContactRequest,
    request: Request,
    _csrf: None = Depends(verify_csrf),
    _rl: None = Depends(rate_limit("contact", per="ip", limit=5, window=60)),
):
    if not await turnstile.verify(payload.turnstile_token, request.client.host):
        raise HTTPException(403, "Verification failed")

    sanitized = html.escape(payload.message)
    task = send_contact_email.delay(
        name=payload.name, email=payload.email,
        subject=payload.subject, body=sanitized,
    )
    audit_log.info("contact.submitted", extra={"ip": hash_ip(request.client.host)})
    return {"status": "queued", "id": task.id}
```

**Security properties:**
- CSRF double-submit cookie + `SameSite=Strict`.
- Cloudflare Turnstile (privacy-preserving CAPTCHA) — no reCAPTCHA tracking.
- IP hashed with rotating HMAC key before logging (GDPR-friendly).
- Email dispatch is **async** — no SMTP latency in request path, no SMTP header injection (subject/body via template engine, not string concat).
- Rate limited at edge (Cloudflare) **and** app (Redis token bucket).

### 6.4 3D Asset Upload Pipeline (Admin)

```
Upload → Virus scan (ClamAV) → Structural validation → Optimize (gltf-transform)
       → Re-sign → S3 (SSE-KMS, private) → CDN invalidation → Manifest update
```

Validation performed server-side in a **sandboxed worker** (gVisor/Firecracker):
- Parse GLB binary header.
- Reject embedded URIs to non-allow-listed domains.
- Strip unknown `extras`/`extensions` fields.
- Enforce triangle/vertex/texture-dimension budget.
- Re-encode via `gltf-transform` — **never serve the original upload**.

### 6.5 Database

- **PostgreSQL with Row-Level Security (RLS)** — even app bugs can't cross tenants (admin vs public).
- Connections via **PgBouncer** with TLS; app user has only `SELECT/INSERT` on needed tables.
- All queries parameterized via SQLAlchemy 2.0 ORM — **no f-string SQL**, enforced by CI lint (`bandit`, `semgrep`).
- PII columns encrypted at rest (pgcrypto) with keys from Vault.

### 6.6 Secrets Management

- **Zero secrets in env vars, code, or CI logs.**
- Runtime fetch from Vault with short-lived tokens (≤15 min TTL).
- CI uses OIDC federation to cloud — no long-lived AWS/GCP keys.
- `.env` files **never** committed; `git-secrets` + `gitleaks` in pre-commit + CI.

---

## 7. Security Architecture (Threat Model — STRIDE)

| Threat | Vector | Mitigation |
|---|---|---|
| **S**poofing | Fake contact submissions | Turnstile + rate limit + email verification |
| **T**ampering | Malicious GLB upload | Server-side re-encode, sandboxed parser, allow-list |
| **R**epudiation | No audit trail | Structured audit logs → SIEM (immutable) |
| **I**nfo disclosure | Verbose errors, source maps | Generic error responses; source maps **not** deployed |
| **D**oS | WebGL tab exhaustion, API flood | Edge WAF, rate limits, WebGL context loss handling |
| **E**levation | Admin endpoint abuse | mTLS + OIDC + IP allow-list + separate hostname |

### 7.1 WebGL-Specific Threats

| Threat | Description | Mitigation |
|---|---|---|
| **Shader injection** | Malicious GLSL in custom materials | Only built-in materials from allow-list; no runtime shader compilation from user strings |
| **GLB decompression bomb** | Draco-encoded huge mesh crashes tab | Enforce `maxVertices`, `maxTriangles`, `maxTextureBytes` **before** decode |
| **Texture format exploits** | Malformed KTX2/Basis | Use `basis_universal` transcoder, strictly validated |
| **Pixel readback** | `preserveDrawingBuffer` → `toDataURL` | Disabled by default |
| **Cross-origin texture** | Leak via `img-src` + canvas | `crossOrigin='anonymous'`, CSP `img-src 'self'` |
| **WebGPU side-channels** | Timing attacks (research-stage) | Feature-flagged off until mature |

### 7.2 OWASP Top 10 Mapping

| Risk | Control |
|---|---|
| A01 Broken Access Control | RLS, admin on separate origin, mTLS |
| A02 Crypto Failures | TLS 1.3 only, HSTS preload, AES-256-GCM at rest |
| A03 Injection | Pydantic strict, ORM-only, `textContent`, CSP |
| A04 Insecure Design | This document; threat model reviewed quarterly |
| A05 Misconfiguration | Distroless containers, CIS benchmark, IaC scan |
| A06 Vulnerable Components | Dependabot, SCA (`pip-audit`, `npm audit`), SBOM |
| A07 Auth Failures | OIDC + MFA for admin, no local passwords |
| A08 Integrity Failures | SRI, SLSA L3 provenance, signed images (Cosign) |
| A09 Logging Failures | OTel → SIEM, alerting on anomalies |
| A10 SSRF | URL allow-list, no user-supplied fetches server-side |

---

## 8. Infrastructure & Deployment

### 8.1 Nginx (hardened, excerpt)

```nginx
server {
    listen 443 ssl http2;
    ssl_protocols TLSv1.3;
    ssl_prefer_server_ciphers off;

    client_max_body_size 1m;
    client_body_timeout 10s;
    keepalive_timeout 15s;
    server_tokens off;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://backend:8000;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /assets/ {
        root /var/www/static;
        add_header Cache-Control "public, max-age=31536000, immutable";
    }
}
```

### 8.2 Container Hardening
- **Distroless** base (`gcr.io/distroless/python3-debian12`).
- Run as **UID 65532** (nonroot), read-only rootfs, no `CAP_*`.
- `seccompProfile: RuntimeDefault`, `allowPrivilegeEscalation: false`.
- Kubernetes `NetworkPolicy`: egress allow-list only (Postgres, Redis, Vault, SMTP relay).

### 8.3 CI/CD Security Gates
Every PR must pass:
1. `ruff` + `mypy --strict` (Python)
2. `eslint` + `tsc --noEmit` (TS)
3. `bandit` + `semgrep` (SAST)
4. `pip-audit` + `npm audit` (SCA)
5. `gitleaks` (secret scan)
6. `trivy` (container image scan)
7. `checkov` (IaC scan)
8. SBOM generation (CycloneDX)
9. Image signing with **Cosign**; admission webhook verifies signature.

---

## 9. Observability & Incident Response

- **Structured JSON logs** with correlation IDs; PII redacted at source.
- **Metrics:** request latency p50/p95/p99, WebGL context-loss rate, asset-load failures, CSP violation reports.
- **CSP reporting** endpoint `/api/v1/csp-report` (rate-limited, sampled).
- **Alerts:** anomalous 4xx/5xx spikes, rate-limit hits, Turnstile failures, WAF blocks.
- **IR runbook:** documented in `SECURITY.md`; 24h triage SLA for critical.

---

## 10. Testing Strategy

| Layer | Tooling | Coverage Target |
|---|---|---|
| Unit (FE) | Vitest | 80% |
| E2E (FE) | Playwright (incl. a11y via axe-core) | Critical flows |
| Unit (BE) | pytest + httpx | 85% |
| Security | ZAP baseline, custom GLB fuzzer | Every release |
| Load | k6 | 10× peak |
| Chaos | context-loss injection, network throttle | Monthly |

**Dedicated security tests:**
- Malformed GLB corpus (fuzzed) → must reject, not crash.
- Oversized asset → 413.
- Missing CSRF → 403.
- SQLi/XSS payloads in every string field → blocked.
- CSP violation → reported, no bypass.

---

## 11. Compliance & Data Handling

- **GDPR:** analytics events store only hashed IP + coarse UA; retention 30 days; DSR endpoint via admin.
- **CCPA:** opt-out toggle disables all non-essential telemetry.
- **Cookies:** only `__Host-session` (HttpOnly, Secure, SameSite=Strict, `__Host-` prefix). No third-party cookies.
- **Data residency:** primary region EU (configurable).

---

## 12. Roadmap & Open Items

| Item | Priority | Notes |
|---|---|---|
| WebGPU renderer path | P3 | Wait for spec stability; side-channel research ongoing |
| WASM asset validator (client) | P2 | Duplicate server checks in browser for UX |
| Signed manifests (Ed25519) | P2 | Prevents CDN tampering |
| Passkey-only admin auth | P2 | Remove password fallback entirely |
| Per-session WebGL budget | P3 | Mitigate cryptojacking via GPU |

---

## 13. References

- OWASP ASVS v4.0.3 — Level 2
- OWASP Top 10 (2021)
- NIST SP 800-53 Rev. 5 (SC, SI, AU families)
- Khronos glTF 2.0 Specification
- SLSA v1.0 — Build Level 3
- CIS Docker Benchmark v1.6

---

**Approval:** Security review required before any production deployment. Contact `security@example.com` for threat-model updates.