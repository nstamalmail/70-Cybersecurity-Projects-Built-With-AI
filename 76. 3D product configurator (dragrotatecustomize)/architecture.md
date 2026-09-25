# Architecture Specification: 3D Product Configurator (Drag / Rotate / Customize)

**Document Version:** 1.0.0
**Classification:** Internal — Customer-Facing System
**Author:** Senior Security Developer
**Last Updated:** 2025-01-15
**Status:** Approved for Implementation
**Document ID:** ARCH-3DCONF-001

---

## 1. Executive Summary

This document defines the architecture for a **customer-facing 3D product configurator** that allows users to **drag, rotate, and customize** products in real time (color, material, size, accessories, engraving), then add configured items to a cart and check out.

The system is a **revenue-critical, PCI-adjacent, high-traffic** application. It combines three risk domains that rarely coexist in one app:

1. **WebGL rendering** (client-side, adversarial input surface via 3D assets).
2. **E-commerce + payments** (PCI-DSS scope, fraud, cart manipulation).
3. **User-generated content** (engraving text, custom uploads, saved configurations).

**Design principles:**

1. **Price is a backend fact, never a client claim.** The client proposes a configuration; the server recomputes and signs the price. Cart manipulation dies here.
2. **Assets are code.** GLTF/GLB, textures, and materials are treated as executable-adjacent — never trusted from user uploads without a full sanitization pipeline.
3. **PCI scope minimized.** No card data ever touches our origin. Hosted fields + tokenization only.
4. **The configurator is fast or it's broken.** 60 fps on mid-tier mobile, or users bounce. Security controls must not add perceptible latency to interaction.
5. **Every customization is auditable.** Saved configurations carry a signed, versioned manifest — reproducible for manufacturing, support, and dispute resolution.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          CLIENT (Browser / Mobile Web)                    │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  Three.js WebGL2 Scene  •  React UI  •  State (Zustand)            │  │
│  │  Trusted Types  •  Strict CSP  •  WASM price preview (unsigned)    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                              │ HTTPS / WSS                                │
└──────────────────────────────┼───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    EDGE / CDN (Cloudflare / CloudFront)                  │
│  • TLS 1.3  • WAF (OWASP)  • Bot Mgmt  • Static asset cache (immutable)  │
│  • Image/asset optimization  • Geo-routing  • Rate limit                 │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                 REVERSE PROXY (Nginx — hardened, L7)                     │
│  • Request caps  • Header hygiene  • Body size limits  • Security hdrs   │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    API GATEWAY (FastAPI — Python 3.12)                   │
│  • Session/mTLS  • Rate limit (Redis)  • WAF delegation  • Audit tap     │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    APPLICATION SERVICES (Python)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Catalog      │  │ Configurator │  │ Cart/Order   │  │ Upload       │  │
│  │ (read-only)  │  │ (pricing,    │  │ (signed      │  │ (engraving,  │  │
│  │              │  │  rules)      │  │  configs)    │  │  logos)      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
└─────────┼─────────────────┼─────────────────┼─────────────────┼──────────┘
          ▼                 ▼                 ▼                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        DATA & INFRASTRUCTURE                             │
│  PostgreSQL (catalog, orders) │ Redis (sessions, hot price cache)        │
│  S3 (3D assets, uploads — SSE-KMS) │ OpenSearch (catalog search)         │
│  Vault (secrets) │ HSM (signing keys) │ OTel → SIEM                      │
└──────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    EXTERNAL SERVICES (Tiered Trust)                      │
│  Payment (Stripe/Adyen — tokenized)  •  Tax  •  Shipping  •  ERP         │
│  Fraud (Sift/Stripe Radar)  •  Email  •  Analytics (self-hosted)         │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Model

### 3.1 Assets

| Asset | Sensitivity | Impact if Compromised |
|---|---|---|
| Pricing rules & margins | **High** | Competitive loss, price manipulation |
| Saved customer configs | **Medium** | PII leak, order errors |
| User uploads (logos, engraving) | **High** | Malware distribution, CSAM, IP theft |
| 3D product assets (unreleased) | **High** | Leak of unreleased products |
| Cart / order data | **High** | Fraud, PCI scope, financial loss |
| Session tokens | **High** | Account takeover |
| Payment tokens | **Critical** (never stored) | Fraud |

### 3.2 Adversary Profiles

1. **Bargain hunter / price manipulator** — modifies price client-side, replays coupons.
2. **Fraudster** — stolen cards, card testing, account takeover.
3. **Competitor** — scrapes catalog, unreleased models, pricing.
4. **Malware distributor** — uploads weaponized "logo" or "engraving."
5. **Scraper/bot** — inventory, pricing, product images.
6. **Opportunistic attacker** — dependency exploit, XSS.
7. **Insider** — leaks unreleased product assets.

### 3.3 STRIDE

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Session hijack, forged config | HttpOnly cookies, TLS-only, signed configs |
| **Tampering** | Client-side price edit | Server recomputes price; configs HMAC-signed |
| **Repudiation** | "I didn't order that" | Signed config manifest + audit log |
| **Info Disclosure** | Unreleased asset leak | Signed URLs, short TTL, referrer checks |
| **DoS** | Configurator flood, upload spam | CDN, rate limits, CAPTCHA on upload |
| **Elevation** | Guest → admin via IDOR | UUIDs, RLS, per-object authz |
| **Price manipulation** | Tampered cart | Server-authoritative pricing; signed line items |
| **Upload weaponization** | Malicious GLB/PNG/SVG | Server-side re-encode; SVG disabled entirely |
| **Card testing** | Rapid small auths | Fraud provider + velocity rules |

### 3.4 The Price Integrity Problem

**The core threat:** Any value that crosses the client is a value the client can lie about.

**Control:** Every price shown is a **preview**. The only price that matters is computed **server-side** at:
1. Add-to-cart (server computes and returns a **signed line item**).
2. Checkout (server recomputes and rejects any mismatch).

```python
# Signed line item — client stores this, server trusts nothing else
class LineItem(BaseModel):
    config_id: UUID
    sku: str
    options: dict[str, str]          # canonical
    quantity: int
    unit_price_cents: int            # server-computed
    currency: str
    computed_at: datetime
    price_signature: str             # Ed25519 over canonical payload
```

If the client returns a modified `unit_price_cents`, signature verification fails → 400 + security event.

---

## 4. Technology Stack

| Layer | Technology | Justification |
|---|---|---|
| Frontend 3D | Three.js r160+ | Mature, WebGL2, Draco/Basis support |
| Frontend UI | React 18 + TypeScript 5 (strict) | Ecosystem, type safety |
| State | Zustand | Lightweight, no boilerplate |
| Bundler | Vite 5 | ESM, HMR, code splitting |
| Backend | FastAPI (Python 3.12) | Async, Pydantic v2 strict |
| ASGI | Uvicorn + Gunicorn | Non-root worker, battle-tested |
| Task queue | Celery + Redis (TLS) | Async asset pipeline, emails |
| DB | PostgreSQL 16 (RLS) | Transactions, integrity |
| Cache | Redis 7 (TLS, ACL) | Sessions, price cache |
| Search | OpenSearch | Catalog search |
| Asset store | S3 (SSE-KMS, versioned) | Private-by-default, versioned |
| CDN | Cloudflare | WAF, DDoS, cache, image resizing |
| Payments | Stripe (Elements + Payment Intents) | PCI SAQ-A-EP, tokenized |
| Fraud | Stripe Radar + custom velocity | Card testing defense |
| Secrets | HashiCorp Vault + AWS Secrets Manager | Rotation, audit |
| Signing | AWS KMS (Ed25519) or HSM | Config + price signatures |
| Container | Distroless | Minimal attack surface |
| Orchestration | Kubernetes + OPA + NetworkPolicy | Zero-trust |
| Observability | OpenTelemetry → Prometheus/Loki/Grafana | Full-stack |
| Asset pipeline | gltf-transform, sharp, libvips | Server-side sanitization/re-encode |

---

## 5. Directory Layout

```
configurator-3d/
├── architecture.md
├── SECURITY.md
├── PCI_SCOPE.md
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
│       │   ├── ProductLoader.ts        # safe GLB loader
│       │   ├── MaterialApplier.ts      # color/finish switching
│       │   ├── OrbitControlsSafe.ts    # rotate/zoom
│       │   ├── DragHandler.ts          # drag-to-explode, part drag
│       │   ├── EngravingPreview.ts     # canvas → texture
│       │   └── Lighting.ts
│       ├── state/
│       │   ├── ConfigStore.ts          # selected options
│       │   ├── PricePreview.ts         # WASM/local estimate (never trusted)
│       │   └── CartSync.ts
│       ├── ui/
│       │   ├── OptionPanel.tsx
│       │   ├── ColorPicker.tsx
│       │   ├── EngravingInput.tsx
│       │   ├── UploadLogo.tsx
│       │   ├── PriceDisplay.tsx        # shows server price only
│       │   └── A11yFallback.tsx        # non-WebGL fallback view
│       └── a11y/
│           ├── ScreenReaderMirror.tsx
│           └── KeyboardNav.ts
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py                   # Vault-backed
│   │   ├── api/
│   │   │   ├── catalog.py              # GET only
│   │   │   ├── configure.py            # POST /configure → price
│   │   │   ├── cart.py
│   │   │   ├── upload.py
│   │   │   ├── orders.py
│   │   │   └── ws.py                   # live price updates
│   │   ├── security/
│   │   │   ├── authn.py                # session cookies
│   │   │   ├── csrf.py
│   │   │   ├── headers.py
│   │   │   ├── ratelimit.py
│   │   │   ├── signing.py              # config & price signatures
│   │   │   ├── upload_guard.py
│   │   │   └── captcha.py              # Turnstile on upload
│   │   ├── catalog/
│   │   │   ├── models.py
│   │   │   ├── pricing.py              # rule engine
│   │   │   └── rules.py                # compatibility, constraints
│   │   ├── assets/
│   │   │   ├── validator.py            # GLB structural validation
│   │   │   ├── sanitizer.py            # gltf-transform pipeline
│   │   │   ├── signer.py               # signed URLs
│   │   │   └── reencoder.py            # image/video re-encode
│   │   ├── uploads/
│   │   │   ├── accept.py               # MIME + magic bytes
│   │   │   ├── scanner.py              # ClamAV + custom
│   │   │   └── store.py                # S3 with SSE-KMS
│   │   ├── cart/
│   │   │   ├── line_items.py           # signed line items
│   │   │   └── validation.py           # signature verify
│   │   ├── payments/
│   │   │   ├── stripe_adapter.py       # Payment Intents only
│   │   │   └── webhooks.py             # signature verification
│   │   ├── orders/
│   │   │   ├── create.py
│   │   │   └── fulfillment.py
│   │   └── db/
│   │       ├── session.py
│   │       └── migrations/
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   ├── security/
│   │   └── price_fuzz/                 # attempt manipulation
│   └── Dockerfile
├── infra/
│   ├── nginx/
│   ├── cloudflare/
│   ├── k8s/
│   └── terraform/
└── .github/workflows/
    ├── ci.yml
    └── cd.yml
```

---

## 6. Data Model

### 6.1 Catalog & Configuration

```python
class Product(BaseModel):
    sku: str
    name: str
    base_price_cents: int
    currency: str
    options: list[OptionGroup]
    assets: list[AssetRef]              # sanitized GLBs only
    active: bool

class OptionGroup(BaseModel):
    id: str
    label: str
    type: Literal["color", "material", "size", "addon", "engraving"]
    required: bool
    max_selections: int
    values: list[OptionValue]
    rules: list[Rule]                   # compatibility constraints

class OptionValue(BaseModel):
    id: str
    label: str
    price_delta_cents: int
    hex: str | None                     # for colors
    texture_ref: str | None             # sanitized texture
    stock: int | None

class Configuration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    config_id: UUID
    sku: str
    selections: dict[str, str]          # group_id → value_id
    engraving: EngravingSpec | None
    upload_id: UUID | None
    quantity: int = Field(ge=1, le=10)
    version: int                        # catalog version for reproducibility
    created_at: datetime
    signature: str                      # Ed25519, HSM-signed
```

### 6.2 Engraving & Upload

```python
class EngravingSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: str = Field(min_length=1, max_length=40)
    font: Literal["serif", "sans", "script"]   # allow-list
    placement: Literal["front", "back", "bottom"]
    render_hash: str                    # SHA-256 of rendered texture

class UploadSpec(BaseModel):
    upload_id: UUID
    kind: Literal["logo"]
    original_filename: str              # sanitized, stored for audit only
    mime: Literal["image/png", "image/jpeg"]   # allow-list, SVG banned
    width: int = Field(ge=64, le=4096)
    height: int = Field(ge=64, le=4096)
    sha256: str
    scan_status: Literal["pending", "clean", "rejected"]
    scanned_at: datetime | None
```

### 6.3 Signed Line Item (Cart)

```python
class LineItem(BaseModel):
    line_id: UUID
    config: Configuration
    unit_price_cents: int
    currency: str
    price_breakdown: dict[str, int]     # base, options, engraving, tax est.
    computed_at: datetime
    catalog_version: int
    price_signature: str                # Ed25519, HSM-signed
```

**Invariant:** The server **never** trusts a client-supplied price. On every cart mutation, on checkout, and on order creation, the server recomputes and compares against the signed value.

---

## 7. Frontend Architecture

### 7.1 Rendering

- **WebGL2 primary**, WebGL1 fallback for old mobile (still ~1% traffic).
- **Three.js scene:**
  - Product mesh (sanitized GLB, Draco-compressed).
  - PBR materials switched by texture swap (no shader recompile).
  - Environment map (HDR, pre-filtered) for realistic finish preview.
- **Interactions:**
  - **OrbitControls** — rotate/zoom (mouse + touch).
  - **Drag** — explode view, drag individual parts (optional).
  - **Raycaster** — pick parts to customize directly.
- **Preview budget:** ≤ 60k triangles for hero product, ≤ 30k on mobile LOD.
- **Textures:** Basis/KTX2, 2k max on mobile, 4k on desktop.

### 7.2 Safe GLB Loading

GLB files are **only** loaded from our CDN, from **server-sanitized** assets. Loader still validates:

```ts
async function loadProductGLB(url: string): Promise<GLTF> {
  if (!url.startsWith('/assets/products/')) throw new Error('URL not allowed');
  const res = await fetch(url, { credentials: 'omit', referrerPolicy: 'no-referrer' });
  if (!res.ok) throw new Error('load failed');
  const buf = await res.arrayBuffer();
  if (buf.byteLength > MAX_GLB_BYTES) throw new Error('too large');
  if (new TextDecoder().decode(new Uint8Array(buf, 0, 4)) !== 'glTF')
    throw new Error('bad magic');
  const loader = new GLTFLoader();
  loader.setDRACOLoader(dracoLoader);          // fixed worker, no dynamic scripts
  loader.setKTX2Loader(ktx2Loader);
  return loader.parseAsync(buf, '');
}
```

**Rule:** Client never loads a GLB from a user upload. If the user uploads a logo, that logo is rasterized server-side and returned as a sanitized PNG (see §8.4).

### 7.3 Price Preview (Client)

The client may compute a **preview** price for UX (instant feedback). This preview is **never trusted** and is displayed with a "calculated" label. On blur / add-to-cart, the server price replaces it.

To avoid a round-trip per click, we ship a WASM module of the pricing engine. It's deterministic and identical to the server (same source, compiled twice). **Discrepancy between client and server → server wins, and a metric fires.**

### 7.4 WebSocket for Live Price / Availability

```ts
type ClientMsg =
  | { type: 'auth'; session: string }
  | { type: 'config.update'; config: Configuration }
  | { type: 'ping' };

type ServerMsg =
  | { type: 'price'; signed: LineItem }
  | { type: 'availability'; sku: string; in_stock: boolean }
  | { type: 'error'; code: string };
```

All server messages include a signature over the payload; client verifies before display.

### 7.5 Security Hardening (Frontend)

**CSP (header, not meta):**

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'wasm-unsafe-eval';
  style-src 'self' 'nonce-{random}';
  img-src 'self' data: blob:;
  font-src 'self';
  connect-src 'self' wss://config.example.com https://api.stripe.com;
  frame-src https://js.stripe.com;
  worker-src 'self' blob:;
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'self';
  object-src 'none';
  require-trusted-types-for 'script';
  trusted-types config-ui;
  upgrade-insecure-requests;
```

`'wasm-unsafe-eval'` is required for the pricing WASM — **not** `'unsafe-eval'`.

Additional headers:
```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(self "https://js.stripe.com")
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

**Trusted Types:** All DOM writes go through `config-ui` policy. **No `innerHTML` anywhere.** Engraving text, filenames, catalog names — all rendered via `textContent`.

### 7.6 Accessibility & Non-WebGL Fallback

- **`<noscript>` and WebGL-unsupported:** Serve a **2D static image + option form**; same pricing path, same checkout. This is a legal (ADA/EAA) and revenue requirement.
- **Screen-reader mirror:** The entire configurator state is available as a form with ARIA live regions.
- **Keyboard navigation:** Tab to options, arrows to rotate, Enter to select.
- **`prefers-reduced-motion`:** Auto-rotate disabled; transitions instant.
- **Contrast:** WCAG AA on all controls; option swatches carry text labels.

---

## 8. Backend Architecture

### 8.1 API Surface

| Method | Path | Purpose | Auth | Rate Limit |
|---|---|---|---|---|
| GET | `/api/v1/catalog` | Product list | None | 120/min/IP |
| GET | `/api/v1/catalog/{sku}` | Product detail | None | 120/min/IP |
| POST | `/api/v1/configure` | Validate config + price | Session | 60/min/session |
| POST | `/api/v1/cart/items` | Add signed line item | Session | 30/min/session |
| PATCH | `/api/v1/cart/items/{id}` | Update qty | Session + CSRF | 30/min/session |
| DELETE | `/api/v1/cart/items/{id}` | Remove | Session + CSRF | 30/min/session |
| POST | `/api/v1/uploads` | Upload logo | Session + Turnstile | 5/min/session |
| POST | `/api/v1/checkout/session` | Create Payment Intent | Session + CSRF | 10/min/session |
| POST | `/api/v1/webhooks/stripe` | Stripe webhook | Stripe signature | — |
| GET | `/api/v1/orders/{id}` | Order status | Session (owner) | 60/min |
| WS | `/api/v1/ws` | Live price/stock | Session | 2/session |

**Every state-changing endpoint:**
- Requires session cookie (`__Host-` prefixed, HttpOnly, Secure, SameSite=Lax).
- Requires CSRF token (double-submit, per-session).
- Rate limited per session AND per IP.
- Emits audit event.

### 8.2 Pricing Engine (Server-Authoritative)

```python
def compute_price(config: Configuration, catalog: Catalog) -> LineItem:
    product = catalog.get(config.sku)                     # raises 404
    if config.version != catalog.version:
        raise StaleCatalog()                              # force refresh

    base = product.base_price_cents
    breakdown = {"base": base}

    for group_id, value_id in config.selections.items():
        group = product.option_group(group_id)            # raises if unknown
        value = group.value(value_id)                     # raises if unknown
        rules.assert_compatible(config, group_id, value)  # raises on conflict
        breakdown[f"option:{group_id}"] = value.price_delta_cents

    if config.engraving:
        breakdown["engraving"] = catalog.engraving_fee(config.engraving)

    if config.upload_id:
        breakdown["custom_logo"] = catalog.logo_fee()

    unit = sum(breakdown.values())
    if unit < product.min_price_cents:
        raise PriceFloorViolation()                       # defense-in-depth

    return LineItem(
        line_id=uuid4(),
        config=config,
        unit_price_cents=unit,
        currency=product.currency,
        price_breakdown=breakdown,
        computed_at=utcnow(),
        catalog_version=catalog.version,
        price_signature=signer.sign(canonical(config, unit)),   # HSM
    )
```

**Properties:**
- Client-supplied prices are **never** parameters.
- Unknown groups/values → 400 (mass-assignment defense via `extra="forbid"`).
- Catalog version pinning prevents TOCTOU on price changes.
- HSM signature — cannot be forged even by a compromised app tier without the HSM key.

### 8.3 Cart Integrity

On **every** cart read and **every** checkout:

```python
def verify_line_item(item: LineItem, catalog: Catalog) -> None:
    if not signer.verify(item.price_signature, canonical(item.config, item.unit_price_cents)):
        raise TamperedCart()
    recomputed = compute_price(item.config, catalog)
    if recomputed.unit_price_cents != item.unit_price_cents:
        audit.warn("price.drift", line_id=item.line_id)
        raise PriceDrift()                # catalog updated; force re-price
```

**Behavior on failure:** Reject the cart operation, log a security event, return 409 with a user-friendly "please refresh" message. Never silently accept the discrepancy.

### 8.4 Upload Pipeline (Untrusted Input)

**Logo upload** is the highest-risk input in the system.

```
1. Session + CSRF + Turnstile verified
2. Content-Length ≤ 5 MB (hard cap at edge + app)
3. Magic-byte check: PNG (89 50 4E 47) or JPEG (FF D8 FF)
4. Decode with libvips into raw RGBA (sandboxed worker, gVisor)
   - Reject if decode fails or exceeds 8192×8192
   - Reject if pixel count > 16M (decompression bomb)
5. Strip all metadata (EXIF, ICC unless sRGB, XMP)
6. Re-encode to PNG (canonical) or JPEG quality 90
7. Compute perceptual hash → dedupe + abuse detection
8. ClamAV scan (defense-in-depth; should never hit)
9. Optional: ML-based CSAM detection (PhotoDNA or vendor)
10. Store to S3 (SSE-KMS, private, versioned)
11. Return upload_id (never a public URL)
12. Signed URL (15 min TTL) for the frontend to texture the preview
```

**Explicitly banned:**
- SVG (XXE, SSRF, script execution).
- WebP/AVIF *uploads* (decoder complexity; can be added later with fuzzing).
- Animated formats (GIF, APNG) — static only.
- ZIP, PDF, and any container format.

**Serving uploaded previews:**
- Served from a **separate origin** (`uploads-cdn.example.com`) with `Content-Disposition: inline` but `Content-Type: image/png` forced.
- `X-Content-Type-Options: nosniff`.
- **No cookies** on that origin — `Set-Cookie` never, `Cookie` stripped.

### 8.5 Payment Integration (PCI SAQ-A-EP)

**PCI scope is minimized by design:**

- Card data **never** enters our origin. Stripe Elements renders in an iframe hosted by Stripe.
- We receive a **PaymentMethod token** and create a **Payment Intent** server-side.
- We **never** store PAN, CVV, or track data — not even encrypted.
- 3D Secure handled by Stripe; we react to webhooks.
- SAQ-A-EP eligibility maintained by CSP `frame-src https://js.stripe.com` and no custom card forms.

```python
@router.post("/checkout/session")
async def create_checkout(session: Session, cart: Cart, csrf: None = Depends(verify_csrf)):
    # Re-verify every line item — belt and suspenders
    for item in cart.items:
        verify_line_item(item, catalog)
    total = sum(i.unit_price_cents * i.quantity for i in cart.items)
    intent = stripe.PaymentIntent.create(
        amount=total,
        currency=cart.currency,
        automatic_payment_methods={"enabled": True},
        metadata={"cart_id": str(cart.id), "session_id": session.id},
        idempotency_key=f"checkout:{cart.id}:{cart.version}",
    )
    audit.emit("checkout.initiated", cart_id=cart.id, amount=total)
    return {"client_secret": intent.client_secret}
```

**Webhook verification** (mandatory):

```python
@router.post("/webhooks/stripe")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    try:
        event = stripe.Webhook.construct_event(payload, sig, settings.stripe_whsec)
    except stripe.error.SignatureVerificationError:
        raise HTTPException(400, "invalid signature")
    # idempotency by event.id
    if await redis.get(f"wh:{event.id}"):
        return {"ok": True}
    await redis.setex(f"wh:{event.id}", 86400, "1")
    await handle_event(event)
    return {"ok": True}
```

### 8.6 Sessions

- Cookie: `__Host-session` — HttpOnly, Secure, SameSite=Lax, Path=/, no Domain.
- Session ID: 256-bit random, stored **hashed** (HMAC) in Redis.
- Rotate on privilege change (login, checkout start).
- Idle timeout: 30 min; absolute: 12h.
- Bind to coarse fingerprint (UA family + TLS JA3) — mismatch triggers re-auth, not hard ban (avoid breaking mobile).

---

## 9. Infrastructure

### 9.1 Nginx (excerpt)

```nginx
server {
    listen 443 ssl http2;
    ssl_protocols TLSv1.3;
    server_tokens off;

    client_max_body_size 6m;
    client_body_timeout 15s;
    keepalive_timeout 20s;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location /api/uploads {
        client_max_body_size 6m;
        limit_req zone=upload burst=3 nodelay;
        proxy_pass http://backend:8000;
    }

    location /assets/ {
        root /var/www/static;
        add_header Cache-Control "public, max-age=31536000, immutable";
    }
}
```

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
- Uploaded-file decoder runs in a **separate pod** with gVisor + no network egress.
- Cosign-signed images; admission webhook verifies.
- Resource limits + HPA on CPU + request latency.

### 9.3 Secrets

- All via Vault (dynamic DB creds, short-lived).
- Stripe keys, signing keys: rotate every 90 days; on suspected compromise immediately.
- Signing key in **HSM / KMS** — never exported, used via API.
- CI/CD uses OIDC federation — zero long-lived cloud keys.

### 9.4 Egress

- API tier egress allow-list: Stripe, tax, shipping, ERP, email.
- Upload processor: **no egress**.
- Frontend never talks to third parties except Stripe (`frame-src`, `connect-src`).

---

## 10. Observability

| Metric | Alert |
|---|---|
| `/configure` p95 | > 200ms → warn |
| Cart signature failures | > 5/min → **page** (possible attack) |
| Price drift events | any → investigate (catalog sync) |
| Upload rejection rate | > 30% → investigate |
| Payment failures | > 5% → page |
| Session fixation indicators | any → investigate |
| CSP violations | > 50/min → investigate |
| 4xx spike | > 3σ → warn |
| WAF blocks | > 10× baseline → investigate |
| Origin latency p99 | > 500ms → warn |

**Audit events** (all to append-only store):
- `config.created`, `cart.item.added`, `cart.tamper.detected`, `checkout.initiated`, `order.created`, `upload.rejected`, `auth.failed`.

---

## 11. Testing Strategy

| Layer | Tool | Coverage |
|---|---|---|
| Unit (BE) | pytest + hypothesis | 90% (pricing: 100%) |
| Unit (FE) | Vitest | 85% |
| Integration | pytest + testcontainers | Critical paths |
| E2E | Playwright (Chrome, Firefox, Safari, mobile) | Full purchase journey |
| Visual | Percy / Chromatic | Every release |
| Load | k6 (Black Friday model) | Quarterly |
| Security | ZAP, Burp, custom | Every release |
| Fuzz | GLB/PNG/JPEG upload corpus | Every release |
| Chaos | Payment provider outage, DB failover | Monthly |

**Dedicated security tests:**
- Tamper with `unit_price_cents` → 409 + audit event.
- Replay old signed line item after catalog change → rejected.
- Upload SVG/PDF/ZIP masquerading as PNG → rejected at magic bytes.
- Upload 200MP PNG (decompression bomb) → rejected at pixel cap.
- Inject XSS into engraving text, filename, catalog name → escaped everywhere.
- IDOR on `/orders/{id}` across sessions → 404.
- CSRF on all mutating endpoints → 403.
- Webhook without valid signature → 400.
- Duplicate Stripe webhook (same event.id) → idempotent.
- Rate limit bypass via header spoofing → ineffective.
- `Configuration` with extra fields → 422 (`extra="forbid"`).

---

## 12. PCI-DSS Scope

**SAQ-A-EP eligible** (self-assessment, e-commerce, payment page hosted by provider):

- No card data ever received, processed, stored, or transmitted by our origin.
- Card capture happens entirely in Stripe-hosted iframes.
- **Controls still required:**
  - Quarterly ASV scans on public hosts.
  - Annual SAQ-A-EP completion.
  - Change management, access control, logging.
  - AOC signed annually.
- **If any card form is custom-implemented → scope jumps to SAQ-D.** This is explicitly forbidden by architecture.

---

## 13. Compliance & Privacy

- **GDPR:** Session data minimal; IPs hashed with rotating HMAC; DSR endpoints; 30-day retention on logs (except audit = 7 years).
- **CCPA:** Opt-out for non-essential telemetry; "Do Not Sell" honored.
- **PCI-DSS:** See §12.
- **ADA / EAA / WCAG 2.2 AA:** Non-WebGL fallback is mandatory, tested with axe + manual SR review.
- **Data residency:** EU deployment available; S3 + DB in region.
- **Product asset confidentiality:** Unreleased SKUs served only via short-lived signed URLs; referrer checks; no directory listing; robots.txt + `X-Robots-Tag: noindex` for `/assets/unreleased/`.

---

## 14. Incident Response

### 14.1 Price Tampering Detected

1. Immediately invalidate affected carts (force re-price).
2. Rotate signing key if signature bypass confirmed.
3. Block offending session + IP range (short TTL, reviewable).
4. Audit impact: how many orders at wrong price? Refund/cancel policy via legal.
5. Post-mortem → add regression test.

### 14.2 Malicious Upload Detected

1. Quarantine upload in S3 (deny all access).
2. Notify trust & safety; if CSAM → NCMEC report per legal.
3. Scan all uploads from the same session/user.
4. Ban account; preserve evidence.

### 14.3 Card Testing Attack

1. Activate Stripe Radar rules (block rules per pattern).
2. Add velocity limit: 3 payment attempts / session / 10 min.
3. Add CAPTCHA to checkout.
4. Alert fraud team.

### 14.4 Site Defacement / XSS

1. Deploy CSP `report-only` → `enforce` (if not already).
2. Invalidate CDN.
3. Rotate session keys (invalidate all).
4. Forensics on editorial/catalog content.

Full runbook in `RUNBOOK.md`.

---

## 15. Performance Budgets (Security Must Not Break UX)

| Metric | Target |
|---|---|
| Interaction → visual feedback | < 16ms (1 frame) |
| Configurator TTI (4G) | < 2.5s |
| Price preview latency (WASM) | < 5ms |
| Server `/configure` p95 | < 200ms |
| Add-to-cart p95 | < 400ms |
| Checkout session p95 | < 600ms |
| 3D scene FPS (mid mobile) | ≥ 30 |
| Initial JS bundle | < 350 KB gzip |

**Rule:** Any security control that adds > 50ms to a perceived user action requires an architecture review. Security must be **invisible**.

---

## 16. Roadmap & Open Items

| Item | Priority | Rationale |
|---|---|---|
| AR "view in your room" | P2 | WebXR; new threat surface (camera permissions) |
| Saved configs in account | P2 | Requires authN upgrade; privacy review |
| Public share links for configs | P2 | Signed URLs; abuse prevention |
| Server-side rendering of product previews | P2 | Email/print; PDF generation security |
| Real-time collaborative config | P3 | WebRTC; complex; defer |
| ML-based abuse detection on uploads | P3 | Depends on data volume |
| Quantum-resistant signatures | P3 | HSM vendor readiness |
| WebGPU renderer path | P3 | Spec stabilizing |

---

## 17. References

- OWASP ASVS v4.0.3 — Level 2
- OWASP Top 10 (2021)
- OWASP File Upload Cheat Sheet
- OWASP WebSocket Security Cheat Sheet
- PCI-DSS v4.0 — SAQ-A-EP
- NIST SP 800-53 Rev. 5 — Moderate baseline
- NIST SP 800-61r3 — Incident Handling
- Khronos glTF 2.0 Specification
- W3C Trusted Types, CSP Level 3
- WCAG 2.2 AA
- SLSA v1.0 — Build Level 3
- Stripe Security Best Practices

---

**Approval:** Requires sign-off from **Security Lead**, **Engineering Lead**, **Product**, and **Legal/Privacy** before production. Changes to the **pricing engine**, **signing scheme**, or **PCI scope** require re-review.

**Review cadence:** Quarterly, or upon (a) pricing model change, (b) new upload type, (c) payment provider change, (d) PCI scope change.

**Contact:** `configurator-security@example.com` — PGP key in `SECURITY.md`.

**Non-negotiables:**
- The server computes every price. Always.
- No card data on our origin. Ever.
- Uploads are re-encoded. Never served as-is.
- Every config is signed. Every order is auditable.
- WebGL is never the only path to purchase.