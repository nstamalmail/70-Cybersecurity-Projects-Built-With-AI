# Architecture Specification: Interactive 3D Network Attack-Path Visualizer (Web-Based BloodHound Viewer)

**Document Version:** 1.0.0
**Classification:** Internal — Restricted (Sensitive Graph Data)
**Author:** Senior Security Developer
**Last Updated:** 2025-01-15
**Status:** Approved for Implementation
**Document ID:** ARCH-AP-VIS-3D-001

---

## 1. Executive Summary

This document defines the architecture for a **web-based 3D network attack-path visualizer** — a BloodHound-style application that renders Active Directory (AD) privilege relationships as an interactive 3D graph, highlights attack paths from footholds to high-value targets (HVTs), and supports Cypher-style querying and pathfinding.

**Context that shapes every decision:**

A BloodHound viewer is not a typical dashboard. It is a **graph-analysis application for the single most sensitive dataset in an enterprise**: the complete privilege topology of Active Directory. Every node is a user, group, computer, or container. Every edge is an abusable privilege — `AdminTo`, `GenericAll`, `WriteDacl`, `DCSync`, `HasSession`, and dozens more.

The threat model is inverted from normal apps:

1. **The data is the crown jewel.** Compromise of the graph database = full knowledge of the enterprise attack surface. The visualizer itself becomes a reconnaissance tool for an attacker who compromises it.
2. **Users are Tier-0 adjacent.** AD admins, red teamers, and security engineers. Their sessions are high-value.
3. **The graph is huge.** Enterprise deployments have 20,000+ users and hundreds of thousands of edges. Rendering and querying at scale is the hard engineering problem, and it intersects directly with security (DoS, cache poisoning, unbounded queries).
4. **Pathfinding is the product.** The whole point is `shortestPath()` from owned principals to Domain Admins. If pathfinding is slow, tampered, or leaks intermediate results, the tool fails.
5. **BloodHound CE is the reference architecture.** Since 2023, BloodHound CE uses **PostgreSQL + Neo4j + Go API + React/Sigma.js frontend**, fully containerized. This document adapts that architecture to a **3D WebGL viewer** with a **Python backend**, while preserving the security invariants SpecterOps established.
6. **Sensitive graph data must be maskable.** When using LLMs or external tools for analysis, identifiers must be masked without breaking graph structure.

**Design principles:**

1. **The graph database is the authority.** The visualizer is a renderer and query engine — it does not invent or modify topology.
2. **Every query is bounded.** No unbounded `MATCH (n)-[*]->(m)` can be allowed to run. Depth limits, timeouts, and result caps are mandatory.
3. **Identifiers are sensitive.** Domain names, usernames, SIDs, and hostnames are PII-adjacent. Masking must be a first-class capability.
4. **3D is a rendering choice, not a data choice.** The same query API serves 3D, 2D, and text views. If WebGL fails, the analyst still works.
5. **The viewer never touches production AD.** It reads from a collector-fed graph database, never connects to a Domain Controller.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    COLLECTION TIER (Separate Process)                    │
│  SharpHound / BloodHound.py / AzureHound  →  JSON/ZIP ingest            │
│  (Runs on hosts with AD read access, never on the viewer)                │
└──────────────────────────────┬───────────────────────────────────────────┘
                               │ Signed ingest (mTLS + HMAC)
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    INGESTION & GRAPH PIPELINE (Python)                   │
│  • File validation (schema, magic bytes, size caps)                      │
│  • Identifier masking (optional, HoundMasker-style)         │
│  • Node/edge normalization (AD SID, objectGUID keys)         │
│  • OpenGraph adapter (MSSQL, SCCM, Tailscale, etc.)│
│  • Neo4j bulk import (batched, transactional)                            │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        GRAPH STORAGE TIER                                │
│  Neo4j (attack graph)  │  PostgreSQL (users, sessions, audit, metadata)  │
│  Redis (query cache, pathfinding cache)  │  S3 (raw collector archives)   │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    QUERY & PATHFINDING API (FastAPI / Python 3.12)       │
│  • Cypher proxy (allow-listed templates only)                            │
│  • Pathfinding service (shortestPath, allShortestPaths, risk-weighted)   │
│  • 3D graph serializer (nodes + edges + positions)                       │
│  • Masking layer (optional identity obfuscation)            │
│  • HMAC-signed responses                                                 │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    EDGE / CDN (Cloudflare — WAF, DDoS, TLS 1.3)          │
│  • Aggressive rate limits (query endpoints)  • Bot Mgmt  • Static cache  │
└──────────────────────────────┬───────────────────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│              WEB FRONTEND (3D WebGL — Three.js / deck.gl)                │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │  3D force-directed graph  •  Path highlighting  •  Cypher console  │  │
│  │  Trusted Types  •  Strict CSP  •  2D fallback (Sigma.js style)     │  │
│  └────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                    ADMIN CONSOLE (Restricted Hostname)                   │
│  • Collector key management  • Masking profile config  • Kill switch    │
│  • Ingest monitoring  • Audit log viewer                                 │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Threat Model

### 3.1 Assets

| Asset | Sensitivity | Impact if Compromised |
|---|---|---|
| Neo4j graph (full AD topology) | **Critical** | Complete attack surface exposed |
| PostgreSQL (identities, sessions) | **Critical** | Credential material, session hijack |
| Masking map (real ↔ masked) | **Critical** | Re-identification of masked data |
| Collector ingest keys | **Critical** | Malicious graph injection |
| Query cache (Redis) | **High** | Pathfinding results, intermediate nodes |
| Analyst sessions | **Critical** | Tier-0 account takeover |
| Audit logs | **High** | Covering tracks |

### 3.2 Adversary Profiles

1. **Compromised analyst workstation** — attacker with access to a legitimate session.
2. **Insider (red teamer gone rogue)** — exfiltrates full graph.
3. **External attacker** — targets the viewer as a pivot into AD.
4. **Opportunistic attacker** — exploits dependency, misconfig, XSS.
5. **Supply-chain attacker** — malicious OpenGraph collector or schema.
6. **DoS actor** — makes pathfinding unavailable during an incident.
7. **LLM provider (untrusted)** — if masked data is sent for analysis, re-identification risk.

### 3.3 STRIDE

| Threat | Vector | Mitigation |
|---|---|---|
| **Spoofing** | Forged collector ingest | mTLS + HMAC signature from collector key |
| **Tampering** | Modify graph in transit/at rest | Signed ingest, append-only raw archive, Neo4j transaction log |
| **Repudiation** | Analyst denies running query | Full query audit (who, what, when, result hash) |
| **Info Disclosure** | Graph exfiltration via API | Rate limits, result caps, masking, DLP monitoring |
| **DoS** | Unbounded Cypher query | Depth limits, timeouts, row caps, query allow-list |
| **Elevation** | Viewer → graph write | Read-only Neo4j user for viewer; write only via ingest pipeline |
| **Cypher injection** | User-supplied query strings | **No raw Cypher from users** — parameterized templates only |
| **Cache poisoning** | Poison Redis path cache | Signed cache entries, per-user cache isolation |
| **Masking bypass** | Re-identify masked data | Local-only mapping; no reverse mapping over network |

### 3.4 The Cypher Injection Problem

**BloodHound's power is Cypher.** Users write arbitrary graph queries. That is also the single largest risk in this application.

**Mitigation: Two-tier query model.**

**Tier 1 — Template queries (default, safe):**
- Pre-built queries with parameters: `{target: "DOMAIN ADMINS@CORP.LOCAL"}`, `{depth: 5}`, `{owned: ["USER1@CORP.LOCAL"]}`.
- Server constructs Cypher with parameterized bindings.
- No string interpolation. Ever.
- Example template:
  ```cypher
  MATCH p=shortestPath((n {owned:true})-[*1..$maxDepth]->(m:Group {name:$target}))
  RETURN p LIMIT $limit
  ```

**Tier 2 — Power user Cypher (restricted):**
- Only for `graph_admin` role.
- Query **parsed and validated** before execution:
  - Reject write clauses (`CREATE`, `MERGE`, `DELETE`, `SET`, `REMOVE`, `DROP`).
  - Reject `LOAD CSV`, `CALL` to procedures outside an allow-list.
  - Enforce mandatory `LIMIT` (default 1000, max 5000).
  - Enforce mandatory `WHERE` on index-backed properties.
  - Timeout at Neo4j level (30s).
- Every query logged with full text + result hash.

**No `$` string interpolation anywhere.** All bindings via driver parameters.

---

## 4. Technology Stack

| Layer | Technology | Justification |
|---|---|---|
| Collector ingest | Python 3.12 + Pydantic v2 strict | Type safety, validation |
| Graph DB | Neo4j 5.x (causal cluster) | Native graph, Cypher, pathfinding |
| Application DB | PostgreSQL 16 (RLS) | Users, sessions, audit, metadata |
| Cache | Redis 7 (TLS, ACL) | Query results, pathfinding cache |
| Object store | S3 (SSE-KMS, versioned, Object Lock) | Raw collector archives (WORM) |
| API | FastAPI (Python 3.12) | Async, typed, Pydantic |
| Query engine | Neo4j driver (async) | Parameterized Cypher only |
| Pathfinding | Neo4j APOC + custom Python | GDS library for weighted paths |
| Frontend 3D | Three.js r160+ (WebGL2) | Instanced nodes/edges, custom shaders |
| Frontend 2D | Sigma.js (canvas) | Fallback, large-graph performance |
| Bundler | Vite 5 | ESM, code splitting |
| Masking | HoundMasker-style (pure Python) | Privacy-preserving analysis |
| Auth | OIDC + WebAuthn (mandatory) | Tier-0 system |
| Secrets | HashiCorp Vault | Dynamic creds, short TTL |
| Signing | Ed25519 (HSM-backed) | Ingest + response signatures |
| Container | Distroless | Minimal surface |
| Orchestration | Kubernetes + OPA + NetworkPolicy | Zero-trust |
| Observability | OTel → Prometheus/Loki/Grafana + SIEM | Full-stack |
| CDN/Edge | Cloudflare | WAF, DDoS, TLS 1.3 |

---

## 5. Directory Layout

```
bloodhound-3d-viewer/
├── architecture.md
├── SECURITY.md
├── MASKING_POLICY.md
├── RUNBOOK.md
├── frontend/
│   ├── index.html
│   ├── vite.config.ts
│   └── src/
│       ├── main.tsx
│       ├── security/
│       │   ├── trustedTypes.ts
│       │   ├── csp.ts
│       │   └── sanitize.ts
│       ├── graph3d/
│       │   ├── SceneManager.ts
│       │   ├── NodeRenderer.ts        # instanced meshes, LOD
│       │   ├── EdgeRenderer.ts        # curved edges, arrowheads
│       │   ├── ForceLayout.ts         # d3-force in Web Worker
│       │   ├── PathHighlighter.ts     # attack path overlay
│       │   ├── NodeIcons.ts           # type-based glyphs
│       │   └── CameraControls.ts
│       ├── graph2d/
│       │   └── SigmaFallback.tsx      # 2D canvas fallback
│       ├── data/
│       │   ├── QueryClient.ts         # typed API client
│       │   ├── PathClient.ts
│       │   └── MaskingClient.ts       # local-only mapping display
│       ├── ui/
│       │   ├── CypherConsole.tsx      # template + power modes
│       │   ├── PathPanel.tsx          # path list, risk scores
│       │   ├── NodeDetail.tsx
│       │   ├── SearchBar.tsx
│       │   ├── Legend.tsx
│       │   └── OwnedMarker.tsx        # mark footholds
│       └── a11y/
│           ├── ScreenReaderMirror.tsx # node/edge list as table
│           └── KeyboardNav.ts
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py                  # Vault-backed
│   │   ├── api/
│   │   │   ├── graph.py               # nodes, edges, search
│   │   │   ├── paths.py               # pathfinding endpoints
│   │   │   ├── queries.py             # template + power Cypher
│   │   │   ├── masking.py             # masking profile mgmt
│   │   │   ├── health.py
│   │   │   └── ws.py                  # live graph updates (optional)
│   │   ├── ingest/
│   │   │   ├── verify.py              # mTLS + HMAC
│   │   │   ├── validate.py            # schema, magic bytes, size
│   │   │   ├── mask.py                # HoundMasker-style
│   │   │   ├── normalize.py           # SID/objectGUID keys
│   │   │   ├── opengraph.py           # OpenGraph adapters
│   │   │   └── loader.py              # batched Neo4j import
│   │   ├── graph/
│   │   │   ├── queries.py             # template query library
│   │   │   ├── templates.py           # parameterized Cypher
│   │   │   ├── validator.py           # power Cypher validation
│   │   │   └── serializer.py          # → 3D payload
│   │   ├── paths/
│   │   │   ├── shortest.py            # shortestPath
│   │   │   ├── all_paths.py           # allShortestPaths, bounded DFS
│   │   │   ├── risk_score.py          # exploitability scoring
│   │   │   └── cache.py               # signed Redis cache
│   │   ├── security/
│   │   │   ├── authn.py               # OIDC + WebAuthn
│   │   │   ├── authz.py               # ABAC, graph_admin gate
│   │   │   ├── headers.py
│   │   │   ├── ratelimit.py
│   │   │   ├── csrf.py
│   │   │   └── response_signer.py     # HMAC responses
│   │   ├── audit/
│   │   │   ├── query_log.py
│   │   │   ├── emitter.py
│   │   │   └── worm_sink.py
│   │   └── db/
│   │       ├── neo4j.py               # read-only driver
│   │       ├── postgres.py
│   │       └── migrations/
│   ├── tests/
│   │   ├── unit/
│   │   ├── integration/
│   │   ├── security/
│   │   ├── cypher_fuzz/               # query injection attempts
│   │   └── masking/                   # re-identification tests
│   └── Dockerfile
├── collector-sdk/
│   ├── python/
│   └── schemas/                        # OpenGraph schema registry
├── infra/
│   ├── nginx/
│   ├── cloudflare/
│   ├── k8s/
│   │   ├── networkpolicy.yaml
│   │   ├── neo4j-readonly.yaml
│   │   └── opa-policies/
│   ├── terraform/
│   └── vault/
└── .github/workflows/
    ├── ci.yml
    └── cd.yml
```

---

## 6. Data Model

### 6.1 Graph Node (Neo4j)

BloodHound's node model, adapted for 3D rendering and masking.

```python
class GraphNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    # Identity (from collector)
    node_id: str                       # AD SID or objectGUID
    kind: Literal["User", "Group", "Computer", "Container",
                  "Domain", "OU", "GPO", "MSSQL_Server", "SCCM_Site",
                  "Tailscale_Device", "Azure_Resource"]   # OpenGraph

    # Display (sanitized, optionally masked)
    name: str                          # SAMACCOUNTNAME@DOMAIN or HOSTNAME.DOMAIN
    display_name: str | None
    domain: str | None

    # Analysis
    owned: bool = False                # marked as foothold
    high_value: bool = False           # marked as target
    risk_score: float | None           # computed

    # 3D position (server-computed, cached)
    position: tuple[float, float, float] | None

    # Masking
    masked_id: str | None              # if masking active
```

**Node identity rules** (critical for correct graph merging):
- AD-native nodes keyed by **SID** (principals) or **objectGUID** (containers).
- OpenGraph nodes keyed by their own stable ID.
- Name format follows SharpHound: `SAMACCOUNTNAME@DOMAIN.FQDN` (uppercase), or `HOSTNAME.DOMAIN.FQDN`.
- **Never emit a partial name** — if domain FQDN is unresolved, omit `name` rather than overwrite a correct SharpHound label.

### 6.2 Graph Edge (Neo4j)

```python
class GraphEdge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    edge_id: str                       # hash of (src, dst, kind)
    src: str                           # node_id
    dst: str
    kind: str                          # AdminTo, GenericAll, WriteDacl,
                                       # DCSync, HasSession, MemberOf,
                                       # MSSQL_HasLogin, SCCM_AssignAllPermissions
    properties: dict[str, str]         # allow-listed keys only

    # Analysis
    difficulty: float | None           # 0.0–1.0, higher = harder
    traversed_in_path: bool = False    # for highlighting
```

**Edge kind allow-list** is schema-driven. OpenGraph extensions register their edge kinds at ingest.

### 6.3 Query Template

```python
class QueryTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    template_id: str                   # "shortest_path_to_da"
    name: str
    description: str
    category: Literal["recon", "pathfinding", "acl", "delegation", "trust"]
    cypher: str                        # parameterized ($params)
    parameters: list[ParameterSpec]    # typed, validated
    max_depth: int | None
    default_limit: int = 500
    requires_role: Literal["analyst", "graph_admin"]
```

**Templates are code.** They are versioned, signed, and reviewed. Adding a template requires security review.

### 6.4 Masking Map (Local-Only)

```python
# Stored ONLY in the viewer's local environment, never transmitted
class MaskingMap(BaseModel):
    profile_id: str
    created_at: datetime
    mapping: dict[str, str]            # real_id → masked_id (bidirectional)
    reverse: dict[str, str]            # masked_id → real_id

    # Invariant: graph structure preserved exactly
```

**Masking rules**:
- Replace domain names, usernames, hostnames, group names with consistent pseudonyms.
- **Preserve SID relationships** — group memberships, ACL edges, delegation must remain identical.
- **Preserve free-text fields carefully** — may contain cleartext credentials; must be scrubbed.
- **Reverse mapping stays local** — never sent to LLM or external analysis tool.
- **Validate masked graph imports cleanly** into BloodHound CE.

### 6.5 What Never Crosses the Boundary

- Cleartext passwords or hashes embedded in node properties.
- Session tokens or credential material.
- Real identifiers if masking is active (the network layer sees only masked IDs).
- Raw Cypher from non-admin users.

---

## 7. Frontend Architecture (3D Graph)

### 7.1 Rendering Strategy

- **WebGL2 required** for 3D mode; Sigma.js 2D fallback for no-WebGL or scale.
- **Instanced meshes** for nodes — each node type is an instanced geometry with per-instance color/scale. Supports 10k+ nodes.
- **Edge rendering:** Curved quadratic Béziers (for readability), instanced with per-edge color by kind.
- **Force-directed layout** in a Web Worker (`d3-force-3d`), delivering positions to the main thread via `SharedArrayBuffer`.
- **LOD tiers:**
  - `overview` (< 500 nodes): full detail, labels.
  - `cluster` (< 5,000 nodes): nodes as points, no labels.
  - `detail` (on-demand subgraph): full detail within a query result.
- **Attack path overlay:** Traversed nodes/edges highlighted with emissive glow; non-path nodes dimmed.
- **Node icons** per kind (glyph or texture atlas).

### 7.2 Query API (Bounded)

```python
# Template query — safe, parameterized
@router.post("/api/v1/query/template")
async def run_template(
    req: TemplateQuery,
    user: Analyst = Depends(current_user),
):
    template = templates.get(req.template_id)
    if not template:
        raise HTTPException(404, "template not found")
    if template.requires_role == "graph_admin" and "graph_admin" not in user.roles:
        raise HTTPException(403, "insufficient role")

    # Validate parameters against template spec
    params = template.parameters.validate(req.parameters)

    # Enforce hard limits
    limit = min(req.limit or template.default_limit, 5000)
    depth = min(req.max_depth or template.max_depth or 5, 10)

    # Execute with driver parameters (NO interpolation)
    async with neo4j_driver.session(readonly=True) as session:
        result = await asyncio.wait_for(
            session.run(template.cypher, **params, limit=limit, maxDepth=depth),
            timeout=30.0,
        )
        records = await result.data()

    # Log + audit
    await audit.log_query(user, template.template_id, params, records)

    # Sign response
    return sign_response({
        "template_id": template.template_id,
        "records": records,
        "truncated": len(records) >= limit,
    })
```

**Bounded execution:**
- Hard `LIMIT` injected into every query.
- Hard `maxDepth` cap (10).
- Hard timeout (30s).
- Result size cap (5000 nodes/edges).
- If exceeded, response is truncated + flagged; client prompts to narrow query.

### 7.3 Power User Cypher (graph_admin only)

```python
@router.post("/api/v1/query/cypher", dependencies=[Depends(require_role("graph_admin"))])
async def run_cypher(req: CypherQuery, user: Analyst):
    # 1. Parse AST
    ast = parse_cypher(req.query)

    # 2. Reject write clauses
    if ast.contains_any(["CREATE", "MERGE", "DELETE", "DETACH DELETE",
                         "SET", "REMOVE", "DROP", "LOAD CSV"]):
        raise HTTPException(400, "write operations forbidden")

    # 3. Reject unallow-listed procedures
    for call in ast.procedure_calls:
        if call not in ALLOWED_PROCEDURES:
            raise HTTPException(400, f"procedure not allowed: {call}")

    # 4. Enforce LIMIT
    ast.ensure_limit(default=1000, max=5000)

    # 5. Enforce timeout hint
    ast.set_timeout(30)

    # 6. Execute
    async with neo4j_driver.session(readonly=True) as session:
        result = await session.run(str(ast), **req.parameters)

    await audit.log_raw_cypher(user, req.query, result)
    return sign_response(result.data())
```

**Even power users cannot write.** The Neo4j connection for the viewer is **read-only** at the database level — belt and suspenders.

### 7.4 Pathfinding Service

```python
async def find_shortest_paths(
    sources: list[str],                # owned principals
    targets: list[str],                # HVT groups/nodes
    max_depth: int = 10,
    limit: int = 100,
) -> list[AttackPath]:
    cypher = """
    UNWIND $sources AS src
    UNWIND $targets AS tgt
    MATCH p = shortestPath((s {node_id: src})-[*1..$maxDepth]->(t {node_id: tgt}))
    RETURN p LIMIT $limit
    """
    async with neo4j_driver.session(readonly=True) as session:
        result = await session.run(
            cypher, sources=sources, targets=targets,
            maxDepth=max_depth, limit=limit,
        )
        paths = [serialize_path(r["p"]) for r in await result.data()]

    # Score each path
    for path in paths:
        path.risk_score = compute_risk(path)

    return paths
```

**Risk scoring** (composite, inspired by attack-path research):
- **Hop count** — shorter = higher risk.
- **Edge difficulty** — sum of per-edge difficulty (base 0.3, +0.3 encrypted, +0.2 trust boundary, −0.1 sensitive target).
- **Crown jewel value** — target criticality.
- **ATT&CK technique presence** — known techniques increase score.

**Caching:** Pathfinding results cached in Redis with:
- Key = `hash(sources, targets, max_depth)`.
- Value = result + HMAC signature.
- TTL = 5 minutes (graph changes invalidate).
- **Signature prevents cache poisoning** — client verifies before rendering.

### 7.5 Security Hardening (Frontend)

**CSP (header):**

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'wasm-unsafe-eval';
  style-src 'self' 'nonce-{random}';
  img-src 'self' data: blob:;
  font-src 'self';
  connect-src 'self' wss://graph.example.com;
  worker-src 'self' blob:;
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'none';
  object-src 'none';
  require-trusted-types-for 'script';
  trusted-types bh-ui;
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

**Trusted Types:** All DOM writes through `bh-ui` policy. Node names, edge labels, query results — all treated as hostile (they come from AD, which can contain attacker-controlled group names).

**Sanitization:** Every string from the graph is sanitized for:
- Control characters.
- Bidi override characters (critical — a group named `Domain Admins‮x` can visually reorder text).
- Zero-width characters.
- Length caps.

### 7.6 2D Fallback (Sigma.js)

If WebGL2 unavailable:
- Auto-detect at boot.
- Render same graph with **Sigma.js** (canvas-based, handles 100k+ nodes).
- Same query API, same pathfinding.
- **Feature parity for core functions** (query, path, detail).
- Manual toggle in UI.

### 7.7 Accessibility

- **Screen-reader mirror:** Node/edge list as semantic table; path as ordered list.
- **Keyboard navigation:** Full graph traversal without mouse.
- **High contrast mode.**
- **`prefers-reduced-motion`:** disables force animation.
- **Color-blind palette** for node kinds + edge kinds (shape differentiation).

---

## 8. Backend Architecture

### 8.1 API Surface

| Method | Path | Purpose | Auth | Rate Limit |
|---|---|---|---|---|
| POST | `/api/v1/query/template` | Run template query | OIDC | 60/min |
| POST | `/api/v1/query/cypher` | Run raw Cypher | OIDC + graph_admin | 10/min |
| GET | `/api/v1/graph/nodes/{id}` | Node detail | OIDC | 120/min |
| GET | `/api/v1/graph/search` | Search nodes | OIDC | 60/min |
| POST | `/api/v1/paths/shortest` | Find shortest paths | OIDC | 30/min |
| POST | `/api/v1/paths/all` | All paths (bounded) | OIDC | 10/min |
| GET | `/api/v1/templates` | List templates | OIDC | 60/min |
| GET | `/api/v1/health` | Liveness | None | 10/min |
| **Admin** (separate hostname) | | | | |
| POST | `/admin/v1/collectors/keys` | Register collector | OIDC + mTLS | 5/min |
| POST | `/admin/v1/masking/profiles` | Create masking profile | OIDC + mTLS | 5/min |
| POST | `/admin/v1/ingest` | Ingest collector data | mTLS + HMAC | 10/min |
| POST | `/admin/v1/kill-switch` | Freeze queries | OIDC + role | 1/min |

### 8.2 Ingest Pipeline

```
Collector uploads JSON/ZIP → mTLS + HMAC verify → Schema validate →
Masking (optional) → Normalize (SID/objectGUID keys) → OpenGraph adapt →
Neo4j batched import → Cache invalidate → Audit emit
```

**Validation:**
- File size cap (500 MB per ZIP).
- Magic bytes check (ZIP, JSON).
- Schema validation against BloodHound collector schema.
- Reject unknown fields (`extra="forbid"`).
- Reject nodes/edges with invalid IDs.

**Normalization**:
- AD principals keyed by SID.
- Containers keyed by objectGUID.
- Names follow SharpHound format.
- **Never overwrite existing correct names with partial ones.**

**Masking**:
- Optional per-ingest.
- Consistent pseudonymization (same real ID → same masked ID within a profile).
- Graph structure preserved exactly.
- Reverse map stored locally only.
- Validation: masked graph must produce identical pathfinding results.

### 8.3 Neo4j Read-Only Access

```python
# Neo4j connection for viewer — read-only at DB level
driver = AsyncGraphDatabase.driver(
    settings.neo4j_uri,
    auth=(settings.neo4j_user, settings.neo4j_password),
    max_connection_lifetime=300,
)

# Server-side enforcement
# CREATE USER viewer SET PASSWORD '...' SET HOME DATABASE neo4j;
# GRANT MATCH {*} ON GRAPH neo4j NODES * TO viewer;
# GRANT MATCH {*} ON GRAPH neo4j RELATIONSHIPS * TO viewer;
# DENY WRITE ON GRAPH neo4j TO viewer;
```

**Even if the API is compromised, the viewer cannot write to the graph.** Ingest uses a separate write user, only reachable from the ingest service.

### 8.4 Audit Logging

Every query is logged:

```json
{
  "ts": "2025-01-15T14:32:11Z",
  "actor": {"sub": "user:analyst1", "roles": ["analyst"], "mfa_ns": 1705329131123000000},
  "action": "query.template",
  "template_id": "shortest_path_to_da",
  "parameters": {"target": "DOMAIN ADMINS@CORP.LOCAL", "max_depth": 5},
  "result_count": 12,
  "result_hash": "sha256:...",
  "duration_ms": 245,
  "ip_hash": "sha256:...",
  "prev_hash": "sha256:...",
  "signature": "ed25519:..."
}
```

- **Hash-chained** + **Ed25519 signed**.
- **WORM** (S3 Object Lock, 7 years).
- Streamed to SIEM in real time.

**Why log queries?** A BloodHound query reveals what an analyst is looking for. If the account is compromised, the query log shows the attacker's reconnaissance. It also provides non-repudiation for red team engagements.

---

## 9. Infrastructure & Deployment

### 9.1 Network Architecture

- **No route to production AD.** The viewer reads from Neo4j, which is fed by collectors that run elsewhere.
- **Three trust zones:** ingest, viewer API, admin console.
- **Neo4j:** private subnet, TLS-only, no public IP, read-only user for viewer.
- **PostgreSQL:** private subnet, TLS-only.
- **Redis:** private subnet, TLS, ACL, no public IP.
- **Service mesh** (Istio/Linkerd) with mTLS between tiers.
- **Kubernetes NetworkPolicy** — default-deny.

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
- Resource limits + HPA on API tier (query load is spiky).

### 9.3 Secrets

- Vault dynamic creds.
- Neo4j password rotated every 30 days.
- Collector HMAC keys rotated quarterly; on compromise, immediately.
- Response signing keys in HSM.
- CI/CD via OIDC federation.

### 9.4 Resilience

- **Multi-AZ** for Neo4j causal cluster (3 core + 2 read replicas).
- **Read replicas** serve query load; writes go to core.
- **Degraded mode:** if Neo4j cluster loses quorum, API returns cached results with staleness banner.
- **Kill switch:** single API call disables all query endpoints (admin console only).

---

## 10. Observability

| Metric | Alert |
|---|---|
| Query p95 latency | > 2s → warn |
| Query timeout rate | > 5% → investigate |
| Result truncation rate | > 10% → warn (analysts need narrower queries) |
| Cypher injection attempts | any → **page** |
| Masking bypass attempts | any → **page** |
| Cache poisoning (HMAC fail) | any → **page** |
| Ingest signature failures | any → **page** |
| Neo4j replication lag | > 30s → warn |
| Unbounded query rejections | > 100/hour → review templates |
| CSP violations | > 50/min → investigate |

**Meta-monitoring:** Audit logs streamed to a separate SIEM the viewer operators cannot modify.

---

## 11. Testing Strategy

| Layer | Tool | Coverage |
|---|---|---|
| Unit (BE) | pytest + hypothesis | 90% |
| Unit (FE) | Vitest | 85% |
| Integration | pytest + testcontainers (Neo4j, Postgres, Redis) | Critical paths |
| E2E | Playwright (Chromium, Firefox, Safari) | Query + path workflows |
| Load | k6 (100 concurrent analysts, 10k-node graphs) | Quarterly |
| Security | ZAP, Burp, custom Cypher fuzzer | Every release |
| Masking | Re-identification test suite | Every release |
| Chaos | Neo4j failover, Redis outage, ingest flood | Monthly |

**Dedicated security tests:**
- Cypher injection via all parameters → parameterized, no escape.
- Write clauses in power Cypher → rejected.
- `LOAD CSV` → rejected.
- Unallow-listed procedure calls → rejected.
- Query without LIMIT → auto-injected.
- Query exceeding maxDepth → rejected.
- Query exceeding timeout → killed, no partial data leaked.
- Masked graph pathfinding → identical results to unmasked.
- Reverse mapping never leaves the local environment.
- Cache poisoning attempt → HMAC fail, cache entry rejected.
- XSS via node name, edge label, query result → escaped.
- Bidi override in node name → stripped.
- Unauthenticated query → 401.
- Analyst attempting graph_admin query → 403.
- IDOR on another analyst's query results → N/A (results not persisted per-user).

---

## 12. Compliance & Privacy

- **Sensitive data:** Graph contains full AD topology. Treat as **Tier-0**.
- **GDPR:** Employee identifiers (usernames, SIDs) are PII in EU deployments. Masking is the primary control.
- **Retention:**
  - Graph data: current + 1 historical snapshot.
  - Query logs: 7 years (WORM).
  - Ingest archives: 1 year.
- **Access control:** Analysts see graph; graph_admins see raw Cypher; nobody sees masking map except the local environment that created it.
- **Right to erasure:** Graph is derived from AD; erasure is handled at the AD level. Query logs are legal records (exempt).
- **LLM/external analysis:** Only masked graphs may be shared externally.

Full policy in `MASKING_POLICY.md`.

---

## 13. Incident Response

### 13.1 Graph Exfiltration Suspected

1. **Kill switch** — disable query endpoints.
2. Review query logs for anomalous patterns (bulk searches, wide queries).
3. Identify compromised analyst account; revoke sessions.
4. Rotate Neo4j credentials.
5. Notify CISO + AD security team.
6. Assess scope: what nodes/edges were returned?
7. Post-mortem → tighten rate limits + anomaly detection.

### 13.2 Malicious Graph Injection

1. **Kill switch** ingest.
2. Identify collector source via mTLS cert.
3. Revoke collector key.
4. Roll back Neo4j to pre-ingest snapshot.
5. Audit all queries since ingest — was malicious graph used for decisions?
6. Post-mortem → strengthen collector onboarding.

### 13.3 Cypher Injection Detected

1. Block offending session.
2. Audit all queries from that session.
3. Review template validator for gaps.
4. Patch + add regression test.
5. Notify security team.

### 13.4 Masking Bypass

1. **Page security + privacy.**
2. Identify leak vector (network, log, cache).
3. Rotate all masking profile keys.
4. Assess scope of re-identifiable data exposed.
5. Notify affected parties if required (GDPR 72h).

Full runbook in `RUNBOOK.md`.

---

## 14. Roadmap & Open Items

| Item | Priority | Rationale |
|---|---|---|
| WebGPU renderer path | P3 | 10× node throughput; spec stabilizing |
| Real-time collaborative analysis | P3 | Multiple analysts on same graph |
| LLM-assisted path explanation (masked only) | P2 | Requires masking integration |
| Time-travel graph (diff between ingests) | P2 | Track privilege drift |
| Automated remediation suggestions | P3 | Requires AD write path (separate system) |
| Quantum-resistant signing | P3 | HSM vendor readiness |
| OpenGraph collector marketplace | P4 | Trust framework needed |

---

## 15. References

- BloodHound Enterprise Security Overview — SpecterOps
- BloodHound CE Architecture — SpecterOps
- BloodHound On-Premises Architecture — SpecterOps
- ConfigManBearPig (OpenGraph collector reference) — SpecterOps
- ADPathFinder (cross-dataset pathfinding) — NetSPI
- TailscaleHound (OpenGraph extension) — SpecterOps
- HoundMasker (privacy-preserving masking) — Altered Security
- BloodHound HMAC API signing scheme
- Attack-path risk scoring (TITO reference)
- OWASP ASVS v4.0.3 — Level 3
- OWASP Top 10 (2021)
- NIST SP 800-53 Rev. 5 — High baseline
- NIST SP 800-207 — Zero Trust
- Neo4j Security Documentation
- Cypher Injection Prevention Cheat Sheet
- SLSA v1.0 — Build Level 3

---

**Approval:** Requires sign-off from **CISO**, **AD Security Lead**, and **Head of Security Architecture** before production. Changes to **query allow-list**, **masking scheme**, **Neo4j access control**, or **ingest trust model** require re-review by all three.

**Review cadence:** Quarterly, or upon: (a) graph data leak, (b) new OpenGraph collector, (c) masking policy change, (d) new query template class.

**Contact:** `bloodhound-viewer-security@example.com` — PGP key in `SECURITY.md`.

**Non-negotiables:**
- No raw Cypher from non-admins. Templates only.
- No write clauses in any query. Neo4j user is read-only.
- Every query is bounded (LIMIT, depth, timeout).
- Masking preserves graph structure. Reverse map never leaves the environment.
- Collector ingest is signed. Unsigned data is rejected.
- Node identity follows SID/objectGUID rules. Partial names never overwrite correct ones.
- Every query is audited. Hash-chained. WORM.
- 3D is a rendering choice. 2D fallback always works.
- The viewer never connects to production AD.