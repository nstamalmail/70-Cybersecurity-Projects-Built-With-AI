# Architecture: Active Directory Attack Path Visualizer (BloodHound-Style, Lab Domain) — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Lab-domain AD attack path collection, graph-based analysis, BloodHound-compatible Cypher querying, and interactive visualization with multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **AD Attack Path Visualizer (ADAPV)** is a GUI-driven desktop application for authorized red teamers, penetration testers, and defensive security engineers who need to **map and visualize privilege escalation paths within a lab Active Directory domain** using the same graph-based methodology as BloodHound. It consolidates data collection (SharpHound-compatible), graph analysis (Cypher querying), and interactive visualization into a single workflow that produces structured, exportable reports.

Active Directory attack path analysis is the industry-standard methodology for understanding privilege escalation risk. The core insight — established by BloodHound — is that **over 70% of AD environments contain an exploitable path from any authenticated user to Domain Admin**, and these paths span multiple object types and ACL relationships that no manual review process can reliably enumerate at scale. The graph model surfaces relationships that manual processes miss, and Cypher querying enables precise, repeatable analysis.

The tool is designed around four principles:

1. **Lab-domain scoped** — explicit allowlist enforcement; collection targets restricted to authorized domains; no production AD enumeration.
2. **BloodHound-compatible** — consumes SharpHound output and supports BloodHound-compatible Cypher queries, enabling analysts to leverage the existing query ecosystem.
3. **Graph-first analysis** — attack paths are the primary output, not raw misconfiguration lists; visual path exploration is the core workflow.
4. **Report-ready** — export attack path findings in JSON, CSV, HTML, and PDF with path visualization, affected principals, and remediation guidance.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Domain    │ │ Collection│ │ Graph     │ │ Path      │ │ Report  │ │
│  │ Config    │ │ Console   │ │ Explorer  │ │ Analysis  │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Cypher    │ │ Principal │ │ Attack    │ │ Remediation│ │ Console│ │
│  │ Query     │ │ Inspector │ │ Path List │ │ Guide     │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Collection │ │ Graph      │ │ Path       │ │ Event Bus / Log    │ │
│  │ Controller │ │ Builder    │ │ Analyzer   │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Graph Engine Layer                               │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ JSON Ingestion │ │ Graph Store    │ │ Cypher Query Engine      │  │
│  │ (SharpHound/   │ │ (SQLite/       │ │ (BloodHound-compatible)  │  │
│  │  RustHound)    │ │  NetworkX)     │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Path Finder    │ │ Edge Analysis  │ │ Attack Path              │  │
│  │ (shortest,     │ │ (ACL, session, │ │ Scoring                  │  │
│  │  all paths)    │ │  delegation)   │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Collection Layer (Optional)                      │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ RustHound      │ │ SharpHound     │ │ JSON Import              │  │
│  │ Wrapper        │ │ Output Parser  │ │ (pre-collected)          │  │
│  │ (Linux)        │ │ (Windows)      │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Graph      │ │ Query      │ │ Path       │ │ Report Store       │ │
│  │ Store      │ │ Store      │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `DomainConfigView` | Configure lab domain: domain name, DC IP, credentials (LDAP bind). Enforce allowlist: only authorized domains can be targeted. |
| `CollectionConsoleView` | **Optional collection view.** Run RustHound (Linux) or parse SharpHound JSON (Windows) to gather AD data. Display collection progress: objects collected, edges discovered, errors. |
| `GraphExplorerView` | **Primary visualization view.** Interactive graph showing nodes (users, groups, computers, OUs, GPOs, domains) and edges (MemberOf, AdminTo, HasSession, DCSync, etc.). Zoom, pan, layout toggle (force-directed, hierarchical). Click node → show details. |
| `PathAnalysisView` | **Primary analysis view.** Attack path list: source principal, target principal, path length, edges traversed, risk score. Click path → highlight in graph. Filter by "owned" principals, target type (Domain Admin, high-value). |
| `CypherQueryView` | **Advanced query view.** Run BloodHound-compatible Cypher queries. Pre-built query library (shortest path to DA, Kerberoastable users, DCSync rights, GPO abuse). Save custom queries. |
| `PrincipalInspectorView` | Drill-down for selected principal: group memberships, admin rights, sessions, delegation, controlling principals, controlled principals. |
| `RemediationGuideView` | Per-path remediation: which edge to remove, which ACL to fix, which group membership to revoke. Prioritized by impact. |
| `ReportBuilderView` | **Export interface.** Format selection (JSON, CSV, HTML, PDF), sections to include (attack paths, graph export, remediation, collection metadata). |
| `ConsoleView` | Live log: collection progress, query execution, graph loading, errors. |

**Key UI Patterns:**
- **Graph-first layout**: the graph explorer dominates; path list and inspector are side panels.
- **Path highlighting**: clicking a path in the list highlights the full chain in the graph with distinct edge coloring.
- **Node color coding**: users (blue), groups (green), computers (orange), domains (red), OUs (purple).
- **Owned principal markers**: compromised accounts marked with a distinct icon; paths from owned principals highlighted.
- **Cypher query templates**: pre-built queries available in a dropdown; results rendered in the graph.

### 3.2 Orchestration Layer

**Collection Controller**
- Manages optional collection lifecycle: target connection → credential validation → collection execution → JSON ingestion.
- Supports RustHound (Linux) and SharpHound JSON import (cross-platform).
- Enforces lab-domain allowlist: refuses to collect from unauthorized domains.

**Graph Builder**
- Ingests SharpHound/RustHound JSON output.
- Builds graph model: nodes (Principal, Computer, Group, OU, GPO, Domain, Container) and edges (MemberOf, AdminTo, HasSession, DCSync, GenericAll, WriteDacl, etc.).
- Stores graph in SQLite with indexed edges for fast path queries.

**Path Analyzer**
- Runs Cypher queries against the graph store.
- Computes shortest paths, all paths, and filtered paths (from owned principals, to high-value targets).
- Scores paths by exploitability and impact.

### 3.3 Graph Engine Layer

**JSON Ingestion**
- Parses SharpHound JSON format (users, groups, computers, OUs, GPOs, domains, containers).
- Maps JSON fields to graph node properties (name, SID, enabled, admincount, hasspn, etc.).
- Maps edges: MemberOf, AdminTo, HasSession, DCSync, GenericAll, GenericWrite, WriteDacl, WriteOwner, ForceChangePassword, AllowedToDelegate, etc.

**Graph Store**
- SQLite-backed graph: nodes table, edges table, indexes on source/target.
- Alternative: NetworkX in-memory graph for smaller domains (< 100k nodes).
- Supports Cypher-like query translation to SQL or NetworkX operations.

**Cypher Query Engine**
- BloodHound-compatible Cypher subset: MATCH, WHERE, RETURN, shortestPath, relationships, property filters.
- Pre-built queries:
  - Shortest path to Domain Admins
  - Kerberoastable users with path to DA
  - Computers where Domain Admins have sessions
  - DCSync rights holders
  - GPO abuse paths
  - ADCS ESC1–ESC13 paths

**Path Finder**
- Shortest path (BFS/Dijkstra).
- All paths (bounded depth).
- Path scoring: edge exploitability × path length × target criticality.

### 3.4 Collection Layer (Optional)

**RustHound Wrapper (Linux)**
- Wraps RustHound-CE for cross-platform collection from Linux attack box.
- Requires LDAP credentials; collects ACLs, group memberships, delegation, trusts.
- Does **not** collect session data (requires SMB access to domain-joined hosts).

**SharpHound Output Parser (Windows)**
- Imports pre-collected SharpHound ZIP/JSON output.
- Parses users, groups, computers, sessions, ACLs.

**JSON Import (pre-collected)**
- Accepts BloodHound-compatible JSON bundles from any collector.

### 3.5 Storage Layer

**Data directory:**
```
~/.adapv/
├── domains/
│   └── <domain_name>/
│       ├── collection/
│       │   ├── users.json
│       │   ├── groups.json
│       │   ├── computers.json
│       │   └── ...
│       ├── graph.db              # SQLite graph store
│       ├── queries/
│       │   └── saved_queries.json
│       └── paths/
│           └── attack_paths.json
├── reports/
│   └── <domain_name>_report.pdf
└── logs/
    └── adapv.log
```

**Graph schema (SQLite):**
```sql
CREATE TABLE nodes (
  id TEXT PRIMARY KEY,
  kind TEXT,              -- 'User', 'Group', 'Computer', 'OU', 'GPO', 'Domain'
  name TEXT,
  sid TEXT,
  enabled INTEGER,
  admincount INTEGER,
  hasspn INTEGER,
  properties_json TEXT
);
CREATE INDEX idx_nodes_name ON nodes(name);
CREATE INDEX idx_nodes_sid ON nodes(sid);
CREATE INDEX idx_nodes_kind ON nodes(kind);
CREATE TABLE edges (
  id INTEGER PRIMARY KEY,
  source_id TEXT,
  target_id TEXT,
  kind TEXT,              -- 'MemberOf', 'AdminTo', 'HasSession', 'DCSync', ...
  properties_json TEXT
);
CREATE INDEX idx_edges_source ON edges(source_id);
CREATE INDEX idx_edges_target ON edges(target_id);
CREATE INDEX idx_edges_kind ON edges(kind);
```

### 3.6 Canonical Data Model

**Attack path:**
```python
@dataclass
class AttackPath:
    path_id: str
    source_principal: str          # node ID
    target_principal: str          # node ID
    hops: list[PathHop]
    length: int
    risk_score: float
    exploitability: str            # 'high', 'medium', 'low'
    description: str

@dataclass
class PathHop:
    source: str
    target: str
    edge_kind: str                 # 'MemberOf', 'AdminTo', 'DCSync', ...
    description: str
```

**Principal:**
```python
@dataclass
class Principal:
    principal_id: str
    name: str
    kind: str                      # 'User', 'Group', 'Computer'
    sid: str
    enabled: bool
    admincount: bool
    hasspn: bool
    memberships: list[str]         # group IDs
    admin_rights: list[str]        # computers this principal administers
    sessions: list[str]            # computers where sessions exist
    delegation: dict | None
```

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, graph rendering, path highlighting
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Collection Worker (single thread, optional)
  ├── RustHound execution or SharpHound JSON parsing
  ├── Progress emission
  └── JSON file writing

Graph Builder Worker (single thread)
  ├── JSON ingestion
  ├── Graph construction
  └── SQLite indexing

Query Worker (QThreadPool, N workers)
  ├── Cypher query execution
  ├── Path finding (BFS/Dijkstra)
  └── Result marshalling
```

**Rules:**
- Collection is optional; pre-collected JSON can be imported directly.
- Graph building is one-time per collection; runs in worker with progress.
- Path queries are CPU-bound; parallelized across queries.
- Graph rendering on main thread; layout computation in worker.
- Cancellation: `threading.Event` checked between queries.

---

## 5. Workflow: End-to-End User Journey

1. **Configure Domain** → enter lab domain name, DC IP, LDAP credentials; acknowledge authorization.
2. **Collect Data** (optional) → run RustHound or import SharpHound JSON.
3. **Build Graph** → ingest JSON, construct graph, index edges.
4. **Explore Graph** → interactive visualization of principals and relationships.
5. **Run Queries** → pre-built queries (shortest path to DA, Kerberoastable users, DCSync rights) or custom Cypher.
6. **Analyze Paths** → view attack paths from owned principals to high-value targets; drill into hops.
7. **Inspect Principals** → view memberships, admin rights, sessions, delegation.
8. **Read Remediation** → per-path guidance on which edge to remove.
9. **Export Report** → JSON/CSV/HTML/PDF with paths, graph export, remediation.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Unauthorized enumeration** | Domain allowlist mandatory; explicit authorization acknowledgment. |
| **Credential handling** | LDAP credentials in OS keychain; never logged. |
| **Lab-only scope** | Documented; production AD enumeration blocked. |
| **Collection opsec** | Collection is optional; pre-collected JSON import supported for opsec-sensitive engagements. |
| **Data sensitivity** | Graph data reveals privilege relationships; local-only storage; optional encryption. |
| **Remediation safety** | Guidance only; tool does not modify AD. |

---

## 7. Extensibility Points

1. **New collector** — implement `Collector` ABC (RustHound, SharpHound, AzureHound, custom JSON).
2. **New Cypher function** — extend `CypherEngine` with custom functions.
3. **New edge analyzer** — extend `EdgeAnalysis` (ACL, session, delegation, ADCS).
4. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF).
5. **BloodHound CE API integration** — optional: query live BloodHound CE instance via REST API.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 3 s |
| Collection (10k objects) | < 5 min |
| Graph build (10k objects) | < 30 s |
| Query execution (shortest path) | < 2 s |
| Graph render (10k nodes) | 30 fps |
| Report generation | < 5 s |
| Memory footprint | < 1 GB RSS |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| Graph visualization | `pyqtgraph` or `networkx` + custom Qt | Interactive graph |
| Graph store | SQLite (indexed edges) or NetworkX | Embedded, fast queries |
| Collection | RustHound (subprocess), SharpHound JSON parser | BloodHound-compatible |
| Cypher engine | Custom translator to SQL/NetworkX | BloodHound query compatibility |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
adapv/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── adapv/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── domain_config.py
│       │   │   ├── collection_console.py
│       │   │   ├── graph_explorer.py
│       │   │   ├── path_analysis.py
│       │   │   ├── cypher_query.py
│       │   │   ├── principal_inspector.py
│       │   │   ├── remediation_guide.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── paths_table_model.py
│       │   │   └── principals_table_model.py
│       │   └── widgets/
│       │       ├── graph_canvas.py
│       │       ├── node_badge.py
│       │       ├── path_highlighter.py
│       │       └── cypher_editor.py
│       ├── core/
│       │   ├── collection/
│       │   │   ├── rusthound.py
│       │   │   ├── sharphound_parser.py
│       │   │   └── json_importer.py
│       │   ├── graph/
│       │   │   ├── builder.py
│       │   │   ├── store.py
│       │   │   └── model.py
│       │   ├── query/
│       │   │   ├── cypher_engine.py
│       │   │   └── prebuilt_queries.py
│       │   ├── path/
│       │   │   ├── finder.py
│       │   │   └── scorer.py
│       │   └── remediation/
│       │       └── generator.py
│       ├── storage/
│       │   ├── graph_store.py
│       │   └── query_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── sid.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── themes/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, domain config, JSON import, graph store | 2 weeks |
| **P1 — Graph Build** | SharpHound JSON parser, node/edge model, SQLite store | 3 weeks |
| **P2 — Graph Explorer** | Interactive visualization, node click, details | 3 weeks |
| **P3 — Path Analysis** | Shortest path, all paths, path list, highlighting | 2 weeks |
| **P4 — Cypher Engine** | Cypher subset parser, pre-built queries, custom queries | 3 weeks |
| **P5 — Principal Inspector** | Memberships, admin rights, sessions, delegation | 1 week |
| **P6 — Remediation** | Edge removal guidance, path scoring | 1 week |
| **P7 — Collection** | RustHound wrapper (Linux), SharpHound import (Windows) | 2 weeks |
| **P8 — Reporting** | JSON/CSV/HTML/PDF export with graph export | 2 weeks |
| **P9 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~22 weeks (single senior dev) / ~11 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: JSON parsing, graph construction, Cypher translation, path finding.
- **Integration**: full workflow on a lab AD domain (e.g., GOAD, DetectionLab); validate paths against BloodHound output.
- **GUI**: `pytest-qt` for graph explorer, path analysis, Cypher editor.
- **Cross-validation**: compare shortest paths against BloodHound CE on same data.
- **Safety**: verify domain allowlist; verify no AD modification.

---

## 13. Open Questions / Decisions Pending

1. **Graph store** — SQLite vs. NetworkX vs. embedded Neo4j. Recommend: SQLite for portability; NetworkX for smaller domains (< 50k nodes).
2. **Cypher compatibility** — full Cypher vs. BloodHound subset. Recommend: BloodHound-compatible subset for v1; expand based on demand.
3. **Collection scope** — RustHound (Linux) vs. SharpHound import (Windows) vs. both. Recommend: both; RustHound optional.
4. **BloodHound CE API integration** — optional query of live BloodHound instance. Recommend: v2 feature.

---

## 14. Glossary

- **Attack Path** — Chain of abusable privileges from a foothold to a high-value target.
- **SharpHound** — C# AD data collector for BloodHound.
- **RustHound** — Rust/Go cross-platform AD collector, runs from Linux.
- **Cypher** — Graph query language used by BloodHound/Neo4j.
- **Domain Admin** — Highest-privilege AD group; typical attack target.
- **DCSync** — AD replication privilege abused to extract password hashes.
- **Kerberoasting** — Offline cracking of service account TGS tickets.
- **ACL** — Access Control List; defines permissions on AD objects.
- **Session** — Active logon on a computer; enables credential theft.
- **Delegation** — AD configuration allowing services to impersonate users.

---

*End of document.*