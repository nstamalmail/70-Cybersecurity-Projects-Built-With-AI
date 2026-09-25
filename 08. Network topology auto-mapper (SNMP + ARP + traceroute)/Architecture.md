# Architecture: Network Topology Auto-Mapper (SNMP + ARP + Traceroute) — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Automated network topology discovery via SNMP MIB walking, ARP table correlation, and traceroute path reconstruction with interactive visualization and multi-format report export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Network Topology Auto-Mapper (NTAM)** is a GUI-driven desktop application for network administrators, security engineers, and penetration testers who need to **automatically discover and visualize network topology** without manual diagramming. It combines three complementary discovery techniques: **SNMP MIB walking** to extract device-level forwarding tables and interface data, **ARP table correlation** to identify active hosts and their physical connections, and **traceroute path reconstruction** to map Layer 3 routing paths between subnets .

Manual network diagramming is a persistent operational burden. As networks change — new nodes, retired paths, periodic upgrades — manually maintained diagrams become stale and misleading. ESnet's TerraNova project, released in 2026, addresses this exact problem: "keeping maps accurate amidst very frequent changes" . The NTAM brings comparable automation to smaller environments without requiring a full server infrastructure or Grafana stack.

The tool is designed around four principles:

1. **Recursive discovery** — start from a seed device, discover neighbors via SNMP and CDP/LLDP, and recurse outward until the network is mapped .
2. **Multi-layer correlation** — combine Layer 2 (ARP, MAC tables, bridge MIBs) and Layer 3 (routing tables, traceroute) data to produce a unified topology .
3. **Interactive visualization** — force-directed or hierarchical graph rendering with clickable nodes, link details, and zoom/pan navigation.
4. **Report-ready** — export topology data as JSON, CSV, Graphviz DOT, PNG/SVG diagrams, and PDF reports for documentation and audits.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Seed      │ │ Discovery │ │ Topology  │ │ Device    │ │ Report  │ │
│  │ Config    │ │ Progress  │ │ Graph     │ │ Inspector │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Device    │ │ Link      │ │ Subnet    │ │ Export    │ │ Console │ │
│  │ Inventory │ │ Detail    │ │ Map       │ │ Options   │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Discovery  │ │ Topology   │ │ Credential │ │ Event Bus / Log    │ │
│  │ Controller │ │ Builder    │ │ Manager    │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Discovery Engine Layer                           │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ SNMP Collector │ │ ARP Correlator │ │ Traceroute Path          │  │
│  │ (MIB walking)  │ │ (host discovery)│ │ Analyzer                 │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Recursive Crawler (seed → neighbors → neighbors...)            │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Visualization Layer                              │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Graph Renderer │ │ Layout Engine  │ │ Export Pipeline          │  │
│  │ (pyqtgraph/    │ │ (force-directed│ │ (Graphviz DOT, PNG,      │  │
│  │  Graphviz)     │ │  / hierarchical)│ │  SVG, JSON, CSV)        │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Topology   │ │ Device     │ │ Credential │ │ Report Store       │ │
│  │ Store      │ │ Inventory  │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `SeedConfigView` | Configure starting point: seed device IP, SNMP community strings (v1/v2c) or credentials (v3), discovery scope (subnet range, max depth). |
| `DiscoveryProgressView` | **Primary status view.** Live progress: devices discovered, SNMP queries sent, ARP entries collected, traceroute hops mapped. Per-phase progress bars. |
| `TopologyGraphView` | **Primary visualization.** Interactive network graph: nodes represent devices/hosts, edges represent links. Click node → show device details. Zoom, pan, layout toggle (force-directed / hierarchical / circular). |
| `DeviceInspectorView` | Drill-down for a selected device: hostname, IP, MAC, vendor (OUI), device type (router/switch/server/host), SNMP sysDescr, interface list, open ports (if scanned). |
| `LinkDetailView` | For a selected link: source device/interface, destination device/interface, link type (L2/L3), bandwidth (if available via SNMP), status. |
| `SubnetMapView` | Subnet-level view: which subnets exist, which devices are in each, inter-subnet routing paths. |
| `DeviceInventoryView` | Table of all discovered devices: IP, MAC, hostname, vendor, type, first seen, last seen. Sortable, filterable, exportable. |
| `ReportBuilderView` | **Export interface.** Format selection (Graphviz DOT, PNG, SVG, JSON, CSV, PDF), layout options, include/exclude sections. |
| `ConsoleView` | Live log: SNMP timeouts, ARP failures, traceroute errors, credential prompts. |

**Key UI Patterns:**
- **Graph-first layout**: topology graph is the dominant view; other panels are collapsible sidebars.
- **Node color coding**: routers (red), switches (blue), servers (green), hosts (gray), unknown (yellow).
- **Live graph population**: nodes and edges appear as discovery progresses, not batched at the end.
- **Click-to-drill**: click a node → inspector shows all known details; click an edge → link details.
- **Layout toggle**: switch between force-directed (organic), hierarchical (tree), and circular layouts.

### 3.2 Orchestration Layer

**Discovery Controller**
- Manages the recursive discovery process: seed → neighbors → neighbors' neighbors, up to configurable depth .
- Coordinates SNMP, ARP, and traceroute collectors.
- Tracks visited devices to avoid loops.

**Topology Builder**
- Merges data from all collectors into a unified graph model.
- Correlates ARP entries with SNMP interface data to infer physical connections.
- Builds the graph structure (nodes = devices, edges = links) .

**Credential Manager**
- Securely stores SNMP community strings and v3 credentials per device.
- Prompts for credentials when a new device is discovered .
- Caches credentials for the session.

### 3.3 Discovery Engine Layer

**SNMP Collector**

Uses SNMP to extract device-level topology data from MIB tables :

| MIB Table | OID | Data Extracted |
|---|---|---|
| **sysDescr** | 1.3.6.1.2.1.1.1 | Device description (vendor, model, OS) |
| **sysName** | 1.3.6.1.2.1.1.5 | Hostname |
| **ifTable** | 1.3.6.1.2.1.2.2 | Interface list (name, status, speed, MAC) |
| **ipAddrTable** | 1.3.6.1.2.1.4.20 | IP addresses assigned to interfaces |
| **ipRouteTable** | 1.3.6.1.2.1.4.21 | Routing table (destinations, next hops) |
| **dot1dTpFdbTable** | BRIDGE-MIB | MAC address forwarding table (which MAC on which port)  |
| **dot1dTpFdbAddress** | BRIDGE-MIB | MAC → forwarding table index mapping  |
| **dot1dTpFdbPort** | BRIDGE-MIB | Port index for each MAC  |

**ARP Correlator**

Uses ARP tables to discover active hosts and correlate them with SNMP data :

- Read ARP tables from discovered devices via SNMP (`ipNetToMediaTable`, OID `1.3.6.1.2.1.4.22`).
- Read global ARP information to identify hosts not directly connected .
- Cross-reference ARP MAC addresses with SNMP bridge MIB forwarding tables to determine which port a host is connected to .
- Use ARP ping for host discovery on local subnets .

**Traceroute Path Analyzer**

Uses traceroute to map Layer 3 paths between subnets :

- Run traceroute from the discovery host to each discovered subnet.
- Parse hop-by-hop output to identify router nodes and inter-subnet paths.
- Correlate traceroute hops with SNMP-discovered device IPs.
- Build Layer 3 topology edges (router → router connections).

**Recursive Crawler**

Orchestrates the discovery process :

1. Start with seed device IP and credentials.
2. Query SNMP for system info, interfaces, ARP table, bridge MIB.
3. Extract neighbor IPs from ARP and routing tables.
4. For each new IP, attempt SNMP query with cached/new credentials.
5. Recurse until max depth or no new devices discovered.
6. Optionally run traceroute to fill in Layer 3 gaps.

### 3.4 Visualization Layer

**Graph Renderer**

Two rendering backends:

1. **pyqtgraph `GLGraphItem`**: For interactive, high-performance graphs with many nodes. Supports node positions, edges, colors, and sizes .
2. **Graphviz**: For static, publication-quality diagrams. Generates DOT language, rendered to PNG/SVG .

**Layout Engine**
- **Force-directed**: Organic layout where connected nodes attract, unconnected repel.
- **Hierarchical**: Tree layout rooted at the seed device.
- **Circular**: Nodes arranged in a circle, useful for star topologies.

**Export Pipeline**
- **Graphviz DOT**: Source representation of the topology graph .
- **PNG/SVG**: Rendered diagram for documentation.
- **JSON**: Machine-readable topology (nodes, edges, attributes).
- **CSV**: Device inventory and link list for spreadsheets.
- **PDF**: Formal report with graph image + device/link tables.

### 3.5 Storage Layer

**Data directory:**
```
~/.ntam/
├── topologies/
│   └── <topology_id>/
│       ├── nodes.json
│       ├── edges.json
│       ├── raw_snmp/
│       ├── arp_data.json
│       └── traceroute_data.json
├── credentials/
│   └── credentials.enc       # Encrypted credential store
├── reports/
│   └── <topology_id>_report.pdf
└── logs/
    └── ntam.log
```

**Topology data model:**
```python
@dataclass
class NetworkDevice:
    device_id: str
    ip: str
    mac: str | None
    hostname: str | None
    sys_descr: str | None
    vendor: str | None           # from OUI lookup
    device_type: str             # 'router', 'switch', 'server', 'host', 'unknown'
    interfaces: list[Interface]
    first_seen: datetime
    snmp_accessible: bool

@dataclass
class Interface:
    index: int
    name: str
    mac: str | None
    ip: str | None
    status: str                  # 'up', 'down'
    speed: int | None            # bits per second

@dataclass
class NetworkLink:
    link_id: str
    source_device: str           # device_id
    source_interface: int | None
    dest_device: str
    dest_interface: int | None
    link_type: str               # 'L2', 'L3', 'unknown'
    bandwidth: int | None

@dataclass
class Topology:
    topology_id: str
    timestamp: datetime
    seed_ip: str
    devices: list[NetworkDevice]
    links: list[NetworkLink]
    subnets: list[str]
    discovery_duration: float
```

### 3.6 Canonical Data Model

See `NetworkDevice`, `NetworkLink`, and `Topology` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, graph rendering, inspector updates
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Discovery Pool (QThreadPool, N workers)
  ├── SNMP collector threads    (parallel across devices)
  ├── ARP correlator thread     (serial per device)
  └── Traceroute threads        (parallel across subnets)

Graph Builder (single thread)
  └── Merge results, compute layout

Writer Thread (serial)
  └── SQLite/JSON writes
```

**Rules:**
- SNMP queries parallelized across devices (default: 10 concurrent).
- Recursive discovery is breadth-first; each level waits for previous level.
- Graph layout computation runs after discovery completes.
- Cancellation: `threading.Event` checked between device queries.

---

## 5. Workflow: End-to-End User Journey

1. **Configure Seed** → enter seed device IP, SNMP credentials, discovery scope.
2. **Start Discovery** → recursive crawl begins; progress view shows live status.
3. **SNMP Collection** → per device: system info, interfaces, ARP table, bridge MIB.
4. **ARP Correlation** → match ARP MACs to bridge forwarding tables to infer physical links .
5. **Traceroute** → map Layer 3 paths between subnets.
6. **Topology Build** → merge all data into unified graph.
7. **Visualize** → interactive graph appears with devices and links.
8. **Inspect** → click nodes/edges to see details.
9. **Export** → DOT, PNG, SVG, JSON, CSV, PDF.
10. **Review Report** → formal documentation with graph and tables.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Credential storage** | SNMP credentials encrypted at rest; never logged in plaintext. |
| **SNMP v1/v2c security** | Community strings transmitted in cleartext; document limitation; prefer SNMPv3 where available. |
| **Network scanning legality** | Discovery generates network traffic; document authorization requirement. |
| **SNMP write access** | Tool performs read-only queries (GET/GETNEXT); never uses SET. |
| **ARP spoofing** | ARP data can be poisoned; cross-validate with SNMP bridge tables . |
| **Traceroute accuracy** | Traceroute shows forward path only; asymmetric routing not captured. Document limitation. |

---

## 7. Extensibility Points

1. **New discovery protocol** — implement `DiscoveryProtocol` ABC (SNMP, CDP, LLDP, NetBIOS).
2. **New MIB table** — add OID mapping in `mib_tables.yaml`.
3. **New layout algorithm** — implement `GraphLayout` ABC (force-directed, hierarchical, circular).
4. **New export format** — `Exporter` ABC (DOT, PNG, SVG, JSON, CSV, PDF, TerraNova-compatible).
5. **Vendor-specific MIB support** — add OID mappings for Cisco, Juniper, HP, etc.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Discovery (100 devices) | < 5 min |
| Graph render (500 nodes) | 60 fps |
| SNMP timeout | 3 s (configurable) |
| Max discovery depth | 5 (configurable) |
| Memory footprint | < 500 MB RSS |
| Report generation | < 10 s |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly; QGraphicsScene for graph |
| SNMP | `pysnmp` or `easysnmp` | Standard SNMP libraries |
| ARP | `scapy` + `psutil` | Packet crafting + system ARP cache |
| Traceroute | `scapy` (custom) or subprocess | Cross-platform |
| Graph rendering | `pyqtgraph` (`GLGraphItem`)  + `graphviz`  | Interactive + static |
| Graph layout | `networkx` (layout algorithms) + custom | Standard algorithms |
| Export | `graphviz`, `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| DB | JSON + optional SQLite | Lightweight |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
ntam/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── ntam/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── seed_config.py
│       │   │   ├── discovery_progress.py
│       │   │   ├── topology_graph.py
│       │   │   ├── device_inspector.py
│       │   │   ├── link_detail.py
│       │   │   ├── subnet_map.py
│       │   │   ├── device_inventory.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── devices_table_model.py
│       │   │   └── links_table_model.py
│       │   └── widgets/
│       │       ├── graph_canvas.py
│       │       ├── device_node.py
│       │       └── topology_legend.py
│       ├── core/
│       │   ├── discovery/
│       │   │   ├── controller.py
│       │   │   ├── snmp_collector.py
│       │   │   ├── arp_correlator.py
│       │   │   ├── traceroute_analyzer.py
│       │   │   └── recursive_crawler.py
│       │   ├── topology/
│       │   │   ├── builder.py
│       │   │   ├── correlator.py
│       │   │   └── model.py
│       │   ├── visualization/
│       │   │   ├── graph_renderer.py
│       │   │   ├── layouts/
│       │   │   │   ├── force_directed.py
│       │   │   │   ├── hierarchical.py
│       │   │   │   └── circular.py
│       │   │   └── graphviz_export.py
│       │   └── credentials/
│       │       └── manager.py
│       ├── storage/
│       │   ├── topology_store.py
│       │   ├── device_store.py
│       │   └── credential_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── dot_exporter.py
│       │   │   ├── png_exporter.py
│       │   │   ├── svg_exporter.py
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── oui.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── resources/
│   ├── icons/
│   └── mib_tables/
└── docs/
    ├── architecture.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, seed config, SNMP collector (system info + interfaces) | 2 weeks |
| **P1 — ARP & Bridge MIB** | ARP table collection, bridge MIB parsing, MAC-to-port mapping  | 2 weeks |
| **P2 — Recursive Discovery** | Crawler logic, credential prompts, depth control  | 2 weeks |
| **P3 — Traceroute** | Traceroute path analysis, L3 topology edges  | 1 week |
| **P4 — Topology Graph** | Graph builder, pyqtgraph rendering, node/edge visualization  | 3 weeks |
| **P5 — Inspector & Inventory** | Device inspector, link detail, inventory table | 2 weeks |
| **P6 — Reporting** | DOT/PNG/SVG/JSON/CSV/PDF export  | 2 weeks |
| **P7 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~17 weeks (single senior dev) / ~9 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: SNMP OID parsing, ARP correlation logic, graph builder, credential manager.
- **Integration**: full discovery on a lab network with 2-3 switches/routers (GNS3 or physical).
- **GUI**: `pytest-qt` for graph rendering, node selection, inspector updates.
- **Cross-validation**: compare discovered topology against manual `show cdp neighbors` / `show mac address-table` output .
- **Performance**: benchmark discovery on /24 subnet with 50 devices.

---

## 13. Open Questions / Decisions Pending

1. **SNMP library** — `pysnmp` (pure Python, complex) vs `easysnmp` (C bindings, faster). Recommend: `pysnmp` for portability; `easysnmp` optional.
2. **CDP/LLDP support** — requires vendor-specific MIBs or packet capture. Recommend: v2 feature; SNMP-only for v1 .
3. **Graph rendering backend** — pyqtgraph for interactivity vs Graphviz for quality. Recommend: pyqtgraph for live view; Graphviz for export .
4. **Credential prompting** — per-device prompt (like Auto_network_map)  vs bulk credential list. Recommend: per-device prompt with session cache.
5. **TerraNova integration** — TerraNova accepts Python adapters for custom data sources . Recommend: export format compatible with TerraNova in v2.

---

## 14. Glossary

- **SNMP** — Simple Network Management Protocol; used to query device MIBs .
- **MIB** — Management Information Base; hierarchical database of device objects.
- **OID** — Object Identifier; address of a MIB variable.
- **ARP** — Address Resolution Protocol; maps IP to MAC .
- **Bridge MIB** — MIB containing switch forwarding tables (MAC-to-port mappings) .
- **Traceroute** — Tool mapping Layer 3 path to a destination .
- **CDP/LLDP** — Cisco Discovery Protocol / Link Layer Discovery Protocol; neighbor discovery.
- **Force-directed layout** — Graph layout where connected nodes attract, unconnected repel.
- **Graphviz** — Graph visualization software using DOT language .
- **OUI** — Organizationally Unique Identifier; MAC address vendor prefix.
- **Seed device** — Starting point for recursive discovery .

---

*End of document.*