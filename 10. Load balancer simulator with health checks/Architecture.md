# Architecture: Load Balancer Simulator with Health Checks — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Simulate L4/L7 load balancing algorithms with configurable health checks, visualize backend server state transitions, and generate exportable reports
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Load Balancer Simulator (LBSim)** is a GUI-driven desktop application for network engineers, DevOps practitioners, and students who need to **understand and experiment with load balancing behavior** without deploying real infrastructure. It provides an interactive environment where backend servers can be added, health checks configured, and load distribution algorithms compared in real time.

Load balancers are critical infrastructure, but their behavior under failure conditions is often poorly understood until production incidents occur. Health checks determine whether a backend is "healthy" based on periodic probes — a TCP connect check only verifies the port accepts connections, while an HTTP check verifies the application returns a valid response . The choice of algorithm (round-robin, weighted round-robin, least connections) and health check thresholds (interval, fall, rise) dramatically affects system behavior during partial failures .

The tool is designed around four principles:

1. **Visualization-first** — backend state transitions, traffic distribution, and health check results are rendered live, not logged to files.
2. **Configurable health checks** — L4 (TCP connect) and L7 (HTTP GET with status code validation) checks, with configurable interval, timeout, fall threshold, and rise threshold .
3. **Algorithm comparison** — switch between round-robin, weighted round-robin, least connections, and IP hash to observe behavioral differences .
4. **Report-ready** — export simulation results as JSON, CSV, HTML, or PDF for documentation, education, or troubleshooting.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Backend   │ │ Algorithm │ │ Health    │ │ Traffic   │ │ Report  │ │
│  │ Manager   │ │ Selector  │ │ Check Cfg │ │ Simulator │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Backend   │ │ Health    │ │ Traffic   │ │ State     │ │ Console │ │
│  │ Table     │ │ Check Log │ │ Chart     │ │ Timeline  │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Simulation │ │ Health     │ │ Algorithm  │ │ Event Bus / Log    │ │
│  │ Controller │ │ Checker    │ │ Engine     │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Core Engine Layer                                │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Backend Pool   │ │ Health Check   │ │ Load Balancing           │  │
│  │ Manager        │ │ Prober         │ │ Algorithms               │  │
│  │                │ │ (TCP/HTTP)     │ │ (RR, WRR, LC, IP Hash)   │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Simulated Backend (mock servers with configurable health)      │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Simulation │ │ Event      │ │ Config     │ │ Report Store       │ │
│  │ Store      │ │ Log        │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `BackendManagerView` | Add/remove simulated backend servers. Configure per-backend: name, address, weight, max connections, initial health state. |
| `AlgorithmSelectorView` | Choose load balancing algorithm: Round Robin, Weighted Round Robin, Least Connections, IP Hash. Display algorithm description and best-use case . |
| `HealthCheckConfigView` | Configure health check type (TCP Connect / HTTP GET), interval, timeout, fall threshold, rise threshold, HTTP path, expected status codes . |
| `TrafficSimulatorView` | **Primary interaction view.** Send simulated requests; observe which backend receives each request. Control request rate, client IP (for IP hash), request duration. |
| `BackendTableView` | Live table of backends: name, weight, active connections, health state (UP/DOWN), consecutive failures, last check time, request count. Color-coded by state. |
| `HealthCheckLogView` | Chronological log of health check probes: timestamp, backend, result (pass/fail), latency, transition trigger (fall/rise). |
| `TrafficChartView` | Real-time bar chart: requests distributed per backend. Updates as traffic flows. |
| `StateTimelineView` | Visual timeline of backend state transitions: UP → DOWN → UP, with markers for health check events. |
| `ReportBuilderView` | **Export interface.** Select simulation session, format (JSON/CSV/HTML/PDF), include sections (config, traffic distribution, state transitions, health check log). |
| `ConsoleView` | Live log: simulation events, health check results, algorithm decisions. |

**Key UI Patterns:**
- **Live simulation**: requests animate from client to selected backend; backend cards show receiving requests.
- **State color coding**: Green (UP), Red (DOWN), Yellow (transitioning/unknown).
- **Click-to-drill**: click a backend → show its health check history and request log.
- **Real-time metrics**: request counts, active connections, and health state update instantly.

### 3.2 Orchestration Layer

**Simulation Controller**
- Manages simulation lifecycle: configure → start → run → stop → report.
- Spawns health check thread and traffic simulation thread.
- Coordinates state transitions and algorithm decisions.

**Health Checker**
- Periodically probes each backend according to configured health check.
- Tracks consecutive failures (fall) and successes (rise) per backend .
- Transitions backend state when thresholds are crossed.
- Emits events for GUI updates and logging.

**Algorithm Engine**
- Implements load balancing algorithms:
  - **Round Robin**: cyclic assignment .
  - **Weighted Round Robin**: proportional to weight .
  - **Least Connections**: assign to backend with fewest active connections .
  - **IP Hash**: consistent hashing of client IP .

### 3.3 Core Engine Layer

**Backend Pool Manager**
- Maintains list of simulated backends with their state, weight, and connection count.
- Tracks active connections per backend (incremented on request start, decremented on request end).
- Removes unhealthy backends from the active pool .

**Health Check Prober**

| Check Type | Method | Success Condition |
|---|---|---|
| **TCP Connect** | Attempt TCP connection to backend port | Connection established within timeout  |
| **HTTP GET** | Send HTTP GET to configured path | Response status code matches expected (e.g., 200-399)  |

**Prober parameters:**
```python
@dataclass
class HealthCheckConfig:
    check_type: str              # 'tcp', 'http'
    interval_seconds: int        # Time between checks
    timeout_seconds: int         # Probe timeout
    fall_threshold: int          # Consecutive failures to mark DOWN
    rise_threshold: int          # Consecutive successes to mark UP
    http_path: str = "/"         # For HTTP checks
    expected_status: list[int] = field(default_factory=lambda: [200])
```

**Simulated Backend**
- Each backend can be configured as "healthy" or "degraded" to simulate real-world failure modes.
- "Degraded" mode can simulate: slow responses, HTTP 500 errors, or connection refused.
- This allows the simulator to demonstrate how health checks detect and react to failures.

### 3.4 Storage Layer

**Data directory:**
```
~/.lbsim/
├── simulations/
│   └── <sim_id>.json          # Full simulation record
├── configs/
│   └── *.yaml                 # Saved configurations
├── reports/
│   └── <sim_id>_report.pdf
└── logs/
    └── lbsim.log
```

**Simulation record model:**
```python
@dataclass
class SimulationResult:
    simulation_id: str
    timestamp: datetime
    algorithm: str
    health_check_config: HealthCheckConfig
    backends: list[BackendState]
    total_requests: int
    state_transitions: list[StateTransition]
    health_check_log: list[HealthCheckResult]

@dataclass
class BackendState:
    backend_id: str
    name: str
    address: str
    weight: int
    health: str                  # 'UP', 'DOWN'
    consecutive_failures: int
    consecutive_successes: int
    active_connections: int
    total_requests: int

@dataclass
class StateTransition:
    timestamp: datetime
    backend_id: str
    from_state: str
    to_state: str
    reason: str                  # 'fall_threshold', 'rise_threshold', 'manual'
```

### 3.5 Canonical Data Model

See `SimulationResult`, `BackendState`, `StateTransition`, and `HealthCheckConfig` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, charts, backend table updates
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Health Check Thread (single)
  ├── Periodic probes per backend
  ├── State machine evaluation (fall/rise)
  └── Emit health check results

Traffic Simulation Thread (single)
  ├── Generate simulated requests at configured rate
  ├── Apply algorithm to select backend
  ├── Track connection lifecycle
  └── Emit distribution events
```

**Rules:**
- Health check thread and traffic thread operate independently; state changes from health checks affect algorithm decisions.
- GUI updates marshalled via Qt signals.
- Simulation state protected by lock for thread-safe access.

---

## 5. Report Generation & Export

**Export formats:**

| Format | Use Case | Library |
|---|---|---|
| **JSON** | Machine-readable, integration | `json` |
| **CSV** | Spreadsheet analysis | `csv` |
| **HTML** | Shareable, formatted report | Jinja2 |
| **PDF** | Formal deliverable, education | WeasyPrint |

**Report sections:**
1. **Configuration Summary**: Algorithm, health check parameters, backend list.
2. **Traffic Distribution**: Requests per backend, percentage, visualization.
3. **State Transitions**: Timeline of UP/DOWN changes with triggers.
4. **Health Check Log**: Full probe history (optional).
5. **Algorithm Comparison** (optional): Side-by-side if multiple runs.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Simulated backends only** | No real network traffic; backends are internal mock objects, not actual servers. |
| **No real infrastructure impact** | Simulation is entirely in-process; no packets sent. |
| **Safe experimentation** | Users can configure failure scenarios without affecting production. |

---

## 7. Extensibility Points

1. **New algorithm** — implement `LoadBalancingAlgorithm` ABC (RR, WRR, LC, IP Hash, Least Response Time).
2. **New health check type** — implement `HealthCheckProber` ABC (TCP, HTTP, HTTPS, gRPC, custom script).
3. **New export format** — `Exporter` ABC (JSON, CSV, HTML, PDF).
4. **Real backend mode** — optional: probe real servers instead of simulated ones.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 2 s |
| Health check interval | 1–60 s (default 5 s) |
| Traffic simulation rate | 1–1000 req/s |
| UI responsiveness | < 100 ms |
| Memory footprint | < 200 MB RSS |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| Report export | `json`, `csv`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
lbsim/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── lbsim/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── backend_manager.py
│       │   │   ├── algorithm_selector.py
│       │   │   ├── health_check_config.py
│       │   │   ├── traffic_simulator.py
│       │   │   ├── backend_table.py
│       │   │   ├── health_check_log.py
│       │   │   ├── traffic_chart.py
│       │   │   ├── state_timeline.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   └── backends_table_model.py
│       │   └── widgets/
│       │       ├── backend_card.py
│       │       ├── state_badge.py
│       │       └── request_animation.py
│       ├── core/
│       │   ├── algorithms/
│       │   │   ├── base.py
│       │   │   ├── round_robin.py
│       │   │   ├── weighted_round_robin.py
│       │   │   ├── least_connections.py
│       │   │   └── ip_hash.py
│       │   ├── health/
│       │   │   ├── prober.py
│       │   │   └── state_machine.py
│       │   ├── backends/
│       │   │   ├── pool.py
│       │   │   └── simulated_backend.py
│       │   └── simulation/
│       │       ├── controller.py
│       │       └── traffic_generator.py
│       ├── storage/
│       │   ├── simulation_store.py
│       │   └── config_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── json_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   └── pdf_exporter.py
│       │   └── templates/
│       └── utils/
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
| **P0 — Skeleton** | Qt shell, backend manager, backend table | 2 weeks |
| **P1 — Algorithms** | Round Robin, Weighted Round Robin, Least Connections | 2 weeks |
| **P2 — Health Checks** | TCP and HTTP probers, state machine (fall/rise), health log | 2 weeks |
| **P3 — Traffic Simulation** | Request generation, algorithm selection, distribution tracking | 2 weeks |
| **P4 — Visualization** | Traffic chart, state timeline, request animation | 2 weeks |
| **P5 — Reporting** | JSON/CSV/HTML/PDF export | 2 weeks |
| **P6 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~15 weeks (single senior dev) / ~8 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: algorithm selection logic, health state machine transitions, report generation.
- **Integration**: full simulation with backend failure/recovery cycle.
- **GUI**: `pytest-qt` for backend table, health log, state timeline.
- **Cross-validation**: compare algorithm behavior against expected distribution (e.g., round-robin should distribute evenly).

---

## 13. Open Questions / Decisions Pending

1. **Real backend mode** — should the tool optionally probe real servers? Recommend: v2 feature; v1 is simulation-only.
2. **Slow start simulation** — NGINX and HAProxy support gradual weight recovery . Recommend: v2 feature.
3. **Agent checks** — HAProxy supports agent-based health checks . Recommend: v2 feature.

---

## 14. Glossary

- **Health Check** — Periodic probe to determine backend server availability .
- **Fall Threshold** — Consecutive failures before marking backend DOWN .
- **Rise Threshold** — Consecutive successes before marking backend UP .
- **Round Robin** — Cyclic request distribution .
- **Weighted Round Robin** — Distribution proportional to server weight .
- **Least Connections** — Assign to backend with fewest active connections .
- **IP Hash** — Consistent hashing of client IP for session affinity .
- **L4 Health Check** — TCP connect check; verifies port accepts connections .
- **L7 Health Check** — HTTP GET check; verifies application response .

---

*End of document.*