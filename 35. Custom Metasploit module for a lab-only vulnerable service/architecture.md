# Architecture: Custom Metasploit Module for a Lab-Only Vulnerable Service — GUI-Based Solution

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS) for the GUI; Metasploit Framework as the execution backend
**Core Capability:** Guided authoring, testing, and packaging of custom Metasploit modules against a deliberately vulnerable lab service, with report generation and multi-format export
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Metasploit Module Builder Workbench (MMBW)** is a GUI-driven desktop application for security engineers, instructors, and CTF players who need to **write, test, and package a custom Metasploit module** targeting a deliberately vulnerable service in a lab environment. It consolidates the Metasploit module development workflow — module skeleton authoring, payload selection, execution via the RPC API, session capture, and validation — into a single guided interface, then produces a documented report of the process.

Metasploit module development is a well-documented but detail-heavy process. The Metasploit documentation provides clear guides for command injection modules, auxiliary modules, and mixin usage . The framework supports custom modules via `$HOME/.msf4/modules` with specific directory conventions, and external modules in Python/Go are also supported . However, the workflow still requires switching between a text editor, `msfconsole`, and manual testing — and documenting the process for training or writeups is entirely manual.

The tool is designed around four principles:

1. **Guided module authoring** — scaffold generation for common module types (command injection, buffer overflow, auxiliary scanner) with correct mixin inclusion and metadata structure .
2. **RPC-driven execution** — use `pymetasploit3` to execute modules programmatically, capture output and sessions, and validate results without manual `msfconsole` interaction .
3. **Lab-scoped** — operates against a configured lab target only; no scanning or exploitation of unauthorized systems.
4. **Report-ready** — export the module source, execution log, session evidence, and development walkthrough in Markdown, HTML, PDF, and JSON formats.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Lab Target│ │ Module    │ │ Payload   │ │ Execution │ │ Report  │ │
│  │ Config    │ │ Editor    │ │ Selector  │ │ Console   │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Module    │ │ Mixin     │ │ Session   │ │ Validation│ │ Console │ │
│  │ Scaffolder│ │ Reference │ │ Inspector │ │ Dashboard │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Workflow   │ │ RPC Client │ │ Module     │ │ Event Bus / Log    │ │
│  │ Controller │ │ Manager    │ │ Deployer   │ │ (structlog)        │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Module Engine Layer                              │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Scaffold       │ │ Mixin Registry │ │ Payload                  │  │
│  │ Generator      │ │ (HttpClient,   │ │ Compatibility            │  │
│  │                │ │  Tcp, Scanner) │ │ Matrix                   │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Static         │ │ Session        │ │ Module                   │  │
│  │ Validator      │ │ Parser         │ │ Packager                 │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Metasploit RPC Layer                             │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ msfrpcd / msgrpc (Metasploit RPC daemon)                       │  │
│  │  - Module management (use, set, execute)                       │  │
│  │  - Session management (list, interact)                         │  │
│  │  - Console management (create, write, read)                    │  │
│  └────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ pymetasploit3 / snek-sploit (Python RPC clients)               │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Module     │ │ Execution  │ │ Session    │ │ Report Store       │ │
│  │ Store      │ │ Log        │ │ Store      │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `LabTargetConfigView` | Configure the lab target: vulnerable service URL/IP, port, protocol, service type (HTTP, TCP, etc.). Store credentials if needed. Enforce lab-scope: only private IP ranges or localhost allowed. |
| `ModuleScaffolderView` | Select module type (command injection, buffer overflow, auxiliary scanner) and generate a skeleton with correct mixins and metadata structure . |
| `ModuleEditorView` | **Primary authoring view.** Edit the Ruby module source with syntax highlighting. Show scaffold structure, required methods (`initialize`, `exploit`/`run`, `check`), and mixin documentation inline. |
| `MixinReferenceView` | Browse available mixins: `HttpClient`, `Tcp`, `Scanner`, `HttpServer`, `SMB`, `Git` . Show usage examples and required datastore options. |
| `PayloadSelectorView` | Browse compatible payloads for the target platform (unix/cmd, linux/x64, windows/meterpreter). Show payload compatibility matrix . |
| `ExecutionConsoleView` | **Primary execution view.** Configure module options (RHOSTS, RPORT, LHOST, LPORT, payload), execute via RPC, display live output and session creation. |
| `SessionInspectorView` | If a session is created, display session details: type, target, connection info. Provide command input to interact with the session . |
| `ValidationDashboardView` | **Primary validation view.** Run module checks: syntax validation, `check` method execution, target responsiveness, payload delivery confirmation. Display pass/fail per check. |
| `ReportBuilderView` | **Export interface.** Format selection (Markdown, HTML, PDF, JSON), include sections (module source, execution log, session evidence, validation results, development walkthrough). |
| `ConsoleView` | Live log: RPC communication, module deployment, errors. |

**Key UI Patterns:**
- **Wizard-guided workflow**: Lab Config → Scaffold → Author → Payload → Execute → Validate → Report.
- **Inline mixin documentation**: hover over a mixin to see its methods, options, and usage examples.
- **Live RPC status**: connection indicator, module load status, execution progress.
- **Session evidence capture**: screenshots/transcripts of successful sessions feed the report.
- **Scaffold-first**: the module editor starts with a working skeleton, not an empty file.

### 3.2 Orchestration Layer

**Workflow Controller**
- Manages the module development lifecycle: target config → scaffold → author → deploy → execute → validate → report.
- Tracks progress and evidence per step.

**RPC Client Manager**
- Manages connection to `msfrpcd` or `msgrpc` via `pymetasploit3` .
- Handles authentication, reconnection, and graceful shutdown.
- Provides module management, console management, and session interaction .

**Module Deployer**
- Deploys the authored module to `$HOME/.msf4/modules/exploits/<category>/` .
- Triggers `reload_all` to load the new module.
- Validates module loading (no syntax errors).

### 3.3 Module Engine Layer

**Scaffold Generator**

Generates module skeletons for common types:

| Module Type | Base Class | Key Mixins | Required Methods |
|---|---|---|---|
| **Command Injection** | `Msf::Exploit::Remote` | `HttpClient` | `initialize`, `execute_command`, `exploit`  |
| **Auxiliary Scanner** | `Msf::Auxiliary` | `Scanner`, `Tcp` | `initialize`, `run_host(ip)`  |
| **Buffer Overflow** | `Msf::Exploit::Remote` | `Tcp` | `initialize`, `exploit`, `check`  |
| **Browser Exploit** | `Msf::Exploit::Remote` | `HttpServer` | `initialize`, `on_request_uri`, `exploit`  |

**Mixin Registry**
- Documents available mixins with their datastore options and methods .
- `HttpClient`: HTTP request methods, URI options.
- `Tcp`: `connect`, `sock.put`, `sock.get_once` .
- `Scanner`: `RHOSTS`, `THREADS`, `run_host(ip)` .
- `HttpServer`: `on_request_uri`, `send_response`, `primer` .

**Payload Compatibility Matrix**
- Maps target platforms to compatible payloads: `cmd/unix/interact`, `cmd/unix/reverse`, `linux/x64/meterpreter/reverse_tcp`, `windows/meterpreter/reverse_tcp` .
- Validates payload selection against module `Platform` and `Arch` metadata.

**Static Validator**
- Validates module Ruby syntax (via `ruby -c`).
- Checks required methods are defined.
- Checks mixins are included.
- Checks metadata completeness (Name, Description, Author, License, Platform, Targets).

**Session Parser**
- Parses RPC session list output.
- Extracts session type, target, connection info.
- Provides command interface for session interaction .

**Module Packager**
- Packages the validated module as a single `.rb` file.
- Optionally creates a `.rc` resource script for automated execution .
- Generates documentation stubs.

### 3.4 Storage Layer

**Data directory:**
```
~/.mmbw/
├── modules/
│   └── <module_name>/
│       ├── module.rb             # The authored module
│       ├── module.rc             # Optional resource script
│       ├── metadata.json         # Module metadata
│       └── evidence/
│           ├── execution.log
│           └── session_transcript.txt
├── reports/
│   └── <module_name>_report.pdf
└── logs/
    └── mmbw.log
```

**Module record model:**
```python
@dataclass
class CustomModule:
    module_id: str
    name: str
    module_type: str              # 'cmd_injection', 'aux_scanner', 'bof', 'browser'
    target_service: str
    target_platform: str          # 'unix', 'windows', 'linux'
    source_code: str
    rpc_path: str | None          # Deployed module path
    payload_used: str | None
    execution_status: str         # 'draft', 'deployed', 'executed', 'session_created'
    session_id: str | None
    validation_results: list[ValidationCheck]
    created_at: datetime
    updated_at: datetime

@dataclass
class ValidationCheck:
    check_name: str               # 'syntax', 'load', 'check_method', 'execution'
    status: str                   # 'pass', 'fail', 'skipped'
    message: str
    timestamp: datetime
```

### 3.5 Canonical Data Model

See `CustomModule` and `ValidationCheck` above.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, module editor, execution console
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

RPC Worker (single thread)
  ├── RPC connection management
  ├── Module deployment and reload
  ├── Execution commands
  └── Session polling

Validation Worker (QThreadPool)
  ├── Syntax validation (ruby -c)
  ├── Static checks
  └── Target responsiveness probes
```

**Rules:**
- RPC operations serialized (single connection, stateful).
- Module deployment requires `reload_all`; blocking but fast.
- Execution is async; polling for session creation.
- Cancellation: `threading.Event` checked between RPC calls.

---

## 5. Workflow: End-to-End User Journey

1. **Configure Lab Target** → enter vulnerable service URL/IP, port, service type.
2. **Scaffold Module** → select module type (command injection, auxiliary scanner, BOF); generate skeleton .
3. **Author Module** → edit Ruby source; use mixin reference for guidance .
4. **Select Payload** → browse compatible payloads; select target payload .
5. **Deploy Module** → copy to `$HOME/.msf4/modules/exploits/<category>/`; trigger `reload_all` .
6. **Validate** → run syntax check, module load check, `check` method .
7. **Execute** → configure options (RHOSTS, RPORT, LHOST, LPORT); run via RPC .
8. **Capture Session** → if session created, interact and capture transcript .
9. **Export Report** → Markdown/HTML/PDF/JSON with module source, execution log, validation results, session evidence.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| **Unauthorized exploitation** | Lab target allowlist (private IPs, localhost only); explicit authorization acknowledgment. |
| **RPC credential exposure** | RPC password stored in OS keychain; never logged. |
| **Module deployment scope** | Deployed only to `$HOME/.msf4/modules/`; no system-wide deployment. |
| **Payload delivery** | Payloads restricted to localhost or lab target; no external C2. |
| **Session data sensitivity** | Session transcripts may contain sensitive data; local-only storage. |
| **Metasploit dependency** | MSF is a powerful tool; tool is lab-scoped and does not automate broad exploitation. |

---

## 7. Extensibility Points

1. **New module type** — extend `ScaffoldGenerator` with new templates.
2. **New mixin reference** — add YAML documentation in `mixins/`.
3. **New RPC client** — swap `pymetasploit3` for `snek-sploit` or custom client .
4. **New export format** — `Exporter` ABC (Markdown, HTML, PDF, JSON).
5. **msfvenom integration** — optional payload generation via `msfvenom` CLI .

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time | < 3 s |
| RPC connection | < 2 s |
| Module deploy + reload | < 10 s |
| Execution latency | < 5 s (excluding payload delivery) |
| Validation | < 5 s |
| Report generation | < 5 s |
| Memory footprint | < 500 MB RSS |
| Localization | i18n-ready |
| Accessibility | Keyboard-navigable |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Ecosystem |
| GUI | PySide6 (LGPL) | Commercial-friendly |
| Metasploit RPC | `pymetasploit3` | Full-featured RPC client  |
| RPC daemon | `msfrpcd` or `msgrpc` | Standard Metasploit RPC  |
| Ruby syntax check | `ruby -c` (subprocess) | Validation |
| Module format | Ruby (`.rb`) | Metasploit standard  |
| Resource scripts | `.rc` files | Automation  |
| Report export | `markdown`, `Jinja2`, `WeasyPrint` | Multi-format |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller | Cross-platform binaries |
| Testing | pytest + pytest-qt | Unit, GUI |

---

## 10. Directory Structure (Source Tree)

```
mmbw/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── mmbw/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── lab_target_config.py
│       │   │   ├── module_scaffolder.py
│       │   │   ├── module_editor.py
│       │   │   ├── mixin_reference.py
│       │   │   ├── payload_selector.py
│       │   │   ├── execution_console.py
│       │   │   ├── session_inspector.py
│       │   │   ├── validation_dashboard.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── payloads_table_model.py
│       │   │   └── sessions_table_model.py
│       │   └── widgets/
│       │       ├── ruby_editor.py
│       │       ├── rpc_status.py
│       │       └── validation_badge.py
│       ├── core/
│       │   ├── scaffold/
│       │   │   ├── generator.py
│       │   │   └── templates/
│       │   │       ├── cmd_injection.rb.j2
│       │   │       ├── aux_scanner.rb.j2
│       │   │       └── bof.rb.j2
│       │   ├── rpc/
│       │   │   ├── client.py
│       │   │   ├── module_manager.py
│       │   │   └── session_manager.py
│       │   ├── validation/
│       │   │   ├── syntax.py
│       │   │   └── static.py
│       │   ├── mixins/
│       │   │   └── registry.yaml
│       │   └── payloads/
│       │       └── compatibility.py
│       ├── storage/
│       │   ├── module_store.py
│       │   └── evidence_store.py
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── markdown_exporter.py
│       │   │   ├── html_exporter.py
│       │   │   ├── pdf_exporter.py
│       │   │   └── json_exporter.py
│       │   └── templates/
│       └── utils/
│           ├── subprocess_runner.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── gui/
├── lab_services/
│   └── (deliberately vulnerable services for testing)
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
| **P0 — Skeleton** | Qt shell, lab target config, RPC connection | 2 weeks |
| **P1 — Scaffold** | Module type templates, scaffold generator  | 2 weeks |
| **P2 — Editor** | Ruby syntax highlighting, mixin reference | 2 weeks |
| **P3 — Deploy** | Module deployment, `reload_all`, load validation  | 1 week |
| **P4 — Execution** | RPC execution, option configuration, output capture  | 2 weeks |
| **P5 — Session** | Session polling, interaction, transcript capture  | 1 week |
| **P6 — Validation** | Syntax check, static checks, validation dashboard | 2 weeks |
| **P7 — Reporting** | Markdown/HTML/PDF/JSON export | 2 weeks |
| **P8 — Polish** | Performance, i18n, docs, packaging | 3 weeks |

**Total:** ~17 weeks (single senior dev) / ~9 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: scaffold generation, syntax validation, RPC client methods, payload compatibility.
- **Integration**: full workflow against a lab vulnerable service (e.g., the FastAPI command injection example from Metasploit docs ); validate module loads, executes, and creates session.
- **GUI**: `pytest-qt` for editor, execution console, validation dashboard.
- **Cross-validation**: compare execution output against manual `msfconsole` execution.
- **Safety**: verify lab-scope enforcement; verify no unauthorized targeting.

---

## 13. Open Questions / Decisions Pending

1. **RPC daemon vs console** — `msfrpcd` is cleaner for programmatic use; `msgrpc` requires `msfconsole` running . Recommend: `msfrpcd` primary; `msgrpc` fallback.
2. **Ruby vs Python modules** — Metasploit supports external Python modules but they need to be executable . Recommend: Ruby for v1 (native, best support); Python module support v2.
3. **Module deployment path** — `$HOME/.msf4/modules/` is user-local and requires no elevated privileges . Recommend: user-local deployment.
4. **msfvenom integration** — useful for payload generation but adds CLI dependency . Recommend: optional integration.

---

## 14. Glossary

- **Metasploit Framework** — Open-source penetration testing framework.
- **Module** — Metasploit exploit, auxiliary, or post-exploitation unit.
- **Mixin** — Ruby module providing reusable functionality (e.g., `HttpClient`, `Tcp`).
- **RHOSTS** — Remote host(s) target option.
- **Payload** — Code executed on target after exploitation (e.g., `cmd/unix/interact`).
- **Session** — Established connection to compromised target.
- **msfrpcd** — Metasploit RPC daemon .
- **pymetasploit3** — Python RPC client for Metasploit .
- **Resource Script (`.rc`)** — Script of `msfconsole` commands for automation .
- **Scaffold** — Generated module skeleton with required structure.

---

*End of document.*