# Memory Forensics Analyzer (MFA-GUI)
## Architecture Design Document (ADD)

**Version:** 1.0.0  
**Author:** Lead Security & Incident Response Software Architect  
**Date:** September 16, 2026  
**Document ID:** ARCH-MFA-2026-09  
**Status:** Approved for Development  

---

## 1. Executive Summary & Purpose

The **Memory Forensics Analyzer (MFA-GUI)** is an enterprise-grade, desktop-based GUI application designed to streamline volatile memory analysis for incident responders, malware analysts, and digital forensic investigators. Built atop the industry-standard **Volatility 3 framework**, MFA-GUI transforms raw CUI-driven memory dumps into an interactive, visual threat-hunting and investigation environment.

Volatility memory extraction requires manual CLI commands, custom symbol table management, and disjointed triage output parsing. MFA-GUI bridges this operational gap by wrapping Volatility 3's core Python library directly into an asynchronous, responsive PyQt6/PySide6 architecture. The application automates symbol downloading, constructs execution timelines, maps process trees, extracts suspicious memory artifacts (injected DLLs, hidden code, rootkit drivers, network sockets), and correlates findings against **YARA rules** and **MITRE ATT&CK TTPs**.

---

## 2. System Scope & Core Requirements

### 2.1 Functional Requirements (FR)
- **FR-1: Dump Ingestion & Symbol Management**
  - Ingest standard raw and structured memory dump formats: `.raw`, `.dmp`, `.vmem`, `.sav`, `.elf`, `.lime`, and Microsoft Crash Dumps (`.dmp`).
  - Automated Volatility 3 Symbol Table (ISF/JSON) resolution via local symbol caches and automated fetching from official Symbol Servers (Microsoft PDB, Linux ISF, Apple PDB).
  - Profile-less OS detection (Windows, Linux, macOS) utilizing Volatility 3's `banners` and kernel heuristic detection layer.
- **FR-2: Automated Memory Triage & Plugin Pipeline**
  - Execute core investigative plugin groups concurrently:
    - **Process & Memory:** `pslist`, `pstree`, `psscan`, `cmdline`, `handles`, `dlllist`, `malfind`, `vadinfo`.
    - **Networking:** `netscan`, `netstat`.
    - **Kernel & Rootkits:** `modules`, `modscan`, `ssdt`, `driverscan`, `callbacks`.
    - **Persistence & Registry:** `amcache`, `hivelist`, `printkey`, `userassist`, `shimcache`.
- **FR-3: Interactive Artifact Visualization**
  - Render an interactive, zoomable Process Hierarchy Tree with suspicious process flagging (e.g., process masquerading, orphan processes, parent-child anomalies).
  - Display memory segment maps (VAD trees) with permissions highlight (e.g., PAGE_EXECUTE_READWRITE / `RWX` detection).
- **FR-4: Automated Threat Scoring & YARA Scanning**
  - Native integration with YARA scanning engines (`yara-python`) over extracted VAD regions, process memory spaces, and raw dump files.
  - Automatic cross-referencing of extracted processes, network IPs, and file hashes against local IOC databases and MITRE ATT&CK framework mapping.
- **FR-5: Payload & Artifact Extraction**
  - One-click extraction/dumping of suspicious executables, DLLs, unpacked memory payloads, and network buffers directly to an isolated quarantine workspace.
- **FR-6: Case Management & Report Generation**
  - Comprehensive export of investigation telemetry into structured (`JSON`, `CSV`, `STIX 2.1`) and executive human-readable (`PDF`, `Markdown`) report formats.

### 2.2 Non-Functional Requirements (NFR)
- **NFR-1: Non-Blocking GUI Responsiveness**
  - The UI event loop must remain strictly decoupled from Volatility 3 execution pipelines. Multi-gigabyte memory scans (16GB–256GB+) must process in background worker threads without freezing UI rendering (60 FPS main thread target).
- **NFR-2: RAM & Resource Bounding**
  - Efficiently stream and page memory table results to avoid memory exhaustion on the analyst's host machine. Target RAM usage for the application <500MB when parsing large memory images.
- **NFR-3: Cross-Platform Native Abstraction**
  - Support execution on Linux (Ubuntu/Debian/Fedora), Microsoft Windows (10/11/Server 2019+), and macOS (Apple Silicon & x86_64).
- **NFR-4: Modularity & Plugin Extensibility**
  - Abstract Volatility 3 module invocation to allow custom community Volatility plugins or YARA rulesets to be loaded dynamically without re-compiling the core UI.

---

## 3. Overall System Architecture & Layering

MFA-GUI follows a 4-tier decoupled architectural pattern: **Presentation Layer (GUI)**, **Controller & Dispatcher Layer**, **Volatility Domain Engine Layer**, and the **Data Storage & Quarantine Layer**.

```
+-----------------------------------------------------------------------+
|                       PRESENTATION LAYER (GUI)                        |
|   PyQt6 / PySide6 Desktop GUI, Event Loop, Process Trees, Timeline    |
+------------------------------------+----------------------------------+
                                     | Event Dispatcher / Qt Signals
                                     v
+-----------------------------------------------------------------------+
|                    APPLICATION CONTROLLER LAYER                       |
|   Task Dispatcher, Thread Pool Manager, Case Manager, Config Sync    |
+------------------------------------+----------------------------------+
                                     | Worker Threads / Queue
                                     v
+-----------------------------------------------------------------------+
|                   VOLATILITY DOMAIN ENGINE LAYER                      |
|  +--------------------+  +-------------------+  +------------------+  |
|  | Volatility 3 Bridge|  | Symbol Resolution |  | Threat Scoring & |  |
|  | & Context Manager  |  | Service (ISF/PDB) |  | YARA Matcher     |  |
|  +--------------------+  +-------------------+  +------------------+  |
|  +-----------------------------------------------------------------+  |
|  | Extraction Manager (Dump Process/DLL/VAD) & Artifact Parser     |  |
|  +-----------------------------------------------------------------+  |
+------------------------------------+----------------------------------+
                                     | Async Cache / File Read-Write
                                     v
+-----------------------------------------------------------------------+
|                   DATA STORAGE & QUARANTINE LAYER                     |
|  SQLite Database (Parsed Artifacts), Local ISF Cache, Quarantine Vault|
+-----------------------------------------------------------------------+
```

---

## 4. Component-Level Design & Modules

### 4.1 System Components Matrix

| Component Module | Class / Package Name | Primary Responsibility | Dependencies |
| :--- | :--- | :--- | :--- |
| **GUI Application** | `mfa.gui.app` | Manages PyQt/PySide main window, dark/light themes, tabbed investigation views, and event dispatchers. | `PyQt6` / `PySide6` |
| **Process Tree Widget** | `mfa.gui.widgets.tree` | Renders dynamic, hierarchical tree graphs of processes with state icons and anomaly warnings. | `qasync`, `pyqtgraph` |
| **Volatility Bridge** | `mfa.engine.vol_bridge` | Programmatic wrapper around `volatility3.framework`. Constructs context, automated symbol discovery, and plugin runner. | `volatility3` |
| **Symbol Manager** | `mfa.engine.symbols` | Manages local JSON/ISF caches, connects to Microsoft/Linux symbol servers, downloads missing PDBs. | `requests`, `aiohttp` |
| **YARA Scanner** | `mfa.analysis.yara` | In-memory YARA scanner targeting process addresses, VADs, or raw memory dump ranges. | `yara-python` |
| **Threat Scorer** | `mfa.analysis.scorer` | Evaluates anomalies (e.g. unbacked executable memory, parent/child mismatch, hidden processes) to generate risk scores. | Internal rule-set |
| **Database & Cache** | `mfa.storage.db` | Caches plugin execution results in SQLite for instant filtering, search, and session recovery without re-running Volatility. | `sqlite3`, `peewee` |
| **Report Generator** | `mfa.reports.builder` | Compiles process maps, YARA hits, network logs, and threat indicators into signed reports. | `reportlab`, `jinja2` |

---

## 5. Detailed Data Flow & Processing Pipeline

The memory analysis execution flows through distinct setup, scanning, caching, and visualization stages:

```
         [ Analyst Ingests Memory Image (.vmem / .raw) ]
                                |
                                v
   +----------------------------------------------------------+
   | Step 1: Image Discovery & Profile Detection              |
   | - Initialize Volatility 3 Context                        |
   | - Run Banner / OS identification heuristics              |
   | - Query Symbol Server for missing ISF/PDB symbols        |
   +----------------------------+-----------------------------+
                                |
                                v
   +----------------------------------------------------------+
   | Step 2: Automated Core Triage (Async Background Queue)    |
   | - Concurrent Plugin Execution: pslist, pstree, netscan,   |
   |   malfind, driverscan, handles                           |
   | - Stream results to SQLite Cache                         |
   +----------------------------+-----------------------------+
                                |
                                v
   +----------------------------------------------------------+
   | Step 3: Threat Analytics & Anomaly Detection             |
   | - Highlight RWX VAD regions (Potential Process Injection)|
   | - Scan extracted VADs against YARA Rulesets              |
   | - Cross-reference suspicious IPs & command lines          |
   +----------------------------+-----------------------------+
                                |
                                v
   +----------------------------------------------------------+
   | Step 4: UI Rendering & Interactive Investigation         |
   | - Build Process Hierarchy Tree & Network Socket Matrix    |
   | - Analyst right-clicks to Dump Payload / Inspect Memory  |
   +----------------------------+-----------------------------+
                                |
                                v
   +----------------------------------------------------------+
   | Step 5: Export & Case Archiving                          |
   | - Save SQLite Case File (.mfa)                           |
   | - Render Executive Forensic PDF Report                   |
   +----------------------------------------------------------+
```

---

## 6. Threat Detection & Anomaly Rules Engine

MFA-GUI incorporates built-in anomaly detection algorithms that automatically flag suspicious behavior in memory dumps:

1. **Process Masquerading Detection:**
   - Evaluates process names against canonical execution paths (e.g., `svchost.exe` executed outside of `%SystemRoot%\System32\` or without `-k` arguments).
2. **Orphan & Hidden Process Analysis:**
   - Compares active process list (`pslist`) against unlinked kernel structures (`psscan`). Discrepancies indicate DKOM (Direct Kernel Object Manipulation) rootkit techniques.
3. **Unbacked Executable Code Detection (`malfind` integration):**
   - Scans Virtual Address Descriptors (VADs) for pages marked with `PAGE_EXECUTE_READWRITE` (`RWX`) that lack backing disk files. High-probability indicator for process injection, shellcode, or reflective DLL loading.
4. **Suspicious Parent-Child Relationships:**
   - Flags abnormal execution chains (e.g., `cmd.exe` or `powershell.exe` spawned directly by `winword.exe`, `excel.exe`, or `lsass.exe`).
5. **Network Anomaly Cross-Correlation:**
   - Maps open network connections (`netscan`) directly to initiating process IDs, highlighting un-signed or untrusted binaries making outbound connections over non-standard ports.

---

## 7. Python Implementation Strategy & Architecture Stack

### 7.1 Framework & Library Selection
- **UI Framework:** `PyQt6` or `PySide6` using dynamic `QAbstractTableModel` for handling high-volume tabular memory data (100,000+ rows) without UI lag.
- **Volatile Memory Core:** `volatility3` installed as a Python library package, invoked programmatically via standard APIs (`volatility3.framework.contexts`, `volatility3.framework.automagic`).
- **Asynchronous Execution:** Python `asyncio` coupled with `qasync` to bridge Python async loops with the Qt Event loop.
- **Local Database / Storage:** `SQLite` with `Peewee ORM` for storing parsed analysis tables, allowing instantaneous full-text searches (`FTS5`) and filtering.
- **Pattern Matching:** `yara-python` for high-throughput signature matching over memory pages.

### 7.2 Scalable Code Directory Structure

```text
mfa_gui/
├── assets/
│   ├── icons/
│   ├── styles/
│   └── yara_rules/
│       ├── malware_index.yar
│       └── webshells.yar
├── src/
│   ├── mfa/
│   │   ├── __init__.py
│   │   ├── app.py                      # Main entry point
│   │   ├── controllers/
│   │   │   ├── case_controller.py      # Case load/save logic
│   │   │   └── scan_controller.py      # Volatility background job control
│   │   ├── engine/
│   │   │   ├── vol_bridge.py           # Direct Volatility 3 API integration
│   │   │   ├── symbol_manager.py       # PDB/ISF symbol server auto-downloader
│   │   │   └── dumper.py               # Memory payload extraction module
│   │   ├── analysis/
│   │   │   ├── anomaly_detector.py     # Heuristic threat scoring rules
│   │   │   ├── yara_engine.py          # YARA memory scanning service
│   │   │   └── mitre_mapper.py         # Mapping indicators to ATT&CK TTPs
│   │   ├── storage/
│   │   │   ├── db_models.py            # Peewee ORM database schemas
│   │   │   └── case_file.py            # .mfa SQLite archive packer
│   │   ├── reports/
│   │   │   └── pdf_builder.py          # Forensic PDF report generator
│   │   └── gui/
│   │       ├── main_window.py
│   │       ├── models/
│   │       │   └── memory_table_model.py # Fast QAbstractTableModel
│   │       ├── views/
│   │       │   ├── process_tree_view.py
│   │       │   ├── hex_viewer.py        # Embedded hex preview for dumped bytes
│   │       │   └── netscan_view.py
│   │       └── widgets/
│   │           └── timeline_widget.py
├── tests/
│   ├── test_vol_bridge.py
│   ├── test_anomaly.py
│   └── test_yara.py
├── docs/
│   └── architecture.md
├── requirements.txt
└── setup.py
```

---

## 8. Database Schema (SQLite Storage Model)

Parsed artifacts are persisted in a local SQLite file (`case_data.mfa`) to enable instant filtering without re-parsing memory dumps:

```sql
-- Case Information Metadata
CREATE TABLE cases (
    case_id TEXT PRIMARY KEY,
    case_name TEXT NOT NULL,
    investigator TEXT NOT NULL,
    image_path TEXT NOT NULL,
    os_detected TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Process Artifacts (pslist / psscan / pstree)
CREATE TABLE processes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    pid INTEGER NOT NULL,
    ppid INTEGER NOT NULL,
    name TEXT NOT NULL,
    path TEXT,
    command_line TEXT,
    create_time TEXT,
    exit_time TEXT,
    is_hidden BOOLEAN DEFAULT 0,
    is_masqueraded BOOLEAN DEFAULT 0,
    risk_score INTEGER DEFAULT 0,
    FOREIGN KEY(case_id) REFERENCES cases(case_id)
);

-- Memory Allocations (malfind / vadinfo)
CREATE TABLE memory_vad (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    pid INTEGER,
    start_address TEXT,
    end_address TEXT,
    protection TEXT,
    is_rwx BOOLEAN DEFAULT 0,
    has_injection BOOLEAN DEFAULT 0,
    yara_hits TEXT,
    FOREIGN KEY(case_id) REFERENCES cases(case_id)
);

-- Network Connections (netscan)
CREATE TABLE network_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT,
    pid INTEGER,
    protocol TEXT,
    local_address TEXT,
    local_port INTEGER,
    foreign_address TEXT,
    foreign_port INTEGER,
    state TEXT,
    FOREIGN KEY(case_id) REFERENCES cases(case_id)
);
```

---

## 9. Resilience, Symbol Handling & Error Management

1. **Symbol Download Failures:**
   - Memory forensic parsing fails if required kernel PDB/ISF files are unavailable. MFA-GUI features an automated fallback chain: Local Cache -> Microsoft/Linux Public Symbol Server -> Heuristic Pattern Scanning. If symbols cannot be fetched, the UI alerts the user with exact missing GUIDs and instructions for offline ingestion.
2. **Corrupted Memory Image Handling:**
   - Incomplete crash dumps or corrupted RAM files can cause Volatility plugins to raise memory page translation exceptions (`PagedInvalidAddressException`). The engine wraps plugin execution in safe exception blocks, logging bad memory pages without aborting the broader scanning queue.
3. **Large Payload Dumping Limits:**
   - Dumping full process address spaces can exhaust disk storage. The extraction engine enforces maximum file size thresholds (configurable, default 1GB) and requires explicit confirmation for mass payload extractions.

---

## 10. Testing, Validation & Benchmarking Strategy

To ensure reliability in court and high-stakes incident response scenarios:

- **Standard Memory Benchmark Datasets:** Testing against public forensic benchmark datasets (e.g., Cridex, Stuxnet, Volatility Foundation test images, and NIST CFReDS memory images).
- **Automated Regression Suite:** PyTest test cases that verify Volatility 3 output parsing accuracy against known ground-truth process trees and network logs.
- **UI Performance Benchmarking:** Validating that rendering 50,000+ VAD entries into `QAbstractTableModel` completes in under 200 milliseconds without UI stutter.
- **Cross-Platform Compilation Audits:** Continuous Integration (CI) workflows building standalone executables via PyInstaller across Windows, macOS, and Linux runners.
