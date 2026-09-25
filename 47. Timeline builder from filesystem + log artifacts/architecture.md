# Timeline Builder & Forensic Event Correlator (TBF-GUI)
## Architecture Design Document (ADD)

**Version:** 1.0.0  
**Author:** Lead Security & Forensic Software Architect  
**Date:** September 16, 2026  
**Document ID:** ARCH-TBF-2026-09  
**Status:** Approved for Development  

---

## 1. Executive Summary & Purpose

The **Timeline Builder & Forensic Event Correlator (TBF-GUI)** is a high-performance, desktop-based digital forensics and incident response (DFIR) application designed to aggregate, parse, normalize, and correlate multi-source timeline artifacts into a unified master forensic timeline. Built to wrap and extend standard forensic timeline frameworks (such as **Plaso / log2timeline**, **mac_apt**, **Hayabusa**, and **EZ Tools**), TBF-GUI provides an intuitive graphical interface for visualizing complex attack chains across file system metadata, operating system event logs, registry hives, network telemetry, and cloud audit logs.

Forensic timeline analysis often requires processing millions of heterogeneous log lines and MACB (Modified, Accessed, Changed, Born) file system timestamps. Command-line log parsing makes cross-artifact correlation slow and difficult to visualize. TBF-GUI bridges this operational bottleneck by offering an asynchronous Python architecture leveraging high-throughput SQLite/DuckDB indexing, interactive time-series visual filtering, automated anomaly detection, and unified MITRE ATT&CK mapping.

---

## 2. System Scope & Core Requirements

### 2.1 Functional Requirements (FR)
- **FR-1: Multi-Source Artifact Ingestion & Parsing**
  - **Filesystem Timestamps (MACB):** Ingest NTFS ($MFT, $LogFile, $UsnJrnl), ext4/XFS inodes, APFS attributes, and raw Bodyfile inputs.
  - **OS Event Logs:** Parse Windows Event Logs (`.evtx`), Linux Systemd Journal / `syslog`, macOS `unified log` (`.tracev3`), and Auditd traces.
  - **System & User Artifacts:** Ingest Windows Registry hives (Amcache, Shimcache, Shellbags, UserAssist), Web Browser history (SQLite), LNK files, Prefetch (`.pf`), and Jump Lists.
  - **Application & Cloud Logs:** Ingest Web server logs (Nginx, IIS, Apache), Cloud audit trails (AWS CloudTrail, Azure Activity Logs, M365 Unified Audit Log), and EDR alert exports.
- **FR-2: Dynamic Timestamp Normalization & Time Zone Handling**
  - Convert all heterogeneous timestamp formats (Unix epoch, FileTime, Cocoa Core Data Time, ISO 8601, Systemd Microseconds) into a unified UTC baseline with nanosecond/microsecond resolution.
  - Interactive multi-timezone conversion interface allowing analysts to switch between UTC, target local time, and investigator local time dynamically.
- **FR-3: High-Performance Filtering & Search**
  - Full-Text Search (FTS) engine supporting Boolean operators, wildcards, regex, and structured column filters (e.g., `source == "EVTX" AND event_id == 4624 AND timestamp WITHIN "2026-09-15T00:00:00" TO "2026-09-15T04:00:00"`).
  - Time-Windowing / Super-Timeline Zooming: Instantly isolate activity within a user-defined timeframe (e.g., $\pm 15$ minutes around an initial alert).
- **FR-4: Automated Anomaly Detection & Threat Correlation**
  - Integrated rule engine (YARA-L / SIGMA rules) running continuously over the ingested timeline to flag suspicious sequences (e.g., privilege escalation followed by log clearing or mass file modification).
  - Detect timestamp manipulation (Time Stomping) by comparing $MFT `$STANDARD_INFORMATION` (SIA) vs `$FILE_NAME` (FNA) timestamp divergence.
- **FR-5: Interactive Timeline Visualization**
  - High-density temporal bar chart / heatmaps showing event volume spikes over time.
  - Interactive event tree linking process creation events with corresponding network connections and file access logs.
- **FR-6: Case Export & Evidence Reporting**
  - Export filtered timelines to structured (`CSV`, `Parquet`, `JSONL`, `STIX 2.1`) and human-readable executive formats (`PDF`, `Markdown`).

### 2.2 Non-Functional Requirements (NFR)
- **NFR-1: High Data Throughput & Scalability**
  - Capable of ingesting and indexing $\ge 10,000,000$ events within 5 minutes on standard analyst workstations (16GB RAM, NVMe SSD).
- **NFR-2: Non-Blocking GUI Responsiveness**
  - Background threading model ensuring the UI remains active (60 FPS rendering) during heavy database indexing or complex multi-million row queries.
- **NFR-3: Bounded RAM Footprint**
  - Utilize disk-backed columnar indexing (DuckDB / SQLite) to maintain application RAM usage $<600	ext{ MB}$ even when analyzing 100GB+ raw timeline databases.
- **NFR-4: Cross-Platform Native Abstraction**
  - Support execution across Linux (Ubuntu/Debian/SLES/Fedora), Microsoft Windows (10/11/Server 2019+), and macOS (Apple Silicon & x86_64).

---

## 3. Overall System Architecture & Layering

TBF-GUI adopts a decoupled 4-tier architecture: **Presentation Layer (GUI)**, **Controller & Dispatcher Layer**, **Engine & Parser Domain Layer**, and **Database & Indexing Storage Layer**.

```
+-----------------------------------------------------------------------+
|                       PRESENTATION LAYER (GUI)                        |
|   PyQt6 / PySide6 Desktop GUI, Timeline Histogram, Filter Bar, Views  |
+------------------------------------+----------------------------------+
                                     | Event Dispatcher / Qt Signals
                                     v
+-----------------------------------------------------------------------+
|                    APPLICATION CONTROLLER LAYER                       |
|   Task Orchestrator, Worker Thread Pool, Filter Engine, Config Sync    |
+------------------------------------+----------------------------------+
                                     | Work Queue / Async Signals
                                     v
+-----------------------------------------------------------------------+
|                    ENGINE & PARSER DOMAIN LAYER                       |
|  +--------------------+  +-------------------+  +------------------+  |
|  | Native & Plaso/    |  | Timestamp Normalizer|| SIGMA & Rule     |  |
|  | Multi-Parser Module|  | & Timezone Engine |  | Detection Engine |  |
|  +--------------------+  +-------------------+  +------------------+  |
|  +-----------------------------------------------------------------+  |
|  | Timestomp Detector, Anomaly Engine & ATT&CK Mapper              |  |
|  +-----------------------------------------------------------------+  |
+------------------------------------+----------------------------------+
                                     | Asynchronous IO / Batch Write
                                     v
+-----------------------------------------------------------------------+
|                   DATABASE & INDEXING STORAGE LAYER                   |
|  DuckDB / SQLite Embedded Engine (Columnar Storage, FTS5, Parquet)    |
+-----------------------------------------------------------------------+
```

---

## 4. Component-Level Design & Modules

### 4.1 System Components Matrix

| Component Module | Class / Package Name | Primary Responsibility | Dependencies |
| :--- | :--- | :--- | :--- |
| **GUI Framework** | `tbf.gui.app` | Manages PyQt main window, dark/light themes, tabbed views, and dockable filter widgets. | `PyQt6` / `PySide6` |
| **Timeline Plotter** | `tbf.gui.widgets.histogram` | Renders high-density event volume histograms with click-and-drag time zoom controls. | `pyqtgraph` / `qasync` |
| **Parser Orchestrator** | `tbf.engine.parsers` | Manages background ingestion drivers for `.evtx`, `$MFT`, `$UsnJrnl`, `regf`, and `.log` files. | `pyevtx`, `evtx`, `python-registry` |
| **Plaso Wrapper** | `tbf.engine.plaso_bridge` | Optional wrapper around native Plaso / `log2timeline` storage files (`.plaso`). | `plasocommands` / C-bindings |
| **Timestamp Normalizer**| `tbf.engine.timestamp` | Standardizes all timestamps into microsecond-accurate UTC ISO 8601 format. | `arrow`, `datetime` |
| **SIGMA Rule Engine** | `tbf.analysis.sigma` | Evaluates SIGMA detection rules against incoming normalized log records. | `pysigma`, `yaml` |
| **Timestomp Detector** | `tbf.analysis.timestomp` | Identifies $MFT timestamp anomalies ($SIA < $FNA divergence). | Internal heuristic logic |
| **Database Manager** | `tbf.storage.db` | Handles high-speed batch writes, SQL indexing, and FTS full-text queries. | `duckdb`, `sqlite3` |
| **Report Generator** | `tbf.reports.export` | Renders structured evidence exports (CSV, JSON, STIX 2.1) and executive PDF reports. | `reportlab`, `jinja2` |

---

## 5. Detailed Data Flow & Processing Pipeline

```
     [ Investigator Selects Data Sources (Evtx, MFT, Syslogs, Plaso DB) ]
                                |
                                v
   +----------------------------------------------------------+
   | Step 1: Parallel Parsing & Ingestion Stage               |
   | - Spawn background worker threads per artifact type       |
   | - Extract raw timestamps, event IDs, message strings     |
   +----------------------------+-----------------------------+
                                |
                                v
   +----------------------------------------------------------+
   | Step 2: Normalization & Telemetry Standardization       |
   | - Convert timestamps to microsecond UTC epoch             |
   | - Extract MACB flags (Modified, Accessed, Changed, Born) |
   | - Normalize source names, hostnames, and user accounts    |
   +----------------------------+-----------------------------+
                                |
                                v
   +----------------------------------------------------------+
   | Step 3: High-Speed Batch Database Ingestion              |
   | - Bulk insert normalized rows into DuckDB columnar tables |
   | - Build Full-Text Search (FTS) index & timestamp B-Trees  |
   +----------------------------+-----------------------------+
                                |
                                v
   +----------------------------------------------------------+
   | Step 4: Automated Analytics & Detection Pass             |
   | - Run SIGMA rules across indexed event records           |
   | - Flag timestomped files ($MFT SIA vs FNA comparison)    |
   | - Highlight high-risk event IDs (e.g. 4624, 7045, 1102)  |
   +----------------------------+-----------------------------+
                                |
                                v
   +----------------------------------------------------------+
   | Step 5: UI Rendering & Interactive Filtering            |
   | - Populate high-performance virtualized event table      |
   | - Render timeline histogram & ATT&CK heatmaps            |
   +----------------------------------------------------------+
```

---

## 6. Threat Detection & Timeline Anomaly Logic

TBF-GUI incorporates dynamic analytics engines designed to surface actionable insights from multi-gigabyte log sets:

1. **Timestomping Detection Algorithm:**
   - In NTFS $MFT analysis, anti-forensic tools often modify `$STANDARD_INFORMATION` (SIA) timestamps. However, `$FILE_NAME` (FNA) timestamps are managed strictly by the Windows kernel and are rarely altered.
   - **Rule:** If $Timestamp_{SIA}(Modified) < Timestamp_{FNA}(Created)$, flag the record as **HIGH PROBABILITY TIMESTOMP**.
2. **Log Clearing & Disruption Sequences:**
   - Detects log erasure events (e.g., Windows Event ID 1102 / 104 or Linux `rm -rf /var/log/*`) followed immediately by privilege escalation or network access.
3. **Sequential Execution Chain Correlator:**
   - Automatically links process creation (`Event ID 4688` / `Sysmon ID 1`) with subsequent network connection (`Sysmon ID 3`) and file creation (`Sysmon ID 11`) sharing the same `ProcessGUID` or `PID`.
4. **Time-Warping / Clock Skew Compensation:**
   - Allows investigators to apply delta offsets (e.g., $+02:14:30$) to specific log sources generated by systems with out-of-sync system clocks.

---

## 7. Python Implementation Strategy & Architecture Stack

### 7.1 Framework & Library Selection
- **UI Framework:** `PyQt6` / `PySide6` with custom dynamic `QAbstractTableModel` implementation using virtual pagination (fetching 500 rows at a time from DuckDB) to ensure instant scrolling over millions of records.
- **Data Engine:** **DuckDB** (Primary) and **SQLite** (Fallback). DuckDB provides vector-optimized columnar query execution, enabling analytical queries over 10M+ rows in under 100 milliseconds.
- **Asynchronous Execution:** Python `asyncio` combined with `qasync` to bridge Qt's event loop with background non-blocking IO operations.
- **Rule Engine:** `pysigma` for native parsing and processing of community SIGMA rules over log fields.

### 7.2 Scalable Code Directory Structure

```text
tbf_gui/
├── assets/
│   ├── icons/
│   ├── styles/
│   └── sigma_rules/
│       ├── execution/
│       └── defense_evasion/
├── src/
│   ├── tbf/
│   │   ├── __init__.py
│   │   ├── app.py                      # Main entry point
│   │   ├── controllers/
│   │   │   ├── timeline_controller.py  # Master query & view orchestrator
│   │   │   └── parser_controller.py    # Background parsing job queue
│   │   ├── engine/
│   │   │   ├── normalizer.py           # Field & timestamp standardization
│   │   │   ├── parsers/
│   │   │   │   ├── evtx_parser.py      # Windows EVTX native reader
│   │   │   │   ├── mft_parser.py       # NTFS $MFT timestamp parser
│   │   │   │   ├── sysmon_parser.py    # Sysmon event extractor
│   │   │   │   └── generic_csv.py      # Generic CSV/TSV log ingestor
│   │   │   └── plaso_bridge.py         # Interface to Plaso / log2timeline
│   │   ├── analysis/
│   │   │   ├── timestomp.py            # MFT timestamp divergence checker
│   │   │   ├── sigma_engine.py         # SIGMA rule evaluator
│   │   │   └── attack_mapper.py        # MITRE ATT&CK taxonomy tagger
│   │   ├── storage/
│   │   │   ├── duckdb_store.py         # DuckDB columnar store interface
│   │   │   └── fts_index.py            # Full-Text Search indexing module
│   │   ├── reports/
│   │   │   └── pdf_export.py           # Timeline PDF report builder
│   │   └── gui/
│   │       ├── main_window.py
│   │       ├── models/
│   │       │   └── timeline_table_model.py # Fast virtualized table model
│   │       ├── views/
│   │       │   ├── timeline_view.py
│   │       │   ├── histogram_view.py   # PyQtGraph histogram component
│   │       │   └── attack_view.py      # MITRE ATT&CK heatmap grid
│   │       └── widgets/
│   │           └── filter_bar.py       # Advanced SQL/FTS query builder bar
├── tests/
│   ├── test_normalizer.py
│   ├── test_duckdb.py
│   └── test_timestomp.py
├── docs/
│   └── architecture.md
├── requirements.txt
└── setup.py
```

---

## 8. Database Schema (DuckDB / Columnar Storage Model)

All ingested events are stored in a unified columnar table to maximize filter performance and compression efficiency:

```sql
-- Master Timeline Storage Table (DuckDB)
CREATE TABLE timeline_events (
    event_id UHUGEINT PRIMARY KEY,
    timestamp_utc TIMESTAMP_NS NOT NULL,  -- Microsecond/Nanosecond UTC
    macb_flags VARCHAR(4) NOT NULL,        -- e.g., 'MACB', 'M...', '..C.'
    source_type VARCHAR(32) NOT NULL,      -- e.g., 'EVTX', 'MFT', 'WEB_LOG'
    artifact_name VARCHAR(128) NOT NULL,    -- e.g., 'Security.evtx', '$MFT'
    hostname VARCHAR(64),
    username VARCHAR(64),
    event_code VARCHAR(16),                -- Event ID or Status Code
    summary TEXT NOT NULL,                 -- Short human-readable summary
    full_message TEXT,                     -- Full unformatted event body
    file_path TEXT,
    process_id INTEGER,
    process_path TEXT,
    source_ip VARCHAR(45),
    destination_ip VARCHAR(45),
    is_timestomped BOOLEAN DEFAULT FALSE,
    sigma_rule_hit VARCHAR(128),
    mitre_tactic VARCHAR(64),
    mitre_technique VARCHAR(16)
);

-- Indexing Strategy for Instant Queries
CREATE INDEX idx_timestamp ON timeline_events(timestamp_utc);
CREATE INDEX idx_source ON timeline_events(source_type);
CREATE INDEX idx_hostname ON timeline_events(hostname);
CREATE INDEX idx_timestomp ON timeline_events(is_timestomped);
```

---

## 9. Error Handling, Resilience & Edge Cases

1. **Malformed & Broken Log Records:**
   - Incomplete or corrupted log files (e.g., ungracefully closed `.evtx` files or truncated `$MFT` chunks) are handled gracefully via resilient exception wrappers. Damaged records are logged to an `ingestion_errors.log` file while processing continues for valid records.
2. **Timezone Ambiguity:**
   - Legacy text logs (e.g., older syslog or Apache logs) lacking explicit timezone offsets are flagged for investigator review. The UI prompts the user to assign a default source timezone rather than making unsafe assumptions.
3. **Out-of-Memory (OOM) Prevention:**
   - Ingestion pipelines stream records into DuckDB using chunked vector batches (100,000 records per write transaction), preventing unbounded RAM growth during multi-gigabyte log ingests.

---

## 10. Testing, Validation & Benchmarking Strategy

To guarantee admissibility and analytical accuracy in production investigations:

- **Benchmark Dataset Validation:** Qualification testing using standard forensic challenge datasets (e.g., SANS DFIR NetWars, NIST CFReDS, and Volatility benchmark logs).
- **Scale & Throughput Benchmarking:** Load testing against synthetic 10-million row event logs to ensure timeline filtering completes in under 200 milliseconds.
- **Verification of Time Integrity:** Cross-verifying normalized timestamps against known raw inputs to guarantee zero timestamp drift or offset errors across conversions.
- **CI/CD Integration:** PyTest suites verifying unit parsing, DuckDB indexing, and SIGMA rule matching accuracy across Windows, Linux, and macOS environments.
