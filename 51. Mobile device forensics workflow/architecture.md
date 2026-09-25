# Architecture: Mobile Device Forensics Workflow (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Android logical acquisition (ADB + backup) and analysis workflow for lab environments
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Mobile Device Forensics Workflow (MDFW)** is a GUI-driven desktop application for digital forensic examiners conducting **Android logical acquisition** and analysis in a lab environment. It automates the acquisition of device artifacts via ADB (Android Debug Bridge) and Android Backup mechanisms, then packages the results into a case directory with SHA-256 chain-of-custody for downstream analysis with ALEAPP or similar tools.

The tool is designed around four principles:

1. **Read-only by default** — acquisition requests artifacts via ADB without modifying device contents .
2. **Evidence integrity** — every acquired file hashed with SHA-256; acquisition metadata and chain-of-custody logged from collection onward .
3. **Logical acquisition focus** — recovers SMS, call logs, contacts, media, app data (where permitted), and device metadata — sufficient for most civil and many criminal cases .
4. **Lab-workflow oriented** — device isolation, documented state, repeatable acquisition, and court-ready reporting.

**Critical constraint:** `adb backup` is effectively dead on Android 12+ for apps targeting API 31+, except for debuggable apps . The tool must detect device/OS version and set appropriate expectations, falling back to alternative logical sources (bugreport, accessible file pulls, per-app backup where permitted).

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Case Mgmt │ │ Device    │ │ Acquisition│ │ Artifact  │ │ Report  │ │
│  │  View     │ │ Prep      │ │ Wizard    │ │ Explorer  │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Device    │ │ Acquisition│ │ Hash      │ │ Chain of  │ │ Console │ │
│  │ State Log │ │ Progress  │ │ Verify    │ │ Custody   │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots (async)
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Acquisition│ │ Pipeline   │ │ Scheduler  │ │ Event Bus / Log    │ │
│  │ Queue      │ │ Engine     │ │ (QThread   │ │ (structlog)        │ │
│  │ (priority) │ │ (staged)   │ │  Pool)     │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Acquisition Engine Layer                         │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ ADB Bridge     │ │ Backup Handler │ │ Bugreport Collector      │  │
│  │ (device comm,  │ │ (.ab parse,    │ │ (adb bugreport,          │  │
│  │  file pull)    │ │  ABE equiv.)   │ │  dumpsys, logcat)        │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Artifact Extractors: SMS/MMS, Call Logs, Contacts, Media,     │  │
│  │ App Data (accessible), Device Metadata, Package Inventory     │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Case DB    │ │ Acquired   │ │ Hash       │ │ Acquisition        │ │
│  │ (SQLite)   │ │ Files      │ │ Manifest   │ │ Metadata           │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     OS / Runtime Abstraction Layer                   │
│  ADB subprocess · USB device enumeration · File I/O · Config store   │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `CaseManagerView` | Create/open cases; analyst metadata; case ID; legal authority reference; chain-of-custody initialization . |
| `DevicePrepView` | Guided device isolation checklist: airplane mode / Faraday bag, USB debugging enablement, screen lock documentation, device photography, state recording (power state, SIM, battery, damage) . |
| `DeviceInfoView` | Display detected device: make, model, serial, IMEI, Android version, API level, build fingerprint, screen lock status, root status. |
| `AcquisitionWizard` | Multi-step: (1) select acquisition type, (2) select artifact categories, (3) configure output, (4) review and execute. |
| `AcquisitionProgressView` | Real-time progress per artifact type; files acquired; bytes; ETA; errors; device disconnection detection. |
| `ArtifactExplorerView` | Browse acquired files in a tree/table; preview SQLite databases, text files, images; search across acquired content. |
| `HashVerificationView` | Display SHA-256 per acquired file; verify manifest; flag mismatches. |
| `ChainOfCustodyView` | Chronological log of all custody events: device receipt, acquisition start/end, hash computation, transfer, storage . |
| `ReportBuilderView` | Export acquisition report (HTML/PDF/JSON/CSV) with device metadata, artifact inventory, hash manifest, and custody log. |
| `ConsoleView` | Live ADB command log; debug output; error details. |

**Key UI Patterns**
- Model/View with `QAbstractTableModel` for artifact listings.
- Worker threads for ADB operations — never block the UI on device I/O.
- Streaming progress: acquisition emits per-file events; UI updates progress incrementally.
- Device disconnection detection: monitor ADB connection; prompt reconnection.

### 3.2 Orchestration Layer

**Acquisition Queue**
- Sequential execution per device (ADB is stateful per connection).
- Job = `(job_id, acquisition_type, artifact_categories, output_dir, case_id)`.
- Persisted to SQLite `acquisitions` table for crash recovery.

**Pipeline Engine (staged)**
```
[ADB Connect] → [Device Info] → [Artifact Selection] → [Acquisition]
       → [Hash Computation] → [Manifest Write] → [Custody Log]
```
- Stages connected by bounded queues.
- Acquisition is device-serialized; hashing can run in parallel post-acquisition.

**Scheduler**
- ADB operations serialized per device.
- Hash computation parallelized across acquired files.
- Report generation parallelized where possible.

### 3.3 ADB Bridge Layer

**Device connection**
- Enumerate devices via `adb devices -l`.
- Handle authorization prompt (device must show "Allow USB debugging" — user must accept).
- Detect unauthorized/offline states; guide user to resolve.

**Command execution wrapper**
- All commands executed via `subprocess` with timeout and output capture.
- Read-only command allowlist (no `adb shell rm`, `adb install`, etc.).
- Command log for audit.

**Core ADB operations**

| Operation | Command | Purpose |
|---|---|---|
| Device list | `adb devices -l` | Enumerate connected devices |
| Device props | `adb shell getprop` | OS version, build, model, etc. |
| Package list | `adb shell pm list packages -f` | Installed app inventory |
| File pull | `adb pull <remote> <local>` | Extract accessible files |
| Backup | `adb backup -f <out.ab> -apk -shared -all` | Full logical backup (legacy) |
| Per-app backup | `adb backup -f <out.ab> <package>` | App-specific backup |
| Bugreport | `adb bugreport <out.zip>` | System diagnostics  |
| Shell command | `adb shell <cmd>` | Targeted queries (read-only) |

**Android 12+ handling**
- Detect `ro.build.version.sdk` ≥ 31.
- `adb backup` will exclude app data for apps targeting API 31+ (unless debuggable) .
- Fall back to: (1) bugreport collection, (2) accessible file pulls via `adb pull` where permissions allow, (3) per-app backup attempts with per-app success/failure reporting.
- Display clear warning: logical acquisition on Android 12+ has reduced scope .

### 3.4 Backup Handler Layer

**Android Backup (.ab) format**
- Header: `ANDROID BACKUP\n`, version (1–5), compression flag, encryption algorithm, salts, IV, master key blob .
- Encrypted backups: AES-256-CBC with PBKDF2 (10,000 rounds, 256-bit key) .
- Passphrase required for encrypted backups.

**Parsing implementation**
- Pure-Python parser (no Java dependency).
- Support versions 1–5.
- Detect encryption; prompt for passphrase if encrypted.
- Decompress (zlib) if compressed.
- Extract TAR payload.

**Output**
- Extract `.ab` to a directory tree mirroring the backup structure (per-app directories).
- Alternatively, convert to TAR for downstream tooling (ALEAPP, Autopsy) .
- Compute SHA-256 of extracted files.

**Limitations handling**
- Empty backups (app opted out of backup, or Android 12+ restriction) → flag in report.
- Truncated backups → attempt partial extraction; flag.
- Unknown version → error with clear message.

### 3.5 Bugreport Collector

**Bugreport generation**
- `adb bugreport <output_dir>` — captures device state, system services (dumpsys), error logs (dumpstate), system messages (logcat) .
- Output: ZIP file with `bugreport-BUILD_ID-DATE.txt`, `version.txt`, optionally `systrace.txt` and FS/ folder .

**Bugreport parsing**
- Extract ZIP.
- Parse `bugreport-*.txt` for:
  - Device properties (`ro.build.*`)
  - Running processes (`dumpsys activity`, `dumpsys package`)
  - Battery stats
  - Network state
  - Storage usage
- Index for searchable access.

**Value in forensic context**
- Device state at acquisition time.
- Running apps/processes (potential evidence of activity).
- System logs (potential evidence of events).
- Non-intrusive: bugreport does not modify device state .

### 3.6 Artifact Extractors

Each extractor targets a specific artifact category, using ADB commands and file pulls where permissions allow.

| Extractor | Source | Method | Notes |
|---|---|---|---|
| **SMS/MMS** | `/data/data/com.android.providers.telephony/databases/mmssms.db` | `adb pull` (rooted only) OR backup | Non-rooted: often inaccessible |
| **Call Logs** | Same database | Same | Same |
| **Contacts** | `/data/data/com.android.providers.contacts/databases/contacts2.db` | Same | Same |
| **Media** | `/sdcard/DCIM/`, `/sdcard/Pictures/`, etc. | `adb pull` | Accessible without root |
| **App Data** | `/data/data/<package>/` | Backup OR pull (rooted) | Android 12+ restrictions apply |
| **Device Metadata** | `getprop`, `dumpsys` | `adb shell` | Always accessible |
| **Package Inventory** | `pm list packages -f` | `adb shell` | Always accessible |
| **Wi-Fi History** | `/data/misc/wifi/WifiConfigStore.xml` | `adb pull` (rooted) | Non-rooted: bugreport may contain |
| **Browser History** | Browser-specific paths | `adb pull` (rooted) | Rooted only |
| **Downloads** | `/sdcard/Download/` | `adb pull` | Accessible without root |

**Non-rooted vs rooted**
- The tool detects root status (`adb shell su -c id` or `adb root`).
- Non-rooted: limited to `/sdcard` and world-readable files.
- Rooted: access to `/data/data`, `/data/misc`, and full filesystem .

**Android 12+ limitations**
- `adb backup` app data exclusion .
- Alternative: targeted `adb pull` of accessible paths, bugreport for system state.
- Document clearly in acquisition report.

### 3.7 Hash & Integrity Layer

**Hashing**
- SHA-256 computed for every acquired file.
- Per-file hashes stored in `manifest.csv` with file path, size, hash, timestamp.
- Optional device-side hash verification where root available (hash file on device, compare to local).

**Manifest**
- `manifest.csv`: `relative_path,size_bytes,sha256,mtime,source`
- `manifest.json`: machine-readable version with acquisition metadata.
- Signed with case HMAC for tamper detection.

**Verification**
- Re-hash acquired files; compare to manifest.
- Flag mismatches (potential corruption or tampering).
- Verification report included in case directory.

### 3.8 Chain of Custody Layer

**Custody events**
- Device receipt (who, when, from whom, condition).
- Device isolation (airplane mode, Faraday bag) .
- Device state documentation (photographs, power state, SIM, battery) .
- Acquisition start/end (timestamps, tool version, analyst).
- Hash computation (algorithms, results).
- Transfer to storage (location, handler).
- Access events (who accessed case data, when, why).

**Log format**
- Append-only log with HMAC hash chain.
- Each entry: `timestamp, actor, action, detail_json, prev_hash, entry_hash`.
- Exportable for court presentation .

**Compliance**
- Supports ISO/IEC 27037 principles: auditability, repeatability, reproducibility, justifiability .

### 3.9 Storage Layer

**Case Directory Layout**
```
cases/<case_id>/
├── case.db                      # SQLite: case metadata, custody log
├── manifest.json                # Case metadata + device info
├── custody/
│   └── custody.jsonl            # Append-only custody log
├── device_state/
│   ├── photographs/             # Device photos (user-provided)
│   └── state_record.json        # Documented device state
├── acquisition/
│   ├── raw/                     # Raw .ab files, bugreports, pulled files
│   ├── extracted/               # Extracted backup contents
│   │   ├── apps/                # Per-app data from backup
│   │   ├── shared/              # Shared storage from backup
│   │   └── system/              # System data (if available)
│   ├── bugreport/               # Parsed bugreport
│   └── metadata/                # Device info, package list
├── manifest/
│   ├── manifest.csv             # Per-file SHA-256
│   └── manifest.json            # Machine-readable
├── verification/
│   └── verification_report.json # Hash verification results
├── analysis_ready/
│   └── aleapp_input/            # Extracted tree ready for ALEAPP
├── reports/
│   ├── acquisition_report.html
│   ├── acquisition_report.pdf
│   ├── acquisition_report.json
│   └── custody_log.pdf
└── logs/
    └── session.log
```

**SQLite Schema (abridged)**
```sql
CREATE TABLE cases (
  id TEXT PRIMARY KEY, name TEXT, analyst TEXT,
  legal_authority TEXT, created_at TIMESTAMP
);
CREATE TABLE devices (
  id TEXT PRIMARY KEY, case_id TEXT,
  make TEXT, model TEXT, serial TEXT, imei TEXT,
  android_version TEXT, api_level INTEGER,
  build_fingerprint TEXT, screen_lock TEXT,
  root_status TEXT, acquisition_ts TIMESTAMP,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE acquisitions (
  id TEXT PRIMARY KEY, case_id TEXT, device_id TEXT,
  acquisition_type TEXT, status TEXT,
  started_at TIMESTAMP, finished_at TIMESTAMP,
  artifact_count INTEGER, total_bytes INTEGER,
  error TEXT, FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE artifacts (
  id INTEGER PRIMARY KEY, case_id TEXT, acquisition_id TEXT,
  category TEXT, source_path TEXT,
  local_path TEXT, size_bytes INTEGER,
  sha256 TEXT, mtime TIMESTAMP,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE INDEX idx_artifacts_cat ON artifacts(category);
CREATE INDEX idx_artifacts_hash ON artifacts(sha256);
CREATE TABLE custody (
  id INTEGER PRIMARY KEY, case_id TEXT,
  ts TIMESTAMP, actor TEXT, action TEXT,
  detail_json TEXT, prev_hash TEXT, entry_hash TEXT
);
```

### 3.10 Canonical Data Model

```python
@dataclass
class DeviceInfo:
    device_id: str
    case_id: str
    make: str
    model: str
    serial: str
    imei: str | None
    android_version: str
    api_level: int
    build_fingerprint: str
    screen_lock: str          # 'none', 'pin', 'pattern', 'password', 'biometric', 'unknown'
    root_status: str          # 'rooted', 'non_rooted', 'unknown'
    acquisition_ts: datetime

@dataclass
class AcquiredArtifact:
    artifact_id: str
    case_id: str
    acquisition_id: str
    category: str             # 'sms', 'call_logs', 'contacts', 'media', 'app_data', 'metadata', ...
    source_path: str          # device path or backup path
    local_path: str           # case directory path
    size_bytes: int
    sha256: str
    mtime: datetime | None

@dataclass
class AcquisitionResult:
    acquisition_id: str
    case_id: str
    device_id: str
    acquisition_type: str     # 'full_backup', 'per_app_backup', 'file_pull', 'bugreport', 'hybrid'
    status: str               # 'success', 'partial', 'failed'
    artifacts: list[AcquiredArtifact]
    warnings: list[str]       # e.g., "Android 12+ app data excluded"
    started_at: datetime
    finished_at: datetime
```

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, model updates
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Acquisition Worker (single thread per device)
  ├── ADB connect
  ├── Device info query
  ├── Artifact acquisition (sequential)
  └── Emits per-file progress events

Hash Pool (QThreadPool, N workers)
  └── SHA-256 computation per acquired file

Writer Thread (serial)
  └── SQLite WAL writes + manifest updates
```

**Rules**
- ADB operations serialized per device (stateful connection).
- File pulls can be parallelized cautiously (ADB supports multiple connections, but device I/O may bottleneck).
- Hashing parallelized across files.
- Cancellation: cooperative `threading.Event`; graceful abort with partial results saved.
- Device disconnection: detect via ADB exit codes; pause and prompt reconnection.

---

## 5. Workflow: End-to-End User Journey

1. **Create Case** → case ID, analyst name, legal authority reference, case description.
2. **Device Prep** → guided checklist: airplane mode/Faraday bag, USB debugging enable, screen lock documentation, device photography, state recording .
3. **Connect Device** → USB connect; ADB authorization; device info displayed.
4. **Select Acquisition** → choose artifact categories based on case needs and device constraints (rooted vs non-rooted, Android version).
5. **Acquire** → pipeline runs; per-artifact progress; device state monitoring; errors surfaced.
6. **Hash & Manifest** → SHA-256 computed per file; manifest written.
7. **Verify** → re-hash and compare; verification report.
8. **Package for Analysis** → create ALEAPP-ready input tree .
9. **Report** → acquisition report (HTML/PDF/JSON) with device metadata, artifact inventory, hash manifest, custody log, and limitations.
10. **Archive** → case directory ready for storage or analysis handoff.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| Device modification | Read-only ADB commands only; no install, no shell write commands; allowlist enforced. |
| Evidence tampering | SHA-256 per file; HMAC-signed manifest; append-only custody log with hash chain. |
| Unauthorized access | Case directories can be encrypted at rest (optional). |
| Malicious device (USB attacks) | ADB is over USB; device is evidence, not trusted; no host filesystem exposure. |
| Data leakage | Sensitive data (SMS, contacts) stored in case dir; access logged. |
| ADB binary supply-chain | Bundle ADB from official Android SDK Platform Tools; verify hash. |
| Passphrase handling (encrypted .ab) | In-memory only; never written to disk unencrypted; zeroed after use. |
| Android 12+ limitations | Clearly documented; no false promises of app data recovery. |
| Rooted device risks | Root access is user's choice; tool documents root status; no rooting performed by tool. |

---

## 7. Extensibility Points

1. **New artifact extractor** — implement `ArtifactExtractor` ABC; register in `extractors/registry.py`.
2. **New acquisition method** — implement `AcquisitionMethod` ABC (e.g., `adb pull`, backup, bugreport).
3. **New analysis integration** — implement `AnalysisIntegration` ABC (ALEAPP, Autopsy, custom).
4. **New report exporter** — `Exporter` ABC; HTML/PDF/JSON/CSV shipped.
5. **Custom custody event** — hook into custody logger.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time (cold) | < 3 s |
| UI responsiveness | < 100 ms for any user action |
| ADB connection detection | < 5 s |
| Backup extraction throughput | ≥ 50 MB/s |
| Hash computation | ≥ 500 MB/s |
| Memory footprint | < 1 GB RSS |
| Device size support | Up to 512 GB shared storage |
| Case size support | Up to 100 GB acquired data |
| Crash recovery | Resume acquisition from last completed artifact within 10 s |
| Localization | i18n-ready (Qt Linguist `.ts`) |
| Accessibility | Keyboard-navigable, screen-reader labels |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Rich ecosystem, cross-platform |
| GUI | PySide6 (LGPL) | Commercial-friendly; mature Model/View |
| ADB | Subprocess wrapper around official ADB | No Python ADB library as mature as ADB itself |
| Backup parsing | Custom pure-Python `.ab` parser | Avoid Java dependency  |
| Bugreport parsing | `zipfile` + `xml.etree` | stdlib |
| Hashing | `hashlib` (SHA-256) | stdlib |
| DB | SQLite (WAL) | Embedded, ACID, resumable |
| Serialization | JSON Lines + MessagePack | Streaming + compact |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller + Briefcase | Cross-platform binaries |
| Testing | pytest + pytest-qt + Hypothesis | Unit, GUI, property-based |
| CI | GitHub Actions | Matrix: Win/Linux/macOS × py3.10–3.12 |

---

## 10. Directory Structure (Source Tree)

```
mdfw/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── mdfw/
│       ├── __init__.py
│       ├── main.py
│       ├── app/
│       │   ├── config.py
│       │   ├── paths.py
│       │   └── event_bus.py
│       ├── ui/
│       │   ├── main_window.py
│       │   ├── views/
│       │   │   ├── case_manager.py
│       │   │   ├── device_prep.py
│       │   │   ├── device_info.py
│       │   │   ├── acquisition_wizard.py
│       │   │   ├── acquisition_progress.py
│       │   │   ├── artifact_explorer.py
│       │   │   ├── hash_verification.py
│       │   │   ├── chain_of_custody.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── artifacts_table_model.py
│       │   │   └── custody_table_model.py
│       │   └── widgets/
│       │       ├── sqlite_viewer.py
│       │       ├── preview_pane.py
│       │       └── progress_badge.py
│       ├── core/
│       │   ├── adb/
│       │   │   ├── bridge.py
│       │   │   ├── device.py
│       │   │   ├── commands.py
│       │   │   └── allowlist.py
│       │   ├── backup/
│       │   │   ├── ab_parser.py
│       │   │   ├── decrypt.py
│       │   │   ├── extract.py
│       │   │   └── tar_utils.py
│       │   ├── bugreport/
│       │   │   ├── collector.py
│       │   │   └── parser.py
│       │   ├── extractors/
│       │   │   ├── base.py
│       │   │   ├── registry.py
│       │   │   ├── sms.py
│       │   │   ├── call_logs.py
│       │   │   ├── contacts.py
│       │   │   ├── media.py
│       │   │   ├── app_data.py
│       │   │   ├── metadata.py
│       │   │   ├── packages.py
│       │   │   └── wifi.py
│       │   ├── pipeline/
│       │   │   ├── stages.py
│       │   │   ├── queue.py
│       │   │   └── scheduler.py
│       │   └── hashing/
│       │       └── manifest.py
│       ├── storage/
│       │   ├── case_db.py
│       │   ├── artifact_store.py
│       │   ├── custody.py
│       │   └── migrations/
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── html_exporter.py
│       │   │   ├── pdf_exporter.py
│       │   │   ├── json_exporter.py
│       │   │   └── csv_exporter.py
│       │   └── templates/
│       ├── security/
│       │   ├── custody.py
│       │   ├── manifest_sign.py
│       │   └── redaction.py
│       └── utils/
│           ├── hashing.py
│           ├── units.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   │   ├── ab_samples/
│   │   ├── bugreport_samples/
│   │   └── device_info/
│   └── gui/
├── resources/
│   ├── icons/
│   ├── checklists/
│   │   ├── device_prep.yaml
│   │   └── custody_template.yaml
│   └── themes/
└── docs/
    ├── architecture.md
    ├── ab_format_notes.md
    ├── custody_guide.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, case mgmt, ADB bridge, device info display | 2 weeks |
| **P1 — ADB Acquisition** | File pulls, package list, device metadata; manifest generation | 3 weeks |
| **P2 — Backup Parsing** | `.ab` parser, decryption, TAR extraction, per-app split | 3 weeks |
| **P3 — Bugreport** | Collection, ZIP parsing, dumpsys/logcat indexing | 2 weeks |
| **P4 — Artifact Extractors** | SMS, call logs, contacts, media, app data (where accessible) | 3 weeks |
| **P5 — Hash & Manifest** | SHA-256 per file, manifest CSV/JSON, HMAC signing | 2 weeks |
| **P6 — Chain of Custody** | Append-only custody log with hash chain, export | 2 weeks |
| **P7 — Device Prep Workflow** | Guided checklist, state recording, photography | 2 weeks |
| **P8 — Reporting** | HTML/PDF/JSON acquisition report, limitations documentation | 3 weeks |
| **P9 — Analysis Integration** | ALEAPP-ready output tree; optional Autopsy handoff | 2 weeks |
| **P10 — Hardening** | ADB allowlist enforcement, timeout handling, disconnection recovery | 3 weeks |
| **P11 — Polish** | Performance, i18n, docs, accessibility | 3 weeks |

**Total:** ~30 weeks (single senior dev) / ~15 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: `.ab` header parsing, TAR extraction, SHA-256 computation, custody log hash chain, ADB command allowlist.
- **Integration**: run against Android emulator (rooted AOSP image) with known test data; validate acquisition and manifest .
- **GUI**: `pytest-qt` for wizard flows, progress updates, artifact explorer.
- **Property-based**: Hypothesis for `.ab` parsing edge cases, timestamp conversions.
- **Security**: fuzz `.ab` parser (header, salts, encrypted blobs) with Atheris; malformed backup files.
- **Recovery correctness**: golden-device tests — create device state, acquire, verify hashes and artifact counts.
- **Cross-validation**: compare extracted SMS/call logs against device UI or ADB direct queries.

---

## 13. Open Questions / Decisions Pending

1. **ADB bundling** — Bundle official ADB or require user to install? Recommend: bundle from official SDK Platform Tools, verify hash on first run.
2. **Android 12+ strategy** — Accept reduced scope and document? Recommend: yes; add explicit warning in wizard when API ≥ 31 detected.
3. **Rooted device support** — Full filesystem access is powerful but requires user rooting device. Recommend: support rooted devices, document risks, never root automatically.
4. **iOS support** — Out of scope v1; design `AcquisitionMethod` so `libimobiledevice` can be added.
5. **Cloud backup extraction** — Out of scope (requires credentials and Google API). Document as manual alternative.
6. **ALEAPP integration** — Ship as optional dependency or external tool? Recommend: external; provide output tree compatible with ALEAPP .
7. **License** — ADB (Apache 2.0); ABE-equivalent parsing is clean-room; verify redistribution.

---

## 14. Glossary

- **ADB** — Android Debug Bridge; command-line tool for device communication.
- **.ab** — Android Backup file format produced by `adb backup`.
- **ALEAPP** — Android Logs Events And Protobuf Parser; open-source analysis tool .
- **Bugreport** — Android system diagnostic snapshot (dumpsys + dumpstate + logcat) .
- **Logical acquisition** — Software-mediated extraction of accessible artifacts via device APIs .
- **Physical acquisition** — Bit-for-bit image of storage; requires exploit or root .
- **Chain of custody** — Audit trail proving evidence integrity from collection onward .
- **Faraday bag** — RF-shielding bag to prevent device communication .
- **PBKDF2** — Password-Based Key Derivation Function 2 (used in encrypted .ab) .
- **SHA-256** — Cryptographic hash for integrity verification.
- **USB debugging** — Android developer option enabling ADB access.
- **Root** — Superuser access to Android filesystem; required for `/data/data` access .

---

*End of document.*