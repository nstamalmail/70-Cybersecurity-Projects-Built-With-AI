# Architecture: Deleted File Recovery Tool — FAT/NTFS Carving (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Metadata-aware recovery + signature carving on FAT12/16/32, exFAT, and NTFS volumes
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **FAT/NTFS Deleted File Recovery Tool (FN-DFRT)** is a GUI-driven desktop application focused exclusively on the two most common Windows-consumer filesystems: **FAT (12/16/32 + exFAT)** and **NTFS**. It combines three recovery techniques into a single, guided workflow:

1. **Metadata-aware recovery** — parse FAT directory entries (0xE5 deleted markers) and NTFS MFT records ($MFT, $Bitmap, $LogFile, $UsnJrnl) to reconstruct deleted files with names, timestamps, and extent lists.
2. **Signature-based carving** — scan raw clusters/sectors for known file headers/footers when metadata is destroyed, using FAT/NTFS cluster-size hints to improve fragment reassembly.
3. **Hybrid reconstruction** — use partially intact metadata (NTFS `$MFT` remnants, FAT LFN residues, `$UsnJrnl` filename records) to *name* carved artifacts and improve confidence scoring.

The tool is designed around four principles:

1. **Read-only by default** — source volumes opened with `O_RDONLY`; write-blocker advisory enforced.
2. **Evidence integrity** — hashing, audit trail, and chain-of-custody baked into every operation.
3. **Non-destructive output** — recovered files land in a case directory, never on the source volume.
4. **Windows-first focus** — every design decision optimizes for FAT/NTFS realities (cluster slack, MFT zone, `$Bitmap` reuse, LFN salvage, USN journal).

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Case Mgmt │ │ Volume /  │ │ Scan      │ │ Recovered │ │ Report  │ │
│  │  View     │ │ Image     │ │ Config    │ │ Files     │ │ Builder │ │
│  │           │ │ Selector  │ │ Wizard    │ │ Browser   │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots (async)
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Scan Queue │ │ Pipeline   │ │ Scheduler  │ │ Event Bus / Log    │ │
│  │ (priority) │ │ Engine     │ │ (QThread   │ │ (structlog)        │ │
│  │            │ │ (staged)   │ │  Pool)     │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                  FAT/NTFS Analysis & Recovery Layer                  │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ FAT Parser     │ │ NTFS Parser    │ │ Carver Registry          │  │
│  │ (12/16/32/     │ │ ($MFT, $Bitmap,│ │ (headers, footers,       │  │
│  │  exFAT)        │ │  $LogFile,     │ │  validators)             │  │
│  │                │ │  $UsnJrnl)     │ │                          │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Recovery Strategy Engine (scoring, fragment stitching, LFN)   │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Case DB    │ │ Recovered  │ │ Scan Cache │ │ Cluster Index      │ │
│  │ (SQLite)   │ │ Files      │ │ (mmap)     │ │ (FAT chains, MFT)  │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     OS / Runtime Abstraction Layer                   │
│  Volume I/O (raw read) · Write-blocker detect · Config store         │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `CaseManagerView` | Create/open cases; analyst metadata; chain-of-custody log; case directory selection. |
| `VolumeSelectorView` | Enumerate volumes (`\\.\C:`, `\\.\PhysicalDrive1`, `/dev/sdX1`) and images (`.dd`, `.img`, `.E01`, `.vhd`, `.vmdk`). Auto-probe FAT/NTFS boot sector. Show volume label, FS type, cluster size, total clusters, dirty flag. |
| `ScanConfigWizard` | Multi-step: (1) filesystem (auto/FAT/NTFS), (2) mode (metadata / carve / hybrid), (3) file-type filters, (4) date & size filters, (5) output options. |
| `ScanProgressView` | Live: MFT records processed, clusters scanned, carve hits, MB/s, ETA. Pause/resume/stop. Bad-sector map. |
| `RecoveredFilesView` | Table + tree: name (recovered or synthetic), original path (if known), size, type, recoverability score, MFT/FAT origin, cluster range, preview thumbnail. |
| `CarveResultsView` | Carved artifacts without metadata; grouped by signature; dedup by hash; name-rescue candidates. |
| `UsnJournalView` | Timeline view of `$UsnJrnl:$J` records — filename renames, deletes, and reasons (great for identifying *what was deleted* and *when*). |
| `MftInspectorView` | Raw MFT record inspector: hex view of `$MFT` entry, attribute headers, resident/non-resident, filename attributes (both `$FILE_NAME` and DOS 8.3). |
| `ReportBuilderView` | Export HTML/PDF/JSON/CSV; manifest with SHA-256 of every recovered file. |
| `ConsoleView` | Live log tail; raw scan events; debug toggle. |

**Key UI Patterns**
- Model/View with `QAbstractTableModel` — virtualization required (MFT can hold millions of records; carve hits can exceed 1M).
- Worker threads via `QThreadPool` + `QRunnable`; UI never blocks.
- Streaming results: parser/carver emit hits incrementally; UI batches appends (200 rows/tick).
- Preview rendering in a dedicated thread pool to avoid blocking the results table.
- Right-click pivots: "Recover with metadata", "Recover as raw carve", "Locate in MFT", "Search USN for this name".

### 3.2 Orchestration Layer

**Scan Queue**
- Priority queue (`queue.PriorityQueue`) with worker pool.
- Job = `(job_id, fs_type, mode, region, filters, case_id)`.
- Persisted to SQLite `scans` table for crash recovery — a 6-hour MFT walk must survive a reboot.

**Pipeline Engine (staged)**
```
[Volume Reader] → [Boot Sector Parse] → [FS Parser OR Carver]
       → [Dedup + Hash] → [Name Rescue ($UsnJrnl / LFN)] → [Scorer]
       → [Writer] → [Indexer]
```
- Stages connected by bounded queues (back-pressure aware).
- Each stage independently testable and replaceable.

**Scheduler**
- Parallelism: `min(4, cpu_count-1)` for CPU-bound stages; volume I/O serialized.
- MFT walk is inherently sequential (record chain), but **record parsing** can be parallelized across workers reading a shared mmap buffer.
- Carve parallelism: split volume into aligned chunks (e.g., 256 MB); carve chunks in parallel; merge results.
- FAT cluster chain following is sequential per file but parallel across files.

### 3.3 FAT Parser Layer

**Boot Sector Parsing**
- BPB (BIOS Parameter Block): bytes-per-sector, sectors-per-cluster, reserved sectors, FAT count, root entry count, total sectors, FAT size.
- Determine FAT12 vs FAT16 vs FAT32 by cluster count thresholds (per Microsoft spec).
- exFAT: separate boot sector layout (VBR), cluster heap offset, FAT offset/length, root directory cluster.

**FAT12/16/32 Recovery**
- Parse the FAT table(s) — primary + mirror for cross-check.
- Parse root directory (fixed region for FAT12/16; cluster chain for FAT32).
- Parse subdirectories recursively.
- Detect deleted entries: first byte `0xE5` in short name.
- Recover Long File Name (LFN) entries (attribute `0x0F`) — even if the short entry is deleted, LFN entries may remain if the delete only touched the short entry.
- Cluster chain reconstruction:
  - If FAT entry for first cluster is `0` (free) → file is fully unrecoverable via metadata; fall back to carving.
  - If FAT entry chain is partially intact → recover the contiguous prefix, then carve for the rest.
  - If FAT entry is `0x0FFFFFF7` (bad cluster) → mark as partial.
- exFAT: directory entry sets (file + stream extension + name entries); detect deleted by `InUse` flag = 0.

**Directory Entry Details Captured**
- Short name (8.3), LFN (UTF-16), attributes (read-only, hidden, system, volume, directory, archive), creation/modified/accessed dates (FAT timestamps are coarse — 2-second granularity), first cluster (high + low), file size (32-bit).

### 3.4 NTFS Parser Layer

**Boot Sector Parsing**
- `$Boot` OEM ID, bytes-per-sector, sectors-per-cluster, MFT cluster number, MFT mirror cluster, clusters-per-MFT-record (typically 1 KB or 4 KB).

**MFT Parsing**
- Locate `$MFT` via boot sector; read record `0` to confirm.
- Stream MFT records in chunks (e.g., 10k records per chunk) using mmap.
- Per record:
  - Parse `FILE` signature, USA (Update Sequence Array) fixups.
  - Parse attribute list: `$STANDARD_INFORMATION`, `$FILE_NAME`, `$DATA`, `$ATTRIBUTE_LIST`, `$BITMAP`, `$INDEX_ROOT`, `$INDEX_ALLOCATION`.
  - Handle resident vs non-resident attributes.
  - Handle attribute lists spanning multiple MFT records (very large/fragmented files).
- Detect deleted records: `InUse` flag = 0 in `$MFT` header.
- Recover filename(s) from `$FILE_NAME` (both Win32 and DOS namespaces).
- Recover timestamps from `$STANDARD_INFORMATION` and `$FILE_NAME` (four timestamps each: created, modified, MFT-modified, accessed).

**Data Run (Extent) Reconstruction**
- Non-resident `$DATA` stores run lists (offset/length pairs, VCN → LCN).
- Even if `InUse=0`, run lists often survive intact → direct file reassembly.
- Detect sparse runs (VCN gap without LCN) — write zeros.
- Detect compressed/encrypted (`$DATA` flags) — decompress on read; decrypt only if keys provided (BitLocker out of scope; EFS requires certs).

**`$Bitmap` Analysis**
- Parse `$Bitmap` (cluster allocation bitmap) to determine which clusters belonging to a deleted file are now **reallocated** → overwrite detection.
- Score each cluster: `free` (good), `allocated to another file` (bad → likely overwritten).

**`$LogFile` (Journal) Replay — read-only**
- Parse `$LogFile` records for recently deleted metadata operations.
- Reconstruct pre-delete MFT state for files deleted within the journal window (typically minutes to hours of activity).
- Strictly **read-only** replay — we never modify the source; we build an in-memory "previous state" view.

**`$UsnJrnl:$J` (USN Change Journal)**
- Parse sparse USN records; each record contains `USN`, `FileReferenceNumber` (MFT entry + sequence), `ParentFileReferenceNumber`, `Reason` (flags: `FILE_DELETE`, `DATA_OVERWRITE`, `RENAME_NEW_NAME`, etc.), and `FileName` (UTF-16).
- **This is the single most valuable source of deleted filenames on NTFS** — even after MFT record reuse.
- Build a timeline: filename ↔ MFT entry ↔ parent directory ↔ event reason.
- Use USN to *name* carved files: match carve candidates to USN records by size/timestamp heuristics.

**`$I30` Index Reconstruction (advanced)**
- Directory indexes (`$INDEX_ROOT` + `$INDEX_ALLOCATION`) sometimes retain deleted entries as slack in B-tree nodes.
- Parse index entries from slack space → recover deleted filenames + MFT references not present in `$MFT` anymore.

### 3.5 Carver Layer

**Signature Registry**
- Signatures defined declaratively in `signatures/*.yaml`:
  ```yaml
  name: jpeg
  category: image
  header: "FF D8 FF"
  footer: "FF D9"
  max_size: 104857600
  cluster_align_hint: true
  validator: jpeg.valid
  extensions: [".jpg", ".jpeg"]
  ```
- Header-only, header+footer, and header+length-prefix carvers supported.
- Validators (Python) run post-carve to reduce false positives (JPEG entropy check, ZIP central directory, PDF `%%EOF` scan, MP4 `moov` atom presence).

**Carving Strategies (FAT/NTFS-aware)**

1. **Linear cluster carve** — walk clusters in order; on header hit, stream until footer or cluster boundary.
2. **Block-wise carve (FAT)** — use FAT free-cluster bitmap to prioritize clusters marked free → faster & higher confidence.
3. **Cluster-chain carve (FAT)** — if FAT chain is partially intact, follow it; else use next-fit cluster matching.
4. **Run-list carve (NTFS)** — if `$MFT` record exists (even deleted) with an intact run list, read directly via extents — no carving needed.
5. **Slack space scan** — scan cluster slack (bytes beyond EOF within last cluster) and MFT record slack for embedded small files, thumbnails, alternate data streams.
6. **Fragmented-aware (hybrid)** — use NTFS `$Bitmap` + FAT allocation hints to stitch fragments by "next free cluster" heuristic, then validate via type-specific validator.

**Deduplication**
- Rolling SHA-256 while streaming; skip writing duplicates.
- Content-defined chunking (FastCDC) for partial-file dedup across carving runs.

### 3.6 Recovery Strategy Engine

Combines signals into a **recoverability score (0.0–1.0)**:

| Signal | Weight |
|---|---|
| Metadata intact (MFT record InUse=0 but attributes intact; FAT dir entry present) | 0.30 |
| Run list / FAT chain complete | 0.20 |
| Clusters marked free in `$Bitmap` / FAT | 0.20 |
| Content signature matches expected type | 0.15 |
| Timestamps consistent (MTIME ≥ CTIME, etc.) | 0.10 |
| Name rescued via `$UsnJrnl` or LFN residue | 0.05 |

Score ≥ 0.8 → **Excellent**, 0.5–0.8 → **Good**, 0.3–0.5 → **Partial**, < 0.3 → **Poor**.

**Overwrite detection**
- NTFS: compare each run-list LCN against `$Bitmap` — any allocated LCN → likely overwritten.
- FAT: compare cluster chain against FAT table — any non-free chain entry → likely overwritten.
- Partial-overwrite handling: recover the unallocated prefix; quarantine the rest.
- **TRIM/SSD caveat**: on TRIM-enabled SSDs, freed clusters may be zeroed by the drive controller — tool detects all-zero regions and warns upfront.

**Name Rescue**
- Priority order: `$UsnJrnl` → `$FILE_NAME` attribute → LFN residue in FAT → `$I30` index slack → synthetic name (`carved_<sig>_<offset>.<ext>`).
- Attach all discovered names as tags (`alt_name_1`, `alt_name_2`).

### 3.7 Storage Layer

**Case Directory Layout**
```
cases/<case_id>/
├── case.db                      # SQLite: cases, scans, entries, custody
├── manifest.json                # Case metadata
├── source_ref.txt               # Path + hash of source (never copied)
├── recovered/
│   ├── by_path/                 # Reconstructed directory tree (FAT/NTFS)
│   ├── by_mft/                  # Named from MFT record ID
│   └── carved/                  # Signature-only recoveries
├── quarantine/                  # Low-confidence recoveries
├── previews/                    # Thumbnails, posters
├── cache/
│   ├── mft_index/               # mmap-friendly MFT record index
│   ├── fat_index/               # FAT chain snapshots per chunk
│   └── dedup/                   # FastCDC fingerprints
├── reports/
│   ├── report.html
│   ├── report.pdf
│   ├── manifest.csv
│   ├── usn_timeline.csv
│   └── custody.json
└── logs/
    └── session.log
```

**SQLite Schema (abridged)**
```sql
CREATE TABLE cases (
  id TEXT PRIMARY KEY, name TEXT, analyst TEXT,
  source_path TEXT, source_sha256 TEXT, source_size INTEGER,
  device_serial TEXT, write_blocker_verified INTEGER,
  fs_type TEXT, cluster_size INTEGER, created_at TIMESTAMP
);
CREATE TABLE scans (
  id TEXT PRIMARY KEY, case_id TEXT, mode TEXT, fs_type TEXT,
  region_start INTEGER, region_end INTEGER,
  status TEXT, started_at TIMESTAMP, finished_at TIMESTAMP,
  mft_records INTEGER, clusters_scanned INTEGER, bytes_written INTEGER,
  error TEXT, FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE entries (
  id INTEGER PRIMARY KEY, case_id TEXT, scan_id TEXT,
  origin TEXT,              -- 'mft' | 'fat' | 'usn' | 'carve' | 'slack'
  path TEXT, name TEXT, alt_names_json TEXT, ext TEXT,
  size INTEGER, mtime TIMESTAMP, ctime TIMESTAMP, atime TIMESTAMP,
  deleted_at TIMESTAMP,
  mft_id INTEGER, mft_seq INTEGER, parent_mft_id INTEGER,
  fat_dir_entry_offset INTEGER, cluster_start INTEGER, cluster_count INTEGER,
  runlist_json TEXT,        -- NTFS extents
  fat_chain_json TEXT,      -- FAT cluster chain
  sha256 TEXT, md5 TEXT,
  confidence REAL, recoverability TEXT,
  output_path TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE INDEX idx_entries_type ON entries(ext);
CREATE INDEX idx_entries_conf ON entries(confidence);
CREATE INDEX idx_entries_mft ON entries(mft_id);
CREATE TABLE usn_events (
  id INTEGER PRIMARY KEY, case_id TEXT,
  usn INTEGER, mft_id INTEGER, mft_seq INTEGER,
  parent_mft_id INTEGER, reason TEXT, name TEXT, ts TIMESTAMP
);
CREATE TABLE custody (
  id INTEGER PRIMARY KEY, case_id TEXT,
  ts TIMESTAMP, actor TEXT, action TEXT, detail_json TEXT
);
```

**Cache Strategy**
- MFT index keyed by `(source_sha256, mft_offset)` — allows resuming MFT walks.
- FAT chain snapshots per chunk for re-analysis.
- Dedup fingerprints persisted so re-running a carve doesn't rewrite existing files.
- LRU eviction on previews only.

---

## 4. Canonical Data Model

```python
@dataclass
class DeletedEntry:
    entry_id: str              # ULID
    case_id: str
    origin: Literal["mft", "fat", "usn", "carve", "slack"]
    fs_type: Literal["fat12", "fat16", "fat32", "exfat", "ntfs"]

    # Naming
    path: str | None
    name: str | None
    alt_names: list[str]
    ext: str | None

    # Sizing & timing
    size_bytes: int | None
    mtime: datetime | None
    ctime: datetime | None
    atime: datetime | None
    mft_mtime: datetime | None      # NTFS $STANDARD_INFORMATION
    deleted_at: datetime | None

    # NTFS-specific
    mft_id: int | None
    mft_seq: int | None
    parent_mft_id: int | None
    runlist: list[tuple[int, int]] | None   # (LCN, length)

    # FAT-specific
    fat_dir_entry_offset: int | None
    fat_chain: list[int] | None
    first_cluster: int | None

    # Content
    resident_data: bytes | None     # small resident NTFS / FAT
    sha256: str | None
    md5: str | None

    # Scoring
    confidence: float
    recoverability: Literal["excellent", "good", "partial", "poor"]
    tags: list[str]                 # ["overwritten-partial","fragmented","usn-named"]

    preview_path: str | None
```

All recovered items flow through this model regardless of source, so the UI, filters, and reporters are parser-agnostic.

---

## 5. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, model updates
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Scan Pool (QThreadPool, N workers)
  ├── Volume reader thread          (sequential device I/O)
  ├── MFT record parser threads     (parallel over mmap'd chunks)
  ├── FAT chain follower thread     (sequential per directory tree)
  ├── Carver threads                (parallel over chunks)
  ├── Hasher + dedup thread         (sequential, CPU-bound)
  ├── Name rescue thread            (USN/LFN correlation)
  └── Writer thread                 (sequential, disk-bound)
       │
       └── Bounded queues between stages (back-pressure)
```

**Rules**
- Volume reader is **single-threaded per volume** — HDD/SSD seek behavior; avoids I/O thrash.
- MFT walk: sequential fetch of chunks, parallel parse (mmap allows lock-free reads).
- Carvers operate on in-memory chunk buffers (e.g., 64 MB) for cache locality.
- SQLite in WAL mode; single writer, many readers.
- Cancellation: cooperative `threading.Event` checked every N records/clusters; graceful flush on stop.
- Pause = stop feeding reader + drain queues; resume = restart reader from last committed offset.

---

## 6. Workflow: End-to-End User Journey

1. **Create Case** → name, analyst, evidence source; app records source path + SHA-256 (streamed; skippable for enormous drives with a warning).
2. **Select Volume** → physical volume, partition, or image. Write-blocker advisory dialog; if source is mounted RW, warn and require "read-only confirmed" checkbox.
3. **Auto-Detect** → boot-sector parse → FS type (FAT12/16/32/exFAT/NTFS), cluster size, volume label, dirty flag, TRIM/SSD hint.
4. **Configure Scan** → mode (metadata / carve / hybrid), file-type filters, date range, min size, output dir.
5. **Execute** → pipeline runs; hits appear in results as they are found. USN journal parsed in parallel for name rescue.
6. **Triage** → filter by type/date/size/confidence; preview; tag; bulk-select. Inspect MFT records; inspect USN timeline.
7. **Recover** → write selected files to `recovered/`; hash each; append to manifest. Preserve original directory tree where known.
8. **Report** → HTML/PDF/JSON/CSV; custody log; verification instructions; USN timeline export.
9. **Archive** → zip case dir; sign with case HMAC.

---

## 7. Security Considerations

| Concern | Mitigation |
|---|---|
| Writing to source volume | Enforce `O_RDONLY`; refuse to proceed if source is mounted RW unless `--force` and audit-logged. |
| Malicious NTFS/FAT metadata (parser exploit) | Parsers run in subprocess with resource limits; fuzz-tested; no `eval`; cyclic run-list detection; recursion depth caps on directory walk. |
| Malicious recovered content (malware) | Recovered files written with `.recovered` extension by default; never auto-executed; previews rendered in sandbox. |
| Path traversal from recovered filenames | Sanitize filenames; reject `..`, `/`, `\`, NUL; mangle reserved names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`); strip trailing dots/spaces (Windows). |
| MFT/USN record spoofing (adversarial) | Cross-validate timestamps, sequence numbers, and run lists; flag inconsistent entries. |
| Evidence tampering | Append-only HMAC hash chain on `custody` table; manifest signed. |
| Sensitive data leakage | Redaction profile: skip known PII patterns on export unless explicitly enabled. |
| Large volume DoS | Configurable scan caps; memory-bounded queues; streaming everywhere; MFT zone skipping option. |
| Symbolic link / reparse point attacks in output | Never follow symlinks when writing recovered tree; NTFS reparse points in recovered files are stripped. |
| EFS/BitLocker encrypted files | Detect and skip; warn user; never attempt to bypass. |

---

## 8. Extensibility Points

1. **New carver signature** — YAML in `~/.fn-dfrt/signatures/`; optional Python validator.
2. **New previewer** — register by MIME/extension.
3. **New exporter** — `Exporter` ABC; HTML/PDF/JSON/CSV shipped.
4. **Custom recovery scorer** — override default weights via plugin.
5. **New FS parser** — implement `FilesystemParser`; drop in `src/fs/`; auto-registered (for future exFAT variants, ReFS, etc.).
6. **Custom name-rescue heuristics** — plugin hooks after USN/LFN stages.

---

## 9. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time (cold) | < 2 s |
| UI responsiveness | < 100 ms for any user action |
| MFT walk throughput | ≥ 20k records/s on SSD |
| Linear carve throughput | ≥ 500 MB/s (I/O bound) |
| FS-aware recovery throughput | ≥ 200 MB/s |
| Memory footprint | < 1.5 GB RSS regardless of volume size |
| Volume size support | Up to 20 TB (64-bit offsets) |
| MFT record support | Up to 500M records (indexed on disk) |
| Concurrency | Up to 8 carve workers (configurable) |
| Crash recovery | Resume any scan from last committed chunk within 5 s |
| Localization | i18n-ready (Qt Linguist `.ts`) |
| Accessibility | Keyboard-navigable, screen-reader labels |

---

## 10. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Rich ecosystem (pytsk3, dfVFS, pyewf) |
| GUI | PySide6 (LGPL) | Commercial-friendly; mature Model/View |
| FS parsing | Custom FAT/NTFS parsers + `pytsk3`/`dfVFS` cross-check | Defense in depth |
| Image formats | `pyewf` (E01), `libvmdk`, `libvhdi` | Open-source, battle-tested |
| DB | SQLite (WAL) | Embedded, ACID, resumable |
| Serialization | JSON Lines + MessagePack | Streaming + compact |
| Hashing | `hashlib` (SHA-256), `blake3` (fast dedup) | Speed + standard |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller + Briefcase | Cross-platform binaries |
| Testing | pytest + pytest-qt + Hypothesis | Unit, GUI, property-based |
| Fuzzing | Atheris / AFL++ | Parser hardening |
| CI | GitHub Actions | Matrix: Win/Linux/macOS × py3.10–3.12 |

---

## 11. Directory Structure (Source Tree)

```
fn-dfrt/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── fn_dfrt/
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
│       │   │   ├── volume_selector.py
│       │   │   ├── scan_wizard.py
│       │   │   ├── scan_progress.py
│       │   │   ├── recovered_files.py
│       │   │   ├── carve_results.py
│       │   │   ├── usn_journal.py
│       │   │   ├── mft_inspector.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── entries_table_model.py
│       │   │   ├── usn_table_model.py
│       │   │   └── tree_model.py
│       │   └── widgets/
│       │       ├── preview_pane.py
│       │       ├── hex_viewer.py
│       │       └── progress_badge.py
│       ├── core/
│       │   ├── io/
│       │   │   ├── volume_reader.py
│       │   │   ├── image_readers/
│       │   │   │   ├── dd_reader.py
│       │   │   │   ├── e01_reader.py
│       │   │   │   ├── vhd_reader.py
│       │   │   │   └── vmdk_reader.py
│       │   │   └── sector_reader.py
│       │   ├── partition/
│       │   │   ├── mbr.py
│       │   │   └── gpt.py
│       │   ├── fs/
│       │   │   ├── base.py
│       │   │   ├── probe.py            # FS auto-detection
│       │   │   ├── fat/
│       │   │   │   ├── boot.py
│       │   │   │   ├── fat_table.py
│       │   │   │   ├── directory.py
│       │   │   │   ├── lfn.py
│       │   │   │   ├── exfat.py
│       │   │   │   └── parser.py
│       │   │   └── ntfs/
│       │   │       ├── boot.py
│       │   │       ├── mft.py
│       │   │       ├── attributes.py
│       │   │       ├── rundata.py      # run-list decode
│       │   │       ├── bitmap.py       # $Bitmap analysis
│       │   │       ├── logfile.py      # $LogFile replay
│       │   │       ├── usn.py          # $UsnJrnl:$J
│       │   │       ├── index.py        # $I30 slack
│       │   │       └── parser.py
│       │   ├── carver/
│       │   │   ├── registry.py
│       │   │   ├── linear.py
│       │   │   ├── blockwise.py
│       │   │   ├── cluster_chain.py
│       │   │   ├── runlist.py
│       │   │   ├── slack.py
│       │   │   ├── fragmented.py
│       │   │   └── validators/
│       │   ├── recovery/
│       │   │   ├── scorer.py
│       │   │   ├── overwrite_detect.py
│       │   │   ├── name_rescue.py
│       │   │   └── strategy.py
│       │   ├── pipeline/
│       │   │   ├── stages.py
│       │   │   ├── queue.py
│       │   │   └── scheduler.py
│       │   └── dedup/
│       │       ├── fastcdc.py
│       │       └── hash_index.py
│       ├── storage/
│       │   ├── case_db.py
│       │   ├── entry_store.py
│       │   ├── cache.py
│       │   └── migrations/
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── html_exporter.py
│       │   │   ├── pdf_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   └── json_exporter.py
│       │   └── templates/
│       ├── security/
│       │   ├── write_blocker.py
│       │   ├── filename_sanitizer.py
│       │   ├── sandbox.py
│       │   └── custody.py
│       └── utils/
│           ├── hashing.py
│           ├── units.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   │   ├── small_images/          # public FAT/NTFS sample images
│   │   └── signature_corpus/
│   └── gui/
├── resources/
│   ├── icons/
│   ├── signatures/
│   │   ├── image.yaml
│   │   ├── document.yaml
│   │   ├── archive.yaml
│   │   ├── media.yaml
│   │   └── office.yaml
│   └── themes/
└── docs/
    ├── architecture.md
    ├── fat_ntfs_notes.md
    └── user_guide.md
```

---

## 12. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, case mgmt, volume reader (dd/E01), FS auto-probe, results table | 2 weeks |
| **P1 — FAT** | FAT12/16/32 boot + FAT table + directory + LFN parsing; deleted entry recovery; cluster chain reconstruction | 4 weeks |
| **P2 — NTFS MFT** | `$MFT` parsing, attribute list, `$DATA` run lists, resident/non-resident, deleted record detection | 5 weeks |
| **P3 — Carvers** | Linear + block-wise + cluster-chain + run-list carvers; 60+ signatures; validators; slack scan | 5 weeks |
| **P4 — USN + LFN Name Rescue** | `$UsnJrnl:$J` parser, timeline view, name-rescue pipeline | 3 weeks |
| **P5 — `$Bitmap` + `$LogFile` + `$I30`** | Overwrite detection, journal replay (read-only), index slack recovery | 4 weeks |
| **P6 — Pipeline + Resume** | Staged pipeline, back-pressure, crash-resume, chunked parallelism | 3 weeks |
| **P7 — Dedup + Scoring** | FastCDC dedup, overwrite detection integration, recoverability scoring, quarantine | 2 weeks |
| **P8 — Reporting + Custody** | HTML/PDF/JSON/CSV exporters, manifest hashing, HMAC custody chain, USN timeline export | 3 weeks |
| **P9 — exFAT** | exFAT boot sector, directory entry sets, allocation bitmap, name entries | 2 weeks |
| **P10 — Hardening** | Parser fuzzing, sandboxing, write-blocker enforcement, TRIM detection, packaging | 4 weeks |
| **P11 — Polish** | Performance tuning, i18n, docs, accessibility | 3 weeks |

**Total:** ~40 weeks (single senior dev) / ~20 weeks (2 devs).

---

## 13. Testing Strategy

- **Unit**: FAT boot-sector math, NTFS run-list decode, USA fixup, LFN assembly, USN record parse, `$Bitmap` lookup, filename sanitizer.
- **Integration**: run against public forensic images (Digital Corpora, NIST CFReDS, dfImage samples) with known deleted-file ground truth; validate recovered SHA-256.
- **GUI**: `pytest-qt` for wizard flows, table filtering, preview loading, MFT inspector.
- **Property-based**: Hypothesis for cluster/offset arithmetic, run-list boundaries, and carving boundary conditions.
- **Performance**: benchmark on 1 TB synthetic NTFS image; regression CI if MFT walk throughput drops > 15%.
- **Security**: fuzz every parser (FAT boot, FAT dir, NTFS MFT, USN, `$LogFile`, `$Bitmap`) with AFL++ / Atheris; malformed MFT, cyclic run lists, huge directories, USA-fixup abuse.
- **Recovery correctness**: golden-image tests — create FS, write N files, delete, image volume, recover, assert SHA-256 match; include fragmented and resident cases.
- **Cross-validation**: compare custom parser results vs `pytsk3`/`dfVFS` on the same images; flag divergences.

---

## 14. Open Questions / Decisions Pending

1. **`$LogFile` replay complexity** — full NTFS journal replay is a large project. Recommend: v1 supports *read-only record scanning* to find recent deletes; full replay deferred to v2.
2. **`$I30` index slack parsing** — high value but tricky across NTFS versions. Recommend: v1 best-effort with confidence flag.
3. **BitLocker / EFS** — detect and skip; do not attempt bypass. Document clearly.
4. **pytsk3 dependency** — GPL-adjacent (Sleepycat/BSD-ish actually); verify commercial redistribution. Custom parsers are primary anyway.
5. **TRIM-enabled SSDs** — detect via `$Bitmap` all-zero clusters + ATA IDENTIFY if available; warn upfront that recovery is often impossible.
6. **Very large MFT (>500M records)** — index on disk (SQLite) rather than in memory; stream.
7. **Cloud/remote imaging** — out of scope v1; design readers so a `RemoteSectorReader` can be added.
8. **License** — pyewf/libewf is LGPL; verify redistribution for commercial build.

---

## 15. Glossary

- **BPB** — BIOS Parameter Block (FAT boot sector fields).
- **MFT** — Master File Table (NTFS metadata for every file).
- **MFT record** — one 1 KB (or 4 KB) entry in `$MFT`.
- **Run list** — NTFS non-resident attribute extent list (VCN → LCN).
- **LCN / VCN** — Logical / Virtual Cluster Number.
- **USA** — Update Sequence Array (NTFS multi-sector write fixup).
- **USN Journal** — `$UsnJrnl:$J`, NTFS change journal recording file events.
- **`$Bitmap`** — NTFS cluster allocation bitmap.
- **`$LogFile`** — NTFS metadata transaction log.
- **LFN** — Long File Name (FAT VFAT extension).
- **Slack space** — unused bytes at end of last cluster or MFT record.
- **Carving** — recovering files by scanning raw bytes for headers/footers.
- **FastCDC** — Fast Content-Defined Chunking, a dedup algorithm.
- **E01** — EnCase forensic image format.
- **Write blocker** — hardware/software preventing writes to evidence media.
- **Chain of custody** — audit trail proving evidence integrity.
- **TRIM** — SSD command that zeroes freed blocks, defeating recovery.

---

*End of document.*