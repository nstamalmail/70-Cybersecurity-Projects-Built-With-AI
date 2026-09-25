# Architecture: Browser Artifact Extractor — History, Cookies, Cache Parser (GUI-Based Solution)

**Document Version:** 1.0
**Author:** Senior Security Developer
**Target Platform:** Cross-platform Desktop (Windows, Linux, macOS)
**Core Capability:** Forensic extraction and analysis of browser artifacts from Chromium-family, Firefox-family, and Safari
**GUI Stack:** Python 3.10+ / PySide6 (Qt6)
**Status:** Design Specification

---

## 1. Executive Summary

The **Browser Artifact Extractor (BAE)** is a GUI-driven desktop application for digital forensics and incident response (DFIR) analysts who need to reconstruct a user's browsing activity from on-disk browser data. It parses SQLite databases, LevelDB stores, cache backends, and JSON/plist configuration files across the major browser families:

- **Chromium-family**: Chrome, Edge, Brave, Opera, Vivaldi, Chromium, Electron apps (Slack, Discord, Teams)
- **Firefox-family**: Firefox, Tor Browser, Waterfox, LibreWolf, Pale Moon
- **Safari / WebKit**: Safari (macOS/iOS backups), WebKitGTK

Extracted artifacts include:
- **History** (URL visits, typed URLs, downloads, redirects, visit durations)
- **Cookies** (name/value/domain/path/expiry, plus encrypted values on Windows/macOS)
- **Cache** (HTTP cache entries: URL, headers, body size, timestamps, content preview)
- **Local Storage / IndexedDB / Session Storage**
- **Autofill / Form history / Saved passwords (encrypted)**
- **Bookmarks, Favicons, Top Sites**
- **Extensions / Add-ons metadata**
- **Downloads, File-selection dialogs**
- **Sessions / Tabs / Recently closed**
- **Favicons, thumbnails, page previews**
- **Network prediction / Prefetch / DNS cache**

The tool is designed around four principles:

1. **Read-only by default** — source profile copied or opened read-only; SQLite opened in immutable mode; LevelDB snapshotted to memory.
2. **Evidence integrity** — every artifact hashed and every extraction step logged with chain-of-custody.
3. **Time-zone aware** — Chromium stores timestamps in microseconds since 1601 (WebKit epoch) and Firefox uses Unix microseconds; the tool normalizes everything to UTC and displays in analyst-selected TZ.
4. **Analyst-first UI** — timeline, per-profile pivoting, cross-browser correlation, and export to CSV/JSON/HTML/STIX.

---

## 2. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Presentation Layer (Qt6)                      │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Case Mgmt │ │ Profile   │ │ Extraction│ │ Artifact  │ │ Report  │ │
│  │  View     │ │ Discovery │ │ Wizard    │ │ Browser   │ │ Builder │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌───────────┐ ┌─────────┐ │
│  │ Timeline  │ │ Cookie    │ │ Cache     │ │ Search /  │ │ Console │ │
│  │  View     │ │ Inspector │ │ Explorer  │ │ Filter    │ │         │ │
│  └───────────┘ └───────────┘ └───────────┘ └───────────┘ └─────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ Qt Signals / Slots (async)
┌───────────────────────────────▼──────────────────────────────────────┐
│                    Application / Orchestration Layer                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Extract    │ │ Pipeline   │ │ Scheduler  │ │ Event Bus / Log    │ │
│  │ Queue      │ │ Engine     │ │ (QThread   │ │ (structlog)        │ │
│  │ (priority) │ │ (staged)   │ │  Pool)     │ │                    │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     Browser Parser Layer (per-family)                │
│  ┌────────────────┐ ┌────────────────┐ ┌──────────────────────────┐  │
│  │ Chromium       │ │ Firefox        │ │ Safari / WebKit          │  │
│  │ Parser Suite   │ │ Parser Suite   │ │ Parser Suite             │  │
│  │ (SQLite,       │ │ (SQLite,       │ │ (SQLite, plist,          │  │
│  │  LevelDB, SNSS)│ │  mozLz4, JSON) │ │  binary plist, cache.db) │  │
│  └────────────────┘ └────────────────┘ └──────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Crypto Layer: DPAPI, Keychain, Keyring, OSCrypt, NSS, PBKDF2 │  │
│  └────────────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ Cache Backend Parsers: Simple Cache, Blockfile, Cache2,       │  │
│  │  IndexedDB (LevelDB+snappy), Service Worker Cache            │  │
│  └────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                       Storage / Persistence Layer                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────────────┐ │
│  │ Case DB    │ │ Artifact   │ │ Snapshot   │ │ Decrypted Secret   │ │
│  │ (SQLite)   │ │ Store      │ │ Cache      │ │ Vault (encrypted)  │ │
│  └────────────┘ └────────────┘ └────────────┘ └────────────────────┘ │
└───────────────────────────────┬──────────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────────┐
│                     OS / Runtime Abstraction Layer                   │
│  File I/O (read-only) · Keychain/DPAPI access · TZ / locale handling │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer (PySide6 / Qt6)

| Widget | Responsibility |
|---|---|
| `CaseManagerView` | Create/open cases; analyst metadata; chain-of-custody log; case directory selection. |
| `ProfileDiscoveryView` | Auto-scan a host, mounted image, or folder for browser profiles. Show browser, profile name, OS user, path, last-modified. Support manual add of a single profile folder. |
| `ExtractionWizard` | Multi-step: (1) select profiles, (2) select artifact categories, (3) date range, (4) decryption options (DPAPI/Keychain/OSCrypt key entry), (5) output options. |
| `ExtractionProgressView` | Per-profile, per-artifact progress bars; rows extracted; errors; elapsed time. |
| `ArtifactBrowserView` | Master table: timestamp, browser, profile, artifact type, URL/host, title, value (truncated), tags. Virtualized for millions of rows. |
| `TimelineView` | Unified chronological view across all artifact types and browsers; zoomable; "swim lanes" per profile. |
| `CookieInspector` | Cookie table + detail pane (name, value, domain, path, expiry, secure, httpOnly, SameSite, encrypted flag, decrypted value with audit note). |
| `CacheExplorer` | HTTP cache entries with URL, method, status, request/response headers, body size, content preview (rendered HTML, image, JSON). |
| `LocalStorageView` | Per-origin LevelDB key/value browser; IndexedDB object store browser with snappy decompression. |
| `SessionTabsView` | Reconstruct open tabs / recently closed tabs from session files (`Current Session`, `Last Session`, `Sessions/`). |
| `CredentialView` | Saved logins (decrypted on demand), autofill entries, form history. Sensitive fields masked by default. |
| `SearchFilterBar` | Full-text search across all extracted text fields; regex support; saved filters; tag-based filters. |
| `ReportBuilderView` | Export HTML/PDF/JSON/CSV/STIX 2.1; per-artifact-type templates; hash manifest. |
| `ConsoleView` | Live log tail; raw parser events; debug toggle. |

**Key UI Patterns**
- Model/View with `QAbstractTableModel` — virtualization required.
- Worker threads via `QThreadPool` + `QRunnable`; UI never blocks.
- Streaming results: parsers emit artifacts incrementally; UI batches appends (200 rows/tick).
- Preview rendering (HTML, images, PDF) in a sandboxed `QWebEngineView` with JS disabled.
- Right-click pivots: "Show all activity for this host", "Show all cookies for this domain", "Pivot to cache body", "Search for this value across artifacts".

### 3.2 Orchestration Layer

**Extract Queue**
- Priority queue (`queue.PriorityQueue`) with worker pool.
- Job = `(job_id, profile_id, artifact_category, filters, decryption_context, case_id)`.
- Persisted to SQLite `extractions` table for crash recovery.

**Pipeline Engine (staged)**
```
[Profile Snapshot] → [DB Open (immutable)] → [Parser] → [Decrypt (opt.)]
       → [Normalize Timestamps] → [Dedup + Hash] → [Writer] → [Indexer]
```
- Stages connected by bounded queues (back-pressure aware).
- Each stage independently testable and replaceable.

**Scheduler**
- Parallelism: `min(4, cpu_count-1)` for CPU-bound stages; SQLite reads serialized per DB file (WAL or immutable mode).
- Profile snapshotting (copy-on-read) done serially per profile to avoid partial reads of live DBs.
- Cache parsing parallelized across cache shards.

### 3.3 Profile Discovery Layer

**Auto-discovery paths (default):**

| Browser | Windows | Linux | macOS |
|---|---|---|---|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\` | `~/.config/google-chrome/` | `~/Library/Application Support/Google/Chrome/` |
| Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\` | `~/.config/microsoft-edge/` | `~/Library/Application Support/Microsoft Edge/` |
| Brave | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\` | `~/.config/BraveSoftware/Brave-Browser/` | `~/Library/Application Support/BraveSoftware/Brave-Browser/` |
| Opera | `%APPDATA%\Opera Software\Opera Stable\` | `~/.config/opera/` | `~/Library/Application Support/com.operasoftware.Opera/` |
| Vivaldi | `%LOCALAPPDATA%\Vivaldi\User Data\` | `~/.config/vivaldi/` | `~/Library/Application Support/Vivaldi/` |
| Firefox | `%APPDATA%\Mozilla\Firefox\Profiles\` | `~/.mozilla/firefox/` | `~/Library/Application Support/Firefox/Profiles/` |
| Tor Browser | `...\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\` | varies | varies |
| Safari | n/a | n/a | `~/Library/Safari/` |

**Discovery sources**
- Live host scan (opt-in, read-only).
- Mounted forensic image (auto-mount or directory walk).
- Extracted user folder (e.g., from a triage collection).
- Manual path entry.

**Profile identification**
- Chromium: `Local State` (JSON) lists profiles; each profile folder has `Preferences` JSON with `profile.name`, `account_info`.
- Firefox: `profiles.ini` + `prefs.js`; profile name and default flag.
- Safari: single profile; `History.db`, `Cookies.binarycookies`, `WebKit` cache dir.

### 3.4 Parser Layer — Chromium Family

**Core SQLite DBs**

| File | Artifacts |
|---|---|
| `History` | `urls`, `visits`, `visits_source`, `downloads`, `downloads_url_chains`, `keyword_search_terms`, `segments`, `segment_usage`, `typed_urls`, `visit_source` |
| `Cookies` | `cookies` table (encrypted_value on Windows/macOS) |
| `Login Data` | `logins` (encrypted_password) |
| `Web Data` | `autofill`, `autofill_profiles`, `credit_cards` (encrypted), `token_service`, `keywords` (search engines) |
| `Favicons` | `favicons`, `favicon_bitmaps`, `icon_mapping` |
| `Top Sites` | `top_sites`, `thumbnails` |
| `Bookmarks` (JSON) | Bookmark tree with GUIDs, dates |
| `Shortcuts` | Omnibox shortcuts |
| `Network Action Predictor` | Prefetch prediction |
| `Reporting and NEL` | Network Error Logging |
| `quota_manager` / `QuotaManager` | Origin storage quotas |

**Session files (SNSS format — binary)**
- `Current Session`, `Current Tabs`, `Last Session`, `Last Tabs`, `Sessions/` directory.
- SNSS parser: command-type records (`SetTabWindow`, `SetWindowBounds`, `TabNavigation`, `SetTabIndexInWindow`, `SessionStorage`, `SetSelectedNavigationIndex`, etc.).
- Reconstruct open tabs at last session save; recover recently closed.

**LevelDB stores**

| Path | Artifacts |
|---|---|
| `Local Storage/leveldb/` | Per-origin localStorage (key = `_<origin>\x00\x01<key>`) |
| `Session Storage/` | Session-scoped storage |
| `IndexedDB/<origin>/` | IndexedDB databases (`.ldb` + `.log`), snappy-compressed values |
| `Sync Data/LevelDB/` | Sync metadata |
| `shared_proto_db/` | Storage APIs |

**Cache backends**
- **Simple Cache** (`Cache/Cache_Data/`): one file per entry with `[key_hash]_0`, `_1`, `_s` (sparse), `_index`. Metadata in `index-dir/the-real-index` (binary).
- **Blockfile Cache** (legacy, Chrome ≤ 65): `index`, `data_0..3`, `f_*` files. Parse `index` header table.
- **Code Cache** (`Code Cache/`): compiled JS/WASM bytecode (used in exploitation analysis).
- **GPUCache**, **Media Cache**, **Application Cache** (deprecated).
- **Service Worker CacheStorage** (`Service Worker/CacheStorage/`): IndexedDB-backed.
- **Back-forward Cache** (in memory only; not on disk).

**Extension metadata**
- `Extensions/<id>/<version>/manifest.json` — permissions, host permissions, content scripts.
- `Extension State/`, `Extension Rules/`, `Extension Scripts/` LevelDBs.

**Network state**
- `Network/Cookies` (newer Chrome), `TransportSecurity` (HSTS), `Network Persistent State` (JSON), DNS cache (in memory only).

**Chromium crypto**
- **Windows**: `Local State` JSON contains `os_crypt.encrypted_key` (base64). Decrypt via DPAPI (user context) to get AES-256-GCM key. `v10` prefix → AES-GCM with nonce; `v20` prefix → app-bound encryption (Chrome 127+) requiring app-bound key from `Local State` + `Google Chrome Elevation Service` context.
- **Linux**: `Local State` `os_crypt.encrypted_key` (v10) decrypted via keyring (GNOME Keyring, KWallet) OR hardcoded `peanuts` password fallback for older versions. PBKDF2-HMAC-SHA1 iterations=1, salt=`saltysalt`, key derived from password.
- **macOS**: `Local State` `os_crypt.encrypted_key` (v10) decrypted via Keychain item "Chrome Safe Storage" → PBKDF2-HMAC-SHA1 iterations=1003, salt=`saltysalt`, keylen=16.
- Passwords additionally protected by DPAPI/Keychain on top of the AES layer.

### 3.5 Parser Layer — Firefox Family

**Core SQLite DBs**

| File | Artifacts |
|---|---|
| `places.sqlite` | `moz_places` (URLs), `moz_historyvisits`, `moz_bookmarks`, `moz_annos`, `moz_items_annos`, `moz_inputhistory` (form history) |
| `cookies.sqlite` | `moz_cookies` (unencrypted by default; encrypted if `signon.rememberSignons` + primary password — rare) |
| `formhistory.sqlite` | Form field history |
| `downloads.sqlite` | Download history |
| `favicons.sqlite` | Favicon data + payloads |
| `permissions.sqlite` | Site permissions (camera, mic, geo, notifications) |
| `webappsstore.sqlite` | Legacy localStorage (pre-Firefox 57) |
| `storage/default/<origin>/` | Modern localStorage/IndexedDB (LevelDB + snappy) |
| `logins.json` | Encrypted saved logins (3DES/AES via NSS key4.db) |
| `key4.db` | NSS key database (SQLite) |
| `cert9.db` | Certificate store |
| `sessionstore-backups/*.jsonlz4` | Session tabs (mozLz4-compressed JSON) |
| `extensions.json` | Installed add-ons with IDs, versions, permissions |
| `prefs.js` | User preferences (may reveal proxy, security settings, telemetry) |
| `addonStartup.json.lz4` | Add-on startup cache |

**Cache backends**
- **Cache2** (`cache2/entries/`): one file per entry; `metadata` binary header + HTTP response body. Metadata format: version, fetch/response times, URI, headers.
- **Legacy Cache** (pre-Firefox 32): `_CACHE_001_`, `_CACHE_002_`, `_CACHE_MAP_`.

**Firefox crypto**
- NSS key4.db stores encrypted master key (3DES or AES) protected by primary password (or empty if none set).
- `logins.json` entries decrypted with master key via 3DES-CBC or AES-CBC.
- Tool supports: no-password profiles (auto-decrypt), primary-password profiles (prompt for password), and key4.db + logins.json pair import.

### 3.6 Parser Layer — Safari / WebKit

**Core files**

| File | Artifacts |
|---|---|
| `History.db` | `history_items`, `history_visits` (macOS/iOS) |
| `Cookies.binarycookies` | Binary cookie format (magic `cook`, page headers, cookie records) |
| `Downloads.plist` | Download history (binary plist) |
| `Bookmarks.plist` | Bookmarks (binary plist) |
| `WebpageIcons.db` | Favicons |
| `LastSession.plist` / `RecentlyClosedTabs.plist` | Session tabs |
| `LocalStorage/` | WebKit localStorage (SQLite `file__0.localstorage`) |
| `Databases/` | WebSQL (SQLite per origin) |
| `WebKit/WebsiteData/` | Modern cache/storage (macOS 10.15+) |
| `Cache.db` (iOS) | HTTP cache (SQLite-backed since iOS 13) |

**Safari crypto**
- Cookies on macOS: encrypted with Keychain item "Safari Safe Storage" (older) or unencrypted (newer macOS stores cookies in binary format, some fields encrypted).
- iCloud Keychain: out of scope; requires user keychain unlock.

### 3.7 Cache Backend Parsers (detail)

**Simple Cache (Chromium, modern)**
- Directory `Cache_Data/` contains entry files named by 20-char hex hash.
- Each entry: `[hash]_0` (header + body), `[hash]_1` (body continuation), `[hash]_s` (sparse data), `[hash]_index` (metadata).
- `index-dir/the-real-index` is a binary hash table mapping key → entry.
- Parser reads `_index` (format: version, key length, key, stream size, etc.) then streams body from `_0`/`_1`.

**Blockfile Cache (Chromium, legacy)**
- `index` file: header + hash table of `CacheAddr` records.
- `data_0..3` files: block data.
- `f_<hash>` files: external files (bodies > 16 KB).
- Parser walks index, resolves addresses, reads block chains.

**Firefox Cache2**
- `cache2/entries/<hash>` files.
- Format: 4-byte version, 4-byte metadata size, metadata (binary: fetch count, last fetch/modify times, URI, headers), then body.
- `cache2/index` (deprecated) or rebuild by scanning `entries/`.
- `cache2/doomed/` contains entries pending deletion — high forensic value.

**IndexedDB (LevelDB + snappy)**
- `IndexedDB/<origin>/<dbname>/` contains `CURRENT`, `MANIFEST-*`, `*.ldb`, `*.log`.
- LevelDB key schema is Chromium-specific (object store ID, index ID, key encoding).
- Values are snappy-compressed for structured clone data; wrapper format: `\x00\x01` (blob) or `\x00\x00` (structured clone).
- Parser: use `plyvel` (LevelDB) or `chromedb` helpers; decompress snappy; decode V8 serialization where possible.

### 3.8 Crypto Layer

Unified interface:

```python
class Decryptor(ABC):
    @abstractmethod
    def derive_key(self, context: DecryptContext) -> bytes: ...
    @abstractmethod
    def decrypt(self, ciphertext: bytes, prefix: str | None) -> bytes: ...
    @abstractmethod
    def supported_prefixes(self) -> set[str]: ...   # {"v10","v11","v20"}
```

**Implementations**
- `ChromiumWinDPAPIDecryptor` — DPAPI unwrap of `os_crypt.encrypted_key`, then AES-256-GCM.
- `ChromiumWinAppBoundDecryptor` — Chrome 127+ app-bound encryption (requires elevation service context or offline key extraction).
- `ChromiumLinuxKeyringDecryptor` — keyring lookup or `peanuts` fallback.
- `ChromiumMacKeychainDecryptor` — Keychain "Chrome Safe Storage" + PBKDF2.
- `FirefoxNSSDecryptor` — key4.db master key + 3DES/AES.
- `SafariKeychainDecryptor` — "Safari Safe Storage" Keychain item.

**Audit**: every decryption produces a `custody` record with timestamp, key source, and item hash — never logs plaintext.

**Key material handling**
- Decrypted keys stored in an in-memory vault; never written to disk unencrypted.
- Optional "secret vault" persistence uses a user-supplied passphrase (Argon2id) and AES-256-GCM.
- Plaintext secrets (passwords, cookie values) masked in UI by default; "reveal" requires explicit click and logs to custody.

### 3.9 Normalization Layer

**Timestamp unification**
- Chromium: microseconds since 1601-01-01 UTC (WebKit epoch) → Unix μs.
- Firefox: microseconds since 1970-01-01 UTC.
- Safari: seconds or microseconds since 2001-01-01 (Cocoa epoch) → Unix μs.
- Windows FILETIME: 100-ns intervals since 1601.
- All stored internally as `datetime` with UTC tz; displayed in analyst-selected TZ; ISO 8601 in exports.

**URL canonicalization**
- Preserve original URL; also compute canonical form (lowercased host, default port stripped, path preserved).
- Extract host, scheme, path, query params (parsed for search terms).

**Search-term extraction**
- Google/Bing/DuckDuckGo/YouTube/etc. query params (`q`, `query`, `search`, `p`).
- Chromium `keyword_search_terms` table.
- Firefox `moz_keywords` / `moz_places.url` parsing.

### 3.10 Storage Layer

**Case Directory Layout**
```
cases/<case_id>/
├── case.db                      # SQLite: cases, extractions, artifacts, custody
├── manifest.json                # Case metadata
├── source_ref.txt               # Paths + hashes of source profiles
├── snapshots/                   # Copy-on-read snapshots of live DBs (optional)
│   └── <profile_id>/
├── artifacts/
│   ├── cache_bodies/            # Extracted HTTP response bodies
│   ├── favicons/
│   ├── thumbnails/
│   └── downloads/               # Download target metadata (not the files)
├── vault/
│   └── secrets.enc              # Encrypted key vault (optional)
├── reports/
│   ├── report.html
│   ├── report.pdf
│   ├── artifacts.csv
│   ├── timeline.csv
│   ├── cookies.csv
│   ├── stix.json
│   └── custody.json
└── logs/
    └── session.log
```

**SQLite Schema (abridged)**
```sql
CREATE TABLE cases (
  id TEXT PRIMARY KEY, name TEXT, analyst TEXT,
  host_name TEXT, os_family TEXT,
  created_at TIMESTAMP
);
CREATE TABLE profiles (
  id TEXT PRIMARY KEY, case_id TEXT,
  browser TEXT,             -- 'chrome','edge','brave','firefox','safari',...
  browser_version TEXT,
  profile_name TEXT, os_user TEXT, path TEXT,
  last_modified TIMESTAMP,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE extractions (
  id TEXT PRIMARY KEY, case_id TEXT, profile_id TEXT,
  category TEXT,            -- 'history','cookies','cache','storage',...
  status TEXT, started_at TIMESTAMP, finished_at TIMESTAMP,
  artifact_count INTEGER, error TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE artifacts (
  id INTEGER PRIMARY KEY, case_id TEXT, profile_id TEXT,
  category TEXT, subtype TEXT,
  ts TIMESTAMP, ts_raw INTEGER, ts_source TEXT,
  url TEXT, host TEXT, title TEXT,
  key TEXT, value TEXT, value_blob_path TEXT,
  size INTEGER, hash_sha256 TEXT,
  encrypted INTEGER, decrypted INTEGER,
  extra_json TEXT,
  FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE INDEX idx_artifacts_ts ON artifacts(ts);
CREATE INDEX idx_artifacts_host ON artifacts(host);
CREATE INDEX idx_artifacts_cat ON artifacts(category);
CREATE INDEX idx_artifacts_profile ON artifacts(profile_id);
CREATE VIRTUAL TABLE artifacts_fts USING fts5(
  url, title, key, value, content='artifacts', content_rowid='id'
);
CREATE TABLE custody (
  id INTEGER PRIMARY KEY, case_id TEXT,
  ts TIMESTAMP, actor TEXT, action TEXT, detail_json TEXT
);
```

**Snapshot strategy**
- Live profile files are copied to `snapshots/` before parsing (SQLite `VACUUM INTO` or plain copy with retry on lock).
- LevelDB: copy the entire directory atomically (files may be mid-write; retry on `MANIFEST` mismatch).
- If source is a forensic image, parse in place read-only.

### 3.11 Canonical Data Model

```python
@dataclass
class BrowserArtifact:
    artifact_id: str              # ULID
    case_id: str
    profile_id: str
    category: ArtifactCategory    # HISTORY, COOKIE, CACHE, STORAGE, CREDENTIAL, ...
    subtype: str | None           # e.g., "visit", "download", "form_field"

    # Time
    timestamp: datetime | None
    timestamp_raw: int | None
    timestamp_source: str | None  # "webkit_us", "unix_us", "cocoa_s", "filetime"

    # Identity
    url: str | None
    host: str | None
    title: str | None
    key: str | None               # cookie name, storage key, form field name
    value: str | None             # truncated value; full in value_blob_path
    value_blob_path: str | None

    # Metadata
    size_bytes: int | None
    hash_sha256: str | None
    encrypted: bool
    decrypted: bool
    extra: dict                   # parser-specific fields
    tags: list[str]
```

All artifacts flow through this model regardless of source, so the UI, filters, and reporters are parser-agnostic.

---

## 4. Threading & Concurrency Model

```
Main Thread (Qt)
  ├── UI events, model updates
  └── EventBus.emit(signal) ──► Qt QueuedConnection ──► UI slots

Extraction Pool (QThreadPool, N workers)
  ├── Snapshot thread          (serial per profile, copy-on-read)
  ├── SQLite reader threads    (one per DB file; WAL/immutable mode)
  ├── LevelDB parser thread    (serial per DB directory)
  ├── Cache parser threads     (parallel per shard)
  ├── Decryptor thread         (serial; may prompt for user input)
  ├── Normalizer thread        (parallel)
  └── Writer thread            (serial, SQLite WAL)
       │
       └── Bounded queues between stages (back-pressure)
```

**Rules**
- Source files are never written; only read (or copied to snapshot).
- SQLite opened with `file:...?immutable=1` when no WAL present, else `mode=ro` and copied to snapshot.
- LevelDB: parse from snapshot only; original untouched.
- Cancellation: cooperative `threading.Event` checked between artifact batches.
- Decryption prompts (password, Keychain unlock) marshalled to main thread via `QMetaObject.invokeMethod`.

---

## 5. Workflow: End-to-End User Journey

1. **Create Case** → analyst name, host name, evidence source description.
2. **Discover Profiles** → scan host, mounted image, or folder. Show detected profiles with browser/version/user/last-modified. Manual add option.
3. **Select Profiles & Categories** → wizard: which profiles, which artifact categories (History, Cookies, Cache, Storage, Credentials, Extensions, Sessions), date range, decryption options.
4. **Provide Keys (if needed)** → DPAPI (Windows), Keychain (macOS), Keyring (Linux), or master password for Firefox. Skip = encrypted fields marked `encrypted`, not decrypted.
5. **Extract** → pipeline runs; live progress; artifacts appear as found; errors surfaced.
6. **Triage** → unified timeline; per-category views; full-text search; filter by host/date/category; tag; preview cache bodies.
7. **Correlate** → pivots: host → all artifacts; URL → cache body + cookie + storage; MFT-free, all in-memory join across the case DB.
8. **Export** → CSV/JSON/HTML/PDF/STIX; redaction profile applied; manifest with SHA-256 of every artifact.
9. **Archive** → zip case dir; sign with case HMAC; chain-of-custody log.

---

## 6. Security Considerations

| Concern | Mitigation |
|---|---|
| Writing to source profile | All opens read-only; snapshots to case dir; original never modified. |
| Malicious browser data (parser exploit) | Parsers run in subprocess with resource limits; fuzz-tested; no `eval`; recursion depth caps; SQLite query allowlist. |
| Malicious cache body (HTML/JS) | Preview rendered with JS disabled, no network, sandboxed; downloaded to disk never auto-opened. |
| Sensitive data leakage (passwords, cookies) | Masked by default; "reveal" requires explicit action + audit log; redaction profile on export. |
| Key vault compromise | In-memory only by default; optional on-disk vault uses Argon2id + AES-256-GCM with user passphrase. |
| DPAPI/Keychain abuse | Only used to decrypt browser keys for the current user context or provided credentials; never used for lateral movement. |
| Path traversal from artifact paths | Sanitize filenames; reject `..`, `/`, `\`, NUL; reserved-name mangling on Windows. |
| Evidence tampering | Append-only HMAC hash chain on `custody` table; manifest signed. |
| Timestamp spoofing (adversarial) | Cross-validate against multiple sources (file mtime, DB, session); flag inconsistencies. |
| Huge profiles DoS | Configurable caps; streaming; memory-bounded queues; FTS indexing optional. |
| Chrome 127+ app-bound encryption | Detect `v20` prefix; if app-bound key unavailable, mark as `encrypted-appbound`; document limitation. |

---

## 7. Extensibility Points

1. **New browser family** — implement `BrowserParser` ABC; register in `parsers/registry.py`.
2. **New artifact category** — implement `ArtifactExtractor` ABC; hook into pipeline.
3. **New cache backend** — implement `CacheBackend` ABC.
4. **New decryptor** — implement `Decryptor` ABC; register with prefix support.
5. **New exporter** — `Exporter` ABC; HTML/PDF/JSON/CSV/STIX shipped.
6. **Custom correlation rule** — Python plugin with access to case DB.
7. **Custom redaction profile** — YAML/JSON with regex rules.

---

## 8. Non-Functional Requirements

| Attribute | Target |
|---|---|
| Startup time (cold) | < 2 s |
| UI responsiveness | < 100 ms for any user action |
| History extraction throughput | ≥ 50k rows/s |
| Cache body extraction | ≥ 200 MB/s |
| Cookie extraction | ≥ 100k rows/s |
| Memory footprint | < 1.5 GB RSS regardless of profile size |
| Profile size support | Up to 50 GB per profile |
| Artifact count support | Up to 100M rows (FTS optional) |
| Concurrency | Up to 8 extraction workers (configurable) |
| Crash recovery | Resume extraction from last committed batch within 5 s |
| Localization | i18n-ready (Qt Linguist `.ts`) |
| Accessibility | Keyboard-navigable, screen-reader labels |
| Timestamp accuracy | Microsecond precision; UTC internal; TZ-aware display |

---

## 9. Technology Stack

| Layer | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Rich ecosystem (`sqlite3`, `plyvel`, `pycryptodome`, `pycryptodomex`) |
| GUI | PySide6 (LGPL) | Commercial-friendly; mature Model/View; QWebEngine for previews |
| SQLite | stdlib `sqlite3` | Zero-dep; immutable/WAL modes |
| LevelDB | `plyvel` (bundled `libleveldb`) | Fast; cross-platform |
| Snappy | `python-snappy` | IndexedDB values |
| Crypto | `pycryptodome` (AES-GCM, 3DES, PBKDF2), `argon2-cffi` | DPAPI on Windows via `ctypes`; Keychain via `pyobjc`; Keyring via `secretstorage` |
| mozLz4 | `lz4` + custom container | Firefox session files |
| Binary plist | `plistlib` (stdlib) | Safari |
| SNSS | custom parser | Chromium session files |
| Protobuf | `protobuf` (for some Chromium state files) | Sync, prefs |
| DB | SQLite (WAL + FTS5) | Embedded, ACID, FTS |
| Serialization | JSON Lines + MessagePack | Streaming + compact |
| Hashing | `hashlib` (SHA-256), `blake3` (fast dedup) | Speed + standard |
| Logging | structlog | Structured JSON |
| Packaging | PyInstaller + Briefcase | Cross-platform binaries |
| Testing | pytest + pytest-qt + Hypothesis | Unit, GUI, property-based |
| Fuzzing | Atheris / AFL++ | Parser hardening |
| CI | GitHub Actions | Matrix: Win/Linux/macOS × py3.10–3.12 |

---

## 10. Directory Structure (Source Tree)

```
bae/
├── pyproject.toml
├── README.md
├── architecture.md
├── src/
│   └── bae/
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
│       │   │   ├── profile_discovery.py
│       │   │   ├── extraction_wizard.py
│       │   │   ├── extraction_progress.py
│       │   │   ├── artifact_browser.py
│       │   │   ├── timeline.py
│       │   │   ├── cookie_inspector.py
│       │   │   ├── cache_explorer.py
│       │   │   ├── local_storage.py
│       │   │   ├── session_tabs.py
│       │   │   ├── credential_view.py
│       │   │   ├── report_builder.py
│       │   │   └── console.py
│       │   ├── models/
│       │   │   ├── artifacts_table_model.py
│       │   │   ├── timeline_model.py
│       │   │   └── profile_tree_model.py
│       │   └── widgets/
│       │       ├── preview_pane.py
│       │       ├── hex_viewer.py
│       │       ├── web_preview.py      # sandboxed QWebEngineView
│       │       └── filter_bar.py
│       ├── core/
│       │   ├── discovery/
│       │   │   ├── paths.py            # default profile paths
│       │   │   ├── scanner.py          # walk host / image / folder
│       │   │   └── profile_id.py
│       │   ├── parsers/
│       │   │   ├── base.py
│       │   │   ├── registry.py
│       │   │   ├── chromium/
│       │   │   │   ├── history.py
│       │   │   │   ├── cookies.py
│       │   │   │   ├── logins.py
│       │   │   │   ├── web_data.py
│       │   │   │   ├── favicons.py
│       │   │   │   ├── top_sites.py
│       │   │   │   ├── bookmarks.py
│       │   │   │   ├── sessions_snss.py
│       │   │   │   ├── local_storage.py
│       │   │   │   ├── indexeddb.py
│       │   │   │   ├── extensions.py
│       │   │   │   ├── network_state.py
│       │   │   │   ├── local_state.py
│       │   │   │   └── paths.py
│       │   │   ├── firefox/
│       │   │   │   ├── places.py
│       │   │   │   ├── cookies.py
│       │   │   │   ├── formhistory.py
│       │   │   │   ├── downloads.py
│       │   │   │   ├── favicons.py
│       │   │   │   ├── permissions.py
│       │   │   │   ├── storage.py
│       │   │   │   ├── logins.py
│       │   │   │   ├── sessionstore.py     # mozLz4
│       │   │   │   ├── extensions.py
│       │   │   │   ├── prefs.py
│       │   │   │   └── paths.py
│       │   │   └── safari/
│       │   │       ├── history.py
│       │   │       ├── cookies_binary.py
│       │   │       ├── downloads.py
│       │   │       ├── bookmarks.py
│       │   │       ├── favicons.py
│       │   │       ├── sessions.py
│       │   │       ├── localstorage.py
│       │   │       ├── websql.py
│       │   │       ├── cachedb.py
│       │   │       └── paths.py
│       │   ├── cache/
│       │   │   ├── base.py
│       │   │   ├── simple_cache.py     # Chromium
│       │   │   ├── blockfile_cache.py  # Chromium legacy
│       │   │   ├── firefox_cache2.py
│       │   │   ├── safari_cachedb.py
│       │   │   └── code_cache.py
│       │   ├── crypto/
│       │   │   ├── base.py
│       │   │   ├── chromium_win_dpapi.py
│       │   │   ├── chromium_win_appbound.py
│       │   │   ├── chromium_linux_keyring.py
│       │   │   ├── chromium_mac_keychain.py
│       │   │   ├── firefox_nss.py
│       │   │   ├── safari_keychain.py
│       │   │   └── vault.py
│       │   ├── normalize/
│       │   │   ├── timestamps.py
│       │   │   ├── urls.py
│       │   │   ├── search_terms.py
│       │   │   └── schema.py
│       │   ├── pipeline/
│       │   │   ├── stages.py
│       │   │   ├── queue.py
│       │   │   └── scheduler.py
│       │   └── dedup/
│       │       ├── fastcdc.py
│       │       └── hash_index.py
│       ├── storage/
│       │   ├── case_db.py
│       │   ├── artifact_store.py
│       │   ├── fts_index.py
│       │   ├── snapshot.py
│       │   ├── cache.py
│       │   └── migrations/
│       ├── reporting/
│       │   ├── exporters/
│       │   │   ├── html_exporter.py
│       │   │   ├── pdf_exporter.py
│       │   │   ├── csv_exporter.py
│       │   │   ├── json_exporter.py
│       │   │   └── stix_exporter.py
│       │   └── templates/
│       ├── security/
│       │   ├── read_only.py
│       │   ├── filename_sanitizer.py
│       │   ├── sandbox.py
│       │   ├── redaction.py
│       │   └── custody.py
│       └── utils/
│           ├── hashing.py
│           ├── units.py
│           └── logging.py
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   │   ├── chromium_profile/
│   │   ├── firefox_profile/
│   │   ├── safari_profile/
│   │   └── cache_corpus/
│   └── gui/
├── resources/
│   ├── icons/
│   ├── redaction_profiles/
│   │   ├── default.yaml
│   │   └── pii_strict.yaml
│   └── themes/
└── docs/
    ├── architecture.md
    ├── browser_notes.md
    ├── crypto_notes.md
    └── user_guide.md
```

---

## 11. Development Roadmap (Phased)

| Phase | Scope | Duration |
|---|---|---|
| **P0 — Skeleton** | Qt shell, case mgmt, profile discovery, SQLite viewer, results table | 2 weeks |
| **P1 — Chromium Core** | `History`, `Cookies` (encrypted field detection), `Bookmarks`, `Favicons`, `Top Sites` | 3 weeks |
| **P2 — Firefox Core** | `places.sqlite`, `cookies.sqlite`, `formhistory`, `downloads`, `favicons` | 3 weeks |
| **P3 — Crypto** | DPAPI, Keychain, Keyring, NSS decryptors; vault; audit logging | 4 weeks |
| **P4 — Cache Backends** | Simple Cache, Cache2, Safari Cache.db, blockfile (legacy) | 4 weeks |
| **P5 — Storage** | Chromium Local Storage + IndexedDB + Session Storage; Firefox storage; Safari localstorage | 4 weeks |
| **P6 — Sessions & Extensions** | Chromium SNSS, Firefox sessionstore (mozLz4), Safari sessions; extensions metadata | 3 weeks |
| **P7 — Safari & WebKit** | `History.db`, binarycookies, plists | 3 weeks |
| **P8 — Timeline & Correlation** | Unified timeline view, pivots, cross-browser joins | 3 weeks |
| **P9 — Reporting** | HTML/PDF/JSON/CSV/STIX exporters; redaction; hash manifest; custody chain | 3 weeks |
| **P10 — Hardening** | Parser fuzzing, sandboxing, subprocess isolation, read-only enforcement | 4 weeks |
| **P11 — Polish** | Performance (streaming, FTS tuning), i18n, docs, accessibility | 3 weeks |

**Total:** ~39 weeks (single senior dev) / ~20 weeks (2 devs).

---

## 12. Testing Strategy

- **Unit**: timestamp conversions, URL canonicalization, snappy decode, mozLz4 decode, DPAPI unwrap, NSS key derivation, binarycookies parse, SNSS command parse.
- **Integration**: run against public forensic images (Digital Corpora, NIST CFReDS, browser-specific test profiles) with known ground truth; validate counts and hashes.
- **GUI**: `pytest-qt` for wizard flows, table filtering, timeline zoom, preview rendering.
- **Property-based**: Hypothesis for timestamp round-trips, URL parsing, cookie domain matching.
- **Performance**: benchmark on 10 GB profile (History, Cache, IndexedDB); regression CI if throughput drops > 15%.
- **Security**: fuzz every parser (SQLite query builder, SNSS, Cache2, binarycookies, mozLz4, LevelDB manifest) with AFL++ / Atheris; malformed DBs, cyclic records, huge values.
- **Crypto correctness**: known-key test vectors for DPAPI, AES-GCM v10, PBKDF2 (`saltysalt`), NSS 3DES, Keychain.
- **Cross-validation**: compare against `Hindsight`, `BrowsingHistoryView`, `DB Browser for SQLite` on the same profiles.

---

## 13. Open Questions / Decisions Pending

1. **Chrome 127+ app-bound encryption (v20)** — requires elevation service context or offline key extraction. Recommend: v1 marks `encrypted-appbound`, documents limitation; v2 explores offline extraction with proper legal/consent framework.
2. **BitLocker/LUKS full-disk encryption** — out of scope; tool works on decrypted images only.
3. **Keychain access on macOS** — requires user unlock; document clearly. Sandboxed apps need entitlement.
4. **iOS backups** — Safari artifacts in iTunes/Finder backups (Manifest.db + `Library/Safari/`). Recommend: v2 feature; design readers to accept it.
5. **Firefox primary password** — prompt once per profile; do not cache in memory beyond session.
6. **IndexedDB V8 deserialization** — complex; recommend: v1 extracts keys and raw values (hex + snappy-decoded blob); v2 adds structured clone decoder.
7. **STIX 2.1 mapping** — define mapping table (URL → `url` object, cookie → `network-traffic` extension, etc.); recommend: v1 minimal, v2 richer.
8. **Cross-browser correlation** — v1 timeline only; v2 adds graph view (host ↔ cookie ↔ storage).
9. **License** — `plyvel` bundles LevelDB (BSD); `pycryptodome` (public domain/BSD); verify redistribution.

---

## 14. Glossary

- **DPAPI** — Windows Data Protection API; user/machine-scoped encryption.
- **OSCrypt** — Chromium's cross-platform wrapper over DPAPI/Keychain/Keyring.
- **App-bound encryption** — Chrome 127+ scheme binding keys to Chrome's elevation service.
- **NSS** — Network Security Services; Firefox's crypto library.
- **key4.db** — Firefox NSS key database.
- **mozLz4** — Firefox's LZ4-based container for session files.
- **SNSS** — Chromium session file binary format.
- **Simple Cache** — Modern Chromium HTTP cache backend.
- **Blockfile Cache** — Legacy Chromium HTTP cache backend.
- **Cache2** — Firefox HTTP cache backend.
- **IndexedDB** — Browser structured storage built on LevelDB + snappy in Chromium.
- **LevelDB** — Google's embedded key-value store.
- **Snappy** — Fast compression algorithm.
- **binarycookies** — Safari's binary cookie file format.
- **WebKit epoch** — 1601-01-01 UTC (microseconds).
- **Cocoa epoch** — 2001-01-01 UTC (seconds).
- **Chain of custody** — Audit trail proving evidence integrity.
- **FTS5** — SQLite full-text search extension.

---

*End of document.*