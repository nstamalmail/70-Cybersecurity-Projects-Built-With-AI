# Forensic Image Acquisition & Hashing Toolkit (FAHT-GUI)
## Architecture Design Document (ADD)

**Version:** 1.0.0  
**Author:** Lead Security & Forensic Software Architect  
**Date:** September 16, 2026  
**Document ID:** ARCH-FAHT-2026-09  
**Status:** Approved for Development  

---

## 1. Executive Summary & Purpose

The **Forensic Image Acquisition & Hashing Toolkit (FAHT-GUI)** is a high-assurance, cross-platform Python desktop application engineered for digital forensics examiners, incident responders, and law enforcement personnel. Its principal mission is to perform bit-stream disk acquisition (raw dd, E01/Expert Witness Format) from target block devices while strictly enforcing data integrity, cryptographic verification, and automated chain-of-custody logging.

In forensic science, the legal admissibility of evidence hinges on demonstrating that digital evidence has remained unaltered from the moment of acquisition through analysis. FAHT-GUI bridges the gap between raw command-line forensic utilities (`dd`, `dc3dd`, `ewf-tools`) and complex commercial forensic suites by providing an extensible, UI-driven framework that automates cryptographic hashing (SHA-256 / SHA-3 / BLAKE3), tracks hardware/media signatures, auto-generates RFC 3161 compliant timestamped custody reports, and maintains an immutable audit trail.

---

## 2. System Scope & Core Requirements

### 2.1 Functional Requirements (FR)
- **FR-1: Block Device Discovery & Enumeration**
  - Dynamically enumerate all connected physical and logical block devices (SATA, NVMe, USB, FireWire, virtual block devices).
  - Extract low-level physical disk attributes: Serial Number, Model, Bus Type, Sector Size (Logical/Physical), Media Type (SSD/HDD), Write-Blocker Status, and Smart Health telemetry.
- **FR-2: Write-Blocking & Safety Assertions**
  - Enforce strict programmatic checks to prevent accidental destination-to-source overwrite.
  - Automatically detect hardware write-blockers (e.g., Tableau, WiebeTech) and provide soft-write-blocking via OS read-only mounts prior to acquisition initiation.
- **FR-3: Forensic Image Acquisition Engine**
  - Support standard raw bit-stream format (`.raw` / `.dd` / `.img`).
  - Support Expert Witness Format (`.E01` / `.Ex01`) with configurable chunk sizes (e.g., 640MB, 2GB, 4GB), compression algorithms (zlib/LZMA), and metadata header injection (Case Number, Evidence ID, Examiner Name, Notes).
  - Implement dynamic multi-threaded streaming read/write buffer management with configurable block sizes (default 64KB - 4MB).
- **FR-4: Multi-Algorithm Cryptographic Hashing**
  - Compute simultaneous real-time baseline hashes during stream read (In-line Hashing) and secondary post-acquisition verification hashes (Post-Hashing).
  - Supported Algorithms: **SHA-256**, **SHA-512**, **SHA3-256**, **BLAKE3**.
  - Provide continuous sector-level bad-block tracking and write zero-fill recovery logs.
- **FR-5: Automated Chain-of-Custody Logging & Reporting**
  - Generate an immutable Audit Log in structural formats (`JSON`, `XML`) and human-readable formats (`PDF`, `Markdown`).
  - Capture host execution telemetry: Examiner Info, Host IP, Host MAC, OS Kernel Version, System Timestamp (UTC), Hardware UUIDs.
  - Compute cryptographic hash over the Audit Log itself (Self-Signing Log) and option for RFC 3161 Trusted Timestamping via external TSA API.

### 2.2 Non-Functional Requirements (NFR)
- **NFR-1: Processing Performance & Throughput**
  - Maximize hardware I/O throughput utilizing memory-mapped buffers, zero-copy socket transfers where applicable, and asynchronous thread workers to achieve disk controller speed limits (e.g., >500 MB/s on NVMe/SATA III SSDs).
- **NFR-2: Memory Safety & Resource Management**
  - Maintain a bounded memory footprint (<250 MB RAM operational usage) regardless of source drive size (100 GB to 20 TB+).
- **NFR-3: Cross-Platform Native Abstraction**
  - Uniform execution abstraction across Linux (Ubuntu/Debian/SLES/Fedora), Microsoft Windows (10/11/Server 2019+), and macOS (ARM64/x86_64).
- **NFR-4: Reliability & Fault Tolerance**
  - Resume capabilities for broken raw streams; detailed bad sector reporting without aborting execution mid-acquisition.

---

## 3. Overall System Architecture & Layering

FAHT-GUI follows a strictly decoupled, 4-tier architectural model: **Presentation Layer (GUI)**, **Application Controller Layer**, **Core Domain Engine Layer**, and **Platform Operating System / Hardware Layer**. Communication between layers occurs via explicit asynchronous signals and event queues to ensure responsiveness during heavy disk IO operations.

```
+-----------------------------------------------------------------------+
|                       PRESENTATION LAYER (GUI)                        |
|   PyQt6 / PySide6 Desktop Interface, Event Loop, Reactive Widgets     |
+------------------------------------+----------------------------------+
                                     | Event Dispatcher / Qt Signals
                                     v
+-----------------------------------------------------------------------+
|                    APPLICATION CONTROLLER LAYER                       |
|   Task Orchestrator, Session Manager, Validation Engine, Config Sync   |
+------------------------------------+----------------------------------+
                                     | Thread Pool / Work Queue
                                     v
+-----------------------------------------------------------------------+
|                     CORE DOMAIN ENGINE LAYER                          |
|  +--------------------+  +-------------------+  +------------------+  |
|  | Device Enumerator  |  | Acquisition Engine|  | Dynamic Crypt-   |  |
|  | & Hardware Probe   |  | (Raw / E01 Stream)|  | Hashing Pipeline |  |
|  +--------------------+  +-------------------+  +------------------+  |
|  +-----------------------------------------------------------------+  |
|  | Chain-of-Custody Generator, JSON/PDF Reporter & TSA Signer     |  |
|  +-----------------------------------------------------------------+  |
+------------------------------------+----------------------------------+
                                     | Subprocess / System Calls / Ctypes
                                     v
+-----------------------------------------------------------------------+
|               PLATFORM OS & HARDWARE INTERFACE LAYER                  |
|  Win32 API (DeviceIoControl) / Linux (/dev/sd*, libewf) / POSIX I/O   |
+-----------------------------------------------------------------------+
```

---

## 4. Component-Level Design & Modules

### 4.1 System Components Matrix

| Component Module | Class / Package Name | Primary Responsibility | Dependencies |
| :--- | :--- | :--- | :--- |
| **GUI Framework** | `faht.gui.app` | Manages PyQt/PySide main application window, wizard panels, event loops, theme management. | `PyQt6` / `PySide6` |
| **Device Enumerator** | `faht.core.devices` | Scans physical system buses to retrieve disk geometry, serials, and write-protection status. | `psutil`, `pywin32` (Win), `pyudev` (Linux) |
| **Acquisition Engine** | `faht.engine.stream` | Manages read streams from block devices, chunks data into dynamic memory buffers, and outputs raw/E01 files. | `libewf-python`, `ctypes`, `os` |
| **Hashing Engine** | `faht.crypto.hasher` | Computes parallel multi-threaded inline and post-acquisition cryptographic hashes. | `hashlib`, `blake3` |
| **Chain-of-Custody** | `faht.custody.logger` | Captures system telemetry, environment variables, case metadata, and emits structured audit logs. | `pydantic`, `cryptography` |
| **Report Generator** | `faht.reports.pdf` | Generates official PDF/HTML audit reports with cryptographic seals and TSA timestamps. | `reportlab` / `weasyprint`, `requests` |

---

## 5. Detailed Data Flow & Execution Pipeline

The acquisition workflow operates as a two-phase transaction ensuring data integrity before, during, and after streaming.

```
       [ Examiner Inits Acquisition ]
                     |
                     v
   +------------------------------------+
   | Step 1: Pre-Acquisition Telemetry  |
   | - Hardware probe (Serial, Model)   |
   | - Probe Write-Blocker Status       |
   | - Prompt Examiner & Case Metadata  |
   +-----------------+------------------+
                     |
                     v
   +------------------------------------+
   | Step 2: Target Locking & Verification|
   | - Verify Source != Target Path     |
   | - Lock Target Handle (Exclusive IO)|
   +-----------------+------------------+
                     |
                     v
   +------------------------------------+
   | Step 3: Concurrent Stream Pipeline |
   | - Dedicated IO Thread reads block  |
   | - Pushes block to Ring Buffer Queue|
   +--------+------------------+--------+
            |                  |
            v                  v
+-----------------------+  +-----------------------+
|  Writer Thread        |  |  Inline Hasher Thread |
|  Writes to Raw / E01  |  |  Updates SHA256/BLAKE3|
+-----------+-----------+  +-----------+-----------+
            |                  |
            +--------+---------+
                     |
                     v
   +------------------------------------+
   | Step 4: Post-Acquisition Hash Pass |
   | - Re-read generated output file    |
   | - Compute post-hash match verify   |
   +-----------------+------------------+
                     |
                     v
   +------------------------------------+
   | Step 5: Custody & Report Generation|
   | - Compile System & Hardware JSON   |
   | - Sign Log with RSA / Timestamp    |
   | - Render Immutable PDF Audit Doc   |
   +------------------------------------+
```

---

## 6. Security, Integrity & Forensic Admissibility

To maintain legal defensibility under the **Federal Rules of Evidence (Rule 901/902)** and ISO/IEC 27037 standards, the architecture incorporates six specific security controls:

1. **Hardware & Logical Write Suppression:**
   - On Linux systems, block devices are accessed using `O_RDONLY | O_DIRECT` flags, explicitly bypassing OS kernel page caches to avoid altering device timestamps (atime/mtime).
   - On Windows systems, source physical disks are opened with `GENERIC_READ` mode and locked using `FSCTL_LOCK_VOLUME` and `FSCTL_DISMOUNT_VOLUME`.
2. **Dual-Pass Verification Algorithm:**
   - Verification requires $Hash_{InLine}(Source) \equiv Hash_{Post}(ImageFile)$.
   - If $Hash_{InLine} 
eq Hash_{Post}$, the system marks the image file as **TAMPERED / CORRUPTED** and locks down output distribution.
3. **Cryptographic Log Signing:**
   - Every session generates a SHA-256 payload of the entire JSON audit log. This payload is signed via an internal RSA-4096 or ECDSA (P-256) private key held by the examiner or embedded within a secure hardware token (HSM / YubiKey / TPM).
4. **RFC 3161 Timestamp Verification:**
   - The SHA-256 digest of the execution log is transmitted over HTTPS to a designated Time Stamping Authority (TSA). The returned digital timestamp token (TST) is embedded directly inside the PDF/JSON evidence packet.
5. **Memory Sanitation:**
   - Passwords, case analyst credentials, and raw memory buffer blocks are explicitly overwritten in RAM using zeroization logic prior to garbage collection.
6. **Defensive Target Validation:**
   - Strict logic prevents selecting any physical drive containing the currently mounted OS boot partition or the target directory path as an input source.

---

## 7. Python Implementation Strategy & Architecture Stack

### 7.1 Framework & Library Selection
- **Desktop UI Framework:** `PyQt6` (or `PySide6`) utilizing `QThread`, `pyqtSignal`, and asynchronous worker patterns to maintain 60 FPS UI responsiveness during heavy processing.
- **System / Low-Level IO Interfaces:** `ctypes`, `cffi`, and platform APIs (`pywin32` for Win32 API calls; native `/dev/` and `fcntl` calls on POSIX).
- **Format Support:** Native Python C-bindings to `libewf` (`pyewf`) for Expert Witness Format (`.E01`) standard creation.
- **High-Performance Hashing:** PyCryptodome or native C-optimized `blake3` bindings capable of hashing at rates exceeding 2 GB/s per thread.
- **Reporting Engine:** `ReportLab` or `WeasyPrint` for automated forensic PDF rendering.

### 7.2 Scalable Code Directory Structure

```text
faht_gui/
├── assets/
│   ├── icons/
│   ├── styles/
│   └── templates/
│       └── custody_report_template.html
├── src/
│   ├── faht/
│   │   ├── __init__.py
│   │   ├── app.py                     # Entry point & PyQt app loop
│   │   ├── controllers/
│   │   │   ├── acquisition_controller.py
│   │   │   └── device_controller.py
│   │   ├── core/
│   │   │   ├── devices.py             # Physical drive enumeration
│   │   │   └── write_blocker.py       # Safety assertion check modules
│   │   ├── engine/
│   │   │   ├── format_raw.py          # Raw DD file stream handler
│   │   │   ├── format_e01.py          # E01 Advanced stream handler
│   │   │   └── ring_buffer.py         # Dynamic memory buffer manager
│   │   ├── crypto/
│   │   │   ├── hashing.py             # Multi-algorithm hash pipeline
│   │   │   └── tsa_signer.py          # RFC 3161 Timestamping & Signatures
│   │   ├── custody/
│   │   │   ├── telemetry.py           # Host system info collector
│   │   │   └── audit_logger.py        # Immutable event logging
│   │   ├── reports/
│   │   │   └── pdf_generator.py       # Audit report layout builder
│   │   └── gui/
│   │       ├── main_window.py
│   │       ├── widgets/
│   │       │   ├── device_selector.py
│   │       │   ├── progress_bar.py
│   │       │   └── log_viewer.py
│   │       └── dialogs/
│   │           └── metadata_dialog.py
├── tests/
│   ├── test_devices.py
│   ├── test_hashing.py
│   └── test_acquisition.py
├── docs/
│   └── architecture.md
├── requirements.txt
└── setup.py
```

---

## 8. Database Schema & Chain-of-Custody Audit Data Model

All audit trail entries are stored locally as structured JSON schema instances before rendering into final signed documents.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "FAHT_ChainOfCustody_AuditRecord",
  "type": "object",
  "properties": {
    "case_metadata": {
      "type": "object",
      "properties": {
        "case_number": { "type": "string" },
        "evidence_id": { "type": "string" },
        "examiner_name": { "type": "string" },
        "organization": { "type": "string" },
        "notes": { "type": "string" }
      },
      "required": ["case_number", "evidence_id", "examiner_name"]
    },
    "source_device": {
      "type": "object",
      "properties": {
        "device_path": { "type": "string" },
        "model": { "type": "string" },
        "serial_number": { "type": "string" },
        "bus_type": { "type": "string" },
        "capacity_bytes": { "type": "integer" },
        "sector_size": { "type": "integer" },
        "is_write_blocked": { "type": "boolean" }
      },
      "required": ["device_path", "serial_number", "capacity_bytes"]
    },
    "acquisition_parameters": {
      "type": "object",
      "properties": {
        "image_format": { "type": "string", "enum": ["RAW", "E01"] },
        "block_size_bytes": { "type": "integer" },
        "output_path": { "type": "string" },
        "compression_enabled": { "type": "boolean" }
      }
    },
    "execution_telemetry": {
      "type": "object",
      "properties": {
        "host_name": { "type": "string" },
        "os_version": { "type": "string" },
        "mac_address": { "type": "string" },
        "start_time_utc": { "type": "string", "format": "date-time" },
        "end_time_utc": { "type": "string", "format": "date-time" },
        "bad_sectors_encountered": { "type": "integer" }
      }
    },
    "verification_hashes": {
      "type": "object",
      "properties": {
        "inline_sha256": { "type": "string" },
        "post_sha256": { "type": "string" },
        "inline_blake3": { "type": "string" },
        "post_blake3": { "type": "string" },
        "hashes_match": { "type": "boolean" }
      },
      "required": ["inline_sha256", "post_sha256", "hashes_match"]
    },
    "digital_signature": {
      "type": "object",
      "properties": {
        "tsa_timestamp_token": { "type": "string" },
        "rsa_signature_b64": { "type": "string" },
        "public_key_fingerprint": { "type": "string" }
      }
    }
  }
}
```

---

## 9. Error Handling, Resilience & Exception Strategy

To ensure seamless recovery and zero data destruction during unforeseen hardware failures:

1. **Physical IO Read Errors (Bad Sectors):**
   - The engine implements an automated retry mechanism (3 retries per sector block).
   - If read failure persists, the zero-fill strategy replaces unreadable physical sectors with null bytes (`0x00`), flags the specific sector offsets in the audit log, and increments the `bad_sectors_encountered` metric without halting execution.
2. **Unexpected Storage Detachment:**
   - Detects sudden drop in storage handle signals. Upon disconnection, the file writer flushes remaining in-memory ring buffers, closes target handles securely, and writes an emergency log entry detailing premature termination.
3. **Out-of-Memory (OOM) Protection:**
   - Uses bounded queue buffers (max 100 blocks in RAM). If processing drops below IO read rates, the stream automatically throttles source reading until buffer capacity is restored.

---

## 10. Verification, Testing & Admissibility Strategy

To validate forensic suitability prior to operational deployment, the toolkit must pass a structured qualification protocol:

- **Unit & Integration Testing:** PyTest suite achieving >90% coverage across enumeration, dynamic hashing, buffer streaming, and log generation modules.
- **NIST CFTT Alignment:** Compliance testing against the National Institute of Standards and Technology (NIST) **Computer Forensic Tool Testing (CFTT)** specification for digital data acquisition tools.
- **Synthesized Corruption Testing:** Executing acquisitions against virtual disk images (`.vhdx`, `.qcow2`, loopback devices) injected with artificial bad sectors and bad parity blocks to verify exact error trapping and hash mismatch alerts.
- **Cross-Verification Benchmarking:** Running comparative acquisitions between FAHT-GUI, `dc3dd`, and `FTK Imager` to ensure byte-for-byte binary parity and hash match consistency across all generated outputs.
