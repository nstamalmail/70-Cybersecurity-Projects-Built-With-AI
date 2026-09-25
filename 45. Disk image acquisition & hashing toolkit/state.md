# State: FAHT-GUI (Forensic Image Acquisition & Hashing Toolkit)

## Current Version: 1.0.0
## Status: Functional Prototype

## Implemented Features
- **Case Management**: Create and save case metadata (case number, evidence ID, examiner, organization, notes)
- **Disk Image Acquisition**: Bit-stream copy from source image/device to destination with configurable block sizes
- **Multi-Algorithm Hashing**: SHA-256, SHA-512, BLAKE3 (optional) inline and post-acquisition verification
- **Hash Verification**: Dual-pass verification ensuring data integrity (inline hash == post hash)
- **Host Telemetry**: Automatic collection of hostname, OS, MAC address, Python version, timestamps
- **Report Generation**: JSON, CSV, TXT, HTML export with full acquisition details
- **Progress Tracking**: Real-time progress bar with bytes processed and completion percentage
- **Cancellation Support**: Graceful cancellation of in-progress acquisitions

## Supported Formats
- RAW (.raw, .dd, .img)
- Source file reading with configurable block sizes (4KB - 1MB)

## Known Limitations
- E01/Expert Witness Format not implemented (requires libewf/pyewf)
- Live device acquisition requires admin/root privileges
- Write-blocker detection is advisory only (software-based)
- No RFC 3161 timestamping integration
- No PDF report generation (HTML serves as alternative)
- Single-threaded acquisition (no parallel chunk processing)

## Testing Status
- Unit tested: Hashing engine, host telemetry collection
- Integration tested: End-to-end acquisition workflow
- GUI tested: Manual verification of all tabs and workflows
