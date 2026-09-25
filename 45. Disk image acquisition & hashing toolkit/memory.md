# Memory: FAHT-GUI Design Decisions & Architecture

## Architecture Overview
- **Pattern**: Single-file MVC with tkinter GUI
- **Language**: Python 3.10+ (stdlib only + hashlib)
- **GUI Framework**: tkinter with ttk widgets
- **Threading**: Background acquisition via threading.Thread

## Data Model

### CaseMetadata
```
case_number: str
evidence_id: str
examiner_name: str
organization: str
notes: str
```

### AcquisitionResult
```
source_path: str
output_path: str
image_format: str (RAW)
file_size: int
sha256_inline: str
sha256_post: str
sha512_inline: str
blake3_inline: str
hashes_match: bool
start_time: str (ISO 8601 UTC)
end_time: str (ISO 8601 UTC)
duration_seconds: float
block_size: int
bad_sectors: int
host_info: dict
status: str
```

## Key Design Decisions

1. **Dual-Pass Hash Verification**: Compute SHA-256 during write (inline), then re-hash output file (post). Match = integrity verified.

2. **Threaded Acquisition**: Acquisition runs in background thread to keep UI responsive. Progress updates via callback to main thread.

3. **Host Telemetry**: Automatically collect system info for chain-of-custody documentation. Includes hostname, OS, MAC, timestamps.

4. **Block Size Configuration**: Default 64KB balances throughput and memory. Larger blocks = fewer syscalls but more memory per chunk.

5. **Read-Only Source**: Source file opened in read-only mode. Write-blocker verification is advisory.

6. **Hash Manifest**: CSV export of all acquisition hashes for external verification tools.

## Security Considerations
- Source files are read-only (no modification risk)
- Destination path validation prevents overwrite of source
- Hash algorithms: SHA-256 (primary), SHA-512 (secondary), BLAKE3 (fast alternative)
- All timestamps in UTC for consistency across time zones
- HMAC chain not implemented (would require key management)

## Future Enhancements
- E01 format support via pyewf
- Hardware write-blocker detection via OS APIs
- RFC 3161 timestamping via TSA
- PDF report generation via reportlab
- Parallel chunk processing for NVMe speeds
- SQLite case database for multi-acquisition tracking
