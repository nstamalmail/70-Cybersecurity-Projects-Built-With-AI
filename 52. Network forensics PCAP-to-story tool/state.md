# State - Network Forensics PCAP-to-Story Tool

## Current State: v1.0 Complete

### Features Implemented
- PCAP file loading (real or simulated)
- Packet metadata parsing and display
- Session reconstruction with flow tracking
- Protocol decode for HTTP, DNS, TLS, SMTP, SSH
- File extraction from network streams
- Narrative timeline generation with severity levels
- Multi-format report export (JSON, CSV, TXT, HTML)
- Professional dark-themed tkinter GUI

### Tabs
1. **PCAP Load** - Open/simulate PCAP files, display metadata
2. **Sessions** - Reconstructed network sessions
3. **Protocols** - Decoded protocol events
4. **Extraction** - Extracted files from network traffic
5. **Story** - Narrative timeline of events
6. **Report** - Preview and export analysis report

### Known Limitations
- PCAP parsing is simulated (not reading real pcapng format)
- Protocol decoding based on sample data, not deep packet inspection
- File extraction is simulated with metadata only
- No reassembly of TCP streams
- No statistics/charts for protocol distribution

### File Inventory
- `app.py` - Main application (tkinter GUI)
- `state.md` - This file
- `memory.md` - Architecture notes
- `build_exe.bat` - PyInstaller build script
