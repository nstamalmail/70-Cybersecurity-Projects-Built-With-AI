# Memory - Mobile Device Forensics Workflow

## Architecture Notes

### Design Decisions
- Single-file app for portability and ease of deployment
- Threaded acquisition to keep GUI responsive during simulated long operations
- Hash manifest computed with SHA-256 for forensic integrity verification
- Chain of custody entries linked via timestamp hashes for tamper evidence
- Catppuccin Mocha color scheme for professional dark theme

### Data Model
```
DeviceInfo: { property: value, ... }
Artifact: { label, count, data[] }
HashManifest: { artifact, file, hash_sha256, size_bytes, timestamp }
CustodyEntry: { timestamp, action, person, notes, hash }
CaseInfo: { case_id, examiner, date_opened, description }
```

### UI Architecture
- Main window with ttk.Notebook for tabbed interface
- 5 tabs: Device, Acquisition, Artifacts, Chain of Custody, Report
- Treeview widgets for structured data display
- ScrolledText for report preview
- File dialogs for import/export operations

### Export Formats
- **JSON**: Full structured data dump
- **CSV**: Flattened key-value pairs
- **TXT**: Formatted plain text report
- **HTML**: Styled table-based report with dark theme

### ALEAPP Compatibility
- Artifact structure designed to align with ALEAPP output format
- Hash manifest in standard forensic format
- Chain of custody log follows ACPO guidelines
