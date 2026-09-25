# Memory - Network Forensics PCAP-to-Story Tool

## Architecture Notes

### Design Decisions
- Single-file app for portability
- Simulated PCAP parsing for demonstration without libpcap dependency
- Session-based view mirrors Wireshark/TShark workflow
- Story timeline converts raw events into human-readable narrative
- Severity scoring for timeline events (Info/Low/Medium/High/Critical)

### Data Model
```
PcapMetadata: { property: value, ... }
Session: { id, src, dst, proto, sport, dport, packets, bytes, start, duration, status }
ProtocolEvent: { id, time, protocol, src, dst, info, length, notes }
ExtractedFile: { id, filename, type, description, size, hash_md5, hash_sha256, src_ip, dst_ip, extracted_from }
StoryEvent: { order, time, event, description, severity, source }
```

### Narrative Engine
- Events classified by severity
- Temporal ordering with timestamps
- Source IP correlation for attribution
- Event clustering for attack chain reconstruction

### Export Formats
- **JSON**: Full structured data with all sessions/events/files
- **CSV**: Flattened view of all sections
- **TXT**: Formatted plain text with section headers
- **HTML**: Styled dark-theme tables with severity color coding
