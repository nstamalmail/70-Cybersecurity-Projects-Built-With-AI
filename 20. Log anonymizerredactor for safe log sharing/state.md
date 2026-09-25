# Application State Documentation

## Log Anonymizer/Redactor - State Management

### Current State Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `input_mode` | str | "file" | Current input mode: "file", "directory", "paste" |
| `input_path` | str | "" | Path to selected file or directory |
| `pasted_text` | str | "" | Text content from paste input |
| `selected_profile` | str | "GDPR" | Active redaction profile |
| `salt` | bytes | random | Salt for deterministic tokenization |
| `salt_path` | str | "" | Path to saved salt file |
| `detectors` | dict | See below | Enabled/disabled detector states |
| `replacement_strategy` | str | "tokenize" | How to replace detected items |
| `redacted_content` | str | "" | Processed/redacted output |
| `original_content` | str | "" | Original unmodified input |
| `processing_stats` | dict | {} | Detection counts by type |
| `total_lines` | int | 0 | Total lines processed |
| `total_detections` | int | 0 | Total items detected |

### Detector Configuration

```python
detectors = {
    "email": True,
    "ip_address": True,
    "uuid": True,
    "api_key": True,
    "bearer_token": True,
    "aws_key": True,
    "ssn": True,
    "credit_card": True,
    "password": True,
    "hostname": True
}
```

### Profile Presets

| Profile | Enabled Detectors |
|---------|-------------------|
| GDPR | email, ip_address, uuid, ssn |
| HIPAA | email, ssn, ip_address, uuid |
| PCI DSS | credit_card, api_key, bearer_token, aws_key |
| Basic | email, ip_address, ssn |
| Strict | All detectors enabled |
| Custom | User-configured |

### UI State

- `preview_mode`: "side_by_side" | "diff" | "original" | "redacted"
- `show_safety_banner`: True (always visible)
- `progress_percent`: 0-100
- `status_message`: str

### Export State

- `export_format`: "json" | "csv" | "html" | "pdf"
- `export_path`: str
- `report_data`: dict with detection statistics
