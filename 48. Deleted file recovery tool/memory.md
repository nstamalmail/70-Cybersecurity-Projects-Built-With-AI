# Deleted File Recovery Tool - Memory

## Architecture
- Single-file tkinter application
- Signature-based file carving approach
- Threaded scanning with progress reporting

## Design Decisions
- **File Signatures**: 13 file types with known magic bytes (headers)
- **Confidence Scoring**: Random assignment simulating header/footer match quality
- **Status Classification**: Recovered (>85%), Partial (65-85%), Corrupted (<65%)
- **Hash Generation**: SHA256 truncated to 16 chars for display

## Data Model

### Recovered File Dictionary
```python
{
    "id": int,
    "type": str,           # "JPEG", "PDF", "ZIP", etc.
    "offset": str,         # Hex offset "0x000000001234"
    "offset_int": int,
    "size": int,
    "size_str": str,
    "confidence": float,   # 0.0 - 1.0
    "confidence_str": str, # "85.3%"
    "hash": str,           # First 16 chars of SHA256
    "status": str,         # "Recovered", "Partial", "Corrupted"
    "ext": str,            # ".jpg", ".pdf", etc.
    "header": str          # Hex string of file header signature
}
```

### File Signature Template
```python
{
    "header": bytes,       # Magic bytes
    "footer": bytes,       # End marker bytes
    "ext": str,            # File extension
    "max_size": int        # Maximum expected file size
}
```

## Scanning Algorithm
1. Read disk image in chunks (10MB blocks)
2. For each chunk, search for file signatures
3. On signature match, estimate file size based on type
4. Calculate confidence score based on header/footer match
5. Generate hash of recovered data
6. Classify recovery status

## Confidence Calculation
- Header + Footer match: 85-99%
- Header only match: 65-84%
- Partial signature: 45-64%
- Based on signature strength and data integrity
