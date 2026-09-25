# Technical Memory - Log Anonymizer/Redactor

## Regex Patterns

### Email Addresses
```python
r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
```
Matches: user@example.com, john.doe@company.org

### IPv4 Addresses
```python
r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
```
Matches: 192.168.1.1, 10.0.0.55, 172.16.0.100

### UUIDs
```python
r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'
```
Matches: 550e8400-e29b-41d4-a716-446655440000

### API Keys
```python
r'(?:api[_-]?key|apikey)[=:]\s*["\']?([a-zA-Z0-9]{20,})["\']?'
r'ak_(?:live|test)_[a-zA-Z0-9]{20,}'
```
Matches: ak_live_4eC39HqLyjWDarjtT1zdp7dc

### Bearer Tokens
```python
r'Bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'
r'sk-proj-[a-zA-Z0-9]{20,}'
```
Matches: Bearer eyJhbGciOiJIUzI1NiIs...

### AWS Keys
```python
r'AKIA[0-9A-Z]{16}'
r'(?:aws[_-]?secret)[=:]\s*["\']?([a-zA-Z0-9/+=]{40})["\']?'
```
Matches: AKIAIOSFODNN7EXAMPLE

### SSN (Social Security Number)
```python
r'\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b'
```
Matches: 123-45-6789

### Credit Cards
```python
r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'
r'\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b'
```
Matches: 4111-1111-1111-1111

### Passwords
```python
r'(?:password|passwd|pwd)[=:]\s*["\']?(\S+)["\']?'
```
Matches: password=Secret123!

### Hostnames
```python
r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.(?:com|org|net|io|co)\b'
```
Matches: example.com, database.prod.internal

## Tokenization Algorithm

### Deterministic Tokenization (Same Input = Same Token)

1. **Salt Application**: Combine input with salt using HMAC-SHA256
2. **Hash Generation**: Generate hash from salted input
3. **Token Creation**: Format as `[TYPE]_[short_hash]`

```python
def tokenize(value, salt, detection_type):
    # Create HMAC using salt
    hmac_obj = hmac.new(salt, value.encode('utf-8'), hashlib.sha256)
    hash_hex = hmac_obj.hexdigest()
    
    # Create short token (8 chars)
    short_hash = hash_hex[:8]
    
    # Format based on type
    type_prefix = {
        "email": "EMAIL",
        "ip_address": "IP",
        "uuid": "UUID",
        "api_key": "APIKEY",
        "bearer_token": "TOKEN",
        "aws_key": "AWSKEY",
        "ssn": "SSN",
        "credit_card": "CARD",
        "password": "PASS",
        "hostname": "HOST"
    }
    
    return f"[{type_prefix[detection_type]}]_{short_hash}"
```

## Replacement Strategies

### 1. Tokenize (Deterministic)
- Same input always produces same output
- Enables correlation across logs
- Format: `[TYPE]_XXXXXXXX`

### 2. Mask (Partial Visibility)
- Shows first/last characters
- Replaces middle with asterisks
- Example: `j***@***.com` for email

### 3. Redact (Complete Removal)
- Replaces entire value with `[REDACTED]`
- No information preserved
- Most secure option

### 4. Label (Type Only)
- Replaces with type label only
- Example: `[EMAIL]`, `[IP_ADDRESS]`
- Preserves no original data

## Color Coding Scheme

| Detection Type | Color | Hex Code |
|----------------|-------|----------|
| Email | Blue | #2196F3 |
| IP Address | Green | #4CAF50 |
| Secrets/Keys | Red | #F44336 |
| PII (SSN, etc.) | Orange | #FF9800 |

## Detection Priority

1. **High Priority** (Red): API keys, Bearer tokens, AWS keys, Passwords
2. **Medium Priority** (Orange): SSN, Credit cards
3. **Low Priority** (Blue/Green): Email, IP addresses, UUIDs, Hostnames

## Performance Considerations

- Regex compilation: Pre-compile all patterns at startup
- Batch processing: Process lines in chunks for large files
- Memory management: Stream large files instead of loading entirely
- Hash caching: Cache hashes for repeated values
