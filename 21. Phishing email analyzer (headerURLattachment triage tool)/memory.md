# Phishing Email Analyzer — Technical Memory

## Email Header Parsing
- Parse using Python `email` stdlib (`email.message_from_string`)
- Extract `authentication-results` header for SPF/DKIM/DMARC
- Parse each `Received` header for routing chain
- Compare `From`, `Return-Path`, `Reply-To` for domain mismatch

## SPF/DKIM/DMARC Extraction
- SPF: Look for `spf=` in `received-spf` or `authentication-results` headers
- DKIM: Look for `dkim=` in `authentication-results` headers
- DMARC: Look for `dmarc=` in `authentication-results` headers
- Status mapping: pass=green, softfail=yellow, fail=red, none=gray

## URL Extraction & Defanging
- Regex: `https?://[^\s<>"]+`
- Also extract from `<a href>` tags in HTML bodies
- Defanging rules:
  - `http://` → `hxxp://`
  - `https://` → `hxxps://`
  - `.` → `[.]` (in domain portion only)
  - `@` → `[at]`

## Risk Scoring Algorithm (0-100)
| Factor | Weight | Condition |
|--------|--------|-----------|
| SPF fail | +25 | spf=fail |
| SPF softfail | +10 | spf=softfail |
| DKIM fail | +20 | dkim=fail |
| DKIM none | +5 | dkim=none |
| DMARC fail | +25 | dmarc=fail |
| From/Return-Path mismatch | +15 | domains differ |
| Suspicious URL patterns | +10 per URL | IP-based, homograph, excessive redirects |
| Known phishing keywords | +5 per hit | "verify", "urgent", "account", "suspended" |
| Macro-enabled attachment | +15 | .docm, .xlsm, .pptm |
| Executable attachment | +10 | .exe, .bat, .ps1, .vbs |
| Large attachment | +3 | >5MB |

### Verdict Thresholds
| Score | Verdict |
|-------|---------|
| 0-29 | Safe |
| 30-59 | Suspicious |
| 60-100 | Likely Phishing |

## Hash Computation
- MD5, SHA1, SHA256 computed on raw attachment bytes
- Used for IOC extraction and threat intel correlation

## Defanging Convention
- IPs: `192.168.1.1` → `192[.]168[.]1[.]1`
- URLs: `http://evil.com` → `hxxp://evil[.]com`
- Emails: `user@domain.com` → `user[at]domain[.]com`

## Report Formats
- **JSON:** Full structured data export
- **CSV:** Flattened table (URLs + Attachments rows)
- **HTML:** Styled report with color-coded results
- **PDF:** HTML rendered to PDF via QPrinter
