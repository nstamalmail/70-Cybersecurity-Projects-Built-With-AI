# Phishing Email Analyzer — Application State

## Version
1.0.0

## Current State
- **GUI Framework:** PySide6 (Qt6)
- **Mode:** Ready to load email (manual paste or .eml file)
- **Risk Score:** 0 (no email loaded)
- **Verdict:** N/A

## Data Flow
1. User loads email via "Upload .eml" or "Paste Raw Email" or "Load Demo Data"
2. Application parses raw email using Python `email` stdlib
3. Header analyzer extracts: SPF, DKIM, DMARC, From/Return-Path/Reply-To, Received chain
4. URL analyzer extracts all URLs, defangs them, identifies redirect chains, computes reputation
5. Attachment analyzer identifies MIME types, computes MD5/SHA1/SHA256 hashes, detects macros
6. Routing chain view renders Received headers as a visual chain
7. Risk score computed from weighted factors (0-100 scale)
8. IOC summary generated (defanged IPs, domains, URLs, emails, hashes)
9. Report exported as JSON/CSV/HTML/PDF

## Tabs / Panels
| Panel | Purpose |
|-------|---------|
| Header Analysis | SPF/DKIM/DMARC, From vs Return-Path vs Reply-To |
| URL Analysis | Defanged URLs, domains, redirect chains, risk |
| Attachment Analysis | Filename, MIME, size, hashes, macro detection |
| Routing Chain | Received headers visualized as hop chain |
| Risk Dashboard | Score gauge, verdict badge, breakdown |
| IOC Summary | Defanged IOCs grouped by type |
| Report Builder | Export formats (JSON, CSV, HTML, PDF) |

## Persistence
None — all analysis is ephemeral per session.

## Last Updated
2026-09-21
