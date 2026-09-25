# memory.md — Durable Knowledge Base

> Long-lived facts, patterns, and lessons for this project. Anything a future
> session must know lives here. Volatile progress belongs in `state.md`.

## 1. Project Identity & Safety Contract

- **Name:** C2 Detection Workbench — synthetic, offline, detection-focused (v1.0.0).
- **Never do:** real network I/O, real C2 emulation, live capture, offensive tradecraft guidance.
- **Always do:** RFC 5737 IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), reserved-TLD
  domains (`.example`, `.invalid`), didactic payloads only.
- Guard: `src/safety.py` AST-scans all sources for network-capable imports and hard-fails runs;
  `tests/test_safety.py` keeps it honest. Pools validated against RFC 5737 / reserved-TLD regexes.

## 2. Domain Knowledge — Why Domain Fronting Is Detectable

- **Core disjunction:** TLS ClientHello `SNI` (passive-sensor-visible) vs HTTP `Host`
  (CDN-visible) can name different hosts. The front domain routes benignly; the origin hides
  behind the tunnel. A sensor sees the mismatch, not the origin.
- **Modern reality:** major CDNs disabled classic fronting (TLS 1.3, ECH, cert/SNI binding);
  the *pattern* remains core defensive vocabulary.
- **The nine teaching signals (all implemented, all unit-tested):**
  1. D1 SNI/Host mismatch — the signature itself; any hit ⇒ malicious.
  2. D2 Beacon periodicity — timing is metadata; encryption doesn't hide rhythm.
  3. D3 JA3-style clusters — one tool ⇒ one ClientHello shape ⇒ same hash, many destinations.
  4. D4 High-entropy bodies — layered content saturates byte entropy near 8 bits/byte.
  5. D5 DGA hostnames — long, class-mixed, structureless labels (scored, not single-feature).
  6. D6 Rare-SNI pivoting — rare name + non-browser fingerprint fanning out ≠ CDN geometry.
  7. D7 URI anomalies — every encoding layer leaves wrapper bulk (Base64 ×1.37).
  8. D8 TTL cohorts — implants on odd stacks start TTL at 57–64, not 125–128.
  9. D9 Decoy discrimination — perfectly periodic NTP is benign; rhythm alone is not malice.

## 3. Detection-Engineering Lessons (learned during this build)

- **Group keys decide whether a detector works at all.** D2 first grouped by
  `(src, dst, ja3)`; edge rotation split a 30-callback beacon into groups under the
  8-event minimum and the rule never fired. Re-keying to `(src, ja3)` fixed it:
  the implant fingerprint is the stable identity, not the CDN edge.
- **Entropy thresholds must be mathematically reachable.** A 3-class char-class
  distribution maxes out at log2(3) ≈ 1.585 bits — a 3.3 threshold can never fire.
  Set D5's class-entropy threshold to 0.85 and demand length + digit share as well.
- **Tiny samples have high sample entropy.** 256 random bytes ≈ 7.2–7.6 bits/byte by
  chance; D4 requires ≥512-byte bodies and ≥2 hot windows. Random bodies used to
  *demonstrate* entropy should be ≥1 KiB (≈7.8+ bits/byte).
- **False positives are scoped by role, not by threshold alone.** Benign clients got the
  allow-listed browser JA3 and normal TTLs; implants/ransomware got distinct fingerprints
  and TTL cohorts. That's what keeps the `benign_only` negative control perfectly quiet
  without gutting the rules.
- **A negative-control scenario is as important as a positive one** — `benign_only` is the
  regression test for the whole threshold set.

## 4. Engineering Patterns Used

- **Determinism:** single `random.Random(seed)` threaded through every generator; verified
  byte-identical PCAP SHA-256 across runs (`test_determinism_same_seed_same_pcaphash`).
- **Pure-function rules:** every detection is `list[FlowRecord] -> list[Finding]`; no I/O,
  no globals. GUI-agnostic and trivially unit-testable.
- **Findings carry evidence + explanation strings** — the GUI "why" pane is the payload.
- **PCAP writer:** magic `0xa1b2c3d4` (LE), v2.4, LINKTYPE_ETHERNET; Ethernet II + IPv4
  (IHL=5, DF, real header checksum) + UDP (csum 0, IPv4-legal) / TCP + minimal DNS/HTTP.
  Wireshark-verified layout; test self-parses the file.
- **Port masking:** synthetic ephemeral ports (e.g. `45000 + rng.randint(0, 20000)`) can
  exceed 65535 — mask `& 0xFFFF` at struct-pack time or the packer throws struct.error.
- **Tkinter responsiveness:** engine in a `threading.Thread` + `queue.Queue` +
  `after(100)` polling; chunked Treeview inserts (500/idle-cycle); never touch Tk off-thread.
- **Extract FlowRecord to its own module** when both the pcap writer and the generator need
  it — otherwise you get an import cycle (traffic ↔ pcap).

## 5. Packaging Notes (Windows)

- `pyinstaller --onefile --windowed --name C2DetectionWorkbench --clean -y app.py` →
  10.4 MB exe, no missing-module warnings, tkinter bundled automatically.
- `--windowed` suppresses the console — so **verify the exe via exit code**
  (`exe --smoke; echo $?`), not stdout. Smoke prints still appear in Git Bash here.
- SmartScreen will warn on unsigned exe builds — expected for demos; document it.
- Console codepage (cp1252) mangles `—`/`…` in smoke output — cosmetic only.

## 6. Environment Facts

- Python 3.12.7 (tkinter OK), pip 26.2.1, PyInstaller 6.22.2, pytest 8.x.
- Windows + Git Bash: POSIX syntax only (`rm`, `mv`, forward slashes).
- `python -m compileall -q src app.py` is a fast pre-pytest syntax gate.

## 7. Glossary (teaching vocabulary used in UI copy)

| Term | Meaning in this demo |
|------|----------------------|
| SNI | Server Name Indication — cleartext hostname in TLS ClientHello |
| Host header | HTTP target hostname — what the CDN routes on |
| JA3 | Fingerprint hash over ClientHello fields (version/ciphers/exts/curves) |
| Beaconing | Regular callback rhythm to C2 (with jitter) |
| DGA | Domain Generation Algorithm — algorithmic domain names |
| CV | Coefficient of variation (stddev/mean) — the periodicity metric |
| Decoy | Synthetic benign/noise flow used to test detections |
| ZTN | Zero-Trust verdict: allow / verify / deny |

## 8. Verification Checklist (all green at v1.0.0)

1. `python -m pytest tests/ -q` — **40 passed**.
2. `python app.py --smoke` — **SMOKE PASSED**, all four scenarios meet expectations.
3. `python app.py --self-test` — **SAFETY OK** (no network imports, round-trips OK).
4. `python scripts/gui_smoke.py` — **GUI SMOKE PASSED** (8 tabs, run + filter exercised).
5. `dist/C2DetectionWorkbench.exe --smoke` — **exit 0** on the frozen exe.
