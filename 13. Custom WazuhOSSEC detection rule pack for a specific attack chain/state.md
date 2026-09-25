# State — Wazuh/OSSEC Rule Pack Builder

> Living document: update after every build step. Tracks what exists, what is
> verified, and what is still pending. See `memory.md` for decisions/context and
> `architecture.md` for the design this build follows.

## Build status: v1 COMPLETE (2026-09-08)

| Area | Status | Notes |
|---|---|---|
| Architecture doc | ✅ Done | `architecture.md` — full design, domain model, pipeline, validation, packaging |
| Domain model | ✅ Done | `app/models.py` — Chain/Step/Technique/Rule, CustomDecoder, PackOptions, RulePackProject |
| Presets | ✅ Done | `app/presets.py` — 4 expert chains: Ransomware, Webshell & RCE, Credential Dumping, Lateral Movement |
| XML generation | ✅ Done | `app/generators.py` — rules/decoders/ossec snippet/README/CSV + zip export |
| Validation | ✅ Done | `app/validator.py` — 15+ checks, ERROR blocks export |
| Persistence | ✅ Done | `app/persistence.py` — versioned JSON, atomic writes |
| GUI (5 tabs) | ✅ Done | `app/ui/` — Chain, Rules, Generators & Export, Preview, Deploy |
| Entry point | ✅ Done | `main.py` |
| Headless tests | ✅ Passing | `tests/test_smoke.py` — 11/11 OK |
| GUI smoke test | ✅ Passing | All 5 tabs construct; model mutation refreshes tabs |
| E2E pack export | ✅ Passing | Zip contains all 5 artifacts; README/CSV correct |
| Portable exe | ✅ Done | `dist/WazuhRulePackBuilder.exe` (11.3 MB single file) — launch-verified on this machine |

## Verified behavior (evidence)

- `python -m unittest discover -s tests -v` → **11 tests, 0 failures**
  (preset integrity, unique IDs, XML round-trip, field rendering, decoder XML,
  zip contents, duplicate IDs, bad level/regex, unknown decoder, project round-trip,
  wrong-format rejection)
- Withdrawn-GUI construct: notebook has 5 tabs, status bar shows live stats
  (e.g. "10 steps · 15 techniques · 21 rules · 1 decoders" for the ransomware preset).
- Ransomware preset: 0 validation errors; `local_rules.xml` = 225 lines, rules
  ordered by chain phase, MITRE mappings present.
- `dist/WazuhRulePackBuilder.exe` (11,282,909 bytes): launched, stayed alive,
  terminated cleanly — windowed onefile bootloader works on this machine.

## How to run / build

```bash
# run from source (no installs needed — pure stdlib)
python main.py

# tests
python -m unittest discover -s tests -v

# build portable exe (Windows)
build_exe.bat          # -> dist/WazuhRulePackBuilder.exe

# build (Unix/CI)
bash build_exe.sh
```

## Defects found & fixed during the build

1. **XML comment `--` crash** — technique comments used `--` separators, which is
   illegal inside XML comments (`<!-- ... -- ... -->` breaks the parser). Fixed with
   a `_comment()` sanitizer in `generators.py` (replaces `--` with `- -`) + unit test.
2. **Rules table column mismatch** — Treeview was configured with columns
   `(level, groups, …)` but headed `id` first → `TclError: Invalid column index id`.
   Added `id` to the columns tuple.
3. **Dead code in UI** — removed a broken `_current_technique()` stub and a no-op
   `_toggle_cond_fields()` body in `rule_tab.py`.

## Pending / next steps

- [x] Build `dist/WazuhRulePackBuilder.exe` and verify it launches.
- [ ] (Optional) Manual QA pass on a staging Wazuh manager: export ransomware pack,
      `verify_rules`, feed a sample event through `wazuh-logtest`.
- [ ] (Later, per architecture.md §12) logtest harness, CDB lists, ATT&CK coverage
      heat-map, CLI headless mode.

## Environment (build machine)

- OS: Windows (bash via Git Bash), Python 3.12.7, tkinter 8.6, PyInstaller 6.22.2
- Runtime dependencies of the app: **none** (stdlib only) — that's what makes the
  single exe portable.