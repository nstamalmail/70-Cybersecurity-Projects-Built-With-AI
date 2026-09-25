# Memory — Wazuh/OSSEC Rule Pack Builder

> Persistent context for future sessions: decisions, rationale, conventions and
> gotchas. Read this before continuing work on the project.

## Project one-liner

GUI desktop app (Python + tkinter, zero runtime deps) that lets a blue-team analyst
design a specific **attack chain**, map each MITRE ATT&CK technique to
Wazuh/OSSEC **detection rules**, and **validate + export** a deployable rule pack
(rules XML, decoders XML, ossec.conf snippet, README, CSV inventory) as a zip —
plus a single-file portable `.exe`.

## Key decisions (and why)

| Decision | Choice | Why |
|---|---|---|
| GUI framework | **tkinter/ttk, stdlib only** | Portable exe with zero dependency risk; consistent with enterprise tooling policy. No pip installs on analyst machines. |
| XML strategy | Render from model with `xml.etree.ElementTree` + `ET.indent()` | Guaranteed well-formed/escape-safe output; `generators.py` is the *only* module that touches XML. |
| Validation gates export | ERROR-severity issues **block** export | A malformed ruleset silently kills all detection on a manager; fail-safe by design. |
| Rule ID range | Default base **100000** (100000–199999) | Above Wazuh's shipped rules; deterministic assignment `base + offset`. |
| MITRE mapping | `mitre_id` + `mitre_tactic` on every rule | Wazuh 4.x `mitre.id`/`mitre.tactic` elements; drives SOC triage and coverage review. |
| Attack chain model | Chain → Step → Technique → Rule (4 levels) | Mirrors Cyber Kill Chain + ATT&CK; file order = attack narrative. |
| Presets | 4 expert chains shipped in code | Analysts start from vetted content, not blank pages. |
| Project persistence | Versioned JSON, atomic write (temp file + `os.replace`) | Load can never run code; no corrupt half-writes. |
| Packaging | PyInstaller one-file windowed via committed `.spec` | Reproducible builds; `build/` + `dist/` are regenerable artifacts. |

## Conventions

- **Modules:** UI in `app/ui/`, domain in `app/models.py`, content in
  `app/presets.py`, services in `generators.py` / `validator.py` / `persistence.py`.
- **Tabs are controllers**: they mutate the single shared `RulePackProject`
  (`MainWindow.project`) and call `app.on_model_changed(msg)`; MainWindow then
  refreshes every tab + status bar. Never cache a second copy of the model.
- **Rule conditions** (enum `ConditionType`): `match`, `regex`, `field`,
  `frequency` (base match/field + `<frequency>/<timeframe>`).
- **Groups** stored as list, rendered comma-joined.
- Tests: stdlib `unittest`, headless (no display needed).
- Doc files: `architecture.md` (design), `state.md` (build status), `memory.md` (this file).

## Gotchas learned (avoid re-hitting these)

1. **XML comments can't contain `--`.** Any comment text must be sanitized
   (`_comment()` in generators.py). ElementTree happily *emits* invalid comments;
   the parser rejects them at round-trip.
2. **tkinter on Windows**: `ttk.Treeview` column headers must be a subset of the
   `columns` tuple — a stray `id` heading threw `TclError: Invalid column index`.
3. **PyInstaller windowed mode** needs `if __name__ == "__main__":` in `main.py`
   and `console=False` in the spec (no traceback console for users).
4. **Windows console encoding** mangles `·`/unicode in `print()` output — cosmetic
   only; the GUI renders it fine (use Segoe UI fonts in widgets, `Consolas` in preview).
5. Bash on Windows: use POSIX paths in commands; `python` on PATH here is 3.12.

## Content quality bar (for future rule/preset authors)

- Every technique must have ≥ 1 rule and a valid `T####[.###]` id.
- Patterns must be realistic for the *decoder* chosen (e.g. don't match Windows
  CLI text under `web-accesslog`).
- Ransomware-style impact rules should sit at level 12–15; informational
  discovery at 3–6.
- `frequency` rules need `frequency > 1` and `timeframe > 0` (seconds).
- Rule IDs within a pack must be unique — validator enforces this.

## External context

- **Wazuh rule schema** (4.x): `<rule id level group><decoded_as/></rule>` with
  `<match>`, `<regex type="pcre2">`, `<field name="">`, `<frequency>/<timeframe>`,
  `<mitre><id>/<tactic></mitre>`.
- **Decoders**: `<decoder name><prematch><regex><order></decoder>`; the `order`
  fields must match the regex capture groups.
- **Deployment**: copy to `/var/ossec/etc/rules/`, add `<include>` to
  `ossec.conf`, `verify_rules`, restart manager, test with `wazuh-logtest`.
- Wazuh docs: https://documentation.wazuh.com/current/user-manual/ruleset/