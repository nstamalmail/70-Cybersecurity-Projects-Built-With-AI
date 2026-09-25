# Architecture — Custom Wazuh/OSSEC Detection Rule Pack Builder

> A GUI-based desktop tool that lets a security analyst design a specific **attack chain**,
> map each technique to Wazuh/OSSEC detection rules, and generate a **validated, deployable
> rule pack** (rules XML, decoders XML, deployment README) — all without hand-editing XML.

**Author role:** Senior Security Developer / Detection Engineering
**Target platform:** Windows (portable single-file exe), Python 3.12
**Compatibility target:** Wazuh 4.x / OSSEC 3.x (`/var/ossec/etc/rules`, `decoders`)

---

## 1. Problem Statement

Writing Wazuh/OSSEC detection rules by hand is error-prone:

- Rule IDs collide across packs or fall outside the reserved ranges.
- XML is malformed → the whole ruleset fails to load and **all detection silently stops**.
- MITRE ATT&CK mappings (`<mitre>`) are inconsistent or missing → poor SOC triage.
- Rules are not tied to an explicit **attack chain**, so coverage gaps go unnoticed.
- Decoders (regex + prematch + order) are written blind and never validated.

The tool solves this by treating a rule pack as a **structured, chain-oriented model**
that is *rendered* to XML and *validated* before export.

## 2. Design Goals

| Goal | How it is met |
|---|---|
| Attack-chain-centric authoring | Chain → Step → Technique → Rule hierarchy, with MITRE ATT&CK mapping at every level |
| Zero hand-written XML | All XML is rendered from the model by one generator module |
| Fail-safe validation | Pack cannot be exported until validation passes (IDs, levels, regex, XML well-formedness, MITRE IDs) |
| Portable & dependency-free | Pure Python stdlib (tkinter + xml + re + zipfile); single-file exe via PyInstaller |
| Reproducible | Projects save/load as JSON; built-in preset chains for common attacks (ransomware, webshell, credential dumping, lateral movement) |
| Analyst-friendly output | Exported pack ships with a deployment README and an optional `ossec.conf` include snippet |

## 3. Domain Model (the "Rule Pack" abstraction)

```
AttackChain  (name, description, metadata)
 └── AttackStep[]       (phase of the chain, e.g. "Execution")
      └── AttackTechnique[]  (a MITRE technique, e.g. T1059.003 PowerShell)
           └── DetectionRule[]   (one or more Wazuh rules detecting that technique)
                └── RuleCondition  (match | regex | field | frequency)
CustomDecoder[]          (regex-based decoders for non-standard log formats)
PackOptions              (base rule ID, group name, output dir, rule file name)
```

### 3.1 DetectionRule — the unit of detection

| Field | Type | Wazuh mapping | Validation |
|---|---|---|---|
| `rule_id` | int | `<rule id="...">` | In user range (default 100000–200000), no duplicates in pack |
| `level` | int | `<level>` | 0–16 (0 = ignore, 16 = top severity) |
| `groups` | list[str] | `<group name="a,b">` | Non-empty; comma-joined |
| `description` | str | `<description>` | Non-empty |
| `decoder` | str | `<decoded_as>` / decoder name | Must exist in built-in list or in the pack's custom decoders |
| `condition` | enum | see below | — |
| `field_name` | str | `<field name="...">` | Required when condition is `field` |
| `pattern` | str | `match` / `regex` / `<field>` content | Must compile (regex), non-empty |
| `frequency` / `timeframe` | int | `<frequency>/<timeframe>` | > 0 when condition is `frequency`; frequency>1 |
| `mitre_id` | str | `<mitre><id>` | `^T\d{3,4}(\.\d{3})?$` |
| `mitre_tactic` | str | `<mitre><tactic>` | From ATT&CK tactic enum |

**Condition → XML mapping (single source of truth in `generators.py`):**

| Condition | Rendered as |
|---|---|
| `match` | `<match>`pattern`</match>` |
| `regex` | `<regex type="pcre2" >pattern</regex>` |
| `field` | `<field name="FIELD" type="pcre2">pattern</field>` |
| `frequency` | `match`/`field` condition + `<frequency>N</frequency><timeframe>M</timeframe>` |

Every rule is wrapped in the pack's `<group>` and carries `<mitre>` if both id and tactic are set.

### 3.2 CustomDecoder

`name`, `prematch` (anchor regex), `regex` (capture groups), `order` (comma-separated field
names matching capture groups), optional `parent` (e.g. `syslog`). Rendered as:

```xml
<decoder name="my_app">
  <prematch>\w+ \d+ \d+:\d+:\d+ \w+ myapp</prematch>
  <regex>\s+user='(\S+)' action=(\S+) path="(\S+)"</regex>
  <order>user, action, path</order>
</decoder>
```

## 4. Component Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                         main.py (entry)                          │
│   boot: build Tk root → load default preset → MainWindow → loop  │
└───────────────────────────────┬──────────────────────────────────┘
                                │
┌───────────────────────────────▼──────────────────────────────────┐
│                       app/ui/main_window.py                       │
│   ttk.Notebook:  Chain | Rules | Generators | Preview | Deploy    │
│   Menu: File (new/load/save/export/exit)   Status bar            │
└───────┬───────────────┬───────────────┬──────────────┬───────────┘
        │               │               │              │
   chain_tab        rule_tab      generator_tab   preview_tab / deploy_tab
        │               │               │              │
        └───────────────┴───────┬───────┴──────────────┘
                                │  (all tabs mutate the SAME model)
┌───────────────────────────────▼──────────────────────────────────┐
│                        app/models.py (dataclasses)                │
│   AttackChain / AttackStep / AttackTechnique / DetectionRule /    │
│   CustomDecoder / PackOptions   ← in-memory single source of truth│
└───────┬───────────────────────┬───────────────────┬──────────────┘
        │                       │                   │
┌───────▼──────────┐   ┌────────▼─────────┐  ┌──────▼──────────────┐
│ app/validator.py │   │ app/generators.py │  │ app/persistence.py │
│ static checks +  │   │ XML rendering,    │  │ project JSON       │
│ XML round-trip   │   │ pack assembly,    │  │ save/load          │
│ (returns issues) │   │ zip export, README│  │                    │
└───────┬──────────┘   └────────┬─────────┘  └────────┬───────────┘
        │                       │                     │
        └─────────── app/presets.py: built-in attack chains ───────┘
```

### 4.1 Layers and responsibilities

| Layer | Module | Responsibility |
|---|---|---|
| **UI** | `app/ui/*` | Event handling, form<->model binding, tree views, preview rendering. **No XML logic.** |
| **Domain** | `app/models.py` | Typed dataclasses; `to_dict/from_dict` for persistence; convenience accessors (`all_rules()`, `rule_ids()`). |
| **Domain** | `app/presets.py` | Pre-baked attack chains (MITRE-mapped) so users start from expert content. |
| **Service** | `app/generators.py` | The only place XML strings are produced. Functions: `render_rules_xml`, `render_decoders_xml`, `render_ossec_snippet`, `render_readme`, `build_pack_zip`, `pack_summary`. |
| **Service** | `app/validator.py` | `validate_pack(chain, decoders, options) -> list[Issue]`; each issue = (severity, rule ref, message). Pure functions, unit-testable. |
| **Service** | `app/persistence.py` | Versioned JSON project format, atomic writes, load-time schema migration hooks. |
| **Entry** | `main.py` | Bootstrap + `if __name__ == "__main__"` guard (required for PyInstaller). |

### 4.2 UI data-flow

1. Chain tab edits the hierarchy (add/rename/delete steps & techniques).
2. Rules tab edits `technique.rules` (table + form bound to one selected rule).
3. Generators tab runs `validate_pack()` → shows issues → `build_pack_zip()` on success.
4. Preview tab re-renders `render_rules_xml` + `render_decoders_xml` live.
5. Save/Load serializes the **entire model** (chain + decoders + options) to JSON.

No tab caches a second copy of the model — the tabs are thin controllers over the
model, so save/export/preview can never disagree with what the user sees.

## 5. Generation Pipeline

```
validate_pack()
  ├─ duplicate rule IDs across pack
  ├─ level ∈ [0,16]
  ├─ groups non-empty, sane characters
  ├─ regex/pcre2 patterns compile (re.compile with fallback)
  ├─ frequency/timeframe consistency
  ├─ MITRE id format + tactic from enum
  ├─ decoder references resolve (builtin ∪ custom)
  └─ XML round-trip: render → ElementTree.fromstring → issues on failure
          │ (pass)
          ▼
build_pack_zip(chain, decoders, options)
  ├─ local_rules.xml      (group-wrapped rules, ordered by chain order)
  ├─ local_decoders.xml   (custom decoders)
  ├─ ossec.conf.snippet   (3 lines: <include> entries)
  ├─ README.md            (deployment steps, verification commands, rule list table)
  └─ rules.csv            (machine-readable rule inventory for SIEM dashboards)
  └─ pack-<name>.zip
```

XML is built with `xml.etree.ElementTree` + `ET.indent()` → guaranteed well-formed,
consistent 2-space indentation, and escape-safe content. Rule order in the file mirrors
the chain order, so the file reads like the attack narrative.

### Rule ID strategy
- Default base range **100000–199999** (above Wazuh's shipped rules, below common local
  ranges that collide with other teams). Analyst picks base, generator assigns
  `base + technique_offset + rule_index` deterministically → stable across saves.

## 6. Validation Rules (fail-safe export)

Export is **blocked** while any `ERROR`-severity issue exists; warnings are shown but allowed.

| Check | Severity |
|---|---|
| Duplicate rule ID | ERROR |
| `level` out of 0–16 | ERROR |
| Empty groups / description | ERROR |
| Invalid regex (compile failure) | ERROR |
| MITRE id not `T####[.###]` | ERROR |
| Unknown decoder reference | ERROR |
| frequency or timeframe ≤ 0 | ERROR |
| Empty chain (0 rules) | ERROR |
| Technique with zero rules | WARNING |
| Rule not mapped to MITRE | WARNING |
| Rules sharing identical pattern+decoder (possible dupe) | WARNING |

## 7. Built-in Preset Attack Chains

Expert-authored starting points, each fully MITRE-mapped:

1. **Ransomware Kill Chain** — phishing → PowerShell/cmd → persistence (run keys,
   services) → UAC bypass → shadow-copy deletion → LSASS/SAM credential access →
   discovery → SMB lateral movement → C2 → encryption impact. (~20 rules)
2. **Webshell & RCE** — suspicious upload paths, `cmd.exe`/`/bin/sh` from web user,
   encoded payloads, webshell file creation, reverse-shell beaconing.
3. **Credential Dumping** — Mimikatz/LSASS access, `sekurlsa`, registry `SAM` reads,
   `procdump` of `lsass`, PowerShell `Invoke-Mimikatz`.
4. **Lateral Movement** — `net use \\host`, SMB admin-share writes, `psexec`/WMI
   remote process creation, RDP logons, service install on remote hosts.

Each preset = `AttackChain` + matching `CustomDecoder`s where needed.

## 8. UI Design

Single window, `ttk.Notebook` with five tabs, status bar, menu bar.

1. **Attack Chain** — left: tree (`Step ▸ Technique`); right: forms + Preset loader
   combo + add/remove/edit buttons.
2. **Rules** — top: rule table (ID, Level, Groups, Condition, Pattern, MITRE); bottom:
   detail form. Add / Update / Delete / Duplicate.
3. **Generators** — decoder list + decoder form (name/prematch/regex/order); pack
   options (base ID, group name, output dir); **Validate** and **Export pack (zip)**;
   issue list with severity coloring.
4. **Preview** — read-only monospace pane with **Refresh**; tabs to flip between
   `local_rules.xml` / `local_decoders.xml` / `ossec.conf.snippet`.
5. **Deploy** — rendered README with per-step instructions and a **Copy** button.

Design decisions:
- **tkinter/ttk only** — zero runtime dependencies ⇒ trivially portable exe, no
  version-skew surprises on analyst machines; consistent with enterprise tooling policy.
- Model mutations go through small controller methods that re-sync the visible tabs.
- All destructive actions (delete step/rule, overwrite export) confirm via dialog.

## 9. Packaging & Distribution

- **PyInstaller** one-file, windowed build (`--onefile --windowed`), spec kept in repo
  (`WazuhRulePackBuilder.spec`) so builds are reproducible.
- `build_exe.bat` (Windows) and `build_exe.sh` (CI/Linux) wrap PyInstaller.
- Output: `dist/WazuhRulePackBuilder.exe` — runs on Windows 10/11 x64, **no Python
  install required**, writes nothing outside its own directory.
- Artifact hygiene: PyInstaller `build/` and `dist/` are git-ignored; the exe is
  regenerated from the spec at release time.

## 10. Security Considerations (of the tool itself)

- The tool only ever **writes** XML/zip to a user-chosen output dir; it never touches
  the Wazuh manager (no agent install, no remote calls) → safe to run on analyst
  workstations, including air-gapped ones.
- Pattern strings from the analyst are only compiled locally for validation; they are
  escaped by ElementTree during XML rendering → no XML injection into the pack.
- Project files are plain JSON with no execution content; loading a project cannot run
  code.
- README instructs users to validate on a **staging** manager first
  (`wazuh-logtest` / `ossec-logtest`), then roll out.

## 11. Testing Strategy

| Level | Approach |
|---|---|
| Unit (headless) | `tests/` using stdlib `unittest`: validator checks, generator round-trip (render → parse → fields match), persistence round-trip, preset integrity (every technique has ≥1 rule, all MITRE ids valid). |
| GUI smoke | Instantiate `Tk` withdrawn, build `MainWindow`, destroy — verifies widget tree constructs. |
| Pack E2E | Generate the ransomware preset to a temp dir, assert zip contains 5 files, XML parses, README contains deploy steps. |
| Manual | Run exe → load preset → validate → export → inspect on a staging Wazuh manager with `ossec-logtest`. |

## 12. Roadmap / Non-goals (v1)

**v1 (this build):** chain designer, rule & decoder editors, validation, preview,
zip export, project save/load, 4 presets, portable exe.

**Later:** rule testing harness against sample logs (`ossec-logtest` integration),
CDB lists, active-response blocks, multi-pack merge/diff, ATT&CK coverage heat-map,
CLI headless mode for CI.

**Non-goals:** agent/manager installation, live log ingestion, SIEM dashboards.