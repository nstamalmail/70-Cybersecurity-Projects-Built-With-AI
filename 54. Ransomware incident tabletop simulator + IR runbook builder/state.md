# State - Ransomware Tabletop Simulator + IR Runbook Builder

## Current State: v1.0 Complete

### Features Implemented
- Dual-mode: Tabletop Simulator and IR Runbook Builder
- Exercise configuration and scenario management
- Inject library with 12 pre-built ransomware injects
- Live simulation control with phase-based inject delivery
- Decision recording with timestamp and phase tracking
- Action item capture
- IR Runbook editor with NIST CSF / CISA alignment
- Runbook validation
- Gap analysis with recommendations
- Multi-format report export (JSON, CSV, TXT, HTML)
- Professional dark-themed tkinter GUI

### Tabs (Simulator Mode)
1. **Exercise** - Configure exercise name, facilitator, scenario
2. **Injects** - Browse inject library, add to exercise
3. **Simulation** - Live inject delivery, decision recording
4. **Report** - Preview and export exercise report

### Tabs (Runbook Mode)
1. **Runbook** - Edit runbook sections, NIST alignment
2. **Gap Analysis** - Identify gaps against NIST/CISA frameworks
3. **Report** - Preview and export runbook report

### Known Limitations
- Inject delivery is manual (not timed/scheduled)
- No multi-player network simulation
- Gap analysis is static (not dynamic based on runbook content)
- No automated compliance scoring
- Decision recording via simple dialog (no voting/consensus)

### File Inventory
- `app.py` - Main application (tkinter GUI)
- `state.md` - This file (NOTE: directory misspelled as "artchitecture.md")
- `memory.md` - Architecture notes
- `build_exe.bat` - PyInstaller build script
