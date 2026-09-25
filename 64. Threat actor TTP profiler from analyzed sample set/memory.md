# Memory: TTP Profiler

## Key Design Decisions

1. **Shared infrastructure**: Uses the same reporting.py, shell.py, widgets.py, theme.py as other workbench tools
2. **Demo fixtures**: All fixtures are synthetic, generated in memory - no live samples needed
3. **Pattern engine**: Domain-specific patterns with glob matching and gap constraints
4. **Report formats**: HTML (styled), PDF (Qt-rendered), JSON, CSV, Markdown
5. **Portable data**: All state stored in `data/` next to executable, falling back to LOCALAPPDATA

## Implementation Notes

- The engine parses Cuckoo/CAPE JSON reports (v1/v2)
- Demo fixtures exercise the full analysis pipeline
- SQLite WAL mode for concurrent read/write
- All charts drawn with QPainter (no plotting dependency)

## Extension Points

- Add new detection patterns in `app/core/detection.py`
- Add new views in `app/ui/views.py`
- Add new demo fixtures in `app/demo.py`
- Export formats configured in `app/reporting.py`
