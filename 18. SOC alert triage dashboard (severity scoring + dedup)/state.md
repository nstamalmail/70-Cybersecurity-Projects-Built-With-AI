# SOC Alert Triage Dashboard - Application State

## Runtime State Model

### Global State
- `alerts`: list[dict] - All loaded alerts (normalized)
- `groups`: dict[str, list[dict]] - Alerts grouped by `group_id`
- `selected_alert_id`: str | None - Currently selected alert in inbox
- `selected_group_id`: str | None - Currently viewed group
- `triage_queue`: list[str] - Alert IDs assigned to current analyst
- `suppression_rules`: list[dict] - Active suppression rules
- `resolved_alerts`: list[str] - IDs of resolved alerts
- `suppressed_alerts`: list[str] - IDs of suppressed alerts
- `escalated_alerts`: list[str] - IDs of escalated alerts

### CTI State
- `cti_data`: dict - Loaded CTI enrichment data (campaigns + IOC lookups)
- `ioc_cache`: dict[str, dict] - IOC lookup results keyed by IOC string

### Metrics State
- `metrics`: dict - SOC metrics (MTTT, MTTR, alert backlog, etc.)
- `triage_start_times`: dict[str, datetime] - When triage started for each alert
- `resolution_times`: dict[str, timedelta] - Time to resolve each alert

### UI State
- `current_tab`: str - Active main tab
- `severity_filter`: str - Current severity filter
- `status_filter`: str - Current status filter
- `source_filter`: str - Current source filter

## Data Flow

1. **Load Demo Data** → `load_sample_data()` → populates `alerts`, `groups`, `cti_data`
2. **Import Alerts** → `import_alerts(file)` → normalizes + appends to `alerts`
3. **Select Alert** → `on_alert_selected(row)` → updates `selected_alert_id`, shows details
4. **Triage Action** → `assign/escalate/resolve/suppress()` → updates alert status + metrics
5. **Apply Suppression** → `apply_suppression_rules()` → checks rules against all alerts
6. **Export** → `export_report(fmt)` → generates JSON/CSV/HTML/PDF from current state
