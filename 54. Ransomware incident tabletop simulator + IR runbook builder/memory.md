# Memory - Ransomware Tabletop Simulator + IR Runbook Builder

## Architecture Notes

### Design Decisions
- Dual-mode app with radiobutton toggle between Simulator and Runbook
- Inject library pre-populated with realistic ransomware scenario injects
- NIST Cybersecurity Framework alignment (Identify/Protect/Detect/Respond/Recover)
- CISA Ransomware Guide alignment for runbook sections
- Gap analysis provides actionable recommendations

### Data Model
```
Exercise: { name, type, date, facilitator, participants, scenario, phases[], status }
Inject: { id, phase, title, description, severity }
Decision: { time, decision, phase }
ActionItem: { time, action, status }
Runbook: { title, version, aligned_to[], sections[] }
RunbookSection: { title, aligned_to, steps }
GapItem: { category, current_state, required, gap_level, recommendation }
```

### Phase Model (Tabletop)
1. **Detection** - Initial alert/observation of suspicious activity
2. **Escalation** - Confirming incident, notifying leadership
3. **Decision** - Making containment/payment/notification decisions
4. **Recovery** - Restoring systems and returning to normal operations

### Inject Library
- 12 pre-built injects covering all 4 phases
- Mix of technical, communication, and legal injects
- Severity levels: Critical, High, Medium
- Custom inject creation supported

### Framework Alignment
- **NIST CSF**: Identify, Protect, Detect, Respond, Recover
- **CISA Ransomware Guide**: Preparation, Detection, Containment, Eradication, Recovery, Post-Incident
- Runbook sections map to both frameworks simultaneously

### Export Formats
- **JSON**: Full structured exercise/runbook data
- **CSV**: Tabular view of decisions, actions, gaps
- **TXT**: Formatted plain text report
- **HTML**: Styled dark-theme report with severity color coding
