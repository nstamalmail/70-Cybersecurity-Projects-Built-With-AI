# SOAR-lite Technical Memory

## Architecture Overview
SOAR-lite follows a Model-View-Controller (MVC) pattern with PySide6 for the GUI layer.

### Core Components
1. **Data Models** (`Playbook`, `PlaybookStep`, `Execution`, `StepExecution`)
2. **GUI Components** (MainWindow, Dialogs, Widgets)
3. **Worker Thread** (`ExecutionWorker` for async execution)
4. **File I/O** (YAML/JSON import/export)

## DAG Scheduling

### Directed Acyclic Graph Implementation
The playbook steps form a DAG where:
- Each node represents a step
- Edges represent execution flow (via `next` field)
- No cycles are allowed

### Topological Execution Order
```
step_1 → step_2 → step_3 → ... → step_n
```

### Parallel Execution (Future Enhancement)
Currently sequential. For parallel execution:
1. Identify steps with no dependencies
2. Execute independent steps concurrently
3. Use barrier synchronization for convergence points

### DAG Visualization
- Nodes rendered as rounded rectangles
- Colors: Blue = Action, Orange = Destructive
- Arrows connect sequential steps
- Layout calculated in `DAGViewerWidget.calculate_positions()`

## Playbook Format (YAML Schema)

### Required Fields
```yaml
name: string          # Playbook name
version: string       # Semantic version
steps:                # List of steps
  - id: string        # Unique step identifier
    name: string      # Human-readable name
    type: string      # "action" | "destructive"
    script: string    # Script/command to execute
    next: string      # ID of next step (optional)
```

### Optional Fields
```yaml
description: string
author: string
severity: low|medium|high|critical
tags: list[string]
triggers: list[trigger]
variables: dict
requires_approval: boolean  # For destructive steps
timeout: integer            # Seconds
outputs: list[string]       # Output variable names
parameters: dict            # Step parameters
dependencies: list[string]  # Step IDs that must complete first
```

### Template Variables
Use `{{variable}}` syntax for dynamic values:
- `{{incident.id}}` - Incident ID from context
- `{{step_1.output_name}}` - Output from previous step
- `{{variable_name}}` - Context variable

## Approval Workflow

### Decision Tree
```
Step requires approval?
├── No → Auto-approve → Execute
└── Yes → Show Approval Dialog
    ├── Approve → Execute
    ├── Reject → Skip Step
    └── Defer → Skip Step
```

### Approval Dialog Features
- Displays step details (name, description, type, script)
- Shows parameters in JSON format
- Shows incident context for reference
- Requires reason for approval/rejection
- Three buttons: APPROVE, REJECT, DEFER

### Thread Synchronization
```python
# Worker thread signals approval request
self.approval_requested.emit(step, context)

# Main thread shows dialog
dialog = ApprovalDialog(step, context)
dialog.exec()

# Response sent back to worker
self.current_worker.approval_response = dialog.result_action

# Worker polls for response
while self.approval_response is None:
    self.msleep(100)
```

## Rollback Logic

### Rollback Procedure
1. Identify completed steps with side effects
2. Execute inverse operations (simulated)
3. Update step status to `rolled_back`
4. Log rollback action in action log

### Rollbackable Actions
- Domain/IP blocking → Unblock
- Password reset → Notify user to reset back
- Host isolation → Remove isolation
- Email quarantine → Restore email

### Rollback Constraints
- Only completed steps can be rolled back
- Rollback order is reverse of execution order
- Dependent steps must be rolled back first
- Rollback failures logged but don't block other rollbacks

## Action Log Structure

### Log Entry Format
```json
{
  "timestamp": "ISO-8601",
  "action": "string",
  "step": "step_id",
  "method": "HTTP_METHOD",
  "url": "API_endpoint",
  "request_body": {},
  "response_code": 200,
  "response_body": {},
  "duration_ms": 1234
}
```

### Action Types
- `execute_step` - Step execution started
- `approval_granted` - Operator approved action
- `approval_rejected` - Operator rejected action
- `rollback` - Step was rolled back
- `error` - Execution error occurred

## Metrics Calculation

### Key Performance Indicators (KPIs)
1. **Total Executions:** Count of all execution records
2. **Success Rate:** (completed / total) * 100
3. **Failed Count:** Count of failed executions
4. **MTTR (Mean Time To Resolve):** Average duration of completed executions

### MTTR Formula
```
MTTR = Σ(execution_duration) / count(completed_executions)
```

### Metrics Update Triggers
- Execution completed
- Execution failed
- New execution started
- Application loaded with sample data

## Report Generation

### Supported Formats
1. **JSON:** Complete execution data with all fields
2. **CSV:** Step-by-step summary table
3. **HTML:** Styled report with CSS, viewable in browser
4. **PDF:** Via HTML export + browser print (PySide6 limitation)

### HTML Report Structure
```html
<!DOCTYPE html>
<html>
<head>
  <title>Incident Report</title>
  <style>/* Dark theme CSS */</style>
</head>
<body>
  <h1>Incident Response Report</h1>
  <div class="meta"><!-- Execution metadata --></div>
  <h2>Step Execution Details</h2>
  <table><!-- Step results --></table>
  <h2>Context</h2>
  <pre><!-- Incident context --></pre>
</body>
</html>
```

## Thread Safety

### Qt Signal/Slot Mechanism
- Worker threads emit signals for UI updates
- Main thread processes signals in event loop
- No direct UI manipulation from worker threads

### Critical Sections
- `self.approval_response` shared between worker and main thread
- Protected by polling loop with `self.msleep(100)`
- No locks needed due to Qt's event-driven architecture

## Performance Considerations

### Memory Management
- Playbooks stored in dict for O(1) lookup
- Execution records in list (append-only)
- UI tables use virtual model for large datasets

### Execution Speed
- Simulated steps use `self.msleep()` for delay
- Maximum delay capped at 3 seconds per step
- Real-world implementation would use actual API calls

### UI Responsiveness
- Execution runs in separate QThread
- UI updates via signal/slot (async)
- Progress bar updated on step completion

## Error Handling Strategy

### Error Types
1. **File I/O Errors:** YAML parsing, file not found
2. **Validation Errors:** Invalid playbook format
3. **Execution Errors:** Step failures, timeouts
4. **UI Errors:** Invalid user input

### Error Recovery
- File errors: Show error dialog, continue execution
- Validation errors: Reject invalid playbooks
- Execution errors: Mark step as failed, continue
- UI errors: Reset to default state

## Future Enhancements

### Short Term
- Database persistence (SQLite)
- Real API integrations
- Authentication system
- Audit logging

### Long Term
- Multi-user support with RBAC
- Workflow designer GUI
- Plugin architecture
- Cloud deployment (Docker)
- Real-time collaboration
- Machine learning for anomaly detection
