# SOAR-lite Application State Documentation

## Current State
**Status:** Production Ready
**Version:** 1.0
**Last Updated:** 2026-09-21

## Application Overview
The Automated Incident Response Playbook Runner (SOAR-lite) is a PySide6-based GUI application designed for managing and executing incident response playbooks in a Security Operations Center (SOC) environment.

## State Components

### 1. Playbook Library State
- **Storage:** In-memory dictionary (`self.playbooks`)
- **Key:** Playbook name (string)
- **Value:** Playbook object containing metadata, steps, and configuration
- **Persistence:** Playbooks loaded from YAML files in `sample_data/` directory on startup
- **Operations:** Import, export, browse, select for execution

### 2. Execution State
- **Storage:** List of execution records (`self.executions`)
- **Current Execution:** Reference to active execution (`self.current_execution`)
- **Worker Thread:** Active execution worker (`self.current_worker`)
- **States:**
  - `pending` - Execution created but not started
  - `running` - Execution in progress
  - `completed` - All steps executed successfully
  - `failed` - Execution failed at some step
  - `cancelled` - Execution stopped by user

### 3. Step Execution States
- **Pending:** Step waiting to be executed
- **Running:** Step currently executing
- **Completed:** Step finished successfully
- **Failed:** Step encountered an error
- **Skipped:** Step skipped (approval rejected or deferred)
- **Rolled_back:** Step action was undone

### 4. Approval Workflow States
- **Auto-approved:** Non-destructive steps (no approval needed)
- **Pending:** Awaiting operator approval
- **Approved:** Operator approved the action
- **Rejected:** Operator rejected the action
- **Deferred:** Operator deferred the decision

### 5. UI State
- **Current Tab:** Active tab in the main tab widget
- **Selected Playbook:** Currently selected playbook in library
- **Console Output:** Live execution log
- **Metrics:** Aggregated execution statistics

## Data Flow

```
User Input → Incident Context → Playbook Selection → Execution
    ↓
Approval Dialog (if destructive) → Approval Decision
    ↓
Step Execution → Console Output → Step Status Update
    ↓
Completion → Metrics Update → Report Generation
```

## State Transitions

### Execution Lifecycle
1. User selects playbook and enters incident context
2. User clicks "Execute Playbook"
3. Execution object created with `pending` state
4. Worker thread starts, state changes to `running`
5. Each step transitions: pending → running → completed/failed/skipped
6. Destructive steps trigger approval dialog
7. On completion, state changes to `completed`
8. Metrics and history tables updated

### Rollback Lifecycle
1. User views completed steps in Rollback Viewer
2. User clicks "Rollback" button for a step
3. Confirmation dialog displayed
4. On confirmation, step status changes to `rolled_back`
5. Rollback action logged in action log

## Memory Management
- Playbooks stored in dictionary for O(1) lookup
- Execution records stored in list (append-only)
- Worker threads properly managed with start/stop/pause
- UI updates queued via Qt signals (thread-safe)

## Error Handling
- YAML parsing errors caught and displayed to user
- File I/O errors handled with error dialogs
- Execution failures logged and displayed in console
- Thread safety ensured via Qt signal/slot mechanism

## Persistence
- Application state is NOT persisted between sessions
- All data loaded from sample_data/ on startup
- Reports can be exported to JSON/CSV/HTML/PDF
- Manual playbook import creates new entries in memory

## Known Limitations
- No database persistence (in-memory only)
- No multi-user support
- Simulated execution (not real API calls)
- No authentication/authorization
- No workflow persistence across restarts
