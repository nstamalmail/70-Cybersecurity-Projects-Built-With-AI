# LBSim - Load Balancer Simulator: State

## Status: COMPLETE (algorithms, health checker, GUI, import, reports verified)

## What this is
Load balancer simulation per `architecture.md`: round robin, weighted (smooth) WRR,
least connections, ip-hash algorithms; active health checks with fall/rise thresholds
driving a UP/DOWN state machine; traffic generator with configurable rate; distribution
and health-log views; simulation import; reports in TXT/JSON/CSV/HTML/PDF. Backends are
in-process mocks - no packets leave the machine.

## Components
- `src/lbsim/engine.py`    - SimulatedBackend (failure modes: healthy/http_500/
  conn_refused/slow), BackendPool, 4 algorithms, HealthChecker thread (fall/rise),
  TrafficGenerator thread (rps pacing), SimulationResult serialize/restore.
- `src/lbsim/reporting.py` - report dict -> TXT/JSON/CSV/HTML/PDF (handles dict or
  dataclass backends).
- `src/lbsim/theme.py`     - dark QSS theme.
- `src/lbsim/main.py`      - PySide6 GUI: Backends tab (add/edit/remove), Simulation
  tab (algorithm, health-check cfg, traffic rate + live event feed), Distribution tab,
  Health Log tab, Report tab; File > Import Simulation (JSON), File > Export Report.
- `sample_data/simulation_web_farm.json` - importable 3-backend weighted WRR run with
  a backend that falls DOWN and recovers.
- `tests/smoke_gui.py`     - algorithms + health checker + reports + import + live GUI run.

## How to run
```
cd "10. Load balancer simulator with health checks"
python src/lbsim/main.py          # GUI
python tests/smoke_gui.py         # smoke test
```

## Verified
- Round robin cycles evenly; smooth WRR yields exactly 10/10/20 over 40 picks for
  weights 1/1/2; least-connections picks the idle backend; ip-hash is sticky per IP.
- Health checker drives http_500 backend UP -> DOWN after fall_threshold; recovery
  via rise_threshold works.
- Live GUI run: 20 rps for 2s produced >0 requests, distribution table filled,
  TXT report rendered, HTML export written.
- 5 report formats from live runs and from the imported sample (2400 requests).

## Notes
- "Slow" backend passes TCP checks but fails HTTP checks (timeout) - demonstrates why
  L7 checks matter.
- Dropping the last healthy backend makes requests fail with "no healthy backends",
  logged in the event feed and counted in reports.
