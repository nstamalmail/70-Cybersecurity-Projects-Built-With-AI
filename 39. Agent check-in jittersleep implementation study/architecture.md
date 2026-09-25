# Architecture — Agent Check-in Jitter/Sleep Implementation Study (GUI)

**Version:** 1.0.0 · **Date:** 2026-09-09 · **Status:** Approved for build
**Type:** Local, offline, single-user engineering study tool

---

## 1. Purpose

A transparent, observable laboratory for studying **agent check-in scheduling**: how
sleep/jitter strategies shape the *arrival pattern* of a fleet of simulated agent
check-ins against a simulated server, and how those patterns show up in
**server load**, **client drift**, and **failure/retry behavior**.

The tool exists to make scheduling behavior **visible and measurable**:

- Compare **deterministic**, **uniform jitter**, **decorrelated jitter**, and
  **full/Equal Jitter (AWS-style)** side by side.
- See the thundering-herd effect (all agents on one interval, zero jitter).
- Study retry storms under a configurable simulated failure rate.
- Inspect every event in a live log — **no hidden behavior**.

### Explicit non-goals (by design)

This tool does **not** and will never include: traffic mimicking to defeat
security controls, host/MAC/user-agent rotation, CAPTCHA solving or bypass,
stealth/evasion features of any kind, or network activity of any sort — the
"server" is a local simulation. It is a capacity-planning and scheduling study aid.

---

## 2. Technology choices

| Concern | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Single source for engine, CLI, and GUI |
| GUI | Tkinter (stdlib `tkinter`, `ttk`) | Zero binary deps, most reliable for a portable exe |
| Charts | matplotlib (Agg backend) | Render to a Tk canvas via `FigureCanvasTkAgg` |
| Packaging | PyInstaller `--onefile --noconsole` | Single portable `exe` |
| Tests | pytest | Engine logic is pure and headless-testable |
| Determinism | `random.Random(seed)` per agent + per server | Reproducible runs from the same config |

No network I/O anywhere in the codebase. One optional JSON export written on demand.

---

## 3. Module layout

```
app.py               entry point (GUI; --smoke flag for build verification)
cli.py               headless runner (CI / scripted experiments)
core/
  config.py          dataclasses for profiles; JSON (de)serialization; validation
  jitter.py          strategy classes: Fixed, Uniform, Decorrelated, EqualJitter
  server.py          simulated server: latency, failure, lockout, load buckets
  fleet.py           event-driven scheduler + agent threads; event stream
  metrics.py         per-agent stats, percentiles, drift, histogram, CSV rows
persistence/
  state.py           state.md + last-session.json (exact resume state)
  memory.py          memory.md: immutable history of every run + notes
  csvexport.py       profile-metrics CSV + per-agent stats CSV (matched pair)
  runlog.py          per-run JSON export
tests/               pytest suite for engine and persistence
build_exe.py         one-shot build script (venv -> pip -> PyInstaller)
```

Dependency direction is strict: `core` ← `persistence` ← `gui`/`cli`.
`core` has no GUI or I/O imports (JSON export helpers only).

---

## 4. Domain model

### 4.1 CheckinProfile (per agent)

| Field | Meaning |
|---|---|
| `name` | Human label, e.g. `herd-baseline` |
| `strategy` | `fixed` \| `uniform` \| `decorrelated` \| `equal` |
| `base_delay_s` | Base interval between check-ins (s) |
| `jitter_s` | Max jitter magnitude for uniform/equal (s) |
| `cap_s` | Upper bound for decorrelated growth (s) |
| `multiplier` | Decorrelated growth factor (default 3.0, AWS-recommended) |
| `startup_spread_s` | Uniform first-check-in spread to avoid boot-time herd (s) |
| `agent_count` | Number of homogeneous agents using this profile |
| `seed` | Per-agent RNG seed; agent *k* uses `seed + k` for full reproducibility |

### 4.2 ServerConfig (simulated target)

| Field | Meaning |
|---|---|
| `failure_rate` | 0.0–1.0 probability a check-in is rejected (HTTP-503 analogue) |
| `latency_ms_range` | (min, max) simulated response latency |
| `lockout_after_failures` | Consecutive-failure threshold triggering lockout; 0 disables |
| `lockout_duration_s` | Lockout window |

Server response model: `{ok, latency_ms, status, lockout_remaining_s}` —
`200` success, `503` rejected by load-shedding simulation, `429` when locked out.

### 4.3 Events

The fleet emits an ordered, timestamped event stream (the single source of truth):

- `start` / `stop` — session boundaries
- `checkin` — one attempt: agent, profile, due time, actual time, drift, response
- `retry` — attempt scheduled after a failure
- `lockout` — a server lockout opened
- `end` — run summary

Drift is defined as `actual_time - scheduled_time`, i.e. how far the real
check-in lands from the ideal schedule. Positive drift = late (thread overhead,
blocking sleep granularity, simulated processing); it is the quantity a scheduler
designer cares about.

---

## 5. Jitter strategies (the actual study material)

All strategies return a **non-negative delay ≥ `base_delay_s` floor where applicable**;
`rng` is the agent's private `random.Random`.

1. **Fixed** — `sleep(base)`. Deterministic baseline; with N agents and no startup
   spread it demonstrates the thundering herd.
2. **Uniform** — `sleep(base + U(0, jitter))`. Simple spread; mean interval grows
   by `jitter/2`.
3. **Decorrelated** (AWS-style) — `sleep(min(cap, U(base, prev * multiplier)))`.
   prev starts at `base`. Self-correcting: fast after a burst, backs off over time.
4. **Equal / full jitter** — `sleep(base/2 + U(0, jitter))` (Equal Jitter variant;
   `jitter_s` may exceed `base`, unlike the classic cap). Spreads arrivals widest
   relative to base.

Retry policy after a failed check-in: exponential backoff with uniform jitter —
`sleep(min(retry_cap, base_retry * 2^attempt) + U(0, min(retry_cap/4, base_retry * 2^attempt / 4)))`,
capped at `retry_cap_s` (default 300), unlimited attempts until success or stop.
This is intentionally visible in the log — retry storms are part of the study.

---

## 6. Simulation core

### 6.1 Time model

Wall-clock driven with a **speed multiplier** (1× real time … 100× accelerated).
The scheduler uses `time.monotonic()` mapped through the multiplier; every event
records both simulated time and wall time.

### 6.2 Fleet scheduler

Each agent runs its own thread:

```
loop until stop_event:
    delay = strategy.next_delay(rng, state)
    sleep_until(sim_now + delay)            # interruptible via stop_event
    resp = server.handle_checkin(agent_id)
    record event {scheduled, actual, drift, response}
    if not resp.ok: schedule retry via backoff strategy
```

- Sleeps are chunked (`stop_event.wait(min(0.05, remaining))`) so **Stop is
  responsive even at 100× or with 300 s sleeps**.
- The server instance is shared and thread-safe (lock around failure/lockout
  accounting) so herd arrivals genuinely contend, as they would in reality.
- Bounded in-memory ring buffer (10,000 events) for the live log; complete
  per-agent aggregates maintained separately so long runs stay cheap.

### 6.3 Server simulation

On each check-in: draw latency from `latency_ms_range`; with probability
`failure_rate` reject (503); count consecutive failures per agent and open a
lockout window when the threshold is crossed (429 during lockout). Maintains a
histogram of arrival counts per `bucket_s` (default 10 s) for the load chart.

---

## 7. Metrics

Computed incrementally per agent (O(1) per event):

- check-in count, success/failure counts, retry count
- mean/stddev/min/max of actual intervals
- drift mean/p50/p95/max
- p50/p95/p99 of **time-to-success** when retries occur
- server-side: arrivals per load bucket (for the histogram chart), rejection rate

Charts (matplotlib, embedded):

1. **Arrival histogram** — check-ins per bucket over time (herd = spikes).
2. **Drift scatter** — per check-in drift vs time (thread/sleep realism).
3. **Interval distribution** — histogram of realized intervals vs the nominal
   base (shows what each jitter strategy actually does to the mean).

---

## 8. Persistence

### 8.1 `state.md` — current snapshot (overwritten every save)

YAML-ish front section: version, timestamps, config fingerprint (sha256 of the
serialized config), run counter, and the **complete last-session state**: full
profile list, server config, elapsed sim time, total events, and per-profile
metric totals — plus a resume hint. Companion `state/last-session.json` carries
the same data machine-readably.

### 8.2 `memory.md` — append-only history

Every completed run appends a dated entry: config fingerprint, profiles used,
duration, totals, and headline metrics (mean interval, p95 drift, rejection
rate). Followed by a `## Notes` section the user edits freely. The file is
append-only; nothing is ever removed, giving a durable cross-session record.

### 8.3 Run exports

`runs/run_YYYYMMDD-HHMMSS.json` — full event stream + config + computed metrics,
for offline analysis. Written on demand from the GUI/CLI.

### 8.4 CSV exports

Exported as a matched pair sharing one run id:

- `runs/metrics_<id>.csv` — one row per profile, mirroring the GUI Metrics tab
  (checkins, successes, failures+retries, interval mean/std, drift p50/p95/max).
- `runs/agents_<id>.csv` — one row per agent via `AgentMetrics.stat_row()`:
  raw counters with **failures and retries reported separately**, plus interval
  min/max, drift mean/p50/p95/max, and attempts-to-success p50/p95.

`None` metrics render as empty cells (never the string `None`). Written atomically.
GUI: **Export CSV** button (timestamped pair in `runs/`) or **File → Export CSV
As…** (Ctrl+E) — a save dialog picks the base name/location and the pair is
written as `<base>_metrics.csv` + `<base>_agents.csv` (`split_base` tolerates a
missing extension or an existing `_metrics`/`_agents` suffix). CLI: `--csv`.

---

## 9. GUI layout (Tkinter)

```
┌ Toolbar: ▶ Start ■ Stop 💾 Save state  📄 Export JSON ─ Speed [1×|10×|100×] ┐
├ Left panel (Profiles)              │  Right panel (Tabs)                    │
│  • profile list + editor form      │  ┌ Live Log ┐ Metrics ┃ Charts ┃     │
│  • strategy combo, delay/jitter/   │  │ timestamped, filterable           │
│    cap/count/seed fields           │  │ ring buffer, pause/resume         │
│  • server settings group           │  └──────────┘                         │
│  • seed + duration controls        │  Metrics: table per profile/agent     │
├ Status bar: sim clock, events,     │  Charts: 3 embedded matplotlib figs   │
│  state file path                   │                                       │
└────────────────────────────────────────────────────────────────────────────┘
```

Threading rules: engine threads never touch Tk. The GUI polls a
`queue.Queue` at 100 ms and drains events onto the log/metrics/charts.
Charts re-render at most once per second (debounced).

---

## 10. Error handling & validation

- All numeric fields validated on Start (ranges, `jitter ≥ 0`, `cap ≥ base` when
  the strategy needs it, `agent_count ≥ 1`, seeds unique per profile).
- Engine errors are captured per agent thread, logged, and surfaced in the status
  bar — a crashing agent never takes down the GUI.
- Persistence writes are atomic (write temp + `os.replace`).

---

## 11. Testing strategy

- **Unit (pytest):** each jitter strategy's statistical properties (bounds, mean
  shift, reproducibility under fixed seed); server failure/lockout accounting;
  metrics math (percentiles on known inputs); state round-trip (save → load →
  identical config); memory append-only behavior.
- **Smoke:** `python app.py --smoke` runs the engine headless for ~2 s, writes
  state/memory/run JSON, exits 0 — used post-build to verify the exe.
- **Manual GUI checklist** in README.

---

## 12. Build & distribution

`build_exe.py`:
1. Ensure a clean `.build-venv`
2. `pip install pyinstaller matplotlib`
3. `pyinstaller --onefile --noconsole --name AgentCheckinLab --collect-subplots matplotlib app.py`
4. Verify `dist/AgentCheckinLab.exe` exists; print size and SHA-256.

Result: a single portable `AgentCheckinLab.exe` (~25–45 MB). No installer, no
admin rights, no network. First launch may be slower (onefile self-extraction).

---

## 13. Roadmap

- ~~v1.1: CSV export of metrics~~ — shipped (profile CSV + per-agent CSV)
- v1.2: A/B compare mode (two profiles overlaid on one chart); config import/export from the GUI.
- v2.0: plugin interface for user-defined strategies.
