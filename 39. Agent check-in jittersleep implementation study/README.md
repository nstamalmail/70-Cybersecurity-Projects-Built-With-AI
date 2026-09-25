# Agent Check-in Jitter/Sleep Study Lab

A local, offline GUI laboratory for studying **agent check-in scheduling**: how
sleep/jitter strategies shape the arrival pattern of a simulated agent fleet,
and how those patterns show up in server load, client drift, and retries.

Built from `architecture.md`. Pure study tool — no network activity; the
"server" is a local simulation, and all behavior is visible in the live log.

## Quick start

```
python app.py                 # GUI
python app.py --smoke         # headless sanity run, exits 0
python cli.py --demo --csv    # headless demo + CSV export
python -m pytest tests/ -q    # test suite (29 tests)
```

Portable exe: `dist/AgentCheckinLab.exe` — single file, no install, no admin.
Double-click to open the GUI; run `AgentCheckinLab.exe --smoke` in a terminal
for a headless self-test (writes `state.md` / `memory.md` next to the cwd).

## Layout

| Path | Role |
|---|---|
| `architecture.md` | Design doc — read this first |
| `app.py` | GUI entry point (+ `--smoke`) |
| `cli.py` | Headless runner for scripted experiments |
| `gui.py` | Tkinter UI: profile editor, live log, metrics, charts |
| `core/` | Engine: config, jitter strategies, simulated server, fleet scheduler, metrics |
| `persistence/` | `state.md` (current snapshot), `memory.md` (append-only history), `runs/*.json`, CSV export |
| `tests/` | pytest suite |

## Jitter strategies

- `fixed` — deterministic `base`; with zero startup spread this is the thundering-herd demo
- `uniform` — `base + U(0, jitter)`; mean interval = base + jitter/2
- `decorrelated` — `U(base, min(cap, prev × multiplier))` (AWS-style, self-correcting)
- `equal` — `base/2 + U(0, jitter)`; widest spread relative to base

Retries use exponential backoff with uniform jitter, capped at 300 s.

## Key metrics

- **Interval mean/std** — realized spacing vs nominal base
- **Drift p50/p95/max** — how late check-ins land vs schedule (thread/sleep realism)
- **Server totals** — arrivals per bucket, rejections (503), lockouts (429)

## GUI walkthrough

1. Left panel: edit one or more profiles (strategy, delays, agent count, seed);
   configure the simulated server (failure rate, lockout) below.
2. Toolbar: **Start** / **Stop**; speed multiplier 0.1–100×; duration
   (0 = until stopped); global seed. Same seed + same config = identical run.
3. **Live log** tab streams every check-in/retry/lockout with drift and status.
4. **Metrics** tab shows per-profile aggregates, refreshed live.
5. **Charts** tab: arrival histogram (herd = spikes), drift scatter, interval
   distribution. Charts refresh at most once per second.
6. **Save state** writes `state.md` + `state/last-session.json`; **Load state**
   restores profiles. Stopping a run appends to `memory.md` automatically.
7. **File → Export CSV As…** (Ctrl+E) — pick a base name/location; writes
   `<base>_metrics.csv` + `<base>_agents.csv` there. The toolbar **Export CSV**
   button writes the same pair to `runs/` with a timestamped id.

## Persistence contract

- `state.md` — overwritten on every save; current config + last-session metrics.
- `memory.md` — append-only; one dated entry per completed run + a Notes section
  you can edit freely. Never pruned.
- `runs/run_<id>.json` — full event stream + config + summary per run.
- `runs/metrics_<id>.csv` + `runs/agents_<id>.csv` — exported together as a
  matched pair (same run id): one row per profile, and one row per agent with
  raw counters (failures and retries reported separately). Empty cell = metric
  not yet observed (e.g. an agent with fewer than two successes has no interval
  stats). Written by the GUI's **Export CSV** button, **File → Export CSV As…**
  (user-chosen base name; `_metrics`/`_agents` suffixes are derived), or
  `cli.py --csv`.

## Rebuild the exe

```
pyinstaller --noconfirm --clean --onefile --noconsole --name AgentCheckinLab app.py
```

Requires Python 3.10+, matplotlib, PyInstaller. Then verify with
`dist/AgentCheckinLab.exe --smoke`.

## Scope note

This tool deliberately contains no traffic-mimicking, host/fingerprint rotation,
CAPTCHA handling, or stealth features of any kind. It is a transparent
capacity-planning aid for scheduling research.
