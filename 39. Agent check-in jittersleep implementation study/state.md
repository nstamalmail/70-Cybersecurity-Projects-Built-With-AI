# State — Agent Check-in Jitter/Sleep Study

> Overwritten on every save. History lives in memory.md.

```yaml
schema_version: 1
saved_at_utc: 2026-09-09T17:37:47+00:00
config_fingerprint: fe9a9e36abd63167
elapsed_sim_s: 171.900
agents: 20
events_recorded: 95
run_counter: 2
```

## Server config

| key | value |
|---|---|
| failure_rate | 0.000 |
| latency_min_ms | 20 |
| latency_max_ms | 120 |
| lockout_after_failures | 0 |
| lockout_duration_s | 30.000 |
| bucket_s | 10.000 |

## Profiles

### herd-fixed — fixed, base=30s, jitter=10.0s, count=10

| metric | value |
|---|---|
| agents | 10 |
| checkins | 40 |
| successes | 40 |
| failures | 0 |
| retries | 0 |
| interval_mean_s | 31.267 |
| drift_p50_s | 1.250 |
| drift_p95_s | 1.300 |
| drift_max_s | 1.300 |

### uniform — uniform, base=30s, jitter=20s, count=10

| metric | value |
|---|---|
| agents | 10 |
| checkins | 34 |
| successes | 34 |
| failures | 0 |
| retries | 0 |
| interval_mean_s | 40.128 |
| drift_p50_s | 0.841 |
| drift_p95_s | 1.293 |
| drift_max_s | 1.341 |

## Server totals

| metric | value |
|---|---|
| total | 74 |
| ok | 74 |
| rejected | 0 |
| locked | 0 |
| rejection_rate | 0.000 |

_Resume hint: open the GUI and press 'Load state', or recreate the run with `python cli.py --demo --record`._
