"""Headless CLI runner — scripted experiments, CI smoke checks, exe verification.

Examples:
  python cli.py --duration 60 --speed 100
  python cli.py --demo            # herd (fixed) vs uniform jitter, 60 sim-seconds
  python cli.py --smoke           # 3-second sanity run, no state writes
"""
from __future__ import annotations

import argparse
import json
import sys

from core.config import AppConfig, CheckinProfile, ServerConfig
from core.fleet import Fleet
from persistence.memory import MemoryStore
from persistence.state import StateStore


def run_once(config: AppConfig, sink=None) -> Fleet:
    fleet = Fleet(config, sink=sink)
    fleet.start()
    try:
        while fleet.is_running():
            import time
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        fleet.stop()
    return fleet


def print_summary(fleet: Fleet) -> None:
    s = fleet.summary()
    print(f"elapsed_sim_s = {s['elapsed_sim_s']:.1f}")
    print(f"agents        = {s['agents']}")
    print(f"server        = total={s['server']['total']} ok={s['server']['ok']} "
          f"rejected={s['server']['rejected']} locked={s['server']['locked']} "
          f"rejection_rate={s['server']['rejection_rate']:.4f}")
    for name, p in s["profiles"].items():
        mean_iv = p["interval_mean_s"]
        drift_p95 = p["drift_p95_s"]
        mean_s = f"{mean_iv:.2f}s" if mean_iv is not None else "n/a"
        drift_s = f"{drift_p95 * 1000:.1f}ms" if drift_p95 is not None else "n/a"
        print(f"[{name}] agents={p['agents']} checkins={p['checkins']} "
              f"successes={p['successes']} retries={p['retries']} "
              f"interval_mean={mean_s} "
              f"drift_p95={drift_s}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Agent check-in jitter/sleep study (headless)")
    ap.add_argument("--duration", type=float, default=60.0, help="simulated seconds")
    ap.add_argument("--speed", type=float, default=100.0)
    ap.add_argument("--seed", type=int, default=1234)
    ap.add_argument("--agents", type=int, default=10)
    ap.add_argument("--strategy", default="uniform",
                    choices=["fixed", "uniform", "decorrelated", "equal"])
    ap.add_argument("--failure-rate", type=float, default=0.0)
    ap.add_argument("--demo", action="store_true",
                    help="two profiles: fixed herd vs uniform jitter")
    ap.add_argument("--smoke", action="store_true", help="3s run, no writes")
    ap.add_argument("--export", action="store_true", help="write runs/*.json")
    ap.add_argument("--csv", action="store_true",
                    help="write runs/metrics_<id>.csv and runs/agents_<id>.csv")
    ap.add_argument("--record", action="store_true", help="append to memory.md / state.md")
    args = ap.parse_args()

    if args.smoke:
        args.duration, args.speed, args.record = 3.0, 10.0, False

    if args.demo:
        config = AppConfig(
            profiles=[
                CheckinProfile(name="herd-fixed", strategy="fixed",
                               base_delay_s=30, agent_count=args.agents, seed=args.seed),
                CheckinProfile(name="uniform", strategy="uniform",
                               base_delay_s=30, jitter_s=20, agent_count=args.agents,
                               seed=args.seed + 500),
            ],
            server=ServerConfig(failure_rate=args.failure_rate),
            seed=args.seed, duration_s=args.duration, speed=args.speed,
        )
    else:
        config = AppConfig(
            profiles=[CheckinProfile(name="default", strategy=args.strategy,
                                     base_delay_s=30, jitter_s=20,
                                     agent_count=args.agents, seed=args.seed)],
            server=ServerConfig(failure_rate=args.failure_rate),
            seed=args.seed, duration_s=args.duration, speed=args.speed,
        )

    errs = config.validate()
    if errs:
        print("Invalid config:", file=sys.stderr)
        for e in errs:
            print(" -", e, file=sys.stderr)
        return 2

    fleet = run_once(config)
    print_summary(fleet)

    if args.record:
        state = StateStore(".")
        memory = MemoryStore(".")
        memory.append_run(fleet.config, fleet.summary(), fleet.events())
        state.save(fleet.config, fleet.summary(), len(fleet.events()))
        print("Recorded to state.md and memory.md.")
    if args.export:
        path = MemoryStore(".").export_run(fleet.config, fleet.summary(),
                                           fleet.events())
        print(f"Exported {path}")
    if args.csv:
        from persistence.csvexport import export_all
        for p in export_all(fleet.summary(), fleet.metrics):
            print(f"Exported {p}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
