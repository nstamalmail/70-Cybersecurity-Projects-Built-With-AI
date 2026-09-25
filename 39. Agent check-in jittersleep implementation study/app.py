"""Application entry point.

  python app.py           -> launch the GUI
  python app.py --smoke   -> headless sanity run, then exit 0 (used to verify the exe)
"""
from __future__ import annotations

import sys


def main() -> int:
    if "--smoke" in sys.argv:
        # Headless sanity check: build a tiny fleet, run ~2 sim-seconds,
        # write state.md / memory.md / a run JSON, and exit 0.
        import time
        from core.config import AppConfig, CheckinProfile, ServerConfig
        from core.fleet import Fleet
        from persistence.memory import MemoryStore
        from persistence.state import StateStore

        config = AppConfig(
            profiles=[
                CheckinProfile(name="smoke-fixed", strategy="fixed",
                               base_delay_s=0.5, agent_count=2, seed=1),
                CheckinProfile(name="smoke-uniform", strategy="uniform",
                               base_delay_s=0.5, jitter_s=0.3, agent_count=2,
                               seed=77),
            ],
            server=ServerConfig(failure_rate=0.2, lockout_after_failures=3,
                                lockout_duration_s=2.0, bucket_s=0.5),
            seed=9, duration_s=2.0, speed=10.0,
        )
        fleet = Fleet(config)
        fleet.start()
        while fleet.is_running():
            time.sleep(0.05)
        fleet.stop()

        s = fleet.summary()
        assert s["server"]["total"] > 0, "smoke run produced no check-ins"

        MemoryStore(".").append_run(config, s, fleet.events())
        StateStore(".").save(config, s, len(fleet.events()),
                             note="smoke build verification")
        print(f"SMOKE OK — {s['server']['total']} check-ins, "
              f"{s['agents']} agents, fingerprint {config.fingerprint()}")
        return 0

    from gui import main as gui_main
    gui_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
