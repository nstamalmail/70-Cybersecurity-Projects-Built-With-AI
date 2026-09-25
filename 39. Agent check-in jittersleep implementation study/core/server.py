"""Simulated server: latency, random failure, consecutive-failure lockout, load buckets."""
from __future__ import annotations

import random
import threading
import time
from typing import Dict, List, Optional


class SimulatedServer:
    """Thread-safe simulated target for agent check-ins.

    Responses follow the architecture doc:
      ok=True            -> success ("200")
      rejected (503)     -> random failure by failure_rate (load-shedding analogue)
      locked (429)       -> agent is in lockout after too many consecutive failures
    """

    def __init__(self, cfg, seed: int = 7) -> None:
        self.cfg = cfg
        self._rng = random.Random(seed)
        self._lock = threading.Lock()
        self._fail_streak: Dict[int, int] = {}
        self._lockout_until: Dict[int, float] = {}
        self._buckets: Dict[int, int] = {}
        self._t0 = time.monotonic()
        # counters
        self.total = 0
        self.ok = 0
        self.rejected = 0
        self.locked = 0

    # ------------------------------------------------------------------ core
    def handle_checkin(self, agent_id: int, sim_time_s: Optional[float] = None) -> Dict:
        """Process one check-in. sim_time_s: simulated clock (seconds since t0)."""
        now = sim_time_s if sim_time_s is not None else (time.monotonic() - self._t0)
        now = max(0.0, now)
        with self._lock:
            self.total += 1
            bucket = int(now / self.cfg.bucket_s) if self.cfg.bucket_s > 0 else 0
            self._buckets[bucket] = self._buckets.get(bucket, 0) + 1

            # lockout check
            until = self._lockout_until.get(agent_id, 0.0)
            if now < until:
                self.locked += 1
                return {
                    "ok": False,
                    "status": 429,
                    "latency_ms": 0,
                    "lockout_remaining_s": round(until - now, 3),
                }

            latency = self._rng.randint(self.cfg.latency_min_ms, self.cfg.latency_max_ms)

            if self._rng.random() < self.cfg.failure_rate:
                self.rejected += 1
                streak = self._fail_streak.get(agent_id, 0) + 1
                self._fail_streak[agent_id] = streak
                if (self.cfg.lockout_after_failures > 0
                        and streak >= self.cfg.lockout_after_failures):
                    self._lockout_until[agent_id] = now + self.cfg.lockout_duration_s
                    self._fail_streak[agent_id] = 0
                    return {
                        "ok": False,
                        "status": 503,
                        "latency_ms": latency,
                        "lockout_remaining_s": self.cfg.lockout_duration_s,
                        "lockout_opened": True,
                    }
                return {"ok": False, "status": 503, "latency_ms": latency,
                        "lockout_remaining_s": 0.0}

            # success
            self.ok += 1
            self._fail_streak[agent_id] = 0
            return {"ok": True, "status": 200, "latency_ms": latency,
                    "lockout_remaining_s": 0.0}

    # -------------------------------------------------------------- reporting
    def load_buckets(self) -> List[Tuple[int, int]]:
        """Sorted (bucket_index, arrivals) — used by the load chart."""
        with self._lock:
            return sorted(self._buckets.items())

    def bucket_seconds(self) -> float:
        return self.cfg.bucket_s

    def rejection_rate(self) -> float:
        with self._lock:
            return (self.rejected / self.total) if self.total else 0.0

    def reset(self, seed: Optional[int] = None) -> None:
        with self._lock:
            if seed is not None:
                self._rng = random.Random(seed)
            self._fail_streak.clear()
            self._lockout_until.clear()
            self._buckets.clear()
            self.total = self.ok = self.rejected = self.locked = 0
            self._t0 = time.monotonic()
