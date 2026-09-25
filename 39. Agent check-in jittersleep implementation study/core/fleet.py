"""Fleet scheduler: one thread per agent, shared simulated server, event stream.

Events pushed to a sink (a queue.Queue in GUI/CLI use):
  {"type": "start",  "sim_t": 0.0, "config_fingerprint": ...}
  {"type": "checkin", ...}   attempt == 1 (scheduled check-in)
  {"type": "retry",  ...}    attempt >= 2 (backoff retry after failure)
  {"type": "lockout", ...}   server opened a lockout for an agent
  {"type": "end",    ...}    per-agent end (reason: "stopped" | "duration")
"""
from __future__ import annotations

import queue
import random
import threading
import time
from typing import Callable, Dict, List, Optional

from .config import AppConfig, CheckinProfile
from .jitter import next_delay, retry_delay
from .server import SimulatedServer
from .metrics import MetricsCollector


class AgentThread(threading.Thread):
    """One agent: sleep per strategy, check in, retry with backoff on failure."""

    def __init__(self, agent_id: int, profile: CheckinProfile,
                 server: SimulatedServer, metrics: MetricsCollector,
                 sink: Callable[[Dict], None], stop_event: threading.Event,
                 speed: float = 1.0, duration_s: float = 0.0) -> None:
        super().__init__(name=f"agent-{agent_id}", daemon=True)
        self.agent_id = agent_id
        self.profile = profile
        self.server = server
        self.metrics = metrics
        self._sink = sink
        self._stop_event = stop_event  # named to avoid shadowing Thread._stop()
        self._speed = max(0.1, speed)
        self._duration_s = duration_s
        self._state: Dict = {}
        self._rng = random.Random((profile.seed + agent_id) & 0xFFFFFFFF)
        self._attempt = 0
        self._t0 = 0.0

    # ------------------------------------------------------------------ time
    def _sim_elapsed(self) -> float:
        return (time.monotonic() - self._t0) * self._speed

    def _interruptible_sleep(self, delay_sim_s: float) -> None:
        """Sleep `delay_sim_s` simulated seconds; wake early if stop is set.

        Chunked in small wall-clock slices so Stop stays responsive even for
        long delays or high speed multipliers.
        """
        if delay_sim_s <= 0:
            return
        deadline = time.monotonic() + (delay_sim_s / self._speed)
        while not self._stop_event.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            self._stop_event.wait(min(0.05, remaining))

    def _emit(self, ev: Dict) -> None:
        try:
            self._sink(ev)
        except Exception:
            pass  # a dead consumer must never kill an agent thread

    # ------------------------------------------------------------------- run
    def run(self) -> None:
        self._t0 = time.monotonic()
        m = self.metrics.get(self.agent_id)

        # startup spread: stagger the first check-in to avoid boot-time herd
        if self.profile.startup_spread_s > 0:
            spread = self._rng.uniform(0, self.profile.startup_spread_s)
            self._interruptible_sleep(spread)

        while not self._stop_event.is_set():
            if self._duration_s > 0 and self._sim_elapsed() >= self._duration_s:
                break

            delay = next_delay(self.profile, self._rng, self._state)
            deadline = time.monotonic() + (delay / self._speed)
            self._interruptible_sleep(delay)
            if self._stop_event.is_set():
                break

            # drift: how late (in simulated seconds) we woke past the deadline
            drift = max(0.0, (time.monotonic() - deadline) * self._speed)
            sim_t = self._sim_elapsed()

            resp = self.server.handle_checkin(self.agent_id, sim_t)
            self._record_and_emit(m, "checkin", sim_t, drift, resp, 1)

            if not resp["ok"]:
                resp = self._retry_loop(m)

        self._emit({"type": "end", "agent_id": self.agent_id,
                    "sim_t": self._sim_elapsed(),
                    "reason": "stopped" if self._stop_event.is_set() else "duration"})

    # ----------------------------------------------------------------- retry
    def _retry_loop(self, m) -> Optional[Dict]:
        """Backoff-retry until success, stop, or duration expiry; emits retry events."""
        resp = None
        while True:
            if self._stop_event.is_set():
                return None
            if self._duration_s > 0 and self._sim_elapsed() >= self._duration_s:
                return None
            self._attempt += 1
            rd = retry_delay(self.profile, self._attempt - 1, self._rng)
            deadline = time.monotonic() + (rd / self._speed)
            self._interruptible_sleep(rd)
            if self._stop_event.is_set():
                return None
            drift = max(0.0, (time.monotonic() - deadline) * self._speed)
            sim_t = self._sim_elapsed()
            resp = self.server.handle_checkin(self.agent_id, sim_t)
            m.record_retry(sim_t, drift)
            self._emit({"type": "retry", "agent_id": self.agent_id,
                        "profile": self.profile.name,
                        "strategy": self.profile.strategy,
                        "sim_t": sim_t, "drift": drift,
                        "ok": resp["ok"], "status": resp["status"],
                        "latency_ms": resp["latency_ms"],
                        "attempt": self._attempt + 1})
            if resp.get("lockout_opened"):
                self._emit({"type": "lockout", "agent_id": self.agent_id,
                            "sim_t": sim_t,
                            "duration_s": resp.get("lockout_remaining_s", 0.0)})
            if resp["ok"]:
                self._attempt = 0
                return resp

    # ---------------------------------------------------------------- helpers
    def _record_and_emit(self, m, kind: str, sim_t: float, drift: float,
                         resp: Dict, attempt: int) -> None:
        if resp["ok"]:
            m.record_success(sim_t, drift)
        else:
            m.record_failure(sim_t, drift)
            if resp.get("lockout_opened"):
                self._emit({"type": "lockout", "agent_id": self.agent_id,
                            "sim_t": sim_t,
                            "duration_s": resp.get("lockout_remaining_s", 0.0)})
        self._emit({"type": kind, "agent_id": self.agent_id,
                    "profile": self.profile.name,
                    "strategy": self.profile.strategy,
                    "sim_t": sim_t, "drift": drift,
                    "ok": resp["ok"], "status": resp["status"],
                    "latency_ms": resp["latency_ms"], "attempt": attempt})

    def request_stop(self) -> None:
        self._stop_event.set()


class Fleet:
    """Builds and runs the agent fleet against a shared simulated server."""

    def __init__(self, config: AppConfig, sink: Optional[Callable[[Dict], None]] = None) -> None:
        self.config = config
        self.sink = sink or (lambda ev: None)
        self.stop_event = threading.Event()
        self.server = SimulatedServer(config.server, seed=config.seed)
        self.metrics = MetricsCollector()
        self.agents: List[AgentThread] = []
        self._events: List[Dict] = []
        self._events_lock = threading.Lock()
        self._t0 = 0.0

        agent_id = 0
        for profile in config.profiles:
            for _ in range(profile.agent_count):
                m = self.metrics.register(agent_id, profile.name)
                self.agents.append(AgentThread(
                    agent_id=agent_id, profile=profile, server=self.server,
                    metrics=self.metrics, sink=self._on_event,
                    stop_event=self.stop_event, speed=config.speed,
                    duration_s=config.duration_s))
                agent_id += 1

    # ------------------------------------------------------------------ events
    def _on_event(self, ev: Dict) -> None:
        with self._events_lock:
            self._events.append(ev)
        try:
            self.sink(ev)
        except Exception:
            pass

    def events(self) -> List[Dict]:
        with self._events_lock:
            return list(self._events)

    # -------------------------------------------------------------------- run
    def start(self) -> None:
        self._t0 = time.monotonic()
        self._on_event({"type": "start", "sim_t": 0.0,
                        "config_fingerprint": self.config.fingerprint()})
        for a in self.agents:
            a.start()

    def stop(self, join_timeout: float = 5.0) -> None:
        self.stop_event.set()
        for a in self.agents:
            a.join(timeout=join_timeout)

    def is_running(self) -> bool:
        return any(a.is_alive() for a in self.agents)

    def elapsed_s(self) -> float:
        if self._t0 == 0.0:
            return 0.0
        return (time.monotonic() - self._t0) * self.config.speed

    def summary(self) -> Dict:
        return {
            "config_fingerprint": self.config.fingerprint(),
            "elapsed_sim_s": self.elapsed_s(),
            "agents": len(self.agents),
            "server": {"total": self.server.total, "ok": self.server.ok,
                       "rejected": self.server.rejected, "locked": self.server.locked,
                       "rejection_rate": self.server.rejection_rate()},
            "profiles": self.metrics.by_profile(),
        }
