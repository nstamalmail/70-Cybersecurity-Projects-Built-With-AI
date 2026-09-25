"""Incremental per-agent metrics: intervals, drift, retries, percentiles."""
from __future__ import annotations

import math
from typing import Dict, List, Optional


def percentile(sorted_vals: List[float], p: float) -> Optional[float]:
    """Linear-interpolated percentile of an already-sorted list."""
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    return sorted_vals[f] + (sorted_vals[c] - sorted_vals[f]) * (k - f)


class AgentMetrics:
    """O(1)-per-event accumulator for one agent."""

    def __init__(self, agent_id: int, profile_name: str) -> None:
        self.agent_id = agent_id
        self.profile_name = profile_name
        self.checkins = 0          # total attempts
        self.successes = 0
        self.failures = 0
        self.retries = 0           # attempts that were retries
        self.intervals: List[float] = []   # time between successful check-ins
        self.drifts: List[float] = []      # actual - scheduled
        self._last_success_t: Optional[float] = None
        self.attempts_to_success: List[int] = []  # retries needed per success

    def record_success(self, sim_t: float, drift: float) -> None:
        self.checkins += 1
        self.successes += 1
        if self._last_success_t is not None:
            self.intervals.append(sim_t - self._last_success_t)
        self._last_success_t = sim_t
        self.drifts.append(drift)
        self.attempts_to_success.append(1)

    def record_failure(self, sim_t: float, drift: float) -> None:
        self.checkins += 1
        self.failures += 1
        self.drifts.append(drift)

    def record_retry(self, sim_t: float, drift: float) -> None:
        self.checkins += 1
        self.retries += 1
        self.drifts.append(drift)
        if self.attempts_to_success:
            self.attempts_to_success[-1] += 1

    # ------------------------------------------------------------- summaries
    def _sorted(self, vals: List[float]) -> List[float]:
        return sorted(vals)

    def mean(self, vals: List[float]) -> Optional[float]:
        return (sum(vals) / len(vals)) if vals else None

    def stddev(self, vals: List[float]) -> Optional[float]:
        n = len(vals)
        if n < 2:
            return None
        m = sum(vals) / n
        return math.sqrt(sum((x - m) ** 2 for x in vals) / (n - 1))

    def summary(self) -> Dict:
        iv = self._sorted(self.intervals)
        dr = self._sorted(self.drifts)
        att = self._sorted([float(a) for a in self.attempts_to_success])
        return {
            "agent_id": self.agent_id,
            "profile": self.profile_name,
            "checkins": self.checkins,
            "successes": self.successes,
            "failures": self.failures + self.retries,
            "retries": self.retries,
            "interval_mean_s": self.mean(self.intervals),
            "interval_std_s": self.stddev(self.intervals),
            "interval_min_s": iv[0] if iv else None,
            "interval_max_s": iv[-1] if iv else None,
            "drift_mean_s": self.mean(self.drifts),
            "drift_p50_s": percentile(dr, 50),
            "drift_p95_s": percentile(dr, 95),
            "drift_max_s": dr[-1] if dr else None,
            "attempts_p50": percentile(att, 50),
            "attempts_p95": percentile(att, 95),
        }

    def interval_samples(self) -> List[float]:
        return list(self.intervals)

    def drift_samples(self) -> List[float]:
        return list(self.drifts)

    def stat_row(self) -> Dict:
        """Flat row for per-agent CSV export. Unlike summary(), failures and
        retries are reported separately (raw counters, no merging)."""
        iv = self._sorted(self.intervals)
        dr = self._sorted(self.drifts)
        att = self._sorted([float(a) for a in self.attempts_to_success])
        return {
            "agent_id": self.agent_id,
            "profile": self.profile_name,
            "checkins": self.checkins,
            "successes": self.successes,
            "failures": self.failures,
            "retries": self.retries,
            "interval_mean_s": self.mean(self.intervals),
            "interval_std_s": self.stddev(self.intervals),
            "interval_min_s": iv[0] if iv else None,
            "interval_max_s": iv[-1] if iv else None,
            "drift_mean_s": self.mean(self.drifts),
            "drift_p50_s": percentile(dr, 50),
            "drift_p95_s": percentile(dr, 95),
            "drift_max_s": dr[-1] if dr else None,
            "attempts_p50": percentile(att, 50),
            "attempts_p95": percentile(att, 95),
        }


class MetricsCollector:
    """Owns one AgentMetrics per agent; threads call record_* concurrently."""

    def __init__(self) -> None:
        self._agents: Dict[int, AgentMetrics] = {}
        import threading
        self._lock = threading.Lock()

    def register(self, agent_id: int, profile_name: str) -> AgentMetrics:
        m = AgentMetrics(agent_id, profile_name)
        with self._lock:
            self._agents[agent_id] = m
        return m

    def get(self, agent_id: int) -> Optional[AgentMetrics]:
        with self._lock:
            return self._agents.get(agent_id)

    def all(self) -> List[AgentMetrics]:
        with self._lock:
            return list(self._agents.values())

    def by_profile(self) -> Dict[str, Dict]:
        """Aggregate summary rows grouped by profile name."""
        with self._lock:
            agents = list(self._agents.values())
        groups: Dict[str, List[AgentMetrics]] = {}
        for m in agents:
            groups.setdefault(m.profile_name, []).append(m)
        out: Dict[str, Dict] = {}
        for name, ms in groups.items():
            n = len(ms)
            def agg(key: str) -> Optional[float]:
                vals = [m.summary()[key] for m in ms]
                vals = [v for v in vals if v is not None]
                return (sum(vals) / len(vals)) if vals else None
            out[name] = {
                "agents": n,
                "checkins": sum(m.checkins for m in ms),
                "successes": sum(m.successes for m in ms),
                "failures": sum(m.failures for m in ms),
                "retries": sum(m.retries for m in ms),
                "interval_mean_s": agg("interval_mean_s"),
                "interval_std_s": agg("interval_std_s"),
                "drift_p50_s": agg("drift_p50_s"),
                "drift_p95_s": agg("drift_p95_s"),
                "drift_max_s": agg("drift_max_s"),
            }
        return out
