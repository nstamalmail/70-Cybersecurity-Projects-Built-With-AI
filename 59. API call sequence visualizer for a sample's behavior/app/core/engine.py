"""Analysis engine: ingest -> normalise -> mine -> match -> report (§3.9).

One call produces the complete :class:`AnalysisResult` that every view renders:

  * ``meta`` / ``calls`` / ``processes``  - parsed and normalised behaviour
  * ``ngrams`` / ``clusters``             - mined sequence motifs
  * ``transitions``                       - Markov API graph
  * ``matches``                           - behavioural pattern hits
  * ``iocs``                              - indicators pulled from arguments
  * ``stats`` / ``bursts``                - timeline statistics
  * ``score`` / ``severity``              - verdict used by the report
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from app.config import APP, demo_dir
from app.core import detection, iocs as iocmod, ingest, sequences
from app.core.store import CaseStore
from app.core.model import ApiCall, CallSequence, NGramHit, PatternMatch, ProcessNode, ReportMeta, Transition
from app.reporting import Report


@dataclass
class AnalysisResult:
    """Everything derived from one sandbox report."""

    meta: ReportMeta = field(default_factory=ReportMeta)
    calls: list[ApiCall] = field(default_factory=list)
    processes: list[ProcessNode] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    matches: list[PatternMatch] = field(default_factory=list)
    ngrams: list[NGramHit] = field(default_factory=list)
    clusters: list[CallSequence] = field(default_factory=list)
    transitions: list[Transition] = field(default_factory=list)
    paths: list[list[str]] = field(default_factory=list)
    iocs: list[dict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    bursts: list[dict] = field(default_factory=list)
    severity: str = "info"
    score: int = 0
    source_path: str = ""
    source_name: str = ""
    source_format: str = "unknown"
    source_size: int = 0
    stored_path: str = ""
    notes: list[str] = field(default_factory=list)
    report: Report | None = None

    def summary_rows(self) -> list[tuple[str, str]]:
        """Headline rows printed by the headless CLI and shown in the console."""
        return [
            ("source", self.source_name or self.meta.sample_name or "-"),
            ("format", self.source_format),
            ("sample sha256", self.meta.sample_sha256 or "-"),
            ("api calls", f"{self.call_count} (records {len(self.calls)})"),
            ("processes", str(len(self.processes))),
            ("unique apis", str(self.stats.get("unique_apis", 0))),
            ("duration", f"{self.duration:.1f}s"),
            ("findings", str(len(self.matches))),
            ("clusters", str(len(self.clusters))),
            ("transitions", str(len(self.transitions))),
            ("indicators", str(len(self.iocs))),
            ("severity", f"{self.severity.upper()} ({self.score}/100)"),
        ]

    # ------------------------------------------------------------- accessors
    @property
    def duration(self) -> float:
        return max((call.timestamp for call in self.calls), default=0.0)

    @property
    def call_count(self) -> int:
        return sum(call.weight for call in self.calls)

    def categories(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for call in self.calls:
            counts[call.category] = counts.get(call.category, 0) + call.weight
        return dict(sorted(counts.items(), key=lambda item: -item[1]))

    def critical_matches(self) -> list[PatternMatch]:
        return [match for match in self.matches if match.severity in ("critical", "high")]

    def timeline_buckets(self, buckets: int = 120) -> tuple[list[float], list[list[int]]]:
        """Per-category counts over a fixed number of time buckets."""
        duration = self.duration or 1.0
        width = max(duration / max(1, buckets), 1e-6)
        categories = [name for name in APP.get("timeline_categories", ()) ] or list(self.categories())
        index = {name: position for position, name in enumerate(categories)}
        matrix = [[0] * len(categories) for _ in range(buckets)]
        for call in self.calls:
            bucket = min(buckets - 1, int(call.timestamp / width))
            column = index.get(call.category)
            if column is None:
                continue
            matrix[bucket][column] += call.weight
        return [round(position * width, 3) for position in range(buckets)], matrix

    def heatmap(self) -> tuple[list[str], list[str], list[list[int]]]:
        """Processes x categories call-count matrix for the heatmap view."""
        processes = sorted(self.processes, key=lambda node: -node.call_count)[:40]
        categories = list(self.categories())
        index = {name: position for position, name in enumerate(categories)}
        grid: list[list[int]] = []
        for node in processes:
            row = [0] * len(categories)
            for name, count in node.categories.items():
                column = index.get(name)
                if column is not None:
                    row[column] = count
            grid.append(row)
        return [f"{node.process_name} ({node.process_id})" for node in processes], categories, grid

    def iocs_as_report_items(self) -> list[dict]:
        return [
            {
                "ioc_type": item["type"],
                "value": item["value"],
                "source": item.get("source", ""),
                "confidence": item.get("confidence", 0.5),
                "context": item.get("context", ""),
            }
            for item in self.iocs
        ]


# --------------------------------------------------------------------------- #
#  Engine
# --------------------------------------------------------------------------- #
class Engine:
    """Runs the analysis pipeline and produces reports."""

    def __init__(self, settings, bus=None) -> None:
        self.settings = settings
        self.bus = bus
        self._store: CaseStore | None = None

    @property
    def store(self) -> CaseStore:
        """Lazily created SQLite case store (see ``app.core.store``)."""
        if self._store is None:
            self._store = CaseStore()
        return self._store

    # ---------------------------------------------------------------- logging
    def log(self, message: str, level: str = "info") -> None:
        if self.bus is not None:
            try:
                self.bus.log(message, level)
                return
            except Exception:
                pass
        print(f"[{level}] {message}")

    # ------------------------------------------------------------------ run
    def analyse_bytes(self, data: bytes, *, name: str = "", path: str = "", progress=None) -> AnalysisResult:
        settings = self.settings
        max_calls = int(settings.get("max_calls", 2_000_000))
        collapse = bool(settings.get("collapse_loops", True))
        threshold = int(settings.get("collapse_threshold", 3))
        min_severity = str(settings.get("pattern_min_severity", "low") or "low")
        ignored = list(settings.get("ignore_categories", []) or [])

        def tick(fraction: float, message: str) -> None:
            if progress:
                progress(fraction, message)

        tick(0.05, f"Parsing {name or 'report'} …")
        meta, calls, processes, summary = ingest.parse_report(
            data, name=name, path=path, limit=max_calls, settings=settings
        )
        result = AnalysisResult(
            meta=meta,
            processes=processes,
            summary=summary,
            source_path=path or name,
            source_name=name or Path(path or "").name,
            source_format=meta.source_format,
            source_size=len(data),
        )
        self.log(
            f"Parsed {meta.source_format} report: {len(calls)} calls, {len(processes)} processes"
        )

        tick(0.25, "Normalising call stream …")
        if ignored:
            calls = [call for call in calls if call.category not in ignored]
        if collapse:
            calls, collapsed = ingest.collapse_loops(calls, threshold)
            if collapsed:
                self.log(f"Collapsed {collapsed} repetitive call runs")
        result.calls = calls
        result.processes = ingest.build_processes(None, None, calls) if processes else processes
        # keep the richer tree (it carries paths and command lines)
        if processes:
            result.processes = processes

        tick(0.4, "Mining API sequences …")
        per_process = bool(settings.get("ngram_per_process", False))
        mine = _sample_for_mining(calls, int(settings.get("mine_max_calls", 120_000)))
        if len(mine) != len(calls):
            self.log(
                f"Mining over an evenly spaced sample of {len(mine)} of {len(calls)} records "
                "(patterns, IOCs and statistics still use every call)",
                "warn",
            )
        result.ngrams = sequences.extract_ngrams(
            mine,
            sizes=tuple(settings.get("ngram_sizes", (2, 3, 4, 5)) or (2, 3, 4, 5)),
            min_occurrences=int(settings.get("ngram_min_occurrences", 2)),
            top=int(settings.get("ngram_top", 60)),
            per_process=per_process,
        )
        result.clusters = sequences.cluster_ngrams(
            mine,
            min_support=int(settings.get("cluster_min_support", 2)),
            top=int(settings.get("cluster_top", 25)),
        )
        result.transitions = sequences.build_markov(
            mine, per_process=bool(settings.get("markov_per_process", False)), top=int(settings.get("markov_top", 400))
        )
        result.paths = sequences.highest_probability_paths(result.transitions, top=10)
        self.log(
            f"Mined {len(result.ngrams)} frequent n-grams, {len(result.clusters)} sequence clusters, "
            f"{len(result.transitions)} transitions"
        )

        tick(0.62, "Matching behavioural patterns …")
        min_rank = detection.SEVERITY_ORDER.get(min_severity.lower(), 1)
        result.matches = [
            match
            for match in detection.match_all(calls, limit=int(settings.get("match_limit", 4000)))
            if detection.SEVERITY_ORDER.get(match.severity, 0) >= min_rank
        ]
        self.log(f"Matched {len(result.matches)} behavioural patterns")

        tick(0.78, "Extracting indicators …")
        raw_iocs = iocmod.extract_from_summary(summary, calls)
        min_conf = float(settings.get("ioc_min_confidence", 0.0) or 0.0)
        result.iocs = [item for item in raw_iocs if float(item.get("confidence", 0)) >= min_conf]
        self.log(f"Extracted {len(result.iocs)} indicators")

        tick(0.88, "Scoring behaviour …")
        result.stats = sequences.sequence_stats(calls, result.processes)
        result.bursts = sequences.burst_detection(
            calls,
            window=float(settings.get("burst_window", 1.0)),
            threshold=int(settings.get("burst_threshold", 40)),
        )
        result.score, result.severity = detection.score_matches(result.matches, calls, result.processes)
        if not calls:
            result.notes.append(
                "No API calls were parsed - confirm the report contains behavior.processes[].calls[]."
            )
        result.report = self.build_report(result)
        if bool(settings.get("store_sqlite", True)):
            stored = self.store.store_run(result, max_calls=int(settings.get("store_max_calls", 50_000)))
            if stored:
                self.log(f"Case stored in {self.store.path}")
            elif self.store.error:
                self.log(f"Case store unavailable: {self.store.error}", "warn")
        tick(1.0, "Analysis complete")
        return result


    def analyse_path(self, path: str | Path, progress=None) -> AnalysisResult:
        target = Path(path)
        data = target.read_bytes()
        result = self.analyse_bytes(data, name=target.name, path=str(target), progress=progress)
        # Keep a copy of the source report beside the case data for reproducibility.
        try:
            store_dir = demo_dir().parent / "reports"
            store_dir.mkdir(parents=True, exist_ok=True)
            copy = store_dir / target.name
            if not copy.exists():
                copy.write_bytes(data)
            result.stored_path = str(copy)
        except Exception:
            pass
        return result

    def analyse_calls(self, calls: list[ApiCall], *, meta: ReportMeta | None = None, name: str = "") -> AnalysisResult:
        """Re-run the mining/matching stages over an already parsed call list."""
        result = AnalysisResult(
            meta=meta or ReportMeta(sample_name=name or "in-memory"),
            calls=calls,
            source_name=name or "in-memory",
            source_format="memory",
        )
        mine = _sample_for_mining(calls, int(self.settings.get("mine_max_calls", 120_000)))
        result.processes = ingest.build_processes(None, None, calls)
        result.ngrams = sequences.extract_ngrams(mine)
        result.clusters = sequences.cluster_ngrams(mine)
        result.transitions = sequences.build_markov(mine)
        result.paths = sequences.highest_probability_paths(result.transitions, top=10)
        result.matches = detection.match_all(calls)
        result.iocs = iocmod.extract_from_calls(calls)
        result.stats = sequences.sequence_stats(calls, result.processes)
        result.bursts = sequences.burst_detection(calls)
        result.score, result.severity = detection.score_matches(result.matches, calls, result.processes)
        result.report = self.build_report(result)
        return result

    # ``Engine.analyze`` is the name the shared headless CLI uses across the suite.
    analyze = analyse_path

    # --------------------------------------------------------------- report
    def build_report(self, result: AnalysisResult) -> Report:
        report = Report(
            title=APP["report_title"],
            subtitle=f"{result.source_name or result.meta.sample_name or 'sandbox report'} · {result.source_format}",
            verdict=result.severity,
            risk_score=result.score,
            run_id=result.meta.report_id or f"{APP['slug']}-run",
        )
        report.artifacts = [value for value in (result.source_path, result.stored_path) if value]
        report.iocs = result.iocs_as_report_items()

        report.summary = self._narrative(result)
        report.meta = {
            "Report": result.meta.report_id,
            "Source": result.source_name or "-",
            "Format": result.source_format,
            "Sample": result.meta.sample_name or "-",
            "SHA-256": result.meta.sample_sha256 or "-",
            "Machine": result.meta.machine or "-",
            "Analysis started": result.meta.analysis_started or "-",
            "Duration": f"{result.duration:.1f}s of behaviour",
            "API calls": f"{result.call_count} (records: {len(result.calls)})",
            "Processes": str(len(result.processes)),
            "Unique APIs": str(result.stats.get("unique_apis", 0)),
            "Patterns matched": str(len(result.matches)),
            "Indicators": str(len(result.iocs)),
            "Behaviour score": f"{result.score}/100 ({result.severity})",
        }
        if result.meta.signatures:
            report.meta["Sandbox signatures"] = ", ".join(result.meta.signatures[:8])

        # ---- key findings ----------------------------------------------------
        if result.matches:
            report.add_table(
                "Behavioural findings",
                ["Severity", "Pattern", "Process", "Start (s)", "Span (s)", "API chain", "Target"],
                [match.to_row() for match in result.matches[:60]],
                note="Ordered API sequences matched by the pattern engine (architecture §3.4).",
            )
            report.add_list(
                "Finding details",
                [
                    f"[{match.severity}] {match.pattern_id} {match.name} — pid {match.process_id} "
                    f"({match.process_name}) at t={match.start_ts:.2f}s"
                    + (f" target: {match.target}" if match.target else "")
                    + (f" | {' -> '.join(match.apis)}" if match.apis else "")
                    for match in result.matches[:40]
                ],
            )
        else:
            report.add_text(
                "Behavioural findings",
                "No behavioural pattern from the catalogue matched the observed API sequences.",
            )

        # ---- statistics ------------------------------------------------------
        report.add_kv(
            "Behaviour statistics",
            {
                "Total calls (records, loop-collapsed)": f"{result.call_count} ({len(result.calls)})",
                "Unique APIs": result.stats.get("unique_apis", 0),
                "Processes": result.stats.get("processes", len(result.processes)),
                "Behaviour duration": f"{result.stats.get('duration_seconds', result.duration)}s",
                "Calls per second": result.stats.get("calls_per_second", 0.0),
                "Failed calls": f"{result.stats.get('failed_calls', 0)} ({result.stats.get('failure_ratio', 0.0) * 100:.1f}%)",
                "Collapsed repeat runs": result.stats.get("repeat_collapsed", 0),
                "Categories observed": ", ".join(result.categories().keys()) or "-",
            },
        )

        report.add_table(
            "API category distribution",
            ["Category", "Calls", "Share"],
            [
                [name, count, f"{count / max(1, result.call_count) * 100:.1f}%"]
                for name, count in result.categories().items()
            ],
            note="Volume per category; a large memory + process share is injection-shaped.",
        )

        if result.stats.get("top_apis"):
            report.add_table(
                "Most frequent APIs",
                ["API", "Calls"],
                [[name, count] for name, count in result.stats["top_apis"]],
            )

        # ---- sequences -------------------------------------------------------
        if result.clusters:
            report.add_table(
                "Recurring API sequences",
                ["Steps", "Support", "Process", "Start (s)", "Span (s)", "Chain"],
                [cluster.to_row() for cluster in result.clusters[:25]],
                note="Frequent ordered chains mined from the call stream (maximal recurring sequences).",
            )
        if result.ngrams:
            report.add_table(
                "Frequent n-grams",
                ["Occurrences", "Length", "Score", "Process", "Chain"],
                [hit.to_row() for hit in result.ngrams[:40]],
            )
        if result.transitions:
            report.add_table(
                "API transition matrix (top)",
                ["From", "To", "Count", "Probability", "Process"],
                [transition.to_row() for transition in result.transitions[:40]],
                note="First-order Markov transitions; these edges drive the behaviour graph.",
            )

        # ---- processes -------------------------------------------------------
        if result.processes:
            report.add_table(
                "Reconstructed process tree",
                ["Process", "PID", "Parent", "First seen (s)", "Calls", "Failures", "Top categories", "Path"],
                [node.to_row() for node in result.processes],
            )
            suspicious = [node for node in result.processes if node.suspicious]
            if suspicious:
                report.add_list(
                    "Suspicious process notes",
                    [f"PID {node.process_id} {node.process_name}: {node.note}" for node in suspicious],
                )

        # ---- timeline --------------------------------------------------------
        if result.bursts:
            report.add_table(
                "Activity bursts",
                ["Start (s)", "End (s)", "Calls", "Rate (calls/s)"],
                [
                    [burst["start"], burst["end"], burst["calls"], burst["rate"]]
                    for burst in result.bursts
                ],
                note="Windows where the call rate spikes - installation, persistence and impact phases.",
            )

        if result.paths:
            report.add_list(
                "Highest-probability behaviour paths",
                [" -> ".join(path) for path in result.paths],
            )

        if result.notes:
            report.add_list("Analyst notes", result.notes)

        if result.meta.warnings:
            report.add_list("Parser warnings", result.meta.warnings)

        report.add_ioc_section("Indicators of Compromise")
        return report

    def _narrative(self, result: AnalysisResult) -> str:
        if not result.calls:
            return "The report contained no parseable API calls, so no behaviour could be analysed."
        names = sorted({match.name for match in result.critical_matches()})
        categories = result.categories()
        parts = [
            f"{result.call_count} API calls across {len(result.processes)} process(es) over "
            f"{result.duration:.1f}s of behaviour were normalised from a {result.source_format} report."
        ]
        if names:
            parts.append("High-severity behaviour matched: " + "; ".join(names[:6]) + ".")
        elif result.matches:
            parts.append(
                "Only lower-severity motifs matched ("
                + "; ".join(sorted({match.name for match in result.matches})[:5])
                + ")."
            )
        else:
            parts.append("No behavioural pattern from the catalogue matched.")
        if categories:
            top = ", ".join(f"{name} {count}" for name, count in list(categories.items())[:4])
            parts.append(f"Dominant categories: {top}.")
        if result.iocs:
            parts.append(f"{len(result.iocs)} indicators were extracted from the call arguments.")
        parts.append(f"Behaviour score {result.score}/100 ({result.severity}).")
        return " ".join(parts)


def _sample_for_mining(calls: list[ApiCall], limit: int) -> list[ApiCall]:
    """Evenly spaced subsample used for the sequence-mining stages.

    Reports with millions of calls would make exhaustive n-gram mining quadratic
    in practice, so the mining stages run over an evenly spaced sample while the
    pattern matcher, the IOC extractor and the statistics keep every record.
    """
    if limit <= 0 or len(calls) <= limit:
        return calls
    step = len(calls) / limit
    return [calls[int(index * step)] for index in range(limit)]


def engine_info() -> dict:
    return {
        "patterns": len(detection.PATTERNS),
        "pattern_catalogue": detection.pattern_catalogue(),
    }
