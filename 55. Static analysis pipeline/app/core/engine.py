"""Staged static analysis pipeline.

    [Load] -> [Hash] -> [PE parse] -> [String extract] -> [Intel] -> [IOCs]
           -> [Verdict] -> [Report]

The engine is pure Python (no Qt) so it can be exercised headlessly by the
``--selftest`` switch and by the test suite, and reused by the other workbenches.
"""
from __future__ import annotations

import datetime as _dt
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from app.config import SETTINGS, cases_dir
from app.core import hashing, ioc as ioc_mod, peanalysis, stringsx, verdict as verdict_mod
from app.core.intel import IntelAggregator, IntelResult, intel_summary
from app.reporting import Report

STAGES = ["load", "hash", "pe", "strings", "intel", "iocs", "verdict", "report"]


@dataclass
class AnalysisResult:
    """Everything one analysis run produced."""

    run_id: str
    path: str
    file_name: str
    size: int
    file_type: str
    hashes: dict = field(default_factory=dict)
    is_pe: bool = False
    pe_info: dict | None = None
    anomalies: list[dict] = field(default_factory=list)
    capabilities: list[dict] = field(default_factory=list)
    strings: list[dict] = field(default_factory=list)
    string_stats: dict = field(default_factory=dict)
    keywords: dict = field(default_factory=dict)
    intel_results: list[IntelResult] = field(default_factory=list)
    intel: dict = field(default_factory=dict)
    verdict: verdict_mod.Verdict | None = None
    iocs: list[dict] = field(default_factory=list)
    duration: float = 0.0
    warnings: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    options: dict = field(default_factory=dict)
    report: Report | None = None

    # ---------------------------------------------------------------- views
    @property
    def sha256(self) -> str:
        return (self.hashes or {}).get("sha256", "")

    def summary_rows(self) -> list[tuple[str, str]]:
        """Generic label/value summary consumed by the CLI (and any front end)."""
        v = self.verdict
        rows: list[tuple[str, str]] = [
            ("artefact", self.file_name),
            ("source", self.path),
            ("size / type", f"{self.size} bytes / {self.file_type}"),
            ("sha256", self.sha256),
            ("duration", f"{self.duration:.2f}s"),
            ("pe sections", str(len((self.pe_info or {}).get("sections", [])))),
            ("anomalies", str(len(self.anomalies))),
            ("capabilities", str(len({c["capability"] for c in self.capabilities}))),
            (
                "strings",
                f"{self.string_stats.get('total', 0)} "
                f"({self.string_stats.get('interesting', 0)} actionable)",
            ),
            ("iocs", str(len(self.iocs))),
            ("intel status", str(self.intel.get("status", "n/a"))),
            (
                "VERDICT",
                f"{v.verdict if v else 'n/a'} "
                f"(score {v.score if v else 0}, raw {v.raw_score if v else 0})",
            ),
            ("report sections", str(len(self.report.sections) if self.report else 0)),
        ]
        return rows

    def interesting_strings(self) -> list[dict]:
        return stringsx.interesting_rows(self.strings)

    def section_rows(self) -> list[list]:
        rows = []
        for sec in (self.pe_info or {}).get("sections", []):
            rows.append(
                [
                    sec["name"],
                    f"0x{sec['virtual_address']:08x}",
                    sec["virtual_size"],
                    sec["raw_size"],
                    f"{sec['entropy']:.2f}",
                    sec["flags"],
                    sec.get("packer") or "",
                    "W+X" if sec["wx"] else "",
                ]
            )
        return rows

    def anomaly_rows(self) -> list[list]:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        rows = [
            [a.get("severity", ""), a.get("title", ""), a.get("detail", "")]
            for a in sorted(self.anomalies, key=lambda a: order.get(a.get("severity", "low"), 9))
        ]
        return rows

    def capability_rows(self) -> list[list]:
        return [
            [h["api"], h["dll"], h["capability"], h["weight"], h["note"]]
            for h in self.capabilities
        ]

    def string_rows(self) -> list[list]:
        return [
            [
                r["offset_hex"],
                r["type"],
                r["length"],
                r["classification"],
                r["value"],
            ]
            for r in self.strings
        ]

    def intel_rows(self) -> list[list]:
        return [r.to_row() for r in self.intel_results]


class AnalysisEngine:
    """Runs the staged pipeline over a file (or in-memory buffer)."""

    #: Aliases so the shared CLI/front-end layer can treat every workbench the same.
    last_result = None

    def __init__(self, settings=None, bus=None, cache_root=None) -> None:
        self.settings = settings or SETTINGS
        self.bus = bus
        self.intel = IntelAggregator(self.settings, bus, cache_root)

    # -------------------------------------------------------------- logging
    def _log(self, message: str, level: str = "info") -> None:
        if self.bus:
            self.bus.log(message, level)

    def _progress(self, progress, stage: str, done: int = 0, total: int = 0) -> None:
        if progress:
            progress(stage, done, total)

    # -------------------------------------------------------------- public
    def analyze(
        self,
        path: str | Path,
        *,
        progress=None,
        simulate_intel: bool = False,
        min_string_length: int | None = None,
        write_artifacts: bool = True,
    ) -> AnalysisResult:
        p = Path(path)
        started = time.perf_counter()
        run_id = f"sap-{_dt.datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}"
        max_bytes = int(self.settings.get("max_file_size_mb", 500)) * 1024 * 1024

        self._progress(progress, "load")
        if not p.exists():
            raise FileNotFoundError(f"No such file: {p}")
        size = p.stat().st_size
        warnings: list[str] = []
        if size > max_bytes:
            warnings.append(
                f"File is larger than the configured {self.settings.get('max_file_size_mb')} MB limit; "
                "only the first bytes were hashed for string extraction."
            )
        self._log(f"Loading {p.name} ({hashing.human_size(size)})")

        data = self._read_bytes(p, max_bytes)
        ftype = hashing.file_type(p, data[:16])

        result = self._run_stages(
            data=data,
            hashes=hashing.compute_hashes(p, max_bytes),
            file_name=p.name,
            path=str(p),
            size=size,
            file_type=ftype,
            run_id=run_id,
            warnings=warnings,
            progress=progress,
            simulate_intel=simulate_intel,
            min_string_length=min_string_length,
        )
        result.duration = time.perf_counter() - started
        if write_artifacts:
            self._write_artifacts(result)
        result.report = self.build_report(result)
        self._progress(progress, "report")
        self._log(
            f"Analysis complete in {result.duration:.2f}s \u2192 "
            f"{result.verdict.verdict} (score {result.verdict.score})",
            "success",
        )
        return result

    def analyze_bytes(
        self,
        data: bytes,
        file_name: str = "buffer.bin",
        *,
        progress=None,
        simulate_intel: bool = False,
        min_string_length: int | None = None,
        write_artifacts: bool = True,
    ) -> AnalysisResult:
        started = time.perf_counter()
        run_id = f"sap-{_dt.datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}"
        result = self._run_stages(
            data=data,
            hashes=hashing.compute_hashes_bytes(data),
            file_name=file_name,
            path=f"(memory) {file_name}",
            size=len(data),
            file_type=hashing.file_type(Path(file_name), data[:16]),
            run_id=run_id,
            warnings=[],
            progress=progress,
            simulate_intel=simulate_intel,
            min_string_length=min_string_length,
        )
        result.duration = time.perf_counter() - started
        if write_artifacts:
            self._write_artifacts(result)
        result.report = self.build_report(result)
        return result

    def _read_bytes(self, path: Path, max_bytes: int, attempts: int = 4) -> bytes:
        """Read a sample defensively.

        Triage happens on files that are frequently locked or briefly
        unreadable: an EDR/AV scanner holding a handle after a write, a live
        forensic image, or a network share.  Retrying briefly turns a hard
        failure into a pause, and the final error explains what happened
        instead of surfacing a bare OSError.
        """
        last: Exception | None = None
        for attempt in range(attempts):
            try:
                return path.read_bytes()[:max_bytes]
            except OSError as exc:
                last = exc
                if attempt < attempts - 1:
                    self._log(
                        f"Read attempt {attempt + 1}/{attempts} failed for {path.name} "
                        f"({exc}); retrying…",
                        "warn",
                    )
                    time.sleep(0.4 * (attempt + 1))
        hint = (
            " If an antivirus is scanning the file it may be locked - wait a moment "
            "and try again, or copy the sample to a local folder first."
            if getattr(last, "errno", None) in (13, 22, 32)
            else ""
        )
        raise OSError(f"Could not read {path}: {last}.{hint}") from last

    # ------------------------------------------------------------- stages
    def _run_stages(
        self,
        *,
        data: bytes,
        hashes: dict,
        file_name: str,
        path: str,
        size: int,
        file_type: str,
        run_id: str,
        warnings: list[str],
        progress,
        simulate_intel: bool,
        min_string_length: int | None,
    ) -> AnalysisResult:
        result = AnalysisResult(
            run_id=run_id,
            path=path,
            file_name=file_name,
            size=size,
            file_type=file_type,
            hashes=hashes,
            warnings=list(warnings),
            options={
                "min_string_length": min_string_length
                or int(self.settings.get("min_string_length", 4)),
                "entropy_threshold": self.settings.get("entropy_threshold", 7.0),
                "network_lookups": bool(self.settings.get("enable_network_lookups")),
                "simulated_intel": bool(simulate_intel),
                "max_file_size_mb": self.settings.get("max_file_size_mb", 500),
            },
        )

        # ---- stage: hash
        self._progress(progress, "hash")
        self._log(
            f"SHA-256 {hashes['sha256']}\nMD5     {hashes['md5']}\nSHA-1   {hashes['sha1']}",
            "info",
        )

        # ---- stage: PE parse
        self._progress(progress, "pe")
        result.is_pe = data[:2] == b"MZ"
        if result.is_pe:
            try:
                result.pe_info = peanalysis.parse_pe(path, data=data)
                result.capabilities = peanalysis.capability_hits(result.pe_info)
                result.anomalies = peanalysis.detect_anomalies(result.pe_info, size)
                self._log(
                    f"PE parsed: {result.pe_info['machine']}, "
                    f"{len(result.pe_info['sections'])} sections, "
                    f"{result.pe_info['import_count']} imports, "
                    f"{len(result.anomalies)} anomalies"
                )
                if result.pe_info.get("pdb_path"):
                    self._log(f"PDB path: {result.pe_info['pdb_path']}", "warn")
            except Exception as exc:
                warnings.append(f"PE parsing failed: {exc}")
                self._log(f"PE parsing failed: {exc}", "error")
                result.pe_info = None
        else:
            warnings.append("Not a PE image - header heuristics were skipped.")
            self._log("Input is not a PE image; running strings-only analysis.", "warn")

        # ---- stage: strings
        self._progress(progress, "strings")
        result.strings, result.string_stats = stringsx.extract_and_classify(
            data,
            min_length=result.options["min_string_length"],
            progress=lambda label, done, total: self._progress(progress, "strings", done, total),
        )
        result.keywords = stringsx.keyword_hits(result.strings)
        self._log(
            f"Strings: {result.string_stats['total']} extracted "
            f"({result.string_stats['interesting']} actionable)",
        )
        for group, hits in result.keywords.items():
            self._log(f"Keyword theme '{group}': {len(hits)} hits", "warn")

        # ---- stage: intel
        self._progress(progress, "intel")
        result.intel_results = self.intel.lookup(hashes, simulate=simulate_intel)
        result.intel = intel_summary(result.intel_results)

        # ---- stage: IOCs
        self._progress(progress, "iocs")
        result.iocs = ioc_mod.compile_iocs(
            hashes=hashes,
            pe_info=result.pe_info or {},
            string_rows=result.strings,
            intel=result.intel,
            file_name=file_name,
        )
        self._log(f"Compiled {len(result.iocs)} unique indicators")

        # ---- stage: verdict
        self._progress(progress, "verdict")
        result.verdict = verdict_mod.compute_verdict(
            intel=result.intel,
            pe_info=result.pe_info or {},
            anomalies=result.anomalies,
            capability_hits=result.capabilities,
            string_stats=result.string_stats,
            interesting_strings=result.interesting_strings(),
            keywords=result.keywords,
            signed=None,
            packer_hints=[
                s["packer"] for s in (result.pe_info or {}).get("sections", []) if s.get("packer")
            ],
            string_only=not result.is_pe,
        )
        for entry in result.verdict.rationale:
            self._log(
                f"indicator {entry['weight']:+d} ({entry['source']}): {entry['indicator']}",
                "debug",
            )
        return result

    # ---------------------------------------------------------- artefacts
    def _write_artifacts(self, result: AnalysisResult) -> None:
        try:
            case_dir = cases_dir() / result.run_id
            case_dir.mkdir(parents=True, exist_ok=True)
            (case_dir / "hashes.json").write_text(
                json.dumps(result.hashes, indent=2), encoding="utf-8"
            )
            if result.pe_info:
                (case_dir / "pe_info.json").write_text(
                    json.dumps(result.pe_info, indent=2, default=str), encoding="utf-8"
                )
            if result.anomalies:
                (case_dir / "anomalies.json").write_text(
                    json.dumps(result.anomalies, indent=2), encoding="utf-8"
                )
            if result.capabilities:
                (case_dir / "capabilities.json").write_text(
                    json.dumps(result.capabilities, indent=2), encoding="utf-8"
                )
            with (case_dir / "strings.jsonl").open("w", encoding="utf-8") as fh:
                for row in result.strings[:200_000]:
                    fh.write(json.dumps(row) + "\n")
            (case_dir / "iocs.json").write_text(
                json.dumps(result.iocs, indent=2), encoding="utf-8"
            )
            if result.intel_results:
                (case_dir / "intel.json").write_text(
                    json.dumps(
                        [
                            {**r.__dict__, "raw": r.raw}
                            for r in result.intel_results
                        ],
                        indent=2,
                        default=str,
                    ),
                    encoding="utf-8",
                )
            if result.verdict:
                (case_dir / "verdict.json").write_text(
                    json.dumps(
                        {
                            "verdict": result.verdict.verdict,
                            "score": result.verdict.score,
                            "raw_score": result.verdict.raw_score,
                            "rationale": result.verdict.rationale,
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
            (case_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "run_id": result.run_id,
                        "file_name": result.file_name,
                        "sha256": result.sha256,
                        "analysed_at": _dt.datetime.now().isoformat(timespec="seconds"),
                        "duration_s": round(result.duration, 3),
                        "options": result.options,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            result.artifacts = [str(f) for f in sorted(case_dir.glob("*"))]
        except Exception as exc:
            self._log(f"Could not write case artefacts: {exc}", "warn")

    # ------------------------------------------------------------- report
    def build_report(self, result: AnalysisResult) -> Report:
        v = result.verdict
        report = Report(
            title=f"Static Analysis Report \u2014 {result.file_name}",
            subtitle="Hash \u00b7 PE structure \u00b7 strings \u00b7 threat intel \u00b7 verdict",
            verdict=v.verdict if v else "",
            risk_score=v.score if v else None,
            summary=self._summary_text(result),
            run_id=result.run_id,
            artifacts=list(result.artifacts),
            iocs=list(result.iocs),
        )
        report.meta = {
            "File name": result.file_name,
            "Path": result.path,
            "Size": f"{result.size} bytes ({hashing.human_size(result.size)})",
            "File type": result.file_type,
            "SHA-256": result.sha256,
            "MD5": result.hashes.get("md5", ""),
            "SHA-1": result.hashes.get("sha1", ""),
            "imphash": (result.pe_info or {}).get("imphash", ""),
            "Analysis duration": f"{result.duration:.2f}s",
            "Analysed at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Analyst": self.settings.get("analyst", "analyst"),
        }
        if v:
            report.meta["Verdict"] = f"{v.verdict} (score {v.score}/100)"
            if v.overridden:
                report.meta["Verdict override"] = (
                    f"{v.override_analyst} @ {v.override_at}: {v.override_note}"
                )

        if result.warnings:
            report.add_list("Warnings", result.warnings)
        if result.pe_info:
            report.add_kv("PE header", self._pe_header_kv(result.pe_info))
            report.add_table(
                "Sections",
                ["Name", "RVA", "Virtual size", "Raw size", "Entropy", "Perms", "Packer", "Risk"],
                result.section_rows(),
                note="Entropy above the configured threshold indicates compressed or encrypted content.",
            )
            if result.pe_info.get("imports"):
                report.add_table(
                    "Imports by DLL",
                    ["DLL", "Functions"],
                    [
                        [dll, ", ".join(funcs[:40]) + ("\u2026" if len(funcs) > 40 else "")]
                        for dll, funcs in sorted(
                            result.pe_info["imports"].items(),
                            key=lambda kv: -len(kv[1]),
                        )
                    ],
                )
            if result.pe_info.get("exports"):
                report.add_list("Exports", result.pe_info["exports"][:200])
            if result.pe_info.get("resources"):
                report.add_table(
                    "Resources",
                    ["Type", "Entries"],
                    [[r["type"], r["count"]] for r in result.pe_info["resources"]],
                )
            if result.pe_info.get("debug_entries"):
                report.add_table(
                    "Debug directory",
                    ["Type", "Timestamp", "PDB path", "Size"],
                    [
                        [d["type"], d["timestamp"], d["pdb"], d["size"]]
                        for d in result.pe_info["debug_entries"]
                    ],
                )
        if result.capabilities:
            report.add_table(
                "Capability indicators (suspicious imports)",
                ["API", "DLL", "Capability", "Weight", "Why it matters"],
                result.capability_rows(),
            )
        if result.anomalies:
            report.add_table(
                "Structural anomalies",
                ["Severity", "Finding", "Detail"],
                result.anomaly_rows(),
            )
        if result.string_stats:
            report.add_kv(
                "String statistics",
                {
                    "Total strings": result.string_stats.get("total", 0),
                    "ASCII": result.string_stats.get("ascii", 0),
                    "UTF-16": result.string_stats.get("unicode", 0),
                    "Actionable": result.string_stats.get("interesting", 0),
                    "Minimum length": result.options.get("min_string_length"),
                    **{
                        f"Class: {k}": v2
                        for k, v2 in sorted(
                            (result.string_stats.get("by_classification") or {}).items(),
                            key=lambda kv: -kv[1],
                        )[:12]
                    },
                },
            )
        interesting = result.interesting_strings()
        if interesting:
            report.add_table(
                "Notable strings",
                ["Offset", "Type", "Length", "Class", "Value"],
                [
                    [r["offset_hex"], r["type"], r["length"], r["classification"], r["value"][:400]]
                    for r in interesting[:400]
                ],
                note="Classified URLs, IPs, domains, registry paths, commands and credential-like strings.",
            )
        for group, hits in (result.keywords or {}).items():
            report.add_list(f"Keyword theme: {group}", hits)
        if result.intel_results:
            report.add_table(
                "Threat intel lookups (hash only)",
                ["Source", "Status", "Detections", "Family", "Tags", "First seen", "Reference"],
                result.intel_rows(),
                note="Samples are never uploaded; lookups are hash based.",
            )
        if v:
            report.add_table(
                "Verdict rationale",
                ["Indicator", "Weight", "Source", "Note"],
                v.to_rows(),
                note=(
                    f"Raw total {v.raw_score}, clamped score {v.score}/100. "
                    f"\u2265{verdict_mod.MALICIOUS_THRESHOLD} = MALICIOUS, "
                    f"{verdict_mod.SUSPICIOUS_THRESHOLD}-{verdict_mod.MALICIOUS_THRESHOLD - 1} = SUSPICIOUS, "
                    f"<{verdict_mod.SUSPICIOUS_THRESHOLD} = LIKELY CLEAN."
                ),
            )
        report.add_ioc_section()
        if result.iocs:
            report.add_table(
                "IOC count by type",
                ["Type", "Count"],
                [[t, c] for t, c in ioc_mod.ioc_stats(result.iocs)],
            )
        report.add_kv("Analysis options", result.options)
        return report

    def _pe_header_kv(self, pe: dict) -> dict:
        return {
            "Machine": f"{pe.get('machine', '')} ({pe.get('machine_raw', '')})",
            "Compile timestamp": pe.get("timestamp", ""),
            "Characteristics": pe.get("characteristics", ""),
            "DLL characteristics": pe.get("dll_characteristics", ""),
            "Entry point": f"0x{pe.get('entry_point', 0):08x} (section {pe.get('entry_section', '?')})",
            "Image base": f"0x{pe.get('image_base', 0):08x}",
            "Subsystem": pe.get("subsystem", ""),
            "Size of image": pe.get("size_of_image", 0),
            "Size of headers": pe.get("size_of_headers", 0),
            "Overlay size": pe.get("overlay_size", 0),
            "Linker version": pe.get("linker", ""),
            "OS version": pe.get("os_version", ""),
            "Checksum": pe.get("checksum", 0),
            "Import count": pe.get("import_count", 0),
            "Section count": pe.get("section_count", 0),
            "Export count": len(pe.get("exports", []) or []),
            "PDB path": pe.get("pdb_path") or "(none)",
            "Rich header": "yes" if pe.get("has_rich_header") else "no",
            "TLS directory": "yes" if pe.get("has_tls") else "no",
            "Load config": "yes" if pe.get("has_load_config") else "no",
        }

    def _summary_text(self, result: AnalysisResult) -> str:
        v = result.verdict
        bits = [
            f"{result.file_name} ({hashing.human_size(result.size)}, {result.file_type}) "
            f"was analysed statically in {result.duration:.2f}s."
        ]
        if v:
            bits.append(
                f"Weighted verdict: {v.verdict} with a risk score of {v.score}/100 "
                f"from {len(v.rationale)} contributing indicators."
            )
        n_anom = len(result.anomalies)
        n_caps = len({c["capability"] for c in result.capabilities})
        bits.append(
            f"Findings: {n_anom} structural anomalies, {n_caps} capability groups, "
            f"{result.string_stats.get('interesting', 0)} actionable strings, "
            f"{len(result.iocs)} compiled IOCs."
        )
        if result.intel.get("status") == "disabled":
            bits.append(
                "Threat intel was not queried (offline mode), so reputation did not "
                "contribute to the score."
            )
        elif result.intel.get("status") == "simulated":
            bits.append(
                "Threat intel columns are SIMULATED demo data, not real intelligence."
            )
        return " ".join(bits)


# The shared CLI, tests and front-end layer refer to every workbench engine as
# ``Engine`` so that main.py stays identical across the suite.
Engine = AnalysisEngine

