"""Application controller — the single facade the GUI talks to.

Responsibilities:
  * translate GUI-level strings into domain calls,
  * wrap domain/IO errors into UserError with actionable messages,
  * log inputs/outputs at INFO level for reproducibility (architecture §3.1),
  * own the persistence repository.
"""

from __future__ import annotations

import logging
from typing import List, Sequence, Tuple

from .domain.calculator import (
    calculate_subnet,
    calculate_subnet_from_mask,
    divide_network,
)
from .domain.models import PersistenceError, PlannerError, SubnetInfo, VlsmPlan
from .domain.vlsm import plan_vlsm, segments_from_rows
from .persistence import config, csv_io, svg_export
from .persistence.repository import (
    export_report,
    load_plan,
    plan_to_dict,
    save_plan,
)

logger = logging.getLogger("vlsm.app")


class UserError(Exception):
    """Friendly, user-displayable error (message is safe to show in a dialog)."""


class AppController:
    def __init__(self) -> None:
        self._last_plan: VlsmPlan | None = None

    # -- Calculator -------------------------------------------------------

    def calculate(self, ip: str, prefix_or_mask: str) -> SubnetInfo:
        text = (prefix_or_mask or "").strip()
        try:
            if "." in text and not text.startswith("/"):
                info = calculate_subnet_from_mask(ip, text)
            else:
                info = calculate_subnet(ip, text)
        except (PlannerError, ValueError) as exc:
            raise UserError(str(exc)) from exc
        logger.info(
            "calc ip=%s mask=%s -> %s usable=%d",
            ip, text, info.network, info.usable_hosts,
        )
        return info

    def divide(self, network: str, parts: int) -> List[SubnetInfo]:
        try:
            results = divide_network(network, parts)
        except (PlannerError, ValueError) as exc:
            raise UserError(str(exc)) from exc
        logger.info("divide net=%s parts=%d -> %d subnets", network, parts, len(results))
        return results

    # -- VLSM -------------------------------------------------------------

    def plan(self, base_network: str, rows: Sequence[Tuple[str, str]]) -> VlsmPlan:
        try:
            segments = segments_from_rows(rows)
            plan = plan_vlsm(base_network, segments)
        except (PlannerError, ValueError) as exc:
            raise UserError(str(exc)) from exc
        self._last_plan = plan
        logger.info(
            "vlsm base=%s segments=%d required=%d wasted=%d eff=%.2f%%",
            plan.base_network,
            len(plan.segments),
            plan.total_required,
            plan.total_wasted,
            plan.efficiency * 100,
        )
        return plan

    def save_plan(self, path: str, plan: VlsmPlan) -> None:
        try:
            save_plan(path, plan)
        except PersistenceError as exc:
            logger.warning("save_plan failed for %s: %s", path, exc)
            raise UserError(str(exc)) from exc
        except Exception as exc:  # unexpected OS errors
            logger.exception("save_plan failed for %s", path)
            raise UserError(f"Unexpected error while saving: {exc}") from exc
        logger.info("saved plan -> %s", path)

    def load_plan(self, path: str) -> VlsmPlan:
        try:
            plan = load_plan(path)
        except PersistenceError as exc:
            logger.warning("load_plan failed for %s: %s", path, exc)
            raise UserError(str(exc)) from exc
        except Exception as exc:
            logger.exception("load_plan failed for %s", path)
            raise UserError(f"Unexpected error while loading: {exc}") from exc
        self._last_plan = plan
        logger.info("loaded plan <- %s (%d segments)", path, len(plan.segments))
        return plan

    def export_report(self, path: str, plan: VlsmPlan) -> None:
        try:
            export_report(path, plan)
        except PersistenceError as exc:
            logger.warning("export failed for %s: %s", path, exc)
            raise UserError(str(exc)) from exc
        except Exception as exc:
            logger.exception("export failed for %s", path)
            raise UserError(f"Unexpected error while exporting: {exc}") from exc
        logger.info("exported report -> %s", path)

    def summary(self, plan: VlsmPlan) -> dict:
        return plan_to_dict(plan)

    # -- CSV -----------------------------------------------------------------

    def import_segments(self, path: str) -> list[tuple[str, int]]:
        """Load and validate a segment CSV; returns [(name, hosts)]."""
        try:
            segments = csv_io.load_segments_csv(path)
        except PersistenceError as exc:
            logger.warning("csv import failed for %s: %s", path, exc)
            raise UserError(str(exc)) from exc
        except Exception as exc:
            logger.exception("csv import failed for %s", path)
            raise UserError(f"Unexpected error while importing CSV: {exc}") from exc
        logger.info("csv import <- %s (%d segments)", path, len(segments))
        return segments

    def export_segments(self, path: str, rows: Sequence[Tuple[str, str]]) -> None:
        """Validate raw GUI rows and write them as a segment CSV."""
        try:
            segments = segments_from_rows(rows)  # raises PlannerError
            csv_io.export_segments_csv(path, segments)
        except PlannerError as exc:
            raise UserError(str(exc)) from exc
        except PersistenceError as exc:
            logger.warning("csv export failed for %s: %s", path, exc)
            raise UserError(str(exc)) from exc
        except Exception as exc:
            logger.exception("csv export failed for %s", path)
            raise UserError(f"Unexpected error while exporting CSV: {exc}") from exc
        logger.info("csv export -> %s (%d segments)", path, len(segments))

    def export_results_csv(self, path: str, plan: VlsmPlan) -> None:
        """Export the allocation result table as CSV."""
        try:
            csv_io.export_results_csv(path, plan)
        except PersistenceError as exc:
            logger.warning("results csv export failed for %s: %s", path, exc)
            raise UserError(str(exc)) from exc
        except Exception as exc:
            logger.exception("results csv export failed for %s", path)
            raise UserError(f"Unexpected error while exporting results CSV: {exc}") from exc
        logger.info("results csv export -> %s", path)

    # -- Preferences -----------------------------------------------------------

    def get_theme(self) -> str:
        """Current UI theme ('light'/'dark'); never raises."""
        try:
            return config.load_theme()
        except Exception:
            logger.exception("load_theme failed; using default")
            return config.DEFAULT_THEME

    def set_theme(self, mode: str) -> str:
        """Persist the UI theme; returns the normalized mode."""
        mode = mode if mode in config.VALID_THEMES else config.DEFAULT_THEME
        try:
            config.save_theme(mode)
        except Exception:
            logger.exception("save_theme failed for %s", mode)
        logger.info("theme -> %s", mode)
        return mode

    # -- SVG -----------------------------------------------------------------

    def export_svg(self, path: str, plan: VlsmPlan) -> None:
        """Export the allocation diagram as a self-contained SVG."""
        try:
            svg_export.export_svg(path, plan)
        except PersistenceError as exc:
            logger.warning("svg export failed for %s: %s", path, exc)
            raise UserError(str(exc)) from exc
        except Exception as exc:
            logger.exception("svg export failed for %s", path)
            raise UserError(f"Unexpected error while exporting SVG: {exc}") from exc
        logger.info("svg export -> %s", path)