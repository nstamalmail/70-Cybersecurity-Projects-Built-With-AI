"""Project persistence — versioned JSON with atomic writes.

Project files are plain JSON (no execution content), so loading a project
can never run code. Schema migrations hook in here via PROJECT_FORMAT_VERSION.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any

from .models import PROJECT_FORMAT_VERSION, RulePackProject


def save_project(project: RulePackProject, path: str) -> None:
    payload = project.to_dict()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    # Atomic write: write to a temp file in the same dir, then rename.
    fd, tmp = tempfile.mkstemp(
        prefix=".wazuhpack-", suffix=".json", dir=os.path.dirname(os.path.abspath(path))
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_project(path: str) -> RulePackProject:
    with open(path, "r", encoding="utf-8") as fh:
        raw: Any = json.load(fh)

    if not isinstance(raw, dict) or raw.get("format") != "wazuh_rule_pack_builder":
        raise ValueError("Not a rule pack builder project file.")

    version = raw.get("version", 0)
    if version > PROJECT_FORMAT_VERSION:
        raise ValueError(
            f"Project version {version} is newer than this build supports "
            f"(max {PROJECT_FORMAT_VERSION})."
        )
    # v1 is the only schema so far; future migrations branch on `version` here.
    return RulePackProject.from_dict(raw)