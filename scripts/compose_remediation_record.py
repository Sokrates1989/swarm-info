"""Private transaction-plan persistence for Compose remediation."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping

from scripts.compose_remediation_engine import (
    PLAN_SCHEMA_VERSION,
    ComposeEvidence,
    ComposeRemediationError,
)
from scripts.vulnerability_models import utc_timestamp, write_json_atomic


def append_event(plan: dict[str, Any], event: str, **details: Any) -> None:
    """Append one bounded transaction event to the private plan."""

    events = plan.setdefault("events", [])
    if isinstance(events, list):
        events.append({"at": utc_timestamp(), "event": event, **details})


def write_plan(path: Path, plan: Mapping[str, Any]) -> None:
    """Publish owner-only transaction evidence atomically."""

    write_json_atomic(path, plan)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def post_check_path(plan_path: Path) -> Path:
    """Return the private focused post-check path for one transaction."""

    return plan_path.with_name(f"{plan_path.name}.post-check.json")


def backup_path(plan_path: Path) -> Path:
    """Return the private exact-byte source backup path."""

    return plan_path.with_name(f"{plan_path.name}.source-backup")


def load_transaction_plan(path: Path) -> dict[str, Any]:
    """Load one private transaction plan for explicit rollback."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ComposeRemediationError("planUnreadable", str(path)) from error
    if not isinstance(payload, dict) or payload.get("schema_version") != PLAN_SCHEMA_VERSION:
        raise ComposeRemediationError("planSchema")
    if payload.get("status") not in {"deployed", "rolled-back"}:
        raise ComposeRemediationError("planNotDeployed", str(payload.get("status")))
    return payload


def rollback_evidence(plan: Mapping[str, Any]) -> ComposeEvidence:
    """Reconstruct only exact non-secret Compose coordinates from a plan."""

    try:
        selector = plan["compose_service"]
        project, service = selector.split("/", 1)
        source = plan["source"]
        current = plan["current"]
        return ComposeEvidence(
            selector=selector,
            project=project,
            service=service,
            container_name="",
            current_reference=current["reference"],
            current_image_id=current["local_image_id"],
            working_directory=Path(source["working_directory"]),
            config_files=tuple(Path(value) for value in source["config_files"]),
            platform="",
            critical=0,
            high=0,
            finding_ids=(),
            completed_at="",
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ComposeRemediationError("planFields") from error
