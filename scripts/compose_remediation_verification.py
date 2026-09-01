"""Focused post-update security verification for Compose remediation."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from scripts.compose_remediation_engine import (
    ComposeRemediationError,
    PreparedComposeRemediation,
)
from scripts.compose_remediation_record import write_plan
from scripts.security_check import run_security_check
from scripts.vulnerability_scan import DockerClient


def _finding_ids(image: Mapping[str, Any]) -> set[str]:
    """Extract normalized finding identities from one report image."""

    findings = image.get("findings")
    return {
        item["id"]
        for item in findings or []
        if isinstance(item, Mapping)
        and isinstance(item.get("id"), str)
        and item["id"]
    }


def run_focused_post_check(
    client: DockerClient,
    prepared: PreparedComposeRemediation,
    output_path: Path,
    *,
    host_os: str = "auto",
) -> Mapping[str, Any]:
    """Publish and validate a fresh exact Compose-service security report."""

    report, exit_code = run_security_check(
        client,
        runtime_mode="containers",
        requested_platform=prepared.evidence.platform,
        host_os_mode=host_os,
        process_environment=os.environ,
        focus_kind="compose-service",
        focus_selector=prepared.evidence.selector,
    )
    write_plan(output_path, report)
    images = report.get("images")
    if exit_code not in {0, 2} or report.get("errors"):
        raise ComposeRemediationError("postCheckIncomplete")
    if (
        not isinstance(images, list)
        or len(images) != 1
        or not isinstance(images[0], Mapping)
    ):
        raise ComposeRemediationError("postCheckImageCount")
    image = images[0]
    candidate_image_id = prepared.plan.get("candidate", {}).get("local_image_id")
    if (
        not isinstance(candidate_image_id, str)
        or image.get("local_image_id") != candidate_image_id
    ):
        raise ComposeRemediationError("postCheckImageChanged")
    if _finding_ids(image) != set(prepared.candidate_validation.finding_ids):
        raise ComposeRemediationError("postCheckFindingsChanged")
    counts = image.get("counts")
    if not isinstance(counts, Mapping) or (
        counts.get("critical") != prepared.candidate_validation.critical
        or counts.get("high") != prepared.candidate_validation.high
    ):
        raise ComposeRemediationError("postCheckCountsChanged")
    return report
