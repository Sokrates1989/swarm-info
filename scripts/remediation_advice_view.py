"""Localized terminal presentation for read-only remediation image advice."""

from __future__ import annotations

import threading
import time
from typing import Any, Mapping, TextIO

from scripts.operator_report import message, safe_text
from scripts.remediation_advice import ImageAdvice, analyze_image
from scripts.remediation_policy import RemediationPolicy
from scripts.terminal_style import TerminalStyle
from scripts.vulnerability_scan import DockerClient, format_elapsed


def _localized_code(
    catalog: Mapping[str, str], prefix: str, code: object
) -> str:
    """Translate one stable advice code with a localized unknown fallback."""

    key = f"{prefix}.{safe_text(code)}"
    return catalog.get(key, catalog[f"{prefix}.unknown"])


def _analyze_with_heartbeat(
    client: DockerClient,
    item: Mapping[str, Any],
    platform: str,
    policy: RemediationPolicy | None,
    catalog: Mapping[str, str],
    output: TextIO,
    style: TerminalStyle,
) -> ImageAdvice:
    """Keep the terminal visibly active during read-only Scout and registry work."""

    stopped = threading.Event()
    started_at = time.monotonic()

    def report_progress() -> None:
        while not stopped.wait(30):
            elapsed = format_elapsed(time.monotonic() - started_at)
            print(
                style.warning(
                    message(
                        catalog,
                        "remediation.analysisHeartbeat",
                        elapsed=elapsed,
                    )
                ),
                file=output,
            )

    reporter = threading.Thread(
        target=report_progress,
        name="swarm-info-remediation-advice",
        daemon=True,
    )
    reporter.start()
    try:
        return analyze_image(client, item, platform, policy)
    finally:
        stopped.set()
        reporter.join(timeout=1)


def _render_current_and_base(
    advice: ImageAdvice,
    catalog: Mapping[str, str],
    output: TextIO,
    style: TerminalStyle,
) -> None:
    """Render current release provenance and Scout base-image advice."""

    if advice.current_version:
        source = _localized_code(
            catalog,
            "remediation.versionSource",
            advice.current_version_source,
        )
        print(
            message(
                catalog,
                "remediation.currentVersion",
                version=advice.current_version,
                source=source,
            ),
            file=output,
        )
    else:
        print(
            style.warning(message(catalog, "remediation.currentVersionUnknown")),
            file=output,
        )

    if advice.scout.status == "available":
        refresh = advice.scout.refresh_tag or catalog["common.unknown"]
        print(
            message(
                catalog,
                "remediation.scoutBaseAdvice",
                base=advice.scout.base_image,
                refresh=refresh,
            ),
            file=output,
        )
    elif advice.scout.status == "no-base":
        print(message(catalog, "remediation.scoutNoBase"), file=output)
    elif advice.scout.status == "error":
        print(
            style.warning(
                message(
                    catalog,
                    "remediation.scoutAdviceFailed",
                    detail=advice.scout.error,
                )
            ),
            file=output,
        )
    else:
        print(message(catalog, "remediation.scoutAdviceUnavailable"), file=output)


def _render_validated_candidate(
    advice: ImageAdvice,
    catalog: Mapping[str, str],
    output: TextIO,
    style: TerminalStyle,
) -> bool:
    """Render one accepted candidate and return whether it was available."""

    if advice.proposal_state != "candidate-validated" or advice.candidate is None:
        return False
    source = _localized_code(
        catalog,
        "remediation.proposalSource",
        advice.candidate_source,
    )
    print(
        style.success(
            message(
                catalog,
                "remediation.proposalValidated",
                candidate=advice.candidate.reference,
                source=source,
                critical=advice.validation.critical if advice.validation else 0,
                high=advice.validation.high if advice.validation else 0,
            )
        ),
        file=output,
    )
    if advice.validation is not None:
        print(
            style.success(
                message(
                    catalog,
                    "remediation.proposalReduction",
                    removed=advice.validation.comparison.removed_total,
                    remaining=advice.validation.comparison.candidate_total,
                )
            ),
            file=output,
        )
    if advice.candidate_version:
        compatibility = _localized_code(
            catalog,
            "remediation.compatibility",
            advice.compatibility,
        )
        print(
            message(
                catalog,
                "remediation.proposedVersion",
                version=advice.candidate_version,
                compatibility=compatibility,
            ),
            file=output,
        )
    if advice.candidate_source == "latest-refresh":
        print(message(catalog, "remediation.latestRefreshAction"), file=output)
    if advice.policy_service_count:
        print(
            message(
                catalog,
                "remediation.policyCoverage",
                count=advice.policy_service_count,
            ),
            file=output,
        )
    return True


def _render_proposal_state(
    advice: ImageAdvice,
    catalog: Mapping[str, str],
    output: TextIO,
    style: TerminalStyle,
) -> None:
    """Render rejected, unresolved, unchanged, or manual-review proposal state."""

    if _render_validated_candidate(advice, catalog, output, style):
        return
    if advice.proposal_state == "candidate-rejected":
        reason = _localized_code(
            catalog,
            "remediation.proposalReason",
            advice.validation_error,
        )
        print(
            style.error(
                message(
                    catalog,
                    "remediation.proposalRejected",
                    candidate=advice.candidate.reference if advice.candidate else "",
                    reason=reason,
                )
            ),
            file=output,
        )
        return
    state_key = f"remediation.proposalState.{advice.proposal_state}"
    state_message = catalog.get(
        state_key,
        catalog["remediation.proposalState.manual-review"],
    )
    print(style.warning(state_message), file=output)


def analyze_and_render_image(
    client: DockerClient,
    item: Mapping[str, Any],
    platform: str,
    policy: RemediationPolicy | None,
    catalog: Mapping[str, str],
    output: TextIO,
    style: TerminalStyle,
) -> ImageAdvice:
    """Analyze one image with heartbeat and render all resulting evidence."""

    advice = _analyze_with_heartbeat(
        client,
        item,
        platform,
        policy,
        catalog,
        output,
        style,
    )
    _render_current_and_base(advice, catalog, output, style)
    _render_proposal_state(advice, catalog, output, style)
    return advice
