"""Localized read-only menus and detailed vulnerability fix guidance."""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, TextIO

from scripts.operator_report import message, safe_text
from scripts.remediation_advice import ImageAdvice
from scripts.remediation_advice_view import analyze_and_render_image
from scripts.remediation_policy import RemediationPolicy, is_mutable_latest
from scripts.terminal_style import TerminalStyle
from scripts.vulnerability_scan import DockerClient


def _localized_code(
    catalog: Mapping[str, str], prefix: str, code: object
) -> str:
    """Translate one stable code with a localized unknown fallback."""

    key = f"{prefix}.{safe_text(code)}"
    return catalog.get(key, catalog[f"{prefix}.unknown"])


def _images(items: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate flattened service records into priority-sorted images."""

    grouped: dict[str, dict[str, Any]] = {}
    for item in items:
        image = str(item.get("scan_reference") or item["image"])
        if image not in grouped:
            grouped[image] = {**item, "image": image}
    return sorted(
        grouped.values(),
        key=lambda item: (-item["critical"], -item["high"], item["image"]),
    )


def _select(
    records: Sequence[Mapping[str, Any]],
    label: Callable[[Mapping[str, Any]], str],
    catalog: Mapping[str, str],
    input_function: Callable[[str], str],
    output: TextIO,
) -> Mapping[str, Any] | None:
    """Render a complete numbered selection and return the selected record."""

    for index, record in enumerate(records, start=1):
        print(f"{index}) {label(record)}", file=output)
    print(f"q) {message(catalog, 'remediation.cancel')}", file=output)
    choice = input_function(message(catalog, "remediation.selectPrompt")).strip().lower()
    if choice == "q":
        return None
    try:
        index = int(choice) - 1
    except ValueError:
        print(message(catalog, "remediation.invalidSelection"), file=output)
        return None
    if index < 0 or index >= len(records):
        print(message(catalog, "remediation.invalidSelection"), file=output)
        return None
    return records[index]


def _mapping_guidance(
    item: Mapping[str, Any],
    mapping: Mapping[str, Any] | None,
    related_mappings: Mapping[str, Mapping[str, Any]] | None,
    advice: ImageAdvice,
    catalog: Mapping[str, str],
    output: TextIO,
    style: TerminalStyle,
) -> bool:
    """Render source edits or redeploy-only guidance for every distinct stack."""

    services = item.get("services", [])
    service_scope = services if related_mappings is not None else [item["service"]]
    record_scope = (
        [related_mappings.get(str(service)) for service in service_scope]
        if related_mappings is not None
        else [mapping]
    )
    mapped_records: list[tuple[Mapping[str, Any], bool]] = []
    seen_sources: set[tuple[str, str]] = set()
    for service, record in zip(service_scope, record_scope):
        if record and record.get("status") == "mapped":
            directory = safe_text(record.get("directory"))
            stack_file = safe_text(record.get("stack_file"))
            stack = safe_text(record.get("stack"))
            if (stack_file, stack) in seen_sources:
                continue
            seen_sources.add((stack_file, stack))
            latest_redeploy = (
                advice.candidate_source == "latest-refresh"
                and advice.validated_candidate is not None
                and is_mutable_latest(record.get("declared_image"))
            )
            mapped_records.append((record, not latest_redeploy))
            print("", file=output)
            print(
                message(
                    catalog,
                    "remediation.detailMappedService",
                    service=service,
                    directory=directory,
                ),
                file=output,
            )
            print(style.command(f"  {shlex.join(['cd', '--', directory])}"), file=output)
            print(message(catalog, "remediation.detailSource", stack_file=stack_file), file=output)
            if advice.validated_candidate is not None:
                key = (
                    "remediation.detailLatestRedeploy"
                    if latest_redeploy
                    else "remediation.detailCandidateSource"
                )
                print(
                    style.success(
                        message(
                            catalog,
                            key,
                            candidate=advice.validated_candidate.reference,
                        )
                    ),
                    file=output,
                )
            if record.get("source_verified") is False:
                print(
                    message(catalog, "remediation.detailSourceUnverified"),
                    file=output,
                )
            continue
        reason = _localized_code(
            catalog,
            "deployment.reason",
            record.get("reason") if record else "unknown",
        )
        print("", file=output)
        print(
            message(
                catalog,
                "remediation.detailUnknownService",
                service=service,
                reason=reason,
            ),
            file=output,
        )
        print(
            style.command(
                "  swarm-info --map-service-deployments --deploy-root /swarm"
            ),
            file=output,
        )
        print(message(catalog, "remediation.detailRuntimeWarning"), file=output)
        runtime_image = (
            advice.validated_candidate.reference
            if advice.validated_candidate is not None
            else "<PATCHED_IMAGE@SHA256>"
        )
        runtime_command = [
            "docker",
            "service",
            "update",
            "--with-registry-auth",
            "--image",
            runtime_image,
            str(service),
        ]
        print(
            style.command(f"  {shlex.join(runtime_command)}"),
            file=output,
        )
    for record, source_edit_required in mapped_records:
        directory = safe_text(record.get("directory"))
        stack_file = safe_text(record.get("stack_file"))
        stack = safe_text(record.get("stack"))
        if source_edit_required:
            print(message(catalog, "remediation.detailEditReview"), file=output)
            print(
                style.command(f"  {shlex.join(['git', 'diff', '--', stack_file])}"),
                file=output,
            )
        quick_start = Path(directory) / "quick-start.sh"
        if quick_start.is_file() and not quick_start.is_symlink():
            print(message(catalog, "remediation.detailQuickStart"), file=output)
            print(style.command("  ./quick-start.sh"), file=output)
            continue
        print(message(catalog, "remediation.detailDeploy"), file=output)
        deploy_command = [
            "docker",
            "stack",
            "deploy",
            "--with-registry-auth",
            "--resolve-image",
            "always",
            "-c",
            stack_file,
            stack,
        ]
        print(
            style.command(f"  {shlex.join(deploy_command)}"),
            file=output,
        )
    return True


def render_detail(
    item: Mapping[str, Any],
    mapping: Mapping[str, Any] | None,
    catalog: Mapping[str, str],
    output: TextIO,
    input_function: Callable[[str], str] | None = None,
    related_mappings: Mapping[str, Mapping[str, Any]] | None = None,
    client: DockerClient | None = None,
    platform: str = "linux/amd64",
    policy: RemediationPolicy | None = None,
) -> None:
    """Render concrete investigation, source, deployment, and verification steps."""

    image = safe_text(item.get("image"))
    services = item.get("services", [])
    style = TerminalStyle(output)
    print("", file=output)
    print(
        style.heading(message(catalog, "remediation.detailTitle", service=item["service"])),
        file=output,
    )
    print("-" * 70, file=output)
    print(
        message(
            catalog,
            "remediation.detailRisk",
            critical=item["critical"],
            high=item["high"],
            shared=item["shared_service_count"],
        ),
        file=output,
    )
    print(message(catalog, "remediation.detailImage", image=image), file=output)
    print(
        message(catalog, "remediation.detailServices", services=", ".join(services)),
        file=output,
    )
    print("", file=output)
    print(style.heading(message(catalog, "remediation.detailTerminal")), file=output)
    if input_function is not None:
        choice = input_function(message(catalog, "remediation.terminalPrompt")).strip().lower()
        if choice == "q":
            return
    print("", file=output)
    print(style.heading(message(catalog, "remediation.detailInspect")), file=output)
    recommendations_command = [
        "docker",
        "scout",
        "recommendations",
        "--platform",
        platform,
        image,
    ]
    print(style.command(f"  {shlex.join(recommendations_command)}"), file=output)
    cves_command = [
        "docker",
        "scout",
        "cves",
        "--only-fixed",
        "--only-severity",
        "critical,high",
        "--platform",
        platform,
        image,
    ]
    print(
        style.command(f"  {shlex.join(cves_command)}"),
        file=output,
    )
    print(message(catalog, "remediation.currentEvidenceReused"), file=output)
    print(style.warning(message(catalog, "remediation.analysisStarting")), file=output)
    advice = analyze_and_render_image(
        client or DockerClient(),
        item,
        platform,
        policy,
        catalog,
        output,
        style,
    )
    print(message(catalog, "remediation.detailMeaning"), file=output)
    print(message(catalog, "remediation.detailFirstParty"), file=output)
    print(message(catalog, "remediation.detailThirdParty"), file=output)
    print(message(catalog, "remediation.detailVex"), file=output)
    if not _mapping_guidance(
        item,
        mapping,
        related_mappings,
        advice,
        catalog,
        output,
        style,
    ):
        return
    print("", file=output)
    print(message(catalog, "remediation.detailVerify"), file=output)
    print(
        style.command(
            f"  {shlex.join(['docker', 'service', 'ps', str(item['service']), '--no-trunc'])}"
        ),
        file=output,
    )
    print(
        style.command(
            "  swarm-info --scan-vulnerabilities --output-file /info_json/vulnerability_scan.json"
        ),
        file=output,
    )


def run_targeted(
    mode: str,
    items: list[dict[str, Any]],
    mappings: Mapping[str, Mapping[str, Any]],
    catalog: Mapping[str, str],
    input_function: Callable[[str], str],
    output: TextIO,
    client: DockerClient | None = None,
    platform: str = "linux/amd64",
    policy: RemediationPolicy | None = None,
) -> None:
    """Select one service/image or walk every image by remediation priority."""

    if mode == "service":
        records = sorted(items, key=lambda item: item["service"])
        selected = _select(
            records,
            lambda item: message(
                catalog,
                "remediation.serviceOption",
                service=item["service"],
                critical=item["critical"],
                high=item["high"],
                shared=item["shared_service_count"],
            ),
            catalog,
            input_function,
            output,
        )
        if selected:
            render_detail(
                selected,
                mappings.get(str(selected["service"])),
                catalog,
                output,
                input_function=input_function,
                client=client,
                platform=platform,
                policy=policy,
            )
        return
    if mode == "image":
        records = _images(items)
        selected = _select(
            records,
            lambda item: message(
                catalog,
                "remediation.imageOption",
                image=item["image"],
                critical=item["critical"],
                high=item["high"],
                shared=item["shared_service_count"],
            ),
            catalog,
            input_function,
            output,
        )
        if selected:
            service = str(selected["services"][0])
            selected = {**selected, "service": service}
            render_detail(
                selected,
                mappings.get(service),
                catalog,
                output,
                input_function=input_function,
                related_mappings=mappings,
                client=client,
                platform=platform,
                policy=policy,
            )
        return
    seen_images: set[str] = set()
    for item in items:
        if item["image"] in seen_images:
            continue
        seen_images.add(item["image"])
        render_detail(
            item,
            mappings.get(str(item["service"])),
            catalog,
            output,
            input_function=input_function,
            related_mappings=mappings,
            client=client,
            platform=platform,
            policy=policy,
        )
        choice = input_function(message(catalog, "remediation.nextPrompt")).strip().lower()
        if choice == "q":
            break
