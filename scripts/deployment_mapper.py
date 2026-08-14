"""CLI renderer for conservative Swarm service deployment-path evidence."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

from scripts.deployment_mapping import DeploymentRootError, build_deployment_map
from scripts.operator_report import load_messages, message, safe_text, selected_locale
from scripts.vulnerability_models import write_json_atomic
from scripts.vulnerability_scan import DockerClient, InventoryError, collect_services


DEFAULT_DEPLOY_ROOT = Path("/swarm")


def default_deploy_roots(environment: Mapping[str, str] | None = None) -> list[Path]:
    """Resolve configured roots from ``SWARM_INFO_DEPLOY_ROOTS`` or ``/swarm``."""

    values = os.environ if environment is None else environment
    configured = values.get("SWARM_INFO_DEPLOY_ROOTS", "").strip()
    if not configured:
        return [DEFAULT_DEPLOY_ROOT]
    return [Path(item) for item in configured.split(os.pathsep) if item]


def parse_arguments(
    arguments: Sequence[str] | None,
    catalog: Mapping[str, str],
) -> argparse.Namespace:
    """Parse the standalone deployment-mapping command line."""

    parser = argparse.ArgumentParser(
        description=message(catalog, "deployment.description")
    )
    parser.add_argument(
        "--deploy-root",
        action="append",
        type=Path,
        dest="deploy_roots",
        help=message(catalog, "deployment.rootHelp"),
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        help=message(catalog, "deployment.outputHelp"),
    )
    return parser.parse_args(arguments)


def reason_text(catalog: Mapping[str, str], reason: object) -> str:
    """Translate one stable mapper reason code."""

    key = f"deployment.reason.{safe_text(reason)}"
    return catalog.get(key, catalog["deployment.reason.unknown"])


def render_deployment_map(
    report: Mapping[str, Any], catalog: Mapping[str, str]
) -> str:
    """Render every service mapping so operators can verify false positives."""

    summary = report.get("summary")
    roots = report.get("deploy_roots")
    renderer = report.get("renderer")
    services = report.get("services")
    if not isinstance(summary, Mapping) or not isinstance(services, list):
        raise ValueError("invalid deployment map")
    root_text = ", ".join(safe_text(root) for root in roots or [])
    lines = [message(catalog, "deployment.title"), "-" * 70]
    lines.append(message(catalog, "deployment.roots", roots=root_text))
    lines.append(
        message(
            catalog,
            "deployment.summary",
            total=summary.get("service_count", 0),
            mapped=summary.get("mapped", 0),
            unknown=summary.get("unknown", 0),
            ambiguous=summary.get("ambiguous", 0),
        )
    )
    if not isinstance(renderer, Mapping) or renderer.get("available") is not True:
        lines.extend(["", message(catalog, "deployment.composeUnavailable")])
    lines.extend(["", message(catalog, "deployment.services")])
    for service in services:
        if not isinstance(service, Mapping):
            continue
        status = safe_text(service.get("status", "unknown"))
        if status == "mapped":
            lines.append(
                message(
                    catalog,
                    "deployment.mapped",
                    name=safe_text(service.get("name", "unknown")),
                    stack_file=safe_text(service.get("stack_file", "unknown")),
                    compose_service=safe_text(
                        service.get("compose_service", "unknown")
                    ),
                    image=safe_text(service.get("image") or "unknown"),
                )
            )
        else:
            lines.append(
                message(
                    catalog,
                    "deployment.unresolved",
                    marker=catalog[
                        "deployment.marker.ambiguous"
                        if status == "ambiguous"
                        else "deployment.marker.unknown"
                    ],
                    name=safe_text(service.get("name", "unknown")),
                    stack=safe_text(service.get("stack") or catalog["common.none"]),
                    image=safe_text(service.get("image") or "unknown"),
                    reason=reason_text(catalog, service.get("reason")),
                )
            )
            candidate_files = service.get("candidate_files")
            if isinstance(candidate_files, list):
                for candidate in candidate_files:
                    lines.append(
                        message(
                            catalog,
                            "deployment.candidate",
                            stack_file=safe_text(candidate),
                        )
                    )
    return "\n".join(lines)


def main(arguments: Sequence[str] | None = None) -> int:
    """Inventory services, map stack files, and optionally publish JSON."""

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    catalog = load_messages(selected_locale())
    options = parse_arguments(arguments, catalog)
    roots = options.deploy_roots or default_deploy_roots()
    try:
        services = collect_services(DockerClient())
        report = build_deployment_map(DockerClient(), services, roots)
        output = render_deployment_map(report, catalog)
        if options.output_file is not None:
            write_json_atomic(options.output_file, report)
    except DeploymentRootError as error:
        print(
            message(
                catalog,
                f"deployment.rootError.{error.code}",
                path=safe_text(error.path or ""),
            ),
            file=sys.stderr,
        )
        return 3
    except InventoryError:
        print(message(catalog, "deployment.inventoryError"), file=sys.stderr)
        return 3
    except (OSError, TypeError, ValueError):
        print(message(catalog, "deployment.unexpectedError"), file=sys.stderr)
        return 3
    print(output)
    if options.output_file is not None:
        print(
            message(
                catalog,
                "deployment.saved",
                path=safe_text(options.output_file),
            )
        )
    summary = report["summary"]
    return 0 if summary["unknown"] == 0 and summary["ambiguous"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
