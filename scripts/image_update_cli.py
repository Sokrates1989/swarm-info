"""Public command boundary for read-only image update candidate discovery."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Mapping, Sequence, TextIO

from scripts.image_update_discovery import (
    DEFAULT_MAX_REGISTRY_TAGS,
    DiscoveryOutcome,
    ImageUpdateDiscoveryError,
    discover_image_updates,
    load_vulnerability_report,
)
from scripts.image_update_registry import RegistryTagClient
from scripts.operator_report import (
    SUPPORTED_LOCALES,
    load_messages,
    message,
    safe_text,
    selected_locale,
)
from scripts.remediation_policy import RemediationPolicyError, load_policy
from scripts.remediation_review import policy_output_path
from scripts.terminal_style import TerminalStyle
from scripts.vulnerability_job import ScanLock
from scripts.vulnerability_models import write_json_atomic
from scripts.vulnerability_scan import DEFAULT_PLATFORM, DockerClient, platform_argument


DEFAULT_REPORT_FILE = (
    Path(__file__).resolve().parent.parent / "swarm_info" / "vulnerability_scan.json"
)
DEFAULT_OUTPUT_FILE = (
    Path(__file__).resolve().parent.parent
    / "swarm_info"
    / "image_update_candidates.json"
)
REGISTRY_HOST_PATTERN = re.compile(
    r"^(?:localhost|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)"
    r"(?::[0-9]{1,5})?$"
)
REGISTRY_AUTH_ENVIRONMENT_KEYS = (
    "DOCKER_AUTH_CONFIG",
    "REGISTRY_AUTH_FILE",
)


def _anonymous_docker_environment(
    config_directory: Path,
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a Docker environment isolated from installed registry credentials."""

    values = dict(os.environ if environment is None else environment)
    values["DOCKER_CONFIG"] = str(config_directory)
    for key in REGISTRY_AUTH_ENVIRONMENT_KEYS:
        values.pop(key, None)
    return values


def registry_host_argument(value: str) -> str:
    """Validate and normalize an explicitly approved registry host."""

    normalized = value.strip().lower()
    if normalized in {"registry-1.docker.io", "index.docker.io"}:
        return "docker.io"
    if (
        not normalized
        or not REGISTRY_HOST_PATTERN.fullmatch(normalized)
        or ".." in normalized
    ):
        raise argparse.ArgumentTypeError("registry host must not contain a scheme or path")
    if ":" in normalized:
        port = int(normalized.rsplit(":", 1)[1])
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError("registry port must be between 1 and 65535")
    return normalized


def positive_tag_limit(value: str) -> int:
    """Parse the bounded maximum tag count accepted from one repository."""

    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("tag limit must be an integer") from error
    if not 1 <= parsed <= 10000:
        raise argparse.ArgumentTypeError("tag limit must be between 1 and 10000")
    return parsed


def _preferred_report_file() -> Path:
    """Prefer the shared production report when it already exists."""

    production = Path("/info_json/vulnerability_scan.json")
    return production if production.is_file() else DEFAULT_REPORT_FILE


def _preferred_output_file() -> Path:
    """Prefer the shared report directory when it is present and writable."""

    production = Path("/info_json/image_update_candidates.json")
    if production.parent.is_dir() and os.access(production.parent, os.W_OK):
        return production
    return DEFAULT_OUTPUT_FILE


def render_outcome(
    outcome: DiscoveryOutcome,
    output_file: Path,
    catalog: Mapping[str, str],
    output: TextIO,
) -> None:
    """Render concise candidate evidence while keeping the full list in JSON."""

    style = TerminalStyle(output)
    report = outcome.report
    summary = report["summary"]
    print(style.heading(message(catalog, "imageDiscovery.title")), file=output)
    print("-" * 70, file=output)
    print(message(catalog, "imageDiscovery.boundary"), file=output)
    print(
        message(
            catalog,
            "imageDiscovery.summary",
            images=summary["image_count"],
            repositories=summary["repository_count"],
            candidates=summary["candidate_count"],
        ),
        file=output,
    )
    required_hosts = report.get("required_registry_hosts") or []
    if required_hosts:
        print(style.warning(message(catalog, "imageDiscovery.approval")), file=output)
        command = "swarm-info --discover-image-updates " + " ".join(
            f"--allow-registry-host {host}" for host in required_hosts
        )
        print(f"  {style.command(command)}", file=output)
    candidate_images = [item for item in report["images"] if item["candidates"]]
    if candidate_images:
        print("", file=output)
        print(style.heading(message(catalog, "imageDiscovery.candidates")), file=output)
    for image in candidate_images[:12]:
        current = image["current"]
        print(
            message(
                catalog,
                "imageDiscovery.current",
                image=current["reference"],
                version=current["version"] or message(catalog, "imageDiscovery.unknown"),
            ),
            file=output,
        )
        for candidate in image["candidates"]:
            track_labels = [
                message(catalog, f"imageDiscovery.track.{track}")
                for track in candidate["tracks"]
            ]
            print(
                message(
                    catalog,
                    "imageDiscovery.candidate",
                    tracks=", ".join(track_labels),
                    image=candidate["immutable_reference"],
                    compatibility=message(
                        catalog,
                        f"imageDiscovery.compatibility.{candidate['compatibility']}",
                    ),
                ),
                file=output,
            )
    if len(candidate_images) > 12:
        print(
            message(catalog, "imageDiscovery.more", count=len(candidate_images) - 12),
            file=output,
        )
    print(message(catalog, "imageDiscovery.report", path=output_file), file=output)


def parse_arguments(
    arguments: Sequence[str] | None,
    catalog: Mapping[str, str],
) -> argparse.Namespace:
    """Parse the internal read-only image candidate discovery command."""

    parser = argparse.ArgumentParser(
        description=message(catalog, "imageDiscovery.description")
    )
    parser.add_argument("--report-file", type=Path, default=_preferred_report_file())
    parser.add_argument("--output-file", type=Path, default=_preferred_output_file())
    parser.add_argument("--platform", type=platform_argument, default=DEFAULT_PLATFORM)
    parser.add_argument(
        "--max-registry-tags",
        type=positive_tag_limit,
        default=DEFAULT_MAX_REGISTRY_TAGS,
    )
    parser.add_argument(
        "--allow-registry-host",
        action="append",
        type=registry_host_argument,
        default=[],
    )
    parser.add_argument("--remediation-policy", type=Path)
    parser.add_argument("--lock-file", type=Path)
    parser.add_argument("--locale", choices=SUPPORTED_LOCALES)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Discover candidates and atomically publish read-only lifecycle evidence."""

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    bootstrap_catalog = load_messages(selected_locale())
    options = parse_arguments(arguments, bootstrap_catalog)
    catalog = load_messages(options.locale)
    lock_path = options.lock_file or options.output_file.with_suffix(
        options.output_file.suffix + ".lock"
    )
    lock = ScanLock(lock_path)
    try:
        if not lock.acquire():
            print(
                message(catalog, "imageDiscovery.locked", path=lock_path),
                file=sys.stderr,
            )
            return 3
        source_report = load_vulnerability_report(options.report_file)
        selected_policy_path = policy_output_path(options.remediation_policy)
        if options.remediation_policy is not None and not selected_policy_path.is_file():
            raise ImageUpdateDiscoveryError("policy-unreadable", str(selected_policy_path))
        policy = load_policy(selected_policy_path) if selected_policy_path.is_file() else None
        with tempfile.TemporaryDirectory(
            prefix="swarm-info-anonymous-docker-"
        ) as docker_config:
            outcome = discover_image_updates(
                source_report,
                options.report_file,
                DockerClient(
                    environment=_anonymous_docker_environment(
                        Path(docker_config)
                    )
                ),
                RegistryTagClient(set(options.allow_registry_host)),
                options.platform,
                options.max_registry_tags,
                policy,
                progress=lambda index, total, repository: print(
                    message(
                        catalog,
                        "imageDiscovery.progress",
                        index=index,
                        total=total,
                        repository=repository,
                    ),
                    flush=True,
                ),
                docker_metadata_config="temporary-empty",
                registry_credentials_used=False,
            )
        write_json_atomic(options.output_file, outcome.report)
        render_outcome(outcome, options.output_file, catalog, sys.stdout)
        return outcome.exit_code
    except (
        ImageUpdateDiscoveryError,
        OSError,
        RemediationPolicyError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as error:
        code = getattr(error, "code", "operational-error")
        detail = getattr(error, "detail", safe_text(error))
        key = f"imageDiscovery.error.{code}"
        if key not in catalog:
            key = "imageDiscovery.error.operational-error"
        print(message(catalog, key, detail=detail), file=sys.stderr)
        return 3
    finally:
        lock.release()


if __name__ == "__main__":
    raise SystemExit(main())
