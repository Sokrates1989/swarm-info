"""Publish and summarize the versioned standalone host capability profile.

The command is intentionally cheap: it reads release metadata and executes only
Docker information, Compose-version, and Scout-version probes. It never scans
images, reads registry credentials, or emits process environment values.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Mapping, Sequence

from scripts.operator_report import load_messages, message, selected_locale
from scripts.platforms import (
    HOST_OS_MODES,
    detect_platform_profile,
    platform_adapter_for,
)
from scripts.security_check import RUNTIME_MODES, security_platform_argument
from scripts.vulnerability_models import write_json_atomic
from scripts.vulnerability_scan import DockerClient


def default_output_file(
    profile_adapter: str,
    environment: Mapping[str, str],
) -> Path:
    """Resolve the platform-owned evidence path for a selected adapter."""

    from scripts.platforms.model import HostOsProfile

    host_os = HostOsProfile(
        family="qnap" if profile_adapter == "qnap" else "generic-linux",
        name="Linux",
        version=None,
        model=None,
        detection="resolved-profile",
        platform_adapter=profile_adapter,
    )
    return platform_adapter_for(host_os).default_evidence_directory(
        environment
    ) / "platform_info.json"


def parse_arguments(
    arguments: Sequence[str] | None,
    catalog: Mapping[str, str],
) -> argparse.Namespace:
    """Parse platform detection, persistence, and output-format options."""

    parser = argparse.ArgumentParser(
        description=message(catalog, "platformInfo.help.description")
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help=message(catalog, "platformInfo.help.json"),
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        help=message(catalog, "platformInfo.help.output"),
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help=message(catalog, "platformInfo.help.noWrite"),
    )
    parser.add_argument("--os", choices=HOST_OS_MODES, default="auto")
    parser.add_argument("--runtime-mode", choices=RUNTIME_MODES, default="auto")
    parser.add_argument(
        "--platform",
        type=security_platform_argument,
        default="auto",
    )
    return parser.parse_args(arguments)


def render_summary(
    payload: Mapping[str, object],
    output_file: Path | None,
    catalog: Mapping[str, str],
) -> str:
    """Render a localized human summary from the public machine contract."""

    os_profile = payload["os"]
    docker = payload["docker"]
    capabilities = payload["capabilities"]
    assert isinstance(os_profile, Mapping)
    assert isinstance(docker, Mapping)
    assert isinstance(capabilities, Mapping)
    available_key = (
        "platformInfo.available"
        if docker.get("compose_available") is True
        else "platformInfo.unavailable"
    )
    lines = [
        message(catalog, "platformInfo.title"),
        message(
            catalog,
            "platformInfo.adapter",
            adapter=payload["platform_adapter"],
        ),
        message(
            catalog,
            "platformInfo.os",
            name=os_profile.get("pretty_name"),
            family=os_profile.get("family"),
            version=os_profile.get("version"),
        ),
        message(
            catalog,
            "platformInfo.docker",
            mode=docker.get("runtime_mode"),
            platform=docker.get("platform"),
        ),
        message(
            catalog,
            "platformInfo.compose",
            status=message(catalog, available_key),
        ),
        message(
            catalog,
            "platformInfo.scheduler",
            scheduler=capabilities.get("scheduler"),
        ),
    ]
    if output_file is not None:
        lines.append(message(catalog, "platformInfo.report", path=output_file))
    return "\n".join(lines)


def main(arguments: Sequence[str] | None = None) -> int:
    """Detect, optionally persist, and print the sanitized platform profile."""

    environment = os.environ
    catalog = load_messages(selected_locale(environment))
    options = parse_arguments(arguments, catalog)
    profile = detect_platform_profile(
        DockerClient(environment=environment),
        requested_os=options.os,
        requested_runtime=options.runtime_mode,
        requested_platform=options.platform,
    )
    payload = profile.to_dict()
    output_file = None
    if not options.no_write:
        output_file = options.output_file or default_output_file(
            profile.host_os.platform_adapter, environment
        )
        try:
            write_json_atomic(output_file, payload)
        except (OSError, TypeError) as error:
            print(
                message(catalog, "platformInfo.writeError", detail=error),
                file=sys.stderr,
            )
            return 1
    if options.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_summary(payload, output_file, catalog))
    return 0 if profile.docker.daemon_available else 1


if __name__ == "__main__":
    raise SystemExit(main())
