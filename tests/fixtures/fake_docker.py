#!/usr/bin/env python3

"""Deterministic Docker CLI fake for vulnerability scanner tests.

The executable supports Docker manager preflight, service inventory/inspect,
Scout version, and Scout CVE scans. It never accesses Docker or the network.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
from typing import Any


FIXTURE_DIRECTORY = Path(__file__).resolve().parent
DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)
DIGEST_C = "sha256:" + ("c" * 64)


def base_services() -> dict[str, dict[str, Any]]:
    """Return the standard three-service inventory.

    Returns:
        Service specifications with one shared clean image and one vulnerable
        private-registry image.
    """

    return {
        "service-alpha": {
            "name": "core_alpha",
            "image": f"acme/shared:1@{DIGEST_A}",
            "stack": "core",
        },
        "service-beta": {
            "name": "core_beta",
            "image": f"docker.io/acme/shared-alias:1@{DIGEST_A}",
            "stack": "core",
        },
        "service-gamma": {
            "name": "edge_gamma",
            "image": f"private.example/app:2@{DIGEST_B}",
            "stack": "edge",
        },
    }


def scenario_services(scenario: str) -> dict[str, dict[str, Any]]:
    """Build the service inventory for one requested fake scenario.

    Args:
        scenario: Scenario selected through `FAKE_DOCKER_SCENARIO`.

    Returns:
        Service specifications for the fake Docker commands.
    """

    if scenario == "zero-services":
        return {}
    if scenario == "mutable-reference":
        return {
            "service-redis": {
                "name": "cache_redis",
                "image": "redis:7-alpine",
                "stack": "cache",
            }
        }
    services = base_services()
    if scenario == "mapping-change":
        services["service-delta"] = {
            "name": "core_delta",
            "image": f"docker.io/acme/shared-third:1@{DIGEST_A}",
            "stack": "core",
        }
    if scenario == "partial-failure":
        services["service-delta"] = {
            "name": "ops_delta",
            "image": f"private.example/broken:3@{DIGEST_C}",
            "stack": "ops",
        }
    return services


def log_invocation(arguments: list[str]) -> None:
    """Append one fake Docker invocation to the configured JSON-lines log.

    Args:
        arguments: Docker arguments received by the fake.

    Returns:
        Nothing. No log is written when `FAKE_DOCKER_LOG` is unset.
    """

    log_path = os.environ.get("FAKE_DOCKER_LOG")
    if not log_path:
        return
    with Path(log_path).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(arguments) + "\n")


def inspect_payload(service: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a fake service to Docker inspect JSON form.

    Args:
        service: Fake name, image, and stack fields.

    Returns:
        Single-element Docker service inspect array.
    """

    return [
        {
            "Spec": {
                "Name": service["name"],
                "Labels": {"com.docker.stack.namespace": service["stack"]},
                "TaskTemplate": {"ContainerSpec": {"Image": service["image"]}},
            }
        }
    ]


def emit_sarif(filename: str, exit_code: int) -> int:
    """Print a checked-in SARIF fixture and return its Scout exit code.

    Args:
        filename: Fixture filename in the current directory.
        exit_code: Simulated Docker Scout exit code.

    Returns:
        The requested process exit code.
    """

    print((FIXTURE_DIRECTORY / filename).read_text(encoding="utf-8"))
    return exit_code


def handle_scout_cves(arguments: list[str], scenario: str) -> int:
    """Return the image-specific fake Docker Scout result.

    Args:
        arguments: Full fake Docker argument sequence.
        scenario: Selected fake scenario.

    Returns:
        Docker Scout-compatible exit code.
    """

    reference = arguments[-1]
    if DIGEST_C in reference:
        print(
            "registry token=secret-value failed for "
            "https://fake-user:fake-password@private.example",
            file=sys.stderr,
        )
        return 1
    if DIGEST_B in reference:
        if scenario == "invalid-sarif":
            print("not-json")
            return 2
        return emit_sarif("scout-vulnerable.sarif.json", 2)
    return emit_sarif("scout-clean.sarif.json", 0)


def main(arguments: list[str] | None = None) -> int:
    """Dispatch the supported fake Docker command surface.

    Args:
        arguments: Docker arguments. Defaults to process arguments.

    Returns:
        Simulated Docker or Docker Scout exit code.
    """

    command = list(sys.argv[1:] if arguments is None else arguments)
    scenario = os.environ.get("FAKE_DOCKER_SCENARIO", "default")
    services = scenario_services(scenario)
    log_invocation(command)
    if command[:2] == ["info", "--format"]:
        separator = "|" if len(command) > 2 and "|" in command[2] else "\t"
        state = ("inactive", "false") if scenario == "not-manager" else ("active", "true")
        print(separator.join(state))
        return 0
    if command == ["service", "ls", "--quiet"]:
        print("\n".join(services))
        return 0
    if command[:2] == ["service", "inspect"]:
        service = services.get(command[2]) if len(command) > 2 else None
        if service is None:
            print("service not found", file=sys.stderr)
            return 1
        print(json.dumps(inspect_payload(service)))
        return 0
    if command == ["scout", "version"]:
        if scenario == "missing-scout":
            print("docker: 'scout' is not a docker command", file=sys.stderr)
            return 1
        print("version: v1.24.0")
        return 0
    if command[:2] == ["scout", "cves"]:
        return handle_scout_cves(command, scenario)
    print(f"unsupported fake Docker command: {command}", file=sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
