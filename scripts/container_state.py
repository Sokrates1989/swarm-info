"""Publish cheap standalone-container operational evidence.

The collector reads Docker's local container inventory only. It never invokes
Docker Scout, changes a container, or interprets desired-state policy. Policy
belongs to the watchdog so this artifact remains raw observed evidence.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import socket
from typing import Any, Mapping, Sequence

from scripts.platforms import platform_adapter_for
from scripts.security_check import HOST_OS_MODES, detect_host_os
from scripts.vulnerability_models import write_json_atomic
from scripts.vulnerability_scan import DockerClient
from scripts.vulnerability_scout import sanitize_command_error


SCHEMA_VERSION = 1
DEFAULT_FRESHNESS_MINUTES = 15.0


def utc_now() -> dt.datetime:
    """Return the current aware UTC time."""

    return dt.datetime.now(dt.timezone.utc)


def timestamp(value: dt.datetime) -> str:
    """Serialize one aware time with stable second precision."""

    return (
        value.astimezone(dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def parse_timestamp(value: object) -> dt.datetime | None:
    """Parse one evidence timestamp without accepting naive values."""

    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def positive_float(value: str) -> float:
    """Parse one strictly positive CLI number."""

    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a number") from error
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def optional_string(value: object) -> str | None:
    """Return stripped non-empty text or ``None``."""

    return value.strip() if isinstance(value, str) and value.strip() else None


def optional_integer(value: object) -> int | None:
    """Return a non-negative integer while rejecting booleans."""

    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else None
    )


def optional_label(labels: object, key: str) -> str | None:
    """Read one optional Compose ownership label."""

    return optional_string(labels.get(key)) if isinstance(labels, dict) else None


def sanitized_ports(value: object) -> list[dict[str, object]]:
    """Normalize published port mappings without exposing host addresses."""

    if not isinstance(value, dict):
        return []
    ports: list[dict[str, object]] = []
    for container_port, bindings in sorted(value.items()):
        if not isinstance(container_port, str):
            continue
        if bindings is None:
            ports.append({"container": container_port, "published": []})
            continue
        published = (
            sorted(
                {
                    host_port
                    for binding in bindings
                    if isinstance(binding, dict)
                    for host_port in [optional_string(binding.get("HostPort"))]
                    if host_port is not None
                }
            )
            if isinstance(bindings, list)
            else []
        )
        ports.append({"container": container_port, "published": published})
    return ports


def load_previous(path: Path) -> dict[str, Any] | None:
    """Load only complete, version-compatible previous evidence."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION:
        return None
    collection = payload.get("collection")
    if not isinstance(collection, dict) or collection.get("complete") is not True:
        return None
    freshness = payload.get("freshness")
    generated_at = (
        freshness.get("generated_at") if isinstance(freshness, dict) else None
    )
    return payload if parse_timestamp(generated_at) else None


def previous_rows(payload: Mapping[str, Any] | None) -> dict[str, Mapping[str, Any]]:
    """Index valid previous container rows by stable Docker ID."""

    rows = payload.get("containers") if payload else None
    if not isinstance(rows, list):
        return {}
    return {
        row["container_id"]: row
        for row in rows
        if isinstance(row, dict)
        and isinstance(row.get("container_id"), str)
        and optional_integer(row.get("restart_count")) is not None
    }


def restart_sample(
    current: Mapping[str, Any],
    previous: Mapping[str, Any] | None,
    generated_at: dt.datetime,
    previous_generated_at: dt.datetime | None,
) -> dict[str, float | int | None]:
    """Calculate a restart rate only across two continuous valid samples."""

    empty: dict[str, float | int | None] = {
        "restart_delta": None,
        "sample_duration_seconds": None,
        "restart_rate_per_hour": None,
    }
    if previous is None or previous_generated_at is None:
        return empty
    current_count = optional_integer(current.get("restart_count"))
    previous_count = optional_integer(previous.get("restart_count"))
    duration = (generated_at - previous_generated_at).total_seconds()
    if (
        current_count is None
        or previous_count is None
        or current_count < previous_count
        or duration <= 0
        or current.get("started_at") != previous.get("started_at")
    ):
        return empty
    delta = current_count - previous_count
    return {
        "restart_delta": delta,
        "sample_duration_seconds": round(duration, 3),
        "restart_rate_per_hour": round(delta * 3600 / duration, 6),
    }


def parse_inspect(container_id: str, raw_json: str) -> dict[str, Any]:
    """Normalize one Docker inspect response into policy-free evidence."""

    try:
        payload = json.loads(raw_json)[0]
        actual_id = optional_string(payload.get("Id")) or container_id
        name = optional_string(payload.get("Name"))
        image_id = optional_string(payload.get("Image"))
        configuration = payload.get("Config") or {}
        state = payload.get("State") or {}
        host_config = payload.get("HostConfig") or {}
        network = payload.get("NetworkSettings") or {}
        image = optional_string(configuration.get("Image"))
    except (IndexError, TypeError, ValueError) as error:
        raise ValueError(
            f"Container {container_id} returned invalid inspect JSON."
        ) from error
    if not name or not image or not image_id or not isinstance(state, dict):
        raise ValueError(f"Container {container_id} has incomplete inspect evidence.")
    labels = configuration.get("Labels") or {}
    project = optional_label(labels, "com.docker.compose.project")
    service = optional_label(labels, "com.docker.compose.service")
    health_payload = state.get("Health")
    health = (
        optional_string(health_payload.get("Status"))
        if isinstance(health_payload, dict)
        else None
    )
    running = state.get("Running") if isinstance(state.get("Running"), bool) else None
    restart_policy = (
        host_config.get("RestartPolicy") if isinstance(host_config, dict) else None
    )
    policy_name = (
        optional_string(restart_policy.get("Name"))
        if isinstance(restart_policy, dict)
        else None
    )
    row: dict[str, Any] = {
        "container_id": actual_id,
        "name": name.lstrip("/"),
        "selectors": {
            "container": f"container:{name.lstrip('/')}",
            "compose": f"compose:{project}/{service}" if project and service else None,
        },
        "image": {"reference": image, "id": image_id},
        "observed_state": optional_string(state.get("Status")) or "unknown",
        "running": running,
        "docker_health": health or "none",
        "exit_code": optional_integer(state.get("ExitCode")),
        "restart_count": optional_integer(payload.get("RestartCount")),
        "restart_policy": policy_name or "unknown",
        "started_at": optional_string(state.get("StartedAt")),
        "finished_at": optional_string(state.get("FinishedAt")),
        "ports": sanitized_ports(
            network.get("Ports") if isinstance(network, dict) else None
        ),
        "compose": {"project": project, "service": service},
    }
    return row


def collect(
    client: DockerClient,
    generated_at: dt.datetime,
    previous: Mapping[str, Any] | None = None,
    freshness_minutes: float = DEFAULT_FRESHNESS_MINUTES,
) -> dict[str, Any]:
    """Collect all local containers and isolate per-container failures."""

    listed = client.run(["container", "ls", "--all", "--quiet", "--no-trunc"])
    errors: list[dict[str, str]] = []
    rows: list[dict[str, Any]] = []
    if listed.return_code != 0:
        errors.append(
            {
                "scope": "inventory",
                "error": sanitize_command_error(listed.stderr or listed.stdout),
            }
        )
        identifiers: list[str] = []
    else:
        identifiers = [
            line.strip() for line in listed.stdout.splitlines() if line.strip()
        ]
    old_rows = previous_rows(previous)
    previous_freshness = previous.get("freshness") if previous else None
    old_time = (
        parse_timestamp(previous_freshness.get("generated_at"))
        if isinstance(previous_freshness, dict)
        else None
    )
    for container_id in identifiers:
        inspected = client.run(["container", "inspect", container_id])
        if inspected.return_code != 0:
            errors.append(
                {
                    "scope": container_id,
                    "error": sanitize_command_error(
                        inspected.stderr or inspected.stdout
                    ),
                }
            )
            continue
        try:
            row = parse_inspect(container_id, inspected.stdout)
        except ValueError as error:
            errors.append({"scope": container_id, "error": str(error)})
            continue
        row.update(
            restart_sample(
                row, old_rows.get(row["container_id"]), generated_at, old_time
            )
        )
        rows.append(row)
    rows.sort(key=lambda item: item["name"])
    running = sum(row["running"] is True for row in rows)
    unhealthy = sum(row["docker_health"] == "unhealthy" for row in rows)
    return {
        "schema_version": SCHEMA_VERSION,
        "resource_type": "container",
        "freshness": {
            "generated_at": timestamp(generated_at),
            "fresh_until": timestamp(
                generated_at + dt.timedelta(minutes=freshness_minutes)
            ),
        },
        "host": socket.gethostname(),
        "scope": {"kind": "all-local-containers"},
        "collection": {
            "complete": not errors,
            "container_count": len(rows),
            "error_count": len(errors),
            "errors": errors,
        },
        "summary": {
            "observed": len(rows),
            "running": running,
            "stopped": len(rows) - running,
            "docker_unhealthy": unhealthy,
        },
        "containers": rows,
    }


def default_output(host_os: str, environment: Mapping[str, str]) -> Path:
    """Resolve the adapter-owned operational evidence destination."""

    return (
        platform_adapter_for(host_os).default_evidence_directory(environment)
        / "container_state.json"
    )


def parse_arguments(arguments: Sequence[str] | None) -> argparse.Namespace:
    """Parse the standalone operational collector command line."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-file", type=Path)
    parser.add_argument("--os", choices=HOST_OS_MODES, default="auto", dest="host_os")
    parser.add_argument(
        "--freshness-minutes", type=positive_float, default=DEFAULT_FRESHNESS_MINUTES
    )
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Publish one operational sample, including incomplete evidence on error."""

    options = parse_arguments(arguments)
    host_os = detect_host_os(options.host_os)
    output = options.output_file or default_output(host_os, os.environ)
    previous = load_previous(output)
    payload = collect(DockerClient(), utc_now(), previous, options.freshness_minutes)
    payload["platform"] = {
        "adapter": platform_adapter_for(host_os).name,
        "profile": "platform_info.json",
    }
    write_json_atomic(output, payload)
    print(f"[OK] Container state evidence: {output}")
    return 0 if payload["collection"]["complete"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
