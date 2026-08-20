"""Validate QNAP scheduled-security evidence without production side effects.

The companion Bash acceptance workflow delegates JSON and file-lock handling
to this module so operators never need to paste nested Python heredocs into an
SSH terminal. The lock helper touches only the explicitly supplied test files.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any, Mapping, Sequence


MINIMUM_VERSION = (1, 14, 2)


def semantic_version(value: str) -> tuple[int, int, int]:
    """Parse one bare three-component semantic version."""

    parts = value.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise ValueError(f"invalid semantic version: {value}")
    return int(parts[0]), int(parts[1]), int(parts[2])


def validate_version(value: str) -> None:
    """Require a swarm-info release containing the durable acceptance flow."""

    if semantic_version(value) < MINIMUM_VERSION:
        minimum = ".".join(str(part) for part in MINIMUM_VERSION)
        raise ValueError(f"swarm-info {minimum} or newer is required")


def load_report(path: Path) -> Mapping[str, Any]:
    """Read one JSON object from the expected scheduled-report path."""

    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, Mapping):
        raise ValueError("the report root must be a JSON object")
    return parsed


def report_contract_errors(report: Mapping[str, Any]) -> list[str]:
    """Return every failed bounded running-container evidence invariant."""

    errors: list[str] = []
    summary = report.get("summary")
    scope = report.get("scope")
    environment = report.get("environment")
    policy = report.get("policy")
    freshness = report.get("freshness")
    images = report.get("images")
    if not isinstance(summary, Mapping):
        return ["summary is missing or invalid"]
    if not isinstance(scope, Mapping):
        return ["scope is missing or invalid"]
    if not isinstance(environment, Mapping):
        return ["environment is missing or invalid"]
    if not isinstance(policy, Mapping):
        return ["policy is missing or invalid"]
    if not isinstance(freshness, Mapping):
        return ["freshness is missing or invalid"]
    if not isinstance(images, list):
        return ["images is missing or invalid"]

    docker = environment.get("docker")
    checks = (
        (report.get("schema_version") == 2, "schema_version must be 2"),
        (summary.get("complete") is True, "summary.complete must be true"),
        (
            summary.get("status") in {"clean", "vulnerable"},
            "summary.status must be clean or vulnerable",
        ),
        (summary.get("failed_images") == 0, "failed_images must be zero"),
        (scope.get("resource_type") == "container", "scope must cover containers"),
        (scope.get("coverage", "full") == "full", "scope coverage must be full"),
        (
            scope.get("inventory_failure_count", 0) == 0,
            "inventory_failure_count must be zero",
        ),
        (
            environment.get("container_scope") == "running",
            "container_scope must be running",
        ),
        (
            isinstance(docker, Mapping)
            and docker.get("inventory_mode") == "containers",
            "Docker inventory mode must be containers",
        ),
        (
            policy.get("scout_timeout_minutes") == 45,
            "Scout timeout must be 45 minutes",
        ),
        (
            policy.get("scan_budget_minutes") == 240,
            "scan budget must be 240 minutes",
        ),
        (
            freshness.get("max_age_hours") == 96,
            "freshness limit must be 96 hours",
        ),
        (bool(freshness.get("last_successful_at")), "last_successful_at is missing"),
        (bool(freshness.get("fresh_until")), "fresh_until is missing"),
        (bool(report.get("completed_at")), "completed_at is missing"),
    )
    errors.extend(detail for passed, detail in checks if not passed)
    missing_durations = [
        str(image.get("reference", image.get("local_image_id", "unknown")))
        for image in images
        if not isinstance(image, Mapping) or "duration_seconds" not in image
    ]
    if missing_durations:
        errors.append(
            "duration_seconds is missing for: " + ", ".join(missing_durations)
        )
    return errors


def validate_report(path: Path) -> None:
    """Validate and print a compact acceptance summary for one report."""

    report = load_report(path)
    errors = report_contract_errors(report)
    if errors:
        raise ValueError("; ".join(errors))
    summary = report["summary"]
    scope = report["scope"]
    freshness = report["freshness"]
    print("[OK] Evidence contract")
    print(f"     Status:            {summary['status']}")
    print(f"     Containers:        {scope.get('resource_count')}")
    print(f"     Unique images:     {summary.get('scanned_images')}")
    print(f"     Vulnerable images: {summary.get('vulnerable_images')}")
    print(f"     Clean images:      {summary.get('clean_images')}")
    print(f"     Completed:         {report.get('completed_at')}")
    print(f"     Fresh until:       {freshness.get('fresh_until')}")


def completed_at(path: Path) -> None:
    """Print the report timestamp used to prove cache and lock behavior."""

    value = load_report(path).get("completed_at")
    if not isinstance(value, str) or not value:
        raise ValueError("completed_at is missing")
    print(value)


def hold_lock(
    lock_path: Path,
    ready_path: Path,
    release_path: Path,
    timeout_seconds: float,
) -> None:
    """Hold one POSIX advisory lock until released by the Bash workflow."""

    import fcntl

    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        ready_path.write_text("ready\n", encoding="utf-8")
        deadline = time.monotonic() + timeout_seconds
        while not release_path.exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("acceptance lock release timed out")
            time.sleep(0.1)


def parse_arguments(arguments: Sequence[str] | None) -> argparse.Namespace:
    """Parse the private operations used by the Bash acceptance workflow."""

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    version_parser = commands.add_parser("validate-version")
    version_parser.add_argument("version")
    report_parser = commands.add_parser("validate-report")
    report_parser.add_argument("path", type=Path)
    completion_parser = commands.add_parser("completed-at")
    completion_parser.add_argument("path", type=Path)
    lock_parser = commands.add_parser("hold-lock")
    lock_parser.add_argument("lock_path", type=Path)
    lock_parser.add_argument("ready_path", type=Path)
    lock_parser.add_argument("release_path", type=Path)
    lock_parser.add_argument("--timeout-seconds", type=float, default=120.0)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Execute one private acceptance helper and report actionable failures."""

    options = parse_arguments(arguments)
    try:
        if options.command == "validate-version":
            validate_version(options.version)
        elif options.command == "validate-report":
            validate_report(options.path)
        elif options.command == "completed-at":
            completed_at(options.path)
        else:
            hold_lock(
                options.lock_path,
                options.ready_path,
                options.release_path,
                options.timeout_seconds,
            )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
