"""Audit local Docker container runtime hardening without exposing secrets.

The collector reads only Docker's container inventory and inspect contracts. It
never serializes environment values, arbitrary labels, host mount sources, or
raw inspect objects, and it never changes Docker state.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
from pathlib import Path
import sys
from typing import Any, Mapping, Sequence

from scripts.operator_report import load_messages, message, selected_locale
from scripts.platforms import HOST_OS_MODES, detect_host_os, platform_adapter_for
from scripts.vulnerability_models import utc_timestamp, write_json_atomic
from scripts.vulnerability_scan import CommandResult, DockerClient
from scripts.vulnerability_scout import sanitize_command_error


SCHEMA_VERSION = 1
MAX_CONTAINERS = 1000
DANGEROUS_CAPABILITIES = frozenset(
    {
        "AUDIT_CONTROL",
        "AUDIT_READ",
        "BLOCK_SUSPEND",
        "BPF",
        "DAC_READ_SEARCH",
        "IPC_LOCK",
        "LEASE",
        "LINUX_IMMUTABLE",
        "MAC_ADMIN",
        "MAC_OVERRIDE",
        "NET_ADMIN",
        "NET_RAW",
        "PERFMON",
        "SYS_ADMIN",
        "SYS_BOOT",
        "SYS_MODULE",
        "SYS_PTRACE",
        "SYS_RAWIO",
        "SYS_RESOURCE",
        "SYS_TIME",
        "SYS_TTY_CONFIG",
        "WAKE_ALARM",
    }
)
RISKY_MOUNT_TARGETS = (
    "/boot",
    "/dev",
    "/etc",
    "/proc",
    "/root",
    "/run",
    "/sys",
    "/usr",
    "/var/run",
)
SEVERITY_RANK = {"ok": 0, "warning": 1, "high": 2, "critical": 3}


class RuntimeHardeningError(RuntimeError):
    """Raised when Docker cannot provide trustworthy audit evidence."""


@dataclasses.dataclass(frozen=True)
class HardeningFinding:
    """One normalized configuration risk without arbitrary Docker values."""

    code: str
    severity: str
    evidence: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the allowlisted finding contract."""

        return {
            "code": self.code,
            "severity": self.severity,
            "evidence": dict(self.evidence),
        }


@dataclasses.dataclass(frozen=True)
class AuditedContainer:
    """One container identity and its sanitized hardening result."""

    name: str
    image: str
    running: bool
    compose_project: str | None
    compose_service: str | None
    findings: tuple[HardeningFinding, ...]

    @property
    def status(self) -> str:
        """Return the highest finding severity or ``ok``."""

        return max(
            (finding.severity for finding in self.findings),
            default="ok",
            key=lambda value: SEVERITY_RANK[value],
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize only UI-safe identity and finding fields."""

        return {
            "name": self.name,
            "image": self.image,
            "running": self.running,
            "compose_project": self.compose_project,
            "compose_service": self.compose_service,
            "status": self.status,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def _required_mapping(value: object, description: str) -> Mapping[str, Any]:
    """Return one mapping or reject malformed inspect evidence."""

    if not isinstance(value, Mapping):
        raise RuntimeHardeningError(f"{description} is missing.")
    return value


def _safe_text(value: object, maximum: int = 512) -> str | None:
    """Return bounded single-line Docker metadata or ``None``."""

    if not isinstance(value, str) or not value.strip():
        return None
    return " ".join(value.replace("\x00", " ").split())[:maximum]


def _compose_label(labels: object, key: str) -> str | None:
    """Read one known Compose label without retaining foreign labels."""

    return _safe_text(labels.get(key), 255) if isinstance(labels, Mapping) else None


def _normalized_capabilities(value: object) -> tuple[str, ...]:
    """Return dangerous explicitly added Linux capabilities."""

    if not isinstance(value, list):
        return ()
    return tuple(
        sorted(
            {
                item.strip().upper()
                for item in value
                if isinstance(item, str)
                and item.strip().upper() in DANGEROUS_CAPABILITIES
            }
        )
    )


def _published_ports(host_config: Mapping[str, Any]) -> tuple[str, ...]:
    """Return container-side ports that have host bindings."""

    bindings = host_config.get("PortBindings")
    if not isinstance(bindings, Mapping):
        return ()
    return tuple(
        sorted(
            str(port)[:32]
            for port, value in bindings.items()
            if isinstance(port, str) and isinstance(value, list) and value
        )
    )


def _mount_findings(payload: Mapping[str, Any]) -> list[HardeningFinding]:
    """Classify Docker-socket and risky bind targets without host sources."""

    mounts = payload.get("Mounts")
    if not isinstance(mounts, list):
        return []
    socket_targets: set[str] = set()
    risky_targets: set[str] = set()
    for mount in mounts:
        if not isinstance(mount, Mapping):
            continue
        target = _safe_text(mount.get("Destination"), 255)
        source = _safe_text(mount.get("Source"), 1024)
        mount_type = _safe_text(mount.get("Type"), 32)
        if target is None:
            continue
        if target == "/var/run/docker.sock" or (
            source is not None and source.rstrip("/").endswith("/docker.sock")
        ):
            socket_targets.add(target)
            continue
        normalized = target.rstrip("/") or "/"
        if mount_type == "bind" and (
            normalized == "/"
            or any(
                normalized == prefix or normalized.startswith(f"{prefix}/")
                for prefix in RISKY_MOUNT_TARGETS
            )
        ):
            risky_targets.add(target)
    findings = []
    if socket_targets:
        findings.append(
            HardeningFinding(
                "docker-socket-mounted",
                "critical",
                {"targets": sorted(socket_targets)},
            )
        )
    if risky_targets:
        findings.append(
            HardeningFinding(
                "risky-host-bind-mount",
                "high",
                {"targets": sorted(risky_targets)},
            )
        )
    return findings


def _healthcheck_missing(configuration: Mapping[str, Any]) -> bool:
    """Return whether Docker has no executable healthcheck contract."""

    healthcheck = configuration.get("Healthcheck")
    if not isinstance(healthcheck, Mapping):
        return True
    test = healthcheck.get("Test")
    return not isinstance(test, list) or not test or test[0] == "NONE"


def parse_container_inspect(container_id: str, raw_json: str) -> AuditedContainer:
    """Normalize one Docker inspect response into secret-free audit evidence."""

    try:
        payload = json.loads(raw_json)[0]
    except (IndexError, TypeError, ValueError) as error:
        raise RuntimeHardeningError(
            f"Container {container_id} returned invalid inspect JSON."
        ) from error
    payload = _required_mapping(payload, f"Container {container_id}")
    configuration = _required_mapping(payload.get("Config"), "Container config")
    host_config = _required_mapping(payload.get("HostConfig"), "Host config")
    state = _required_mapping(payload.get("State"), "Container state")
    name = _safe_text(payload.get("Name"), 255)
    image = _safe_text(configuration.get("Image"), 512)
    if name is None or image is None:
        raise RuntimeHardeningError(
            f"Container {container_id} has no valid name or image."
        )

    findings: list[HardeningFinding] = []

    def add(code: str, severity: str, evidence: Mapping[str, Any]) -> None:
        """Append one deterministic finding."""

        findings.append(HardeningFinding(code, severity, evidence))

    if host_config.get("Privileged") is True:
        add("privileged", "critical", {"enabled": True})
    if host_config.get("NetworkMode") == "host":
        add("host-network", "high", {"enabled": True})
    if host_config.get("PidMode") == "host":
        add("host-pid", "critical", {"enabled": True})
    findings.extend(_mount_findings(payload))
    capabilities = _normalized_capabilities(host_config.get("CapAdd"))
    if capabilities:
        add("dangerous-capabilities", "high", {"capabilities": list(capabilities)})

    user = _safe_text(configuration.get("User"), 128) or ""
    if user.lower() in {"", "0", "root"} or user.startswith("0:"):
        add("root-user", "warning", {"configured_user": "root"})
    security_options = host_config.get("SecurityOpt")
    normalized_options = {
        option.strip().lower().replace("=", ":", 1)
        for option in security_options
        if isinstance(option, str)
    } if isinstance(security_options, list) else set()
    if not any(option.startswith("no-new-privileges:true") for option in normalized_options):
        add("no-new-privileges-missing", "warning", {"enabled": False})
    if host_config.get("ReadonlyRootfs") is not True:
        add("writable-root-filesystem", "warning", {"read_only": False})
    if _healthcheck_missing(configuration):
        add("healthcheck-missing", "warning", {"configured": False})

    memory_limited = isinstance(host_config.get("Memory"), int) and host_config["Memory"] > 0
    cpu_limited = any(
        isinstance(host_config.get(key), int) and host_config[key] > 0
        for key in ("NanoCpus", "CpuQuota")
    )
    if not memory_limited or not cpu_limited:
        add(
            "resource-limits-missing",
            "warning",
            {"cpu_limited": cpu_limited, "memory_limited": memory_limited},
        )
    ports = _published_ports(host_config)
    if ports:
        add("ports-published", "warning", {"container_ports": list(ports)})

    labels = configuration.get("Labels")
    return AuditedContainer(
        name=name.lstrip("/"),
        image=image,
        running=state.get("Running") is True,
        compose_project=_compose_label(labels, "com.docker.compose.project"),
        compose_service=_compose_label(labels, "com.docker.compose.service"),
        findings=tuple(
            sorted(
                findings,
                key=lambda finding: (
                    -SEVERITY_RANK[finding.severity],
                    finding.code,
                ),
            )
        ),
    )


def _require_command(
    client: DockerClient, arguments: Sequence[str], description: str
) -> CommandResult:
    """Run one Docker command or raise a sanitized operational error."""

    result = client.run(arguments)
    if result.return_code != 0:
        detail = sanitize_command_error(result.stderr or result.stdout)
        raise RuntimeHardeningError(f"{description}: {detail}")
    return result


def collect_runtime_hardening(
    client: DockerClient, scope: str
) -> tuple[list[AuditedContainer], list[dict[str, str]]]:
    """Audit local containers while isolating individual inspect failures."""

    arguments = ["container", "ls"]
    if scope == "all":
        arguments.append("--all")
    arguments.extend(("--quiet", "--no-trunc"))
    listed = _require_command(client, arguments, "Docker container inventory failed")
    identifiers = list(
        dict.fromkeys(
            line.strip()
            for line in listed.stdout.splitlines()
            if line.strip()
        )
    )
    if len(identifiers) > MAX_CONTAINERS:
        raise RuntimeHardeningError(
            f"Docker returned more than {MAX_CONTAINERS} containers."
        )
    containers: list[AuditedContainer] = []
    failures: list[dict[str, str]] = []
    for container_id in identifiers:
        inspected = client.run(["container", "inspect", container_id])
        if inspected.return_code != 0:
            failures.append(
                {
                    "container_id": container_id[:64],
                    "error": "container-inspect-failed",
                }
            )
            continue
        try:
            containers.append(parse_container_inspect(container_id, inspected.stdout))
        except RuntimeHardeningError:
            failures.append(
                {
                    "container_id": container_id[:64],
                    "error": "container-inspect-invalid",
                }
            )
    return sorted(containers, key=lambda item: item.name), failures


def build_report(
    containers: Sequence[AuditedContainer],
    failures: Sequence[Mapping[str, str]],
    scope: str,
) -> dict[str, Any]:
    """Build the versioned read-only hardening evidence contract."""

    finding_counts: dict[str, int] = {}
    severity_counts = {"critical": 0, "high": 0, "warning": 0}
    for container in containers:
        for finding in container.findings:
            finding_counts[finding.code] = finding_counts.get(finding.code, 0) + 1
            severity_counts[finding.severity] += 1
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": utc_timestamp(),
        "complete": not failures,
        "scope": scope,
        "policy": {
            "read_only": True,
            "docker_mutation_authorized": False,
            "environment_values_serialized": False,
            "label_values_serialized": False,
            "host_mount_sources_serialized": False,
        },
        "summary": {
            "listed_containers": len(containers) + len(failures),
            "audited_containers": len(containers),
            "failed_inspections": len(failures),
            "compliant_containers": sum(not item.findings for item in containers),
            "affected_containers": sum(bool(item.findings) for item in containers),
            "total_findings": sum(finding_counts.values()),
            **severity_counts,
        },
        "finding_counts": dict(sorted(finding_counts.items())),
        "containers": [container.to_dict() for container in containers],
        "failures": [dict(failure) for failure in failures],
    }


def default_output_file(requested_os: str, environment: Mapping[str, str]) -> Path:
    """Resolve the adapter-owned hardening evidence path."""

    adapter = platform_adapter_for(detect_host_os(requested_os))
    return adapter.default_evidence_directory(environment) / "runtime_hardening.json"


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse the read-only runtime-hardening command."""

    catalog = load_messages(selected_locale(os.environ))
    parser = argparse.ArgumentParser(
        description=message(catalog, "runtimeHardening.help.description")
    )
    parser.add_argument("--scope", choices=("all", "running"), default="all")
    parser.add_argument("--os", choices=HOST_OS_MODES, default="auto")
    parser.add_argument("--output-file", type=Path)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Audit local Docker configuration and publish private evidence."""

    options = parse_arguments(arguments)
    catalog = load_messages(selected_locale(os.environ))
    output_file = options.output_file or default_output_file(options.os, os.environ)
    try:
        containers, failures = collect_runtime_hardening(DockerClient(), options.scope)
        report = build_report(containers, failures, options.scope)
        write_json_atomic(output_file, report)
    except (OSError, RuntimeHardeningError, TypeError, ValueError) as error:
        print(
            message(catalog, "runtimeHardening.error", detail=error),
            file=sys.stderr,
        )
        return 3
    summary = report["summary"]
    print(
        message(
            catalog,
            "runtimeHardening.result",
            audited=summary["audited_containers"],
            affected=summary["affected_containers"],
            findings=summary["total_findings"],
        )
    )
    print(message(catalog, "runtimeHardening.report", path=output_file))
    return 0 if report["complete"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
