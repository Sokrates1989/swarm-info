"""Versioned, non-secret host platform and capability data types."""

from __future__ import annotations

import dataclasses
from typing import Any


PLATFORM_SCHEMA_VERSION = 1


@dataclasses.dataclass(frozen=True)
class HostOsProfile:
    """Sanitized operating-system identity and adapter selection evidence.

    The first five fields retain the positional compatibility contract used by
    the existing security scanner tests and embedded callers.
    """

    family: str
    name: str
    version: str | None
    model: str | None
    detection: str
    os_id: str = "unknown"
    platform_adapter: str = "standard-linux"

    @property
    def pretty_name(self) -> str:
        """Return the safe operator-facing distribution name."""

        return self.name

    def to_dict(self) -> dict[str, str | None]:
        """Serialize additive legacy report metadata without release contents."""

        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class DockerRuntimeProfile:
    """Selected Docker inventory mode and observed runtime capabilities."""

    inventory_mode: str
    swarm_state: str
    manager: bool
    detection: str
    platform: str = "unknown"
    compose_available: bool = False
    daemon_available: bool = True

    def to_dict(self) -> dict[str, str | bool]:
        """Serialize both the legacy and shared platform runtime names."""

        payload = dataclasses.asdict(self)
        payload["runtime_mode"] = self.inventory_mode
        return payload


@dataclasses.dataclass(frozen=True)
class HostCapabilities:
    """Evidence and safe-action capabilities available on one host."""

    image_vulnerability_scan: bool
    focused_container_scan: bool
    container_health: bool
    expected_state_policy: bool
    scan_progress: bool
    runtime_hardening: bool
    guided_remediation: str
    image_cleanup: bool
    scheduler: str

    def to_dict(self) -> dict[str, bool | str]:
        """Serialize the stable capability contract."""

        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class HostProfile:
    """Versioned producer profile shared with watchdog and UI consumers."""

    detected_at: str
    host_os: HostOsProfile
    docker: DockerRuntimeProfile
    capabilities: HostCapabilities
    schema_version: int = PLATFORM_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Return the public schema without credentials or environment values."""

        return {
            "schema_version": self.schema_version,
            "detected_at": self.detected_at,
            "platform_adapter": self.host_os.platform_adapter,
            "os": {
                "id": self.host_os.os_id,
                "family": self.host_os.family,
                "version": self.host_os.version or "unknown",
                "pretty_name": self.host_os.pretty_name,
                "model": self.host_os.model,
                "detection": self.host_os.detection,
            },
            "docker": {
                "runtime_mode": self.docker.inventory_mode,
                "platform": self.docker.platform,
                "compose_available": self.docker.compose_available,
                "daemon_available": self.docker.daemon_available,
                "swarm_state": self.docker.swarm_state,
                "manager": self.docker.manager,
            },
            "capabilities": self.capabilities.to_dict(),
        }
