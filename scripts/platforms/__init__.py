"""Capability-first host platform model and adapter selection.

The package owns operating-system detection and genuine host integration
differences. Scanner, report, cache, and lock code consume its stable profile
and adapter interfaces without branching on distribution names.
"""

from scripts.platforms.detect import (
    HOST_OS_MODES,
    OS_RELEASE_PATH,
    QNAP_RELEASE_PATHS,
    build_host_profile,
    detect_docker_runtime,
    detect_host_os,
    detect_platform_profile,
    normalize_architecture,
    parse_release_values,
    resolve_platform,
)
from scripts.platforms.model import (
    DockerRuntimeProfile,
    HostCapabilities,
    HostOsProfile,
    HostProfile,
)
from scripts.platforms.qnap import QnapPlatformAdapter
from scripts.platforms.standard_linux import StandardLinuxPlatformAdapter


def platform_adapter_for(
    host_os: HostOsProfile,
) -> StandardLinuxPlatformAdapter | QnapPlatformAdapter:
    """Return the behavior adapter selected by sanitized host metadata."""

    if host_os.platform_adapter == "qnap" or host_os.family == "qnap":
        return QnapPlatformAdapter()
    return StandardLinuxPlatformAdapter()


__all__ = [
    "DockerRuntimeProfile",
    "HOST_OS_MODES",
    "HostCapabilities",
    "HostOsProfile",
    "HostProfile",
    "OS_RELEASE_PATH",
    "QNAP_RELEASE_PATHS",
    "QnapPlatformAdapter",
    "StandardLinuxPlatformAdapter",
    "build_host_profile",
    "detect_docker_runtime",
    "detect_host_os",
    "detect_platform_profile",
    "normalize_architecture",
    "parse_release_values",
    "platform_adapter_for",
    "resolve_platform",
]
