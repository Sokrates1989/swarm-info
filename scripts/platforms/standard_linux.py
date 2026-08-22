"""Standard-Linux paths, Scout behavior, and user-crontab capabilities."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from scripts.vulnerability_cron import CrontabClient


class StandardLinuxPlatformAdapter:
    """Provide conventional PATH, XDG/home, and user-crontab behavior."""

    name = "standard-linux"
    scheduler = "user-crontab"

    def default_evidence_directory(self, environment: Mapping[str, str]) -> Path:
        """Resolve the installation-owned XDG state directory."""

        state_home = environment.get("XDG_STATE_HOME")
        if state_home:
            return Path(state_home) / "swarm-info"
        home = environment.get("HOME")
        if home:
            return Path(home) / ".local/state/swarm-info"
        return Path.home() / ".local/state/swarm-info"

    def prepare_scout_client(
        self, client: Any, environment: Mapping[str, str]
    ) -> tuple[Any, dict[str, str] | None]:
        """Retain the operator's normal standard-Linux process environment."""

        del environment
        return client, None

    def crontab_client(
        self, catalog: Mapping[str, str] | None = None
    ) -> CrontabClient:
        """Return the current operating-system user's crontab boundary."""

        del catalog
        return CrontabClient()
