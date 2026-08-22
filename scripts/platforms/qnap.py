"""QNAP QPKG, Scout-storage, and persistent-crontab integration adapter."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any, Mapping, Sequence

from scripts.operator_report import load_messages, message, selected_locale
from scripts.vulnerability_cron import (
    CommandResult as CronCommandResult,
    CrontabClient,
)
from scripts.vulnerability_scan import InventoryError


QNAP_SCOUT_WORK_SUBDIRECTORY = Path(".cache/swarm-info/docker-scout")
QNAP_SYSTEM_CRONTAB = Path("/etc/config/crontab")
QNAP_CROND_RESTART = Path("/etc/init.d/crond.sh")


class QnapSystemCrontabClient(CrontabClient):
    """Atomically maintain and activate QNAP's persistent system crontab."""

    def __init__(
        self,
        crontab_path: Path = QNAP_SYSTEM_CRONTAB,
        restart_path: Path = QNAP_CROND_RESTART,
    ) -> None:
        """Select exact vendor configuration and daemon-reload paths."""

        self.crontab_path = crontab_path
        self.restart_path = restart_path

    def run(
        self, arguments: Sequence[str], input_text: str | None = None
    ) -> CronCommandResult:
        """Read or atomically replace and activate the persistent table."""

        if list(arguments) == ["-l"]:
            try:
                return CronCommandResult(
                    0, self.crontab_path.read_text(encoding="utf-8"), ""
                )
            except OSError as error:
                return CronCommandResult(2, "", str(error))
        if list(arguments) != ["-"] or input_text is None:
            return CronCommandResult(64, "", "unsupported crontab operation")
        try:
            self._write_atomic(input_text)
        except OSError as error:
            return CronCommandResult(1, "", str(error))
        activated = super().run([self.crontab_path.as_posix()])
        if activated.return_code != 0:
            return activated
        try:
            completed = subprocess.run(
                [self.restart_path.as_posix(), "restart"],
                capture_output=True,
                check=False,
                text=True,
            )
        except OSError as error:
            return CronCommandResult(127, "", str(error))
        return CronCommandResult(
            completed.returncode, completed.stdout, completed.stderr
        )

    def _write_atomic(self, content: str) -> None:
        """Replace the vendor crontab without a partially written file."""

        metadata = self.crontab_path.stat()
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".swarm-info-crontab.", dir=self.crontab_path.parent
        )
        temporary_path = Path(temporary_name)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode))
            if hasattr(os, "fchown"):
                os.fchown(descriptor, metadata.st_uid, metadata.st_gid)
            with os.fdopen(
                descriptor, "w", encoding="utf-8", newline="\n"
            ) as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.crontab_path)
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            temporary_path.unlink(missing_ok=True)
            raise


class QnapPlatformAdapter:
    """Provide QNAP-only filesystem, Scout, and scheduler behavior."""

    name = "qnap"
    scheduler = "qnap-persistent-crontab"

    def default_evidence_directory(self, environment: Mapping[str, str]) -> Path:
        """Return the accepted QNAP Public evidence directory."""

        del environment
        return Path("/share/Public/swarm-info")

    def crontab_client(
        self, catalog: Mapping[str, str] | None = None
    ) -> QnapSystemCrontabClient:
        """Require root and return the vendor-persistent cron implementation."""

        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            effective_catalog = catalog or load_messages(selected_locale())
            raise PermissionError(
                message(effective_catalog, "securityJob.qnapRootRequired")
            )
        return QnapSystemCrontabClient()

    def prepare_scout_client(
        self, client: Any, environment: Mapping[str, str]
    ) -> tuple[Any, dict[str, str]]:
        """Move Scout extraction and cache storage off capacity-limited `/tmp`."""

        home_directory = Path(environment.get("HOME") or str(Path.home()))
        work_root = home_directory / QNAP_SCOUT_WORK_SUBDIRECTORY
        overrides: dict[str, str] = {}
        automatic_directories: list[Path] = []

        temporary_directory = environment.get("TMPDIR")
        if not temporary_directory:
            automatic_temp = work_root / "tmp"
            temporary_directory = str(automatic_temp)
            overrides["TMPDIR"] = temporary_directory
            automatic_directories.append(automatic_temp)

        cache_directory = environment.get("DOCKER_SCOUT_CACHE_DIR")
        if not cache_directory:
            automatic_cache = work_root / "cache"
            cache_directory = str(automatic_cache)
            overrides["DOCKER_SCOUT_CACHE_DIR"] = cache_directory
            automatic_directories.append(automatic_cache)

        try:
            for directory in automatic_directories:
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            catalog = load_messages(selected_locale(environment))
            raise InventoryError(
                message(
                    catalog,
                    "security.scoutWorkStorageError",
                    path=work_root,
                    detail=error,
                )
            ) from error

        configured_client = client.with_environment_overrides(
            {
                "TMPDIR": temporary_directory,
                "DOCKER_SCOUT_CACHE_DIR": cache_directory,
            }
        )
        return configured_client, {
            "temporary_directory": temporary_directory,
            "cache_directory": cache_directory,
            "selection": (
                "operator-environment" if not overrides else "qnap-home-default"
            ),
        }
