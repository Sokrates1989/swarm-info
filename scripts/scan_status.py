"""Publish machine-readable progress for the standalone security scan."""

from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import threading
from typing import Any, Mapping

from scripts.vulnerability_models import write_json_atomic


SCHEMA_VERSION = 1
HEARTBEAT_SECONDS = 30.0
TERMINAL_STATUSES = {"complete", "failed", "cancelled", "timed_out"}


def utc_now() -> dt.datetime:
    """Return current aware UTC time."""

    return dt.datetime.now(dt.timezone.utc)


def timestamp(value: dt.datetime) -> str:
    """Serialize a UTC timestamp with second precision."""

    return (
        value.astimezone(dt.timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def next_daily_run(
    hour: int,
    minute: int,
    now: dt.datetime | None = None,
) -> dt.datetime:
    """Calculate the next daily scheduled run in the host local timezone."""

    reference = now or dt.datetime.now().astimezone()
    candidate = reference.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= reference:
        candidate += dt.timedelta(days=1)
    return candidate.astimezone(dt.timezone.utc)


def status_path_for(report_path: Path) -> Path:
    """Return the sibling status path required by the evidence contract."""

    name = report_path.name
    stem = name[:-5] if name.endswith(".json") else name
    return report_path.with_name(f"{stem}.status.json")


def completed_at_from_report(report_path: Path) -> str | None:
    """Read the last completed report time without requiring valid findings."""

    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return None
    value = payload.get("completed_at") if isinstance(payload, dict) else None
    return value if isinstance(value, str) and value else None


def report_timed_out(report_path: Path) -> bool:
    """Return whether terminal report errors identify an execution timeout."""

    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return False
    images = payload.get("images") if isinstance(payload, dict) else None
    if not isinstance(images, list):
        return False
    return any(
        isinstance(image, dict)
        and image.get("error_code") in {"scan-budget-exhausted", "scout-timeout"}
        for image in images
    )


class ScanStatusSession:
    """Own one scan's atomic status document and heartbeat thread."""

    def __init__(
        self,
        report_path: Path,
        next_run_at: str | None = None,
        heartbeat_seconds: float = HEARTBEAT_SECONDS,
    ) -> None:
        """Initialize status without publishing until ``start`` is called."""

        self.report_path = report_path
        self.path = status_path_for(report_path)
        self.next_run_at = next_run_at
        self.heartbeat_seconds = heartbeat_seconds
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._thread: threading.Thread | None = None
        self._payload: dict[str, Any] = {}

    @property
    def started(self) -> bool:
        """Return whether the session published its initial state."""

        return bool(self._payload)

    def _publish_locked(self) -> None:
        """Refresh heartbeat and atomically publish while holding the lock."""

        self._payload["heartbeat_at"] = timestamp(utc_now())
        write_json_atomic(self.path, self._payload)

    def start(self) -> None:
        """Publish running state and start the 30-second heartbeat."""

        started = timestamp(utc_now())
        self._payload = {
            "schema_version": SCHEMA_VERSION,
            "status": "running",
            "phase": "inventory",
            "started_at": started,
            "heartbeat_at": started,
            "completed_at": None,
            "progress": {"current": 0, "total": None, "image": None},
            "last_complete_report_at": completed_at_from_report(self.report_path),
            "next_run_at": self.next_run_at,
            "failure": None,
        }
        with self._lock:
            self._publish_locked()

        def heartbeat() -> None:
            while not self._stopped.wait(self.heartbeat_seconds):
                with self._lock:
                    if self._payload.get("status") == "running":
                        self._publish_locked()

        self._thread = threading.Thread(
            target=heartbeat,
            name="swarm-info-status-heartbeat",
            daemon=True,
        )
        self._thread.start()

    def progress(self, event: Mapping[str, Any]) -> None:
        """Publish one structured phase or image-progress update."""

        with self._lock:
            if self._payload.get("status") != "running":
                return
            phase = event.get("phase")
            if isinstance(phase, str) and phase:
                self._payload["phase"] = phase
            current = event.get("current")
            total = event.get("total")
            image = event.get("image")
            self._payload["progress"] = {
                "current": current if isinstance(current, int) and current >= 0 else 0,
                "total": total if isinstance(total, int) and total >= 0 else None,
                "image": image if isinstance(image, str) and image else None,
            }
            self._publish_locked()

    def finish(self, status: str, failure: str | None = None) -> None:
        """Publish a terminal state and stop heartbeat updates."""

        if status not in TERMINAL_STATUSES:
            raise ValueError(f"Invalid terminal scan status: {status}")
        self._stopped.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
        with self._lock:
            completed = timestamp(utc_now())
            self._payload.update(
                {
                    "status": status,
                    "phase": "finished",
                    "completed_at": completed,
                    "failure": failure,
                    "last_complete_report_at": completed_at_from_report(
                        self.report_path
                    ),
                }
            )
            self._publish_locked()
