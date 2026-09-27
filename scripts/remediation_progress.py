"""Report long-running option-4 actions without changing their execution boundary."""

from __future__ import annotations

from typing import Callable, Mapping, TextIO, TypeVar

from scripts.operator_report import message
from scripts.vulnerability_scan import run_with_progress_heartbeat


Result = TypeVar("Result")


def run_visible_action(
    operation: Callable[[], Result],
    service: str,
    catalog: Mapping[str, str],
    output: TextIO,
    heartbeat_seconds: float = 15.0,
) -> Result:
    """Show immediate and periodic status during one blocking update or rollback."""

    print(message(catalog, "remediation.taskRunning", service=service), file=output, flush=True)

    def show_heartbeat(_: str) -> None:
        """Keep scanner heartbeat formatting out of the localized CLI message."""

        print(
            message(catalog, "remediation.taskStillRunning", service=service),
            file=output,
            flush=True,
        )

    return run_with_progress_heartbeat(
        operation, show_heartbeat, "", heartbeat_seconds
    )
