"""Small TTY-aware terminal styling for operator-facing Python CLIs."""

from __future__ import annotations

import os
from typing import Mapping, TextIO


class TerminalStyle:
    """Apply ANSI emphasis only when the destination is an interactive TTY."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RED = "\033[31m"

    def __init__(
        self,
        output: TextIO,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        """Enable color for a TTY unless the standard ``NO_COLOR`` opt-out exists."""

        values = os.environ if environment is None else environment
        is_terminal = getattr(output, "isatty", lambda: False)()
        self.enabled = bool(is_terminal and "NO_COLOR" not in values)

    def _apply(self, value: str, *codes: str) -> str:
        """Wrap one value in ANSI codes when styling is enabled."""

        if not self.enabled:
            return value
        return f"{''.join(codes)}{value}{self.RESET}"

    def heading(self, value: str) -> str:
        """Highlight a section heading."""

        return self._apply(value, self.BOLD)

    def command(self, value: str) -> str:
        """Highlight a copy-ready command."""

        return self._apply(value, self.BOLD, self.CYAN)

    def success(self, value: str) -> str:
        """Highlight validated evidence."""

        return self._apply(value, self.BOLD, self.GREEN)

    def warning(self, value: str) -> str:
        """Highlight a compatibility or safety warning."""

        return self._apply(value, self.BOLD, self.YELLOW)

    def error(self, value: str) -> str:
        """Highlight rejected evidence."""

        return self._apply(value, self.BOLD, self.RED)
