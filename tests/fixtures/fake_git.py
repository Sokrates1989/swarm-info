#!/usr/bin/env python3

"""Deterministic Git fake for swarm-info self-update tests.

The executable models clean, dirty, behind, ahead, divergent, and fetch-error
states without modifying a repository or contacting a remote server.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys


def normalized_command(arguments: list[str]) -> list[str]:
    """Remove the optional Git `-C` working-directory prefix.

    Args:
        arguments: Raw fake Git arguments.

    Returns:
        Git operation arguments after the repository selector.
    """

    if len(arguments) >= 2 and arguments[0] == "-C":
        return arguments[2:]
    return arguments


def log_invocation(arguments: list[str]) -> None:
    """Append one normalized Git invocation to the configured log.

    Args:
        arguments: Git operation arguments to record.

    Returns:
        Nothing. No file is written when `FAKE_GIT_LOG` is unset.
    """

    log_path = os.environ.get("FAKE_GIT_LOG")
    if not log_path:
        return
    with Path(log_path).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(arguments) + "\n")


def divergence_for_scenario(scenario: str) -> tuple[int, int]:
    """Return local-ahead and remote-behind counts for a scenario.

    Args:
        scenario: State selected through `FAKE_GIT_SCENARIO`.

    Returns:
        Local-ahead and remote-behind commit counts.
    """

    return {
        "ahead": (1, 0),
        "behind": (0, 2),
        "diverged": (1, 2),
    }.get(scenario, (0, 0))


def main(arguments: list[str] | None = None) -> int:
    """Dispatch the Git command surface used by `update_tool.sh`.

    Args:
        arguments: Optional Git arguments. Defaults to process arguments.

    Returns:
        Simulated Git exit code.
    """

    command = normalized_command(list(sys.argv[1:] if arguments is None else arguments))
    scenario = os.environ.get("FAKE_GIT_SCENARIO", "current")
    log_invocation(command)

    if command == ["--version"]:
        print("git version 2.45.0-fake")
        return 0
    if command == ["rev-parse", "--is-inside-work-tree"]:
        print("true")
        return 0
    if command == ["status", "--porcelain", "--untracked-files=normal"]:
        if scenario == "dirty":
            print(" M get_info.sh")
        return 0
    if command == [
        "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"
    ]:
        if scenario == "no-upstream":
            return 128
        print("origin/main")
        return 0
    if command == ["fetch", "--quiet", "--prune", "origin"]:
        return 1 if scenario == "fetch-error" else 0
    if command == ["rev-list", "--left-right", "--count", "HEAD...origin/main"]:
        ahead, behind = divergence_for_scenario(scenario)
        print(f"{ahead}\t{behind}")
        return 0
    if command == ["rev-parse", "--short", "HEAD"]:
        print("abc1234")
        return 0
    if command == ["merge", "--ff-only", "origin/main"]:
        return 1 if scenario == "merge-error" else 0

    print(f"unsupported fake Git command: {command}", file=sys.stderr)
    return 64


if __name__ == "__main__":
    raise SystemExit(main())
