"""Secret-safe state helper for the two-phase QNAP cron lifecycle gate."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Sequence


SCHEMA_VERSION = 1


def write_state(
    path: Path,
    producer_commit: str,
    runtime_user: str,
) -> None:
    """Atomically persist the minimum non-secret evidence needed after reboot."""

    if path.exists() or path.is_symlink():
        raise FileExistsError(f"lifecycle state already exists: {path}")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "phase": "awaiting-reboot-verification",
        "producer_commit": producer_commit,
        "runtime_user": runtime_user,
        "prepared_at": datetime.now(timezone.utc).isoformat(),
    }
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        else:
            os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary_path.unlink(missing_ok=True)
        raise


def read_state(path: Path, runtime_user: str) -> str:
    """Validate private state and return its prepared producer commit."""

    if path.is_symlink() or not path.is_file():
        raise ValueError(f"lifecycle state is not a regular file: {path}")
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) != 0o600:
        raise ValueError("lifecycle state mode must be 0600")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("lifecycle state must be a JSON object")
    expected = {
        "schema_version": SCHEMA_VERSION,
        "phase": "awaiting-reboot-verification",
        "runtime_user": runtime_user,
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise ValueError(f"lifecycle state {key} does not match")
    producer_commit = payload.get("producer_commit")
    if not isinstance(producer_commit, str) or not producer_commit:
        raise ValueError("lifecycle state producer_commit is invalid")
    return producer_commit


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse one intentionally small helper operation."""

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    write_parser = commands.add_parser("write-state")
    write_parser.add_argument("path", type=Path)
    write_parser.add_argument("producer_commit")
    write_parser.add_argument("runtime_user")
    read_parser = commands.add_parser("read-state")
    read_parser.add_argument("path", type=Path)
    read_parser.add_argument("runtime_user")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Run a helper operation while printing no persistent cron content."""

    options = parse_arguments(arguments)
    try:
        if options.command == "write-state":
            write_state(
                options.path,
                options.producer_commit,
                options.runtime_user,
            )
        else:
            print(read_state(options.path, options.runtime_user))
    except (OSError, ValueError) as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
