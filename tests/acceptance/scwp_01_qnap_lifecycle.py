"""Secret-safe state helper for the two-phase QNAP cron lifecycle gate."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Sequence


BLOCK_BEGIN = "# BEGIN swarm-info managed container security scan"
BLOCK_END = "# END swarm-info managed container security scan"
HASH_PATTERN = re.compile(r"[0-9a-f]{64}")
SCHEMA_VERSION = 1


def unmanaged_crontab(crontab_text: str) -> str:
    """Return normalized entries outside the exactly marked managed block."""

    if crontab_text.count(BLOCK_BEGIN) != crontab_text.count(BLOCK_END):
        raise ValueError("managed cron markers are incomplete")
    retained: list[str] = []
    inside_block = False
    for line in crontab_text.splitlines():
        if line == BLOCK_BEGIN:
            if inside_block:
                raise ValueError("managed cron markers are nested")
            inside_block = True
            continue
        if line == BLOCK_END:
            if not inside_block:
                raise ValueError("managed cron markers are out of order")
            inside_block = False
            continue
        if not inside_block:
            retained.append(line)
    if inside_block:
        raise ValueError("managed cron markers are incomplete")
    while retained and not retained[-1]:
        retained.pop()
    return "\n".join(retained) + ("\n" if retained else "")


def unmanaged_hash(crontab_text: str) -> str:
    """Hash normalized unrelated entries without disclosing their contents."""

    content = unmanaged_crontab(crontab_text).encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def crontab_hash(path: Path) -> str:
    """Read the privileged persistent table and return only its safe hash."""

    return unmanaged_hash(path.read_text(encoding="utf-8"))


def write_state(
    path: Path,
    producer_commit: str,
    runtime_user: str,
    crontab_hash_value: str,
) -> None:
    """Atomically persist the minimum non-secret evidence needed after reboot."""

    if not HASH_PATTERN.fullmatch(crontab_hash_value):
        raise ValueError("unmanaged crontab hash is invalid")
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"lifecycle state already exists: {path}")
    payload = {
        "schema_version": SCHEMA_VERSION,
        "phase": "awaiting-reboot-verification",
        "producer_commit": producer_commit,
        "runtime_user": runtime_user,
        "unmanaged_crontab_sha256": crontab_hash_value,
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


def read_state(path: Path, producer_commit: str, runtime_user: str) -> str:
    """Validate private state and return its recorded unrelated-entry hash."""

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
        "producer_commit": producer_commit,
        "runtime_user": runtime_user,
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise ValueError(f"lifecycle state {key} does not match")
    hash_value = payload.get("unmanaged_crontab_sha256")
    if not isinstance(hash_value, str) or not HASH_PATTERN.fullmatch(hash_value):
        raise ValueError("lifecycle state contains an invalid crontab hash")
    return hash_value


def parse_arguments(arguments: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse one intentionally small helper operation."""

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    hash_parser = commands.add_parser("cron-hash")
    hash_parser.add_argument("path", type=Path)
    write_parser = commands.add_parser("write-state")
    write_parser.add_argument("path", type=Path)
    write_parser.add_argument("producer_commit")
    write_parser.add_argument("runtime_user")
    write_parser.add_argument("unmanaged_hash")
    read_parser = commands.add_parser("read-state")
    read_parser.add_argument("path", type=Path)
    read_parser.add_argument("producer_commit")
    read_parser.add_argument("runtime_user")
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    """Run a helper operation while printing no persistent cron content."""

    options = parse_arguments(arguments)
    try:
        if options.command == "cron-hash":
            print(crontab_hash(options.path))
        elif options.command == "write-state":
            write_state(
                options.path,
                options.producer_commit,
                options.runtime_user,
                options.unmanaged_hash,
            )
        else:
            print(
                read_state(
                    options.path,
                    options.producer_commit,
                    options.runtime_user,
                )
            )
    except (OSError, ValueError) as error:
        print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
