"""Fail-closed source editing for approved vulnerability remediations."""

from __future__ import annotations

import dataclasses
import difflib
import os
from pathlib import Path
import re
import stat
import tempfile
from typing import Any, Mapping

from scripts.deployment_mapping import image_references_match
from scripts.remediation_policy import CandidateImage, PolicyTarget, SourceEdit


class SourceEditError(ValueError):
    """Describe an unsafe or stale source edit using a stable code."""

    def __init__(self, code: str, detail: str = "") -> None:
        """Store a stable reason and non-secret path/key detail."""

        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclasses.dataclass(frozen=True)
class SourceChange:
    """One reviewed source-file replacement with rollback bytes."""

    path: Path
    original: bytes
    replacement: bytes
    diff: str
    original_mode: int


def _resolved_source_path(directory: Path, relative: str) -> Path:
    """Resolve one policy path and prove it stays below the mapped directory."""

    try:
        root = directory.resolve(strict=True)
        unresolved = root / relative
        if unresolved.is_symlink():
            raise SourceEditError("source-outside-mapping", relative)
        candidate = unresolved.resolve(strict=True)
    except OSError as error:
        raise SourceEditError("source-unavailable", relative) from error
    if candidate.is_symlink() or candidate == root or root not in candidate.parents:
        raise SourceEditError("source-outside-mapping", relative)
    if not candidate.is_file():
        raise SourceEditError("source-not-file", relative)
    return candidate


def _decode_source(path: Path) -> tuple[bytes, str]:
    """Read strict UTF-8 source while retaining exact rollback bytes."""

    try:
        raw = path.read_bytes()
        return raw, raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        raise SourceEditError("source-encoding", str(path)) from error


def _dotenv_assignment(lines: list[str], key: str) -> tuple[int, str, str]:
    """Locate one unambiguous dotenv assignment and preserve its quoting."""

    pattern = re.compile(
        rf"^(?P<prefix>\s*{re.escape(key)}\s*=\s*)"
        rf"(?P<value>.*?)(?P<ending>\r?\n)?$"
    )
    matches: list[tuple[int, re.Match[str]]] = []
    for index, line in enumerate(lines):
        if line.lstrip().startswith("#"):
            continue
        match = pattern.fullmatch(line)
        if match:
            matches.append((index, match))
    if len(matches) != 1:
        raise SourceEditError("dotenv-key-count", key)
    index, match = matches[0]
    raw_value = match.group("value").strip()
    if " #" in raw_value or raw_value.startswith(("'", '"')) and len(raw_value) < 2:
        raise SourceEditError("dotenv-value-unsupported", key)
    quote = ""
    value = raw_value
    if (
        len(raw_value) >= 2
        and raw_value[0] == raw_value[-1]
        and raw_value[0] in {"'", '"'}
    ):
        quote = raw_value[0]
        value = raw_value[1:-1]
    elif any(character.isspace() for character in raw_value):
        raise SourceEditError("dotenv-value-unsupported", key)
    return index, value, quote


def _replace_dotenv_line(
    lines: list[str], index: int, key: str, value: str, quote: str
) -> None:
    """Replace one dotenv value without changing surrounding line endings."""

    ending = (
        "\r\n"
        if lines[index].endswith("\r\n")
        else "\n" if lines[index].endswith("\n") else ""
    )
    prefix_match = re.match(r"^(\s*[^=]+?\s*=\s*)", lines[index])
    if prefix_match is None:
        raise SourceEditError("dotenv-key-count", key)
    prefix = prefix_match.group(1)
    lines[index] = f"{prefix}{quote}{value}{quote}{ending}"


def _candidate_tagged(candidate: CandidateImage) -> tuple[str, str]:
    """Return the policy-spelled repository and tag without its digest."""

    tagged = candidate.reference.partition("@")[0]
    repository, tag = tagged.rsplit(":", 1)
    return repository, tag


def _prepare_dotenv(
    path: Path,
    source: SourceEdit,
    current_image: str,
    candidate: CandidateImage,
) -> tuple[bytes, bytes]:
    """Prepare an exact dotenv key replacement after a live-image precondition."""

    original, text = _decode_source(path)
    lines = text.splitlines(keepends=True)
    candidate_repository, candidate_tag = _candidate_tagged(candidate)
    if source.image_key:
        index, current_value, quote = _dotenv_assignment(lines, source.image_key)
        if not image_references_match(current_value, current_image):
            raise SourceEditError("source-image-stale", source.image_key)
        _replace_dotenv_line(
            lines, index, source.image_key, candidate.reference, quote
        )
    else:
        if not source.name_key or not source.version_key:
            raise SourceEditError("source-keys-required")
        name_index, current_name, name_quote = _dotenv_assignment(
            lines, source.name_key
        )
        version_index, current_version, version_quote = _dotenv_assignment(
            lines, source.version_key
        )
        if not image_references_match(
            f"{current_name}:{current_version}", current_image
        ):
            raise SourceEditError("source-image-stale", source.name_key)
        _replace_dotenv_line(
            lines, name_index, source.name_key, candidate_repository, name_quote
        )
        _replace_dotenv_line(
            lines, version_index, source.version_key, candidate_tag, version_quote
        )
    return original, "".join(lines).encode("utf-8")


def _yaml_service_bounds(lines: list[str], compose_service: str) -> tuple[int, int]:
    """Locate one exact two-space-indented Compose service block."""

    service_pattern = re.compile(rf"^  {re.escape(compose_service)}:\s*(?:#.*)?(?:\r?\n)?$")
    starts = [index for index, line in enumerate(lines) if service_pattern.fullmatch(line)]
    if len(starts) != 1:
        raise SourceEditError("yaml-service-count", compose_service)
    start = starts[0]
    if not any(line.rstrip("\r\n") == "services:" for line in lines[:start]):
        raise SourceEditError("yaml-services-missing", compose_service)
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = lines[index]
        if line and not line.startswith((" ", "\t", "\r", "\n")):
            end = index
            break
        if re.match(r"^  \S[^:]*:\s*(?:#.*)?(?:\r?\n)?$", line):
            end = index
            break
    return start, end


def _prepare_yaml_image(
    path: Path,
    compose_service: str,
    current_image: str,
    candidate: CandidateImage,
) -> tuple[bytes, bytes]:
    """Replace one simple scalar image in the exact mapped service block."""

    original, text = _decode_source(path)
    if any(marker in text for marker in ("&", "*", "${")):
        raise SourceEditError("yaml-advanced-syntax", str(path))
    lines = text.splitlines(keepends=True)
    start, end = _yaml_service_bounds(lines, compose_service)
    image_pattern = re.compile(
        r"^(?P<prefix> {4}image:\s*)"
        r"(?P<value>[^#\r\n]+?)(?P<ending>\r?\n)?$"
    )
    matches = [
        (index, image_pattern.fullmatch(lines[index]))
        for index in range(start + 1, end)
        if image_pattern.fullmatch(lines[index])
    ]
    if len(matches) != 1:
        raise SourceEditError("yaml-image-count", compose_service)
    index, match = matches[0]
    if match is None:
        raise SourceEditError("yaml-image-count", compose_service)
    raw_value = match.group("value").strip()
    quote = ""
    value = raw_value
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        quote = value[0]
        value = value[1:-1]
    if not image_references_match(value, current_image):
        raise SourceEditError("source-image-stale", compose_service)
    ending = match.group("ending") or ""
    lines[index] = f"{match.group('prefix')}{quote}{candidate.reference}{quote}{ending}"
    return original, "".join(lines).encode("utf-8")


def prepare_source_change(
    target: PolicyTarget,
    plan_entry: Mapping[str, Any],
) -> SourceChange:
    """Build a source diff after rechecking mapping and current-image evidence."""

    mapping = plan_entry.get("mapping")
    current_image = plan_entry.get("current_image")
    if (
        target.source is None
        or not isinstance(mapping, Mapping)
        or mapping.get("status") != "mapped"
        or mapping.get("source_verified", True) is not True
        or not isinstance(current_image, str)
    ):
        raise SourceEditError("declarative-evidence-required")
    directory_value = mapping.get("directory")
    if not isinstance(directory_value, str):
        raise SourceEditError("mapping-directory-missing")
    path = _resolved_source_path(Path(directory_value), target.source.file)
    if target.source.edit_type == "yaml_image":
        stack_file = mapping.get("stack_file")
        compose_service = mapping.get("compose_service")
        if not isinstance(stack_file, str) or path != Path(stack_file).resolve():
            raise SourceEditError("yaml-not-mapped-stack", str(path))
        if not isinstance(compose_service, str):
            raise SourceEditError("mapping-service-missing")
        original, replacement = _prepare_yaml_image(
            path, compose_service, current_image, target.candidate
        )
    else:
        original, replacement = _prepare_dotenv(
            path, target.source, current_image, target.candidate
        )
    if original == replacement:
        raise SourceEditError("source-unchanged", str(path))
    diff = "".join(
        difflib.unified_diff(
            original.decode("utf-8").splitlines(keepends=True),
            replacement.decode("utf-8").splitlines(keepends=True),
            fromfile=str(path),
            tofile=str(path),
            n=0,
        )
    )
    mode = stat.S_IMODE(path.stat().st_mode)
    return SourceChange(path, original, replacement, diff, mode)


def write_source_change(change: SourceChange, replacement: bytes | None = None) -> None:
    """Atomically apply or restore one already-reviewed source change."""

    payload = change.replacement if replacement is None else replacement
    if change.path.is_symlink():
        raise SourceEditError("source-became-symlink", str(change.path))
    current = change.path.read_bytes()
    expected = change.original if replacement is None else change.replacement
    if current != expected:
        raise SourceEditError("source-changed-after-review", str(change.path))
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{change.path.name}.", dir=change.path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, change.original_mode)
        os.replace(temporary, change.path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
