"""Bounded JSON inputs and exclusive private outputs; no secret values in errors."""

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol, TextIO

MAX_JSON_BYTES = 1024 * 1024


class ReadableSource(Protocol):
    """Anything with a size-bounded ``read``: text or binary handles alike."""

    def read(self, size: int, /) -> Any: ...


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate object keys so configuration cannot silently shadow itself."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field")
        result[key] = value
    return result


def _bounded_read(source: ReadableSource, limit: int) -> str | bytes:
    raw: str | bytes = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("JSON input exceeds size bound")
    return raw


def read_json(
    path: str | Path | None = None,
    *,
    stream: ReadableSource | None = None,
    limit: int = MAX_JSON_BYTES,
) -> Any:
    """Read one bounded JSON document from a path or an already-open stream.

    ``limit`` counts bytes for a path or binary handle and characters for a text
    stream, so text input can occupy up to four times the bound in UTF-8 bytes.
    Either way the read itself stays bounded, which is the property callers need.
    """
    if path is not None:
        with Path(path).open("rb") as source:
            raw = _bounded_read(source, limit)
    elif stream is not None:
        raw = _bounded_read(stream, limit)
    else:
        raise ValueError("Provide a path or a stream")
    text = raw.decode("utf-8-sig") if isinstance(raw, bytes) else raw
    return json.loads(text, object_pairs_hook=unique_object)


def private_output(path: str | Path) -> TextIO:
    """Create a new owner-only file, failing if the path already exists."""
    # On Windows use a protected parent directory: POSIX mode does not install a DACL.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, "w", encoding="utf-8")


def save_json(stream: TextIO, value: Mapping[str, Any]) -> None:
    json.dump(value, stream, ensure_ascii=False, indent=2)
    stream.flush()
    os.fsync(stream.fileno())
