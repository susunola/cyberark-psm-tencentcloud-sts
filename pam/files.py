"""Bounded JSON inputs and exclusive private outputs; no secret values in errors."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, TextIO


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def read_json(path: str | Path | None = None, *, stream: TextIO | None = None, limit: int = 1024 * 1024) -> Any:
    if path is not None:
        with Path(path).open('rb') as source:
            raw = source.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('JSON input exceeds size bound')
        text = raw.decode('utf-8-sig')
    elif stream is not None:
        text = stream.read(limit + 1)
        if len(text) > limit:
            raise ValueError('JSON input exceeds size bound')
    else:
        raise ValueError('Provide a JSON path or stream')
    return json.loads(text, object_pairs_hook=unique_object)


def private_output(path: str | Path) -> TextIO:
    # On Windows use a protected parent directory: POSIX mode does not install a DACL.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, 'w', encoding='utf-8')


def save_json(stream: TextIO, value: Any) -> None:
    json.dump(value, stream, ensure_ascii=False, indent=2)
    stream.flush()
    os.fsync(stream.fileno())
