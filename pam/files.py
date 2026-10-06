"""Bounded JSON inputs and exclusive private outputs; no secret values in errors."""
import json
import os
from pathlib import Path


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON field')
        result[key] = value
    return result


def read_json(path=None, *, stream=None, limit=1024 * 1024):
    if path is not None:
        with Path(path).open('rb') as source:
            raw = source.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('JSON input exceeds size bound')
        raw = raw.decode('utf-8-sig')
    else:
        raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('JSON input exceeds size bound')
    return json.loads(raw, object_pairs_hook=unique_object)


def private_output(path):
    # On Windows use a protected parent directory: POSIX mode does not install a DACL.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, 'w', encoding='utf-8')


def save_json(stream, value):
    json.dump(value, stream, ensure_ascii=False, indent=2)
    stream.flush()
    os.fsync(stream.fileno())
