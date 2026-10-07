"""Strict startup validation with errors that never echo configuration secrets."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from federation import MIN_CREDENTIAL_MARGIN_SECONDS, validate_destination, validate_region
from validate import MAX_CONFIG_BYTES, MAX_PROFILE_NAME_LEN, is_identifier, unique_json_object


def load_settings(path: str | Path) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        return unique_json_object(pairs, message='Duplicate configuration field')

    with Path(path).open('rb') as source:
        raw = source.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError('Configuration exceeds size limit')
    return validate_settings(json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique_object))


def validate_settings(settings: Any) -> dict[str, Any]:
    if not isinstance(settings, dict) or set(settings) != {'profiles'}:
        raise ValueError('Expected a profiles object only')
    profiles = settings['profiles']
    if not isinstance(profiles, dict) or not 1 <= len(profiles) <= 100:
        raise ValueError('Configure 1..100 profiles')
    seen_ids: set[str] = set()
    required = {'role_arn', 'allowed_secret_ids', 'destination', 'duration_seconds', 'region'}
    for name, p in profiles.items():
        if not is_identifier(name, 1, MAX_PROFILE_NAME_LEN):
            raise ValueError('Invalid profile name')
        if not isinstance(p, dict) or set(p) != required:
            raise ValueError('Invalid profile fields')
        if not isinstance(p['role_arn'], str) or not re.fullmatch(r'qcs::cam::uin/[0-9]+:role(?:Name)?/[A-Za-z0-9_-]+', p['role_arn']):
            raise ValueError('Invalid ordinary CAM role ARN')
        validate_destination(p['destination'])
        minimum = MIN_CREDENTIAL_MARGIN_SECONDS + 1
        if type(p['duration_seconds']) is not int or not minimum <= p['duration_seconds'] <= 300:
            raise ValueError(f'Duration must be {minimum}..300 seconds')
        ids = p['allowed_secret_ids']
        if not isinstance(ids, list) or not 1 <= len(ids) <= 10:
            raise ValueError('Configure 1..10 caller SecretIds per profile')
        for sid in ids:
            if not is_identifier(sid, 2, 256) or 'REPLACE' in sid:
                raise ValueError('Configure real caller SecretIds')
            if sid in seen_ids:
                raise ValueError('Each caller SecretId must belong to one profile only')
            seen_ids.add(sid)
        validate_region(p['region'])
    return copy.deepcopy(settings)
