"""Strict startup validation with errors that never echo configuration secrets."""
import copy
import re
import json
from pathlib import Path
from federation import validate_destination


def load_settings(path):
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate configuration field')
            result[key] = value
        return result
    with Path(path).open('rb') as source:
        raw = source.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError('Configuration exceeds size limit')
    return validate_settings(json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique_object))


def validate_settings(settings):
    if not isinstance(settings, dict) or set(settings) != {'profiles'}:
        raise ValueError('Expected a profiles object only')
    profiles = settings['profiles']
    if not isinstance(profiles, dict) or not 1 <= len(profiles) <= 100:
        raise ValueError('Configure 1..100 profiles')
    seen_ids = set()
    required = {'role_arn', 'allowed_secret_ids', 'destination', 'duration_seconds', 'region'}
    for name, p in profiles.items():
        if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', name):
            raise ValueError('Invalid profile name')
        if not isinstance(p, dict) or set(p) != required:
            raise ValueError('Invalid profile fields')
        if not isinstance(p['role_arn'], str) or not re.fullmatch(r'qcs::cam::uin/[0-9]+:role(?:Name)?/[A-Za-z0-9_-]+', p['role_arn']):
            raise ValueError('Invalid ordinary CAM role ARN')
        validate_destination(p['destination'])
        if type(p['duration_seconds']) is not int or not 1 <= p['duration_seconds'] <= 300:
            raise ValueError('Duration must be 1..300 seconds')
        ids = p['allowed_secret_ids']
        if not isinstance(ids, list) or not 1 <= len(ids) <= 10:
            raise ValueError('Configure 1..10 caller SecretIds per profile')
        for sid in ids:
            if not isinstance(sid, str) or not re.fullmatch(r'[A-Za-z0-9_-]{2,256}', sid) or 'REPLACE' in sid:
                raise ValueError('Configure real caller SecretIds')
            if sid in seen_ids:
                raise ValueError('Each caller SecretId must belong to one profile only')
            seen_ids.add(sid)
        if not isinstance(p['region'], str) or not re.fullmatch(r'[a-z]+-[a-z]+', p['region']):
            raise ValueError('Invalid STS region')
    return copy.deepcopy(settings)
