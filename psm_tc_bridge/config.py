"""Fail-closed settings. Unknown keys and placeholder secrets are rejected."""

import json
import re
from pathlib import Path

from psm_tc_bridge.federation import FederationError, validate_destination

PROFILE_NAME = re.compile(r'[A-Za-z0-9_-]{1,80}')
ROLE_ARN = re.compile(r'qcs::cam::uin/[0-9]+:role(?:Name)?/[A-Za-z0-9_-]+')
REGION = re.compile(r'[a-z]+-[a-z0-9-]+')
STS_ENDPOINT = re.compile(r'sts(\.[a-z0-9-]+)?\.tencentcloudapi\.com')
EXTERNAL_ID = re.compile(r'[\w+=,.@:/-]{2,128}')
SECRET_ID = re.compile(r'[A-Za-z0-9_-]{8,128}')
LOGIN_HOST = 'cloud.tencent.com'
PROFILE_KEYS = {
    'role_arn', 'allowed_secret_ids', 'destination', 'duration_seconds', 'region',
    'external_id', 'session_policy', 'sts_endpoint',
}
ROOT_KEYS = {'submit_method', 'profiles'}


class ConfigError(ValueError):
    pass


def _reject_placeholder(value, label):
    if not isinstance(value, str) or 'REPLACE' in value or not value.strip():
        raise ConfigError(f'{label} still contains a placeholder or is empty')


def _session_policy(value, label):
    if not isinstance(value, dict):
        raise ConfigError(f'{label} must be a CAM policy object')
    if 'principal' in value or 'Principal' in value:
        raise ConfigError(f'{label} must not contain a principal')
    encoded = json.dumps(value, separators=(',', ':'), ensure_ascii=True)
    if not 2 <= len(encoded) <= 2048:
        raise ConfigError(f'{label} must be 2..2048 bytes once encoded')
    return encoded


def load_settings(source):
    if isinstance(source, (str, Path)):
        data = json.loads(Path(source).read_text(encoding='utf-8'))
    elif isinstance(source, dict):
        data = source
    else:
        raise ConfigError('Settings must be a path or object')
    return validate_settings(data)


def validate_settings(data):
    if not isinstance(data, dict) or set(data) - ROOT_KEYS:
        raise ConfigError('Settings only allow submit_method and profiles')
    method = data.get('submit_method', 'post')
    if method not in ('post', 'get'):
        raise ConfigError('submit_method must be post or get')
    profiles = data.get('profiles')
    if not isinstance(profiles, dict) or not profiles:
        raise ConfigError('At least one role profile required')
    cleaned = {}
    for name, raw in profiles.items():
        if not PROFILE_NAME.fullmatch(name) or not isinstance(raw, dict) or set(raw) - PROFILE_KEYS:
            raise ConfigError('Invalid profile name or unknown profile key')
        if not ROLE_ARN.fullmatch(raw.get('role_arn', '')):
            raise ConfigError('Invalid ordinary CAM role ARN')
        try:
            destination = validate_destination(raw.get('destination', ''))
        except FederationError as exc:
            raise ConfigError('Invalid console destination') from exc
        duration = raw.get('duration_seconds')
        if type(duration) is not int or not 1 <= duration <= 300:
            raise ConfigError('Duration must be 1..300 seconds')
        region = raw.get('region', '')
        if not REGION.fullmatch(region):
            raise ConfigError('Invalid STS region')
        allow = raw.get('allowed_secret_ids')
        if not isinstance(allow, list) or not allow or len(allow) > 20:
            raise ConfigError('Configure 1..20 allowed broker SecretIds for each role')
        if any(not isinstance(item, str) or not SECRET_ID.fullmatch(item) or 'REPLACE' in item for item in allow):
            raise ConfigError('Configure allowed broker SecretIds for each role')
        endpoint = raw.get('sts_endpoint', 'sts.tencentcloudapi.com')
        if not STS_ENDPOINT.fullmatch(endpoint):
            raise ConfigError('STS endpoint must be a tencentcloudapi.com STS host')
        profile = {
            'role_arn': raw['role_arn'],
            'allowed_secret_ids': tuple(allow),
            'destination': destination,
            'duration_seconds': duration,
            'region': region,
            'sts_endpoint': endpoint,
            'login_host': LOGIN_HOST,
        }
        if 'external_id' in raw:
            _reject_placeholder(raw['external_id'], 'external_id')
            if not EXTERNAL_ID.fullmatch(raw['external_id']):
                raise ConfigError('Invalid ExternalId')
            profile['external_id'] = raw['external_id']
        if 'session_policy' in raw:
            profile['session_policy'] = _session_policy(raw['session_policy'], 'session_policy')
        cleaned[name] = profile
    return {'submit_method': method, 'profiles': cleaned}
