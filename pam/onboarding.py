"""Validate complete account inputs before submitting a PVWA write."""
from __future__ import annotations

import copy
import re
from typing import Any

from pam.lifecycle import validate_identifier


def validate_account(payload: Any, safe: str, platform: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError('Expected an account object')
    result = copy.deepcopy(payload)
    component = result.pop('connection_component', None)
    if component not in (None, 'PSM-RDP', 'PSM-SSH'):
        raise ValueError('Unknown proposal component')
    required = {'name', 'address', 'userName', 'platformId', 'safeName', 'secretType', 'secret'}
    allowed = required | {'platformAccountProperties', 'secretManagement'}
    if (
        not required <= set(result)
        or set(result) - allowed
        or result['safeName'] != safe
        or result['platformId'] != platform
    ):
        raise ValueError('Account outside the approved schema or scope')
    for field in required - {'secret'}:
        value = result[field]
        if not isinstance(value, str) or not value.strip() or len(value) > 1024 or any(ord(c) < 32 for c in value):
            raise ValueError('Invalid account metadata')
    if (
        result['secretType'] != 'password'
        or not isinstance(result['secret'], str)
        or not 1 <= len(result['secret']) <= 4096
    ):
        raise ValueError('Explicit bounded password credential required')
    properties = result.get('platformAccountProperties', {})
    if not isinstance(properties, dict) or any(
        not isinstance(k, str) or not isinstance(v, str) or not k or len(k) > 128 or len(v) > 1024
        for k, v in properties.items()
    ):
        raise ValueError('Platform properties must be bounded strings')
    if 'TencentSecretId' in properties or 'TencentRoleProfile' in properties:
        validate_identifier(properties.get('TencentSecretId'))
        profile = properties.get('TencentRoleProfile')
        if not isinstance(profile, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', profile):
            raise ValueError('Complete Tencent caller/profile binding required')
    management = result.get('secretManagement')
    if 'secretManagement' in result:
        if (
            not isinstance(management, dict)
            or set(management) - {'automaticManagementEnabled', 'manualManagementReason'}
            or type(management.get('automaticManagementEnabled')) is not bool
        ):
            raise ValueError('Invalid management flags')
        reason = management.get('manualManagementReason') if isinstance(management, dict) else None
        if 'manualManagementReason' in (management or {}) and (
            not isinstance(reason, str) or len(reason) > 1024
        ):
            raise ValueError('Invalid management reason')
    if 'TencentSecretId' in properties and (
        not isinstance(management, dict) or management.get('automaticManagementEnabled') is not False
    ):
        raise ValueError('CAM key accounts must explicitly disable native automatic management')
    return result
