"""Credential-free CVM onboarding proposals; never assume guest credentials."""
from __future__ import annotations

import ipaddress
from typing import Any


def cvm_plan(
    inventory: dict[str, Any],
    safe: str,
    linux_platform: str,
    windows_platform: str,
    usernames: dict[str, str],
) -> dict[str, list[dict[str, Any]]]:
    if not all((safe, linux_platform, windows_platform)):
        raise ValueError('Explicit Safe and platform IDs required')
    result: dict[str, list[dict[str, Any]]] = {'accounts': [], 'skipped': []}
    for instance in inventory.get('instances', []):
        os_name = (instance.get('os') or '').lower()
        kind = 'windows' if 'windows' in os_name else 'linux' if any(n in os_name for n in ('linux', 'ubuntu', 'centos', 'debian', 'rocky', 'suse')) else None
        username = usernames.get(instance['id'])
        ips = instance.get('private_ips') or []
        if not kind or not username or not ips:
            result['skipped'].append({'id': instance['id'], 'reason': 'Need known OS, explicit guest username and private IP'})
            continue
        ipaddress.ip_address(ips[0])
        result['accounts'].append({'name': 'tc-' + instance['region'] + '-' + instance['id'],
            'address': ips[0], 'userName': username, 'platformId': windows_platform if kind == 'windows' else linux_platform,
            'safeName': safe, 'secretType': 'password',
            'secretManagement': {'automaticManagementEnabled': False,
                                 'manualManagementReason': 'Guest credential and native CPM configuration required'},
            'connection_component': 'PSM-RDP' if kind == 'windows' else 'PSM-SSH'})
    return result
