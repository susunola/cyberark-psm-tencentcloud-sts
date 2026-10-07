"""Bounded exports, durable batch attempts and read-only deployment evidence."""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from collections.abc import Iterator
from typing import Any, TextIO
from urllib.parse import quote

from pam.onboarding import validate_account
from pam.vault import VaultError


def export_records(vault: Any, resource: str, limit: int = 100, max_pages: int = 100) -> Iterator[dict[str, Any]]:
    fields = {'Accounts': 'value', 'LiveSessions': 'LiveSessions', 'Recordings': 'Recordings'}
    if (
        resource not in fields
        or type(limit) is not int
        or not 1 <= limit <= 100
        or type(max_pages) is not int
        or not 1 <= max_pages <= 100
    ):
        raise ValueError('Use a bounded paginated resource')
    offset, seen = 0, set()
    for _ in range(max_pages):
        response = vault.list_operations(resource, limit, offset)
        if not isinstance(response, dict) or not isinstance(response.get(fields[resource]), list):
            raise ValueError('Unsupported page response')
        page = response[fields[resource]]
        if len(page) > limit or any(not isinstance(item, dict) for item in page):
            raise ValueError('Invalid page bounds or record schema')
        total = response.get('Total')
        if total is not None and (type(total) is not int or total < 0):
            raise ValueError('Invalid page total')
        if not page:
            if response.get('nextLink') or (total is not None and offset < total):
                raise ValueError('Incomplete empty page')
            return
        fingerprint = hashlib.sha256(json.dumps(page, sort_keys=True).encode()).hexdigest()
        if fingerprint in seen:
            raise ValueError('Repeated page; endpoint may not honor offsets')
        seen.add(fingerprint)
        yield from page
        offset += len(page)
        if total is not None and offset >= total and not response.get('nextLink'):
            return
        if len(page) < limit and not response.get('nextLink') and (total is None or offset >= total):
            count = response.get('count', offset)
            if type(count) is not int or count < 0:
                raise ValueError('Invalid account count')
            if count <= offset:
                return
    raise ValueError('Export page cap reached; output is incomplete')


def append_record(stream: TextIO, record: dict[str, Any], *, durable: bool = True) -> None:
    # JSONL preserves every fsynced attempt even if a later cloud/Vault call fails.
    stream.write(json.dumps(record, ensure_ascii=False) + '\n')
    if durable:
        stream.flush()
        os.fsync(stream.fileno())


def onboard_batch(
    payloads: list[dict[str, Any]],
    safe: str,
    platform: str,
    vault: Any,
    journal: TextIO,
) -> dict[str, Any]:
    if not isinstance(payloads, list) or not 1 <= len(payloads) <= 100:
        raise ValueError('Provide 1..100 complete accounts through stdin')
    accounts = [validate_account(p, safe, platform) for p in payloads]
    names = [p['name'].casefold() for p in accounts]
    if len(set(names)) != len(names):
        raise ValueError('Duplicate account names in batch')
    # Preflight every lookup before the first creation. PVWA remains authoritative.
    for account in accounts:
        if vault.find_accounts_by_name(account['name'], safe):
            raise ValueError('Existing account name; reconcile instead of creating duplicates')
    operation = uuid.uuid4().hex
    append_record(journal, {'event': 'batch_started', 'operation': operation, 'count': len(accounts)})
    created: list[str] = []
    for index, account in enumerate(accounts):
        append_record(journal, {
            'event': 'create_attempt', 'operation': operation,
            'index': index, 'name': account['name'], 'safe': safe, 'platform': platform,
        })
        account_id = vault.create(account)
        append_record(journal, {
            'event': 'create_confirmed', 'operation': operation,
            'index': index, 'account_id': account_id,
        })
        created.append(account_id)
    append_record(journal, {'event': 'batch_completed', 'operation': operation, 'count': len(created)})
    return {'operation': operation, 'status': 'batch-completed', 'account_ids': created}


def preflight(
    vault: Any,
    settings: dict[str, Any],
    account_id: str,
    safe: str,
    platform: str,
    component: str,
) -> dict[str, Any]:
    if (
        not isinstance(component, str)
        or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', component)
        or not safe
        or not platform
    ):
        raise ValueError('Explicit preflight scope and component required')
    account = vault.account(account_id)
    properties = account.get('platformAccountProperties', {})
    profile_name = properties.get('TencentRoleProfile')
    profile = settings['profiles'].get(profile_name)
    checks = {'account_scope': account.get('safeName') == safe and account.get('platformId') == platform}
    if 'TencentSecretId' in properties or 'TencentRoleProfile' in properties:
        checks['caller_profile_binding'] = bool(
            profile and properties.get('TencentSecretId') in profile['allowed_secret_ids']
        )
    probes: dict[str, str] = {}
    for name, path in [
        ('platform_read', '/Platforms/' + quote(platform, safe='')),
        ('connector_list_read', '/PSM/Connectors'),
    ]:
        try:
            value = vault.request('GET', path)
            probes[name] = 'available-read' if isinstance(value, (dict, list)) else 'unexpected-response'
        except VaultError as error:
            probes[name] = {
                401: 'authentication-required',
                403: 'permission-denied',
                404: 'unsupported-or-hidden',
            }.get(error.status if error.status is not None else -1, 'probe-failed')
    return {
        'account_id': account_id,
        'checks': checks,
        'probes': probes,
        'requested_component': component,
        'scope_binding_ready': all(checks.values()),
        'not_verified': [
            'component assignment', 'native CPM engine', 'live console/SSH/RDP',
            'approval/recording', 'write permissions', 'production compatibility',
        ],
    }
