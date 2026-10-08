"""Scheduler-neutral, scoped one-shot maintenance; never auto-finalize a rotation."""
from __future__ import annotations

import copy
import os
import re
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from federation import DEFAULT_SITE, assume_role
from pam.cloud import uin
from pam.files import private_output, save_json
from pam.lifecycle import prepare
from validate import MAX_ACCOUNT_FIELD_LEN, is_identifier, is_readable_text


def validate_jobs(configuration: Any) -> list[dict[str, str]]:
    if not isinstance(configuration, dict) or set(configuration) != {'jobs'}:
        raise ValueError('Expected maintenance jobs only')
    jobs = copy.deepcopy(configuration['jobs'])
    if not isinstance(jobs, list) or not 1 <= len(jobs) <= 100:
        raise ValueError('Configure 1..100 jobs')
    identifiers: set[str] = set()
    targets: set[str] = set()
    for job in jobs:
        expected = {'id', 'action', 'account', 'target_uin', 'profile', 'safe', 'platform'}
        if not isinstance(job, dict) or set(job) != expected:
            raise ValueError('Invalid maintenance job fields')
        if not all(isinstance(value, str) and value for value in job.values()):
            raise ValueError('Maintenance fields must be nonempty strings')
        reserved = re.fullmatch(r'(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])', job['id'])
        if (
            not is_identifier(job['id'], 1, 80)
            or job['id'].casefold() in identifiers
            or reserved
        ):
            raise ValueError('Use distinct safe job IDs')
        job['target_uin'] = str(uin(job['target_uin']))
        if (
            not is_identifier(job['account'], 1, 128)
            or not is_identifier(job['profile'], 1, 80)
        ):
            raise ValueError('Invalid maintenance account/profile')
        if any(not is_readable_text(job[k], MAX_ACCOUNT_FIELD_LEN) for k in ('safe', 'platform')):
            raise ValueError('Invalid maintenance scope')
        if job['action'] not in ('verify-cam', 'prepare-key'):
            raise ValueError('Maintenance cannot finalize, delete, approve or reset credentials')
        if job['action'] == 'prepare-key' and job['target_uin'] in targets:
            raise ValueError('One preparation per target UIN per run')
        if job['action'] == 'prepare-key':
            targets.add(job['target_uin'])
        identifiers.add(job['id'].casefold())
    return jobs


def run(
    configuration: Any,
    settings: Mapping[str, Any],
    state_dir: str | Path,
    cloud: Any,
    vault: Any,
    role_verifier: Callable[..., Mapping[str, str]] = assume_role,
) -> list[dict[str, str]]:
    jobs = validate_jobs(configuration)
    state = Path(state_dir)
    if not state.is_dir():
        raise ValueError('Pre-create a protected maintenance state directory')
    lock_path = state / '.maintenance.lock'
    # Fail if another runner or a crash journal exists; do not steal potentially active locks.
    with private_output(lock_path) as lock:
        save_json(lock, {'pid': os.getpid()})
    try:
        results: list[dict[str, str]] = []
        for job in jobs:
            old = vault.account(job['account'])
            props = old.get('platformAccountProperties', {})
            sid = props.get('TencentSecretId')
            profile = settings['profiles'].get(job['profile'])
            if (
                old.get('safeName') != job['safe']
                or old.get('platformId') != job['platform']
                or props.get('TencentRoleProfile') != job['profile']
            ):
                raise ValueError('Maintenance account outside approved scope')
            if not profile or not sid or sid not in profile['allowed_secret_ids']:
                raise ValueError('Maintenance caller not authorized in bridge profile')
            if job['action'] == 'verify-cam':
                secret = vault.secret(job['account'], 'Scheduled Tencent credential verification ' + job['id'])
                try:
                    cloud.verify(sid, secret, job['target_uin'])
                    role_verifier(
                        sid, secret, profile['role_arn'], 'verify-' + uuid.uuid4().hex,
                        profile['duration_seconds'], profile['region'],
                        profile.get('site', DEFAULT_SITE),
                    )
                finally:
                    secret = None
                results.append({'job': job['id'], 'status': 'identity-and-role-verified'})
            else:
                ticket_path = state / (job['id'] + '.json')
                operation = uuid.uuid4().hex
                with private_output(ticket_path) as journal:
                    save_json(journal, {
                        'operation': operation, 'status': 'preparing',
                        'target_uin': job['target_uin'],
                        'old_account': job['account'], 'profile': job['profile'],
                    })
                ticket = prepare(cloud, vault, job['account'], job['target_uin'], job['profile'], operation)
                temporary = state / (job['id'] + '.json.tmp')
                with private_output(temporary) as sink:
                    save_json(sink, ticket.public())
                Path(temporary).replace(ticket_path)
                results.append({
                    'job': job['id'],
                    'status': 'prepared-awaiting-tested-cutover',
                    'ticket': str(ticket_path),
                })
        return results
    finally:
        lock_path.unlink()
