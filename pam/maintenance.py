"""Scheduler-neutral, scoped one-shot maintenance; never auto-finalize a rotation."""
from pathlib import Path
import os
import re
import uuid
from federation import assume_role
from pam.files import private_output, save_json
from pam.lifecycle import prepare


def validate_jobs(configuration):
    if not isinstance(configuration, dict) or set(configuration) != {'jobs'}:
        raise ValueError('Expected maintenance jobs only')
    jobs = configuration['jobs']
    if not isinstance(jobs, list) or not 1 <= len(jobs) <= 100:
        raise ValueError('Configure 1..100 jobs')
    identifiers, targets = set(), set()
    for job in jobs:
        if not isinstance(job, dict) or set(job) != {'id', 'action', 'account', 'target_uin', 'profile', 'safe', 'platform'}:
            raise ValueError('Invalid maintenance job fields')
        if not all(isinstance(value, str) and value for value in job.values()):
            raise ValueError('Maintenance fields must be nonempty strings')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', job['id']) or job['id'] in identifiers:
            raise ValueError('Use distinct safe job IDs')
        if job['action'] not in ('verify-cam', 'prepare-key'):
            raise ValueError('Maintenance cannot finalize, delete, approve or reset credentials')
        if job['action'] == 'prepare-key' and job['target_uin'] in targets:
            raise ValueError('One preparation per target UIN per run')
        if job['action'] == 'prepare-key':
            targets.add(job['target_uin'])
        identifiers.add(job['id'])
    return jobs


def run(configuration, settings, state_dir, cloud, vault, role_verifier=assume_role):
    jobs = validate_jobs(configuration)
    state = Path(state_dir)
    if not state.is_dir():
        raise ValueError('Pre-create a protected maintenance state directory')
    lock_path = state / '.maintenance.lock'
    # Fail if another runner or a crash journal exists; do not steal potentially active locks.
    with private_output(lock_path) as lock:
        save_json(lock, {'pid': os.getpid()})
    try:
        results = []
        for job in jobs:
            old = vault.account(job['account'])
            props = old.get('platformAccountProperties', {})
            sid = props.get('TencentSecretId')
            profile = settings['profiles'].get(job['profile'])
            if old.get('safeName') != job['safe'] or old.get('platformId') != job['platform'] or props.get('TencentRoleProfile') != job['profile']:
                raise ValueError('Maintenance account outside approved scope')
            if not profile or not sid or sid not in profile['allowed_secret_ids']:
                raise ValueError('Maintenance caller not authorized in bridge profile')
            if job['action'] == 'verify-cam':
                secret = vault.secret(job['account'], 'Scheduled Tencent credential verification ' + job['id'])
                try:
                    cloud.verify(sid, secret, job['target_uin'])
                    role_verifier(sid, secret, profile['role_arn'], 'verify-' + uuid.uuid4().hex,
                                  profile['duration_seconds'], profile['region'])
                finally:
                    secret = None
                results.append({'job': job['id'], 'status': 'identity-and-role-verified'})
            else:
                ticket_path = state / (job['id'] + '.json')
                operation = uuid.uuid4().hex
                with private_output(ticket_path) as journal:
                    save_json(journal, {'operation': operation, 'status': 'preparing', 'target_uin': job['target_uin'],
                                       'old_account': job['account'], 'profile': job['profile']})
                ticket = prepare(cloud, vault, job['account'], job['target_uin'], job['profile'], operation)
                temporary = state / (job['id'] + '.json.tmp')
                with private_output(temporary) as sink:
                    save_json(sink, ticket.public())
                os.replace(temporary, ticket_path)
                results.append({'job': job['id'], 'status': 'prepared-awaiting-tested-cutover', 'ticket': str(ticket_path)})
        return results
    finally:
        lock_path.unlink()
