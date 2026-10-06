"""Two-stage rotation; old credentials stay active until explicit cutover confirmation."""
from dataclasses import dataclass, asdict
import re
from federation import FederationError, assume_role
from pam.cloud import uin


class LifecycleError(Exception):
    pass


@dataclass(frozen=True)
class Ticket:
    operation: str
    target_uin: str
    old_account: str
    new_account: str
    old_secret_id: str
    new_secret_id: str
    profile: str

    def public(self):
        return asdict(self)


def prepare(cloud, vault, old_account_id, target, profile, operation):
    if not re.fullmatch(r'[a-f0-9]{32}', operation):
        raise ValueError('Use a UUID hex operation ID')
    target = str(uin(target))
    old = vault.account(old_account_id)
    props = old.get('platformAccountProperties', {})
    old_sid = props.get('TencentSecretId')
    if not old_sid or props.get('TencentRoleProfile') != profile:
        raise LifecycleError('Account/profile binding mismatch')
    keys = cloud.keys(target)
    if any(k['description'] == 'psm-rotation:' + operation for k in keys):
        raise LifecycleError('Operation already created a key; reconcile inventory instead of retrying')
    if old_sid not in {k['id'] for k in keys}:
        raise LifecycleError('Old key is not owned by target UIN')
    if next(k['status'] for k in keys if k['id'] == old_sid) != 'Active':
        raise LifecycleError('Rotation requires an active old key; reconcile inactive credentials first')
    if len(keys) >= 2:
        raise LifecycleError('No conservative spare key slot; do not delete keys automatically')
    # No automatic retry after creation or Vault write: uncertain outcomes must be reconciled.
    new_sid, new_key = cloud.create_key(target, operation)
    try:
        cloud.verify(new_sid, new_key, target)
        payload = {'name': 'tc-rotation-' + operation, 'address': old['address'],
            'userName': old['userName'], 'platformId': old['platformId'], 'safeName': old['safeName'],
            'secretType': 'password', 'secret': new_key,
            'platformAccountProperties': {**props, 'TencentSecretId': new_sid},
            'secretManagement': {'automaticManagementEnabled': False,
                                 'manualManagementReason': 'External staged rotation; native CPM not configured'}}
        new_account = vault.create(payload)
    except Exception:
        # Preserve old key and the new cloud key. Vault save may have succeeded despite timeout.
        raise LifecycleError('Preparation incomplete; old key retained. Reconcile cloud/Vault before retrying.') from None
    finally:
        new_key = None
    return Ticket(operation, target, old_account_id, new_account, old_sid, new_sid, profile)


def finalize(cloud, vault, ticket, settings, *, confirmed_cutover=False, role_verifier=assume_role):
    if not confirmed_cutover:
        raise LifecycleError('Explicit tested PSM cutover confirmation required')
    if ticket.old_secret_id == ticket.new_secret_id or ticket.old_account == ticket.new_account:
        raise LifecycleError('Old and new credentials must differ')
    old, new = vault.account(ticket.old_account), vault.account(ticket.new_account)
    for account, sid in ((old, ticket.old_secret_id), (new, ticket.new_secret_id)):
        props = account.get('platformAccountProperties', {})
        if props.get('TencentSecretId') != sid or props.get('TencentRoleProfile') != ticket.profile:
            raise LifecycleError('Vault account binding changed')
    for field in ('safeName', 'platformId', 'userName', 'address'):
        if old[field] != new[field]:
            raise LifecycleError('Replacement account scope mismatch')
    profile = settings['profiles'].get(ticket.profile)
    if not profile or ticket.new_secret_id not in profile['allowed_secret_ids']:
        raise LifecycleError('Bridge configuration must authorize replacement key first')
    states = {k['id']: k['status'] for k in cloud.keys(ticket.target_uin)}
    if states.get(ticket.new_secret_id) != 'Active' or states.get(ticket.old_secret_id) not in ('Active', 'Inactive'):
        raise LifecycleError('Unexpected target key state')
    secret = vault.secret(ticket.new_account, 'Verify staged Tencent Cloud rotation ' + ticket.operation)
    try:
        cloud.verify(ticket.new_secret_id, secret, ticket.target_uin)
        role_verifier(ticket.new_secret_id, secret, profile['role_arn'], 'rotate-' + ticket.operation,
                      profile['duration_seconds'], profile['region'])
    finally:
        secret = None
    if states[ticket.old_secret_id] == 'Active':
        cloud.set_key_status(ticket.target_uin, ticket.old_secret_id, 'Inactive')
    return {'operation': ticket.operation, 'status': 'old-key-inactive', 'new_account': ticket.new_account}


def restore_old(cloud, target, old_sid):
    keys = {k['id'] for k in cloud.keys(target)}
    if old_sid not in keys:
        raise LifecycleError('Cannot restore a deleted key')
    cloud.set_key_status(target, old_sid, 'Active')
    return {'status': 'old-key-reactivated'}
