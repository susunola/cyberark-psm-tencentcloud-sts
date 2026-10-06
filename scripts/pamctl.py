"""Explicit PAM lifecycle operations. Secrets come from environment/stdin, never argv."""
import argparse
import json
import os
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from configuration import load_settings
from pam.cloud import Cloud
from pam.vault import Vault
from pam.lifecycle import Ticket, prepare, finalize, restore_old
from pam.planning import cvm_plan


def vault():
    return Vault(os.environ['PVWA_API_URL'], os.environ['PVWA_TOKEN'], ca=os.environ.get('PVWA_CA_BUNDLE') or True)


def cloud():
    return Cloud(os.environ['TENCENTCLOUD_SECRET_ID'], os.environ['TENCENTCLOUD_SECRET_KEY'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('capabilities')
    listing = commands.add_parser('list')
    listing.add_argument('resource', choices=('LiveSessions', 'Recordings', 'IncomingRequests', 'MyRequests'))
    listing.add_argument('--limit', type=int, default=100); listing.add_argument('--offset', type=int, default=0)
    session = commands.add_parser('session')
    session.add_argument('--id', required=True); session.add_argument('--action', required=True, choices=('suspend', 'resume', 'terminate'))
    session.add_argument('--apply', action='store_true')
    request = commands.add_parser('request')
    request.add_argument('--account', required=True); request.add_argument('--component', required=True)
    request.add_argument('--reason', required=True); request.add_argument('--apply', action='store_true')
    decision = commands.add_parser('decision')
    decision.add_argument('--id', required=True); decision.add_argument('--decision', choices=('confirm', 'reject'), required=True)
    decision.add_argument('--reason', required=True); decision.add_argument('--apply', action='store_true')
    discover = commands.add_parser('discover'); discover.add_argument('--regions', nargs='+', required=True)
    plan = commands.add_parser('cvm-plan')
    for name in ('inventory', 'usernames', 'safe', 'linux-platform', 'windows-platform'):
        plan.add_argument('--' + name, required=True)
    onboard = commands.add_parser('onboard'); onboard.add_argument('--apply', action='store_true')
    onboard.add_argument('--safe', required=True); onboard.add_argument('--platform', required=True)
    verify = commands.add_parser('verify'); verify.add_argument('--target-uin', required=True)
    prepare_cmd = commands.add_parser('prepare')
    for name in ('old-account', 'target-uin', 'profile', 'ticket'):
        prepare_cmd.add_argument('--' + name, required=True)
    prepare_cmd.add_argument('--apply', action='store_true')
    final = commands.add_parser('finalize'); final.add_argument('--ticket', required=True)
    final.add_argument('--settings', required=True); final.add_argument('--confirm-psm-cutover', action='store_true')
    final.add_argument('--apply', action='store_true')
    restore = commands.add_parser('restore-old'); restore.add_argument('--ticket', required=True)
    restore.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if args.command in ('prepare', 'finalize', 'restore-old', 'onboard', 'session', 'request', 'decision') and not args.apply:
        print(json.dumps({'status': 'no-write', 'operation': args.command, 'next': 'Review configuration, then explicitly supply --apply'}))
        return
    try:
        if args.command == 'capabilities':
            result = vault().capability_probe()
        elif args.command == 'list':
            result = vault().list_operations(args.resource, args.limit, args.offset)
        elif args.command == 'session':
            result = vault().session_action(args.id, args.action)
        elif args.command == 'request':
            result = vault().access_request(args.account, args.reason, args.component)
        elif args.command == 'decision':
            result = vault().request_decision(args.id, args.decision, args.reason)
        elif args.command == 'discover':
            result = cloud().discover(args.regions)
        elif args.command == 'cvm-plan':
            result = cvm_plan(json.loads(Path(args.inventory).read_text()), args.safe,
                args.linux_platform, args.windows_platform, json.loads(Path(args.usernames).read_text()))
        elif args.command == 'verify':
            credential = json.loads(sys.stdin.read(8193))
            result = {'verified': cloud().verify(credential['secret_id'], credential['secret_key'], args.target_uin)}
        elif args.command == 'onboard':
            payload = json.loads(sys.stdin.read(65537))
            if isinstance(payload, dict):
                # Local proposal metadata is not a PVWA account property.
                component = payload.pop('connection_component', None)
                if component not in (None, 'PSM-RDP', 'PSM-SSH'):
                    raise ValueError('Unknown proposal component')
            allowed = {'name', 'address', 'userName', 'platformId', 'safeName', 'secretType', 'secret', 'platformAccountProperties', 'secretManagement'}
            if not isinstance(payload, dict) or set(payload) - allowed or payload.get('safeName') != args.safe or payload.get('platformId') != args.platform:
                raise ValueError('Onboarding payload outside approved Safe/platform')
            if not payload.get('secret') or payload.get('secretType') != 'password':
                raise ValueError('Explicit credential required; no automatic password generation')
            result = {'account_id': vault().create(payload)}
        elif args.command == 'prepare':
            # Reserve a journal path BEFORE cloud mutation; never overwrite a previous attempt.
            path = Path(args.ticket)
            with path.open('x', encoding='utf-8') as journal:
                operation = uuid.uuid4().hex
                journal.write(json.dumps({'operation': operation, 'status': 'preparing', 'target_uin': args.target_uin}))
            try:
                ticket = prepare(cloud(), vault(), args.old_account, args.target_uin, args.profile, operation)
            except Exception:
                raise RuntimeError('Preparation incomplete. Inspect reserved journal and cloud/Vault inventory; do not retry blindly.') from None
            # Atomic same-directory replacement; the journal never contains a SecretKey.
            temporary = path.with_name(path.name + '.tmp')
            with temporary.open('x', encoding='utf-8') as stream:
                json.dump(ticket.public(), stream)
            os.replace(temporary, path)
            result = {'status': 'prepared-old-key-retained', **ticket.public()}
        else:
            ticket = Ticket(**json.loads(Path(args.ticket).read_text()))
            if args.command == 'finalize':
                result = finalize(cloud(), vault(), ticket, load_settings(args.settings), confirmed_cutover=args.confirm_psm_cutover)
            else:
                result = restore_old(cloud(), ticket.target_uin, ticket.old_secret_id)
    except Exception:
        parser.exit(2, 'Operation failed. No secrets or raw API errors are emitted. Reconcile uncertain write outcomes before retry.\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
