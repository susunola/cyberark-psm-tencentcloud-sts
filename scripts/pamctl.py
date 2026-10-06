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
from pam.lifecycle import Ticket, prepare, finalize, restore_old, recover_ticket
from pam.planning import cvm_plan
from pam.files import read_json, private_output, save_json
from pam.onboarding import validate_account
from pam.delivery import export_records, append_record, onboard_batch, preflight
from pam.audit import summarize


def vault():
    return Vault(os.environ['PVWA_API_URL'], os.environ['PVWA_TOKEN'], ca=os.environ.get('PVWA_CA_BUNDLE') or True)


def cloud():
    return Cloud(os.environ['TENCENTCLOUD_SECRET_ID'], os.environ['TENCENTCLOUD_SECRET_KEY'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('capabilities')
    readiness = commands.add_parser('preflight')
    for name in ('account','safe','platform','component','settings'):
        readiness.add_argument('--'+name, required=True)
    export = commands.add_parser('export')
    export.add_argument('resource', choices=('Accounts','LiveSessions','Recordings'))
    export.add_argument('--out', required=True); export.add_argument('--limit', type=int, default=100); export.add_argument('--max-pages', type=int, default=100)
    audit = commands.add_parser('audit-report'); audit.add_argument('--input', required=True); audit.add_argument('--max-lines', type=int, default=100000)
    batch = commands.add_parser('onboard-batch')
    for name in ('safe','platform','journal'):
        batch.add_argument('--'+name, required=True)
    batch.add_argument('--apply', action='store_true')
    session_info = commands.add_parser('session-info')
    session_info.add_argument('--id', required=True); session_info.add_argument('--section', choices=('details','activities','properties'), default='details')
    request_info = commands.add_parser('request-info'); request_info.add_argument('--id', required=True); request_info.add_argument('--incoming', action='store_true')
    cancel = commands.add_parser('cancel-request'); cancel.add_argument('--id', required=True); cancel.add_argument('--apply', action='store_true')
    account_status = commands.add_parser('status'); account_status.add_argument('--account', required=True)
    cpm = commands.add_parser('cpm')
    cpm.add_argument('--account', required=True); cpm.add_argument('--action', choices=('Verify', 'Change', 'Reconcile'), required=True)
    cpm.add_argument('--safe', required=True); cpm.add_argument('--platform', required=True); cpm.add_argument('--apply', action='store_true')
    connect = commands.add_parser('connect')
    connect.add_argument('--account', required=True); connect.add_argument('--component', required=True)
    connect.add_argument('--reason', required=True); connect.add_argument('--out', required=True)
    connect.add_argument('--ticket-id'); connect.add_argument('--ticket-system'); connect.add_argument('--apply', action='store_true')
    recover = commands.add_parser('recover-ticket')
    recover.add_argument('--journal', required=True); recover.add_argument('--ticket', required=True); recover.add_argument('--apply', action='store_true')
    recording = commands.add_parser('recording')
    recording.add_argument('--id', required=True); recording.add_argument('--section', choices=('details','activities','properties','valid'), default='details')
    playback = commands.add_parser('playback')
    playback.add_argument('--id', required=True); playback.add_argument('--out', required=True); playback.add_argument('--apply', action='store_true')
    listing = commands.add_parser('list')
    listing.add_argument('resource', choices=('Accounts', 'LiveSessions', 'Recordings', 'IncomingRequests', 'MyRequests'))
    listing.add_argument('--limit', type=int, default=100); listing.add_argument('--offset', type=int, default=0)
    session = commands.add_parser('session')
    session.add_argument('--id', required=True); session.add_argument('--action', required=True, choices=('suspend', 'resume', 'terminate'))
    session.add_argument('--apply', action='store_true')
    request = commands.add_parser('request')
    request.add_argument('--account', required=True); request.add_argument('--component', required=True)
    request.add_argument('--reason', required=True); request.add_argument('--apply', action='store_true')
    request.add_argument('--ticket-id'); request.add_argument('--ticket-system')
    request.add_argument('--from-date', type=int, help='Unix seconds UTC'); request.add_argument('--to-date', type=int, help='Unix seconds UTC')
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
    if args.command in ('prepare', 'finalize', 'restore-old', 'onboard', 'session', 'request', 'decision', 'cpm', 'connect', 'recover-ticket', 'playback', 'onboard-batch', 'cancel-request') and not args.apply:
        print(json.dumps({'status': 'no-write', 'operation': args.command, 'next': 'Review configuration, then explicitly supply --apply'}))
        return
    try:
        if args.command == 'capabilities':
            result = vault().capability_probe()
        elif args.command == 'preflight':
            result = preflight(vault(), load_settings(args.settings), args.account, args.safe, args.platform, args.component)
        elif args.command == 'audit-report':
            with Path(args.input).open(encoding='utf-8') as source:
                result = summarize(source, args.max_lines)
        elif args.command == 'export':
            count = 0
            with private_output(args.out) as sink:
                append_record(sink, {'type':'export-started','resource':args.resource})
                for record in export_records(vault(), args.resource, args.limit, args.max_pages):
                    append_record(sink, {'type':'record','value':record}, durable=False); count += 1
                append_record(sink, {'type':'export-completed','records':count,'complete':True})
            result = {'status':'export-completed','records':count,'path':args.out,'snapshot_consistency':'not guaranteed'}
        elif args.command == 'onboard-batch':
            payloads = read_json(stream=sys.stdin)
            with private_output(args.journal) as sink:
                result = onboard_batch(payloads, args.safe, args.platform, vault(), sink)
        elif args.command == 'session-info':
            result = vault().session_details(args.id, args.section)
        elif args.command == 'request-info':
            result = vault().request_details(args.id, args.incoming)
        elif args.command == 'cancel-request':
            result = vault().cancel_request(args.id)
        elif args.command == 'status':
            result = vault().account_status(args.account)
        elif args.command == 'recording':
            result = vault().recording(args.id, args.section)
        elif args.command == 'playback':
            with private_output(args.out) as sink:
                save_json(sink, vault().recording(args.id, 'play'))
            result = {'status':'native-playback-response-saved', 'path':args.out,
                      'note':'Use the native player; treat playback URLs as credentials'}
        elif args.command == 'cpm':
            result = vault().native_cpm(args.account, args.action, args.safe, args.platform)
        elif args.command == 'connect':
            # Reserve the protected sink before requesting a sensitive native launch response.
            with private_output(args.out) as sink:
                launch = vault().connect(args.account, args.component, args.reason, args.ticket_id, args.ticket_system)
                save_json(sink, launch)
            result = {'status': 'native-connection-response-saved', 'path': args.out,
                      'note': 'Treat this file as a credential; use the configured native PSM client'}
        elif args.command == 'recover-ticket':
            with private_output(args.ticket) as sink:
                ticket = recover_ticket(cloud(), vault(), read_json(args.journal))
                save_json(sink, ticket.public())
            result = {'status': 'verified-ticket-recovered', **ticket.public()}
        elif args.command == 'list':
            result = vault().list_operations(args.resource, args.limit, args.offset)
        elif args.command == 'session':
            result = vault().session_action(args.id, args.action)
        elif args.command == 'request':
            result = vault().access_request(args.account, args.reason, args.component, ticket_id=args.ticket_id,
                                           ticket_system=args.ticket_system, from_date=args.from_date, to_date=args.to_date)
        elif args.command == 'decision':
            result = vault().request_decision(args.id, args.decision, args.reason)
        elif args.command == 'discover':
            result = cloud().discover(args.regions)
        elif args.command == 'cvm-plan':
            result = cvm_plan(read_json(args.inventory), args.safe,
                args.linux_platform, args.windows_platform, read_json(args.usernames))
        elif args.command == 'verify':
            credential = read_json(stream=sys.stdin, limit=8192)
            caller = Cloud(credential['secret_id'], credential['secret_key'])
            result = {'verified': caller.verify(credential['secret_id'], credential['secret_key'], args.target_uin)}
        elif args.command == 'onboard':
            payload = validate_account(read_json(stream=sys.stdin, limit=65536), args.safe, args.platform)
            result = {'account_id': vault().create(payload)}
        elif args.command == 'prepare':
            # Reserve a journal path BEFORE cloud mutation; never overwrite a previous attempt.
            path = Path(args.ticket)
            with private_output(path) as journal:
                operation = uuid.uuid4().hex
                save_json(journal, {'operation': operation, 'status': 'preparing', 'target_uin': args.target_uin,
                                   'old_account': args.old_account, 'profile': args.profile})
            try:
                ticket = prepare(cloud(), vault(), args.old_account, args.target_uin, args.profile, operation)
            except Exception:
                raise RuntimeError('Preparation incomplete. Inspect reserved journal and cloud/Vault inventory; do not retry blindly.') from None
            # Atomic same-directory replacement; the journal never contains a SecretKey.
            temporary = path.with_name(path.name + '.tmp')
            with private_output(temporary) as stream:
                save_json(stream, ticket.public())
            os.replace(temporary, path)
            result = {'status': 'prepared-old-key-retained', **ticket.public()}
        else:
            ticket = Ticket(**read_json(args.ticket))
            if args.command == 'finalize':
                result = finalize(cloud(), vault(), ticket, load_settings(args.settings), confirmed_cutover=args.confirm_psm_cutover)
            else:
                result = restore_old(cloud(), ticket.target_uin, ticket.old_secret_id)
    except Exception:
        parser.exit(2, 'Operation failed. No secrets or raw API errors are emitted. Reconcile uncertain write outcomes before retry.\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.command == 'preflight' and not result['scope_binding_ready']:
        parser.exit(3, 'Preflight account scope or caller binding failed. Native acceptance remains required.\n')


if __name__ == '__main__':
    main()
