"""Explicit PAM lifecycle operations. Secrets come from environment/stdin, never argv."""
import argparse
import json
import os
import socket
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from configuration import load_settings
from pam.audit import summarize
from pam.cloud import DEFAULT_MAX_CAM_USERS, Cloud
from pam.delivery import append_record, export_records, onboard_batch, preflight
from pam.files import private_output, read_json, save_json
from pam.lifecycle import LifecycleError, Ticket, finalize, prepare, recover_ticket, restore_old
from pam.onboarding import validate_account
from pam.planning import cvm_plan
from pam.vault import Vault
from validate import MAX_CREDENTIAL_JSON_BYTES, MAX_ONBOARD_JSON_BYTES


def vault() -> Vault:
    return Vault(os.environ['PVWA_API_URL'], os.environ['PVWA_TOKEN'], ca=os.environ.get('PVWA_CA_BUNDLE') or True)


def cloud() -> Cloud:
    # CAM's ListUsers cannot be paginated, so the bound is explicit and overridable
    # rather than a hidden hard limit in a large organisation.
    max_users = os.environ.get('PSM_TC_MAX_CAM_USERS') or str(DEFAULT_MAX_CAM_USERS)
    return Cloud(
        os.environ['TENCENTCLOUD_SECRET_ID'],
        os.environ['TENCENTCLOUD_SECRET_KEY'],
        max_users=int(max_users),
        site=os.environ.get('PSM_TC_SITE') or 'intl',
    )


PREPARE_LOCK_MAX_AGE_SECONDS = 3 * 60 * 60


def target_lock(target_uin: object) -> Path:
    """Serialise preparations per target UIN across tickets on a shared lock root.

    The spare-slot check in prepare is check-then-act, so two preparations that read
    the inventory before either creates a key leave three keys behind and a cutover
    that cannot be trusted. The lock name is the UIN (not the ticket path) so two
    operators using different --ticket locations still collide. Point
    PSM_TC_PREPARE_LOCK_DIR at a shared filesystem when several machines or
    accounts run prepare; default is per-user home. PID checks only apply when
    the lock was taken on this host.
    """
    from pam.cloud import uin as parse_uin

    resolved = str(parse_uin(target_uin))
    root = Path(os.environ.get('PSM_TC_PREPARE_LOCK_DIR') or (Path.home() / '.psm-tencent' / 'prepare-locks'))
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root / f'{resolved}.lock'


def _pid_alive(pid: object) -> bool:
    """True when *pid* is a live process **on this machine**.

    Windows: os.kill(pid, 0) is TerminateProcess — it ends the target instead of
    probing it (CPython posixmodule.c). Use OpenProcess/GetExitCodeProcess.
    Permission errors mean the process exists but is not ours to signal.
    """
    if type(pid) is not int or pid <= 0:
        return False
    if os.name == 'nt':
        return _windows_pid_alive(pid)
    try:
        os.kill(pid, 0)
    except PermissionError:
        return True
    except (OSError, ValueError):
        return False
    return True


def _windows_pid_alive(pid: int) -> bool:
    import ctypes
    from typing import Any

    process_query_limited_information = 0x1000
    still_active = 259
    windll = getattr(ctypes, 'windll', None)
    if windll is None:
        return False
    kernel32: Any = windll.kernel32
    handle = kernel32.OpenProcess(process_query_limited_information, 0, pid)
    if not handle:
        # ERROR_ACCESS_DENIED (5): the process exists but belongs to another user.
        return bool(ctypes.get_last_error() == 5)
    try:
        code = ctypes.c_ulong()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


def prepare_lock_stale(path: Path) -> str:
    """Return a reason the lock looks abandoned, or '' when it may still be live.

    PID liveness is only meaningful on the host that took the lock. A shared
    lock directory across machines must expire by age alone.
    """
    try:
        meta = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return 'lock metadata unreadable'
    if not isinstance(meta, dict):
        return 'lock metadata unreadable'
    acquired_at = meta.get('acquired_at_epoch')
    if type(acquired_at) is not int or acquired_at <= 0:
        return 'lock metadata has no acquisition time'
    age = time.time() - acquired_at
    if age > PREPARE_LOCK_MAX_AGE_SECONDS:
        return f'lock is older than {PREPARE_LOCK_MAX_AGE_SECONDS} seconds'
    holder_host = meta.get('host')
    if holder_host and holder_host != socket.gethostname():
        # Foreign host: this process table cannot prove the holder is gone.
        return ''
    pid = meta.get('pid')
    if not _pid_alive(pid):
        return f'holder process {pid} is not running'
    return ''


def acquire_prepare_lock(path: Path) -> None:
    """Create the lock exclusively and record who holds it for later diagnosis."""
    with private_output(path) as sink:
        save_json(sink, {
            'pid': os.getpid(),
            'acquired_at_epoch': int(time.time()),
            'host': socket.gethostname(),
            'note': 'pamctl prepare; stale locks: unlock-prepare --apply; live holders: --force --apply',
        })


def build_parser() -> argparse.ArgumentParser:
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
    unlock_cmd = commands.add_parser('unlock-prepare')
    unlock_cmd.add_argument('--target-uin', required=True)
    unlock_cmd.add_argument('--force', action='store_true')
    unlock_cmd.add_argument('--apply', action='store_true')
    for name in ('old-account', 'target-uin', 'profile', 'ticket'):
        prepare_cmd.add_argument('--' + name, required=True)
    prepare_cmd.add_argument('--apply', action='store_true')
    final = commands.add_parser('finalize'); final.add_argument('--ticket', required=True)
    final.add_argument('--settings', required=True); final.add_argument('--confirm-psm-cutover', action='store_true')
    final.add_argument('--apply', action='store_true')
    restore = commands.add_parser('restore-old')
    restore.add_argument('--ticket', required=True)
    restore.add_argument('--settings', required=True)
    restore.add_argument('--apply', action='store_true')
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command in ('prepare', 'finalize', 'restore-old', 'onboard', 'session', 'request', 'decision', 'cpm', 'connect', 'recover-ticket', 'playback', 'onboard-batch', 'cancel-request', 'unlock-prepare') and not args.apply:
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
            credential = read_json(stream=sys.stdin, limit=MAX_CREDENTIAL_JSON_BYTES)
            caller = Cloud(credential['secret_id'], credential['secret_key'])
            result = {'verified': caller.verify(credential['secret_id'], credential['secret_key'], args.target_uin)}
        elif args.command == 'onboard':
            payload = validate_account(read_json(stream=sys.stdin, limit=MAX_ONBOARD_JSON_BYTES), args.safe, args.platform)
            result = {'account_id': vault().create(payload)}
        elif args.command == 'unlock-prepare':
            lock = target_lock(args.target_uin)
            if not lock.exists():
                result = {'status': 'no-lock', 'path': str(lock)}
            else:
                reason = prepare_lock_stale(lock)
                if reason or args.force:
                    lock.unlink(missing_ok=True)
                    result = {'status': 'unlocked', 'path': str(lock), 'reason': reason or 'forced by operator'}
                else:
                    parser.exit(
                        2,
                        f'{lock.name} still looks live ({reason or "holder process running"}); '
                        'use --force only when the holder is known dead.\n',
                    )
        elif args.command == 'prepare':
            # Reserve a journal path BEFORE cloud mutation; never overwrite a previous attempt.
            path = Path(args.ticket)
            lock = target_lock(args.target_uin)
            try:
                acquire_prepare_lock(lock)
            except FileExistsError:
                reason = prepare_lock_stale(lock)
                hint = (
                    f' Lock looks abandoned ({reason}); run unlock-prepare --target-uin {args.target_uin} --apply.'
                    if reason else ''
                )
                # parser.exit raises SystemExit, so this survives the sanitizing handler
                # below; an operator needs to know this is contention, not a cloud fault.
                parser.exit(
                    2,
                    f'Another preparation holds {lock.name}. Preparations for one target must be '
                    f'serialised: reconcile the existing run before retrying.{hint}\n',
                )
            try:
                with private_output(path) as journal:
                    operation = uuid.uuid4().hex
                    save_json(journal, {'operation': operation, 'status': 'preparing', 'target_uin': args.target_uin,
                                       'old_account': args.old_account, 'profile': args.profile})
                try:
                    ticket = prepare(cloud(), vault(), args.old_account, args.target_uin, args.profile, operation)
                except Exception:  # noqa: BLE001 - never forward error text
                    raise RuntimeError('Preparation incomplete. Inspect reserved journal and cloud/Vault inventory; do not retry blindly.') from None
                # Atomic same-directory replacement; the journal never contains a SecretKey.
                temporary = path.with_name(path.name + '.tmp')
                with private_output(temporary) as stream:
                    save_json(stream, ticket.public())
                Path(temporary).replace(path)
            finally:
                lock.unlink(missing_ok=True)
            result = {'status': 'prepared-old-key-retained', **ticket.public()}
        else:
            ticket = Ticket(**read_json(args.ticket))
            if args.command == 'finalize':
                result = finalize(cloud(), vault(), ticket, load_settings(args.settings), confirmed_cutover=args.confirm_psm_cutover)
            else:
                result = restore_old(cloud(), vault(), ticket, load_settings(args.settings))
    except (RuntimeError, LifecycleError) as error:
        # These messages are written for operators and already avoid secrets.
        parser.exit(2, f'{error}\n')
    except Exception:  # noqa: BLE001 - never forward error text
        parser.exit(2, 'Operation failed. No secrets or raw API errors are emitted. Reconcile uncertain write outcomes before retry.\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.command == 'preflight' and not result['scope_binding_ready']:
        parser.exit(3, 'Preflight account scope or caller binding failed. Native acceptance remains required.\n')


if __name__ == '__main__':
    main()
