"""Explicit PAM lifecycle operations. Secrets come from environment/stdin, never argv."""

import argparse
import json
import os
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from configuration import load_settings
from pam.audit import summarize
from pam.cloud import Cloud
from pam.delivery import (
    append_record,
    export_records,
    onboard_batch,
    preflight,
)
from pam.files import private_output, read_json, save_json
from pam.lifecycle import (
    Ticket,
    finalize,
    prepare,
    recover_ticket,
    restore_old,
)
from pam.onboarding import validate_account
from pam.planning import cvm_plan
from pam.vault import Vault

RESOURCES = ("Accounts", "LiveSessions", "Recordings")
LIST_RESOURCES = ("Accounts", "LiveSessions", "Recordings", "IncomingRequests", "MyRequests")
SESSION_SECTIONS = ("details", "activities", "properties")
RECORDING_SECTIONS = ("details", "activities", "properties", "valid")
CPM_ACTIONS = ("Verify", "Change", "Reconcile")
SESSION_ACTIONS = ("suspend", "resume", "terminate")
DECISIONS = ("confirm", "reject")
STDIN_CREDENTIAL_LIMIT = 8192
STDIN_ACCOUNT_LIMIT = 65536

# Commands that mutate cloud, Vault or on-disk state require an explicit --apply.
WRITE_COMMANDS = (
    "prepare",
    "finalize",
    "restore-old",
    "onboard",
    "session",
    "request",
    "decision",
    "cpm",
    "connect",
    "recover-ticket",
    "playback",
    "onboard-batch",
    "cancel-request",
)

Handler = Callable[[argparse.Namespace], Any]


def vault() -> Vault:
    return Vault(
        os.environ["PVWA_API_URL"],
        os.environ["PVWA_TOKEN"],
        ca=os.environ.get("PVWA_CA_BUNDLE") or True,
    )


def cloud() -> Cloud:
    return Cloud(os.environ["TENCENTCLOUD_SECRET_ID"], os.environ["TENCENTCLOUD_SECRET_KEY"])


def run_prepare(args: argparse.Namespace) -> dict[str, Any]:
    # Reserve a journal path BEFORE cloud mutation; never overwrite a previous attempt.
    path = Path(args.ticket)
    with private_output(path) as journal:
        operation = uuid.uuid4().hex
        save_json(
            journal,
            {
                "operation": operation,
                "status": "preparing",
                "target_uin": args.target_uin,
                "old_account": args.old_account,
                "profile": args.profile,
            },
        )
    try:
        ticket = prepare(cloud(), vault(), args.old_account, args.target_uin, args.profile, operation)
    except Exception:  # noqa: BLE001 - journal stays authoritative, errors are sanitized
        raise RuntimeError(
            "Preparation incomplete. Inspect reserved journal and cloud/Vault inventory; "
            "do not retry blindly."
        ) from None
    # Atomic same-directory replacement; the journal never contains a SecretKey.
    temporary = path.with_name(path.name + ".tmp")
    with private_output(temporary) as stream:
        save_json(stream, ticket.public())
    os.replace(temporary, path)
    return {"status": "prepared-old-key-retained", **ticket.public()}


def run_finalize(args: argparse.Namespace) -> dict[str, Any]:
    return finalize(
        cloud(),
        vault(),
        Ticket(**read_json(args.ticket)),
        load_settings(args.settings),
        confirmed_cutover=args.confirm_psm_cutover,
    )


def run_restore(args: argparse.Namespace) -> dict[str, Any]:
    ticket = Ticket(**read_json(args.ticket))
    return restore_old(cloud(), ticket.target_uin, ticket.old_secret_id)


def run_audit_report(args: argparse.Namespace) -> dict[str, Any]:
    with Path(args.input).open(encoding="utf-8") as source:
        return summarize(source, args.max_lines)


def run_export(args: argparse.Namespace) -> dict[str, Any]:
    count = 0
    with private_output(args.out) as sink:
        append_record(sink, {"type": "export-started", "resource": args.resource})
        for record in export_records(vault(), args.resource, args.limit, args.max_pages):
            append_record(sink, {"type": "record", "value": record}, durable=False)
            count += 1
        append_record(sink, {"type": "export-completed", "records": count, "complete": True})
    return {
        "status": "export-completed",
        "records": count,
        "path": args.out,
        "snapshot_consistency": "not guaranteed",
    }


def run_onboard_batch(args: argparse.Namespace) -> dict[str, Any]:
    payloads = read_json(stream=sys.stdin)
    with private_output(args.journal) as sink:
        return onboard_batch(payloads, args.safe, args.platform, vault(), sink)


def run_playback(args: argparse.Namespace) -> dict[str, Any]:
    with private_output(args.out) as sink:
        save_json(sink, vault().recording(args.id, "play"))
    return {
        "status": "native-playback-response-saved",
        "path": args.out,
        "note": "Use the native player; treat playback URLs as credentials",
    }


def run_connect(args: argparse.Namespace) -> dict[str, Any]:
    # Reserve the protected sink before requesting a sensitive native launch response.
    with private_output(args.out) as sink:
        launch = vault().connect(
            args.account, args.component, args.reason, args.ticket_id, args.ticket_system
        )
        save_json(sink, launch)
    return {
        "status": "native-connection-response-saved",
        "path": args.out,
        "note": "Treat this file as a credential; use the configured native PSM client",
    }


def run_recover_ticket(args: argparse.Namespace) -> dict[str, Any]:
    with private_output(args.ticket) as sink:
        ticket = recover_ticket(cloud(), vault(), read_json(args.journal))
        save_json(sink, ticket.public())
    return {"status": "verified-ticket-recovered", **ticket.public()}


def run_verify(args: argparse.Namespace) -> dict[str, Any]:
    credential = read_json(stream=sys.stdin, limit=STDIN_CREDENTIAL_LIMIT)
    caller = Cloud(credential["secret_id"], credential["secret_key"])
    return {"verified": caller.verify(credential["secret_id"], credential["secret_key"], args.target_uin)}


def run_onboard(args: argparse.Namespace) -> dict[str, Any]:
    payload = validate_account(
        read_json(stream=sys.stdin, limit=STDIN_ACCOUNT_LIMIT), args.safe, args.platform
    )
    return {"account_id": vault().create(payload)}


def run_cvm_plan(args: argparse.Namespace) -> dict[str, Any]:
    return cvm_plan(
        read_json(args.inventory),
        args.safe,
        args.linux_platform,
        args.windows_platform,
        read_json(args.usernames),
    )


def _vault_call(method: str, *args: Any, **kwargs: Any) -> Any:
    return getattr(vault(), method)(*args, **kwargs)


HANDLERS: dict[str, Handler] = {
    "capabilities": lambda args: vault().capability_probe(),
    "preflight": lambda args: preflight(
        vault(),
        load_settings(args.settings),
        args.account,
        args.safe,
        args.platform,
        args.component,
    ),
    "audit-report": run_audit_report,
    "export": run_export,
    "onboard-batch": run_onboard_batch,
    "session-info": lambda args: _vault_call("session_details", args.id, args.section),
    "request-info": lambda args: _vault_call("request_details", args.id, args.incoming),
    "cancel-request": lambda args: _vault_call("cancel_request", args.id),
    "status": lambda args: _vault_call("account_status", args.account),
    "recording": lambda args: _vault_call("recording", args.id, args.section),
    "playback": run_playback,
    "cpm": lambda args: _vault_call("native_cpm", args.account, args.action, args.safe, args.platform),
    "connect": run_connect,
    "recover-ticket": run_recover_ticket,
    "list": lambda args: _vault_call("list_operations", args.resource, args.limit, args.offset),
    "session": lambda args: _vault_call("session_action", args.id, args.action),
    "request": lambda args: _vault_call(
        "access_request",
        args.account,
        args.reason,
        args.component,
        ticket_id=args.ticket_id,
        ticket_system=args.ticket_system,
        from_date=args.from_date,
        to_date=args.to_date,
    ),
    "decision": lambda args: _vault_call("request_decision", args.id, args.decision, args.reason),
    "discover": lambda args: cloud().discover(args.regions),
    "cvm-plan": run_cvm_plan,
    "verify": run_verify,
    "onboard": run_onboard,
    "prepare": run_prepare,
    "finalize": run_finalize,
    "restore-old": run_restore,
}


def _add_apply_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--apply", action="store_true")


def _add_read_commands(commands: Any) -> None:
    commands.add_parser("capabilities")

    readiness = commands.add_parser("preflight")
    for name in ("account", "safe", "platform", "component", "settings"):
        readiness.add_argument("--" + name, required=True)

    export = commands.add_parser("export")
    export.add_argument("resource", choices=RESOURCES)
    export.add_argument("--out", required=True)
    export.add_argument("--limit", type=int, default=100)
    export.add_argument("--max-pages", type=int, default=100)

    audit = commands.add_parser("audit-report")
    audit.add_argument("--input", required=True)
    audit.add_argument("--max-lines", type=int, default=100000)

    session_info = commands.add_parser("session-info")
    session_info.add_argument("--id", required=True)
    session_info.add_argument("--section", choices=SESSION_SECTIONS, default="details")

    request_info = commands.add_parser("request-info")
    request_info.add_argument("--id", required=True)
    request_info.add_argument("--incoming", action="store_true")

    account_status = commands.add_parser("status")
    account_status.add_argument("--account", required=True)

    recording = commands.add_parser("recording")
    recording.add_argument("--id", required=True)
    recording.add_argument("--section", choices=RECORDING_SECTIONS, default="details")

    listing = commands.add_parser("list")
    listing.add_argument("resource", choices=LIST_RESOURCES)
    listing.add_argument("--limit", type=int, default=100)
    listing.add_argument("--offset", type=int, default=0)

    discover = commands.add_parser("discover")
    discover.add_argument("--regions", nargs="+", required=True)

    plan = commands.add_parser("cvm-plan")
    for name in ("inventory", "usernames", "safe", "linux-platform", "windows-platform"):
        plan.add_argument("--" + name, required=True)

    verify = commands.add_parser("verify")
    verify.add_argument("--target-uin", required=True)


def _add_write_commands(commands: Any) -> None:
    batch = commands.add_parser("onboard-batch")
    for name in ("safe", "platform", "journal"):
        batch.add_argument("--" + name, required=True)
    _add_apply_flag(batch)

    cancel = commands.add_parser("cancel-request")
    cancel.add_argument("--id", required=True)
    _add_apply_flag(cancel)

    cpm = commands.add_parser("cpm")
    cpm.add_argument("--account", required=True)
    cpm.add_argument("--action", choices=CPM_ACTIONS, required=True)
    cpm.add_argument("--safe", required=True)
    cpm.add_argument("--platform", required=True)
    _add_apply_flag(cpm)

    connect = commands.add_parser("connect")
    connect.add_argument("--account", required=True)
    connect.add_argument("--component", required=True)
    connect.add_argument("--reason", required=True)
    connect.add_argument("--out", required=True)
    connect.add_argument("--ticket-id")
    connect.add_argument("--ticket-system")
    _add_apply_flag(connect)

    recover = commands.add_parser("recover-ticket")
    recover.add_argument("--journal", required=True)
    recover.add_argument("--ticket", required=True)
    _add_apply_flag(recover)

    playback = commands.add_parser("playback")
    playback.add_argument("--id", required=True)
    playback.add_argument("--out", required=True)
    _add_apply_flag(playback)

    session = commands.add_parser("session")
    session.add_argument("--id", required=True)
    session.add_argument("--action", required=True, choices=SESSION_ACTIONS)
    _add_apply_flag(session)

    request = commands.add_parser("request")
    request.add_argument("--account", required=True)
    request.add_argument("--component", required=True)
    request.add_argument("--reason", required=True)
    request.add_argument("--ticket-id")
    request.add_argument("--ticket-system")
    request.add_argument("--from-date", type=int, help="Unix seconds UTC")
    request.add_argument("--to-date", type=int, help="Unix seconds UTC")
    _add_apply_flag(request)

    decision = commands.add_parser("decision")
    decision.add_argument("--id", required=True)
    decision.add_argument("--decision", choices=DECISIONS, required=True)
    decision.add_argument("--reason", required=True)
    _add_apply_flag(decision)


def _add_lifecycle_commands(commands: Any) -> None:
    onboard = commands.add_parser("onboard")
    onboard.add_argument("--safe", required=True)
    onboard.add_argument("--platform", required=True)
    _add_apply_flag(onboard)

    prepare_command = commands.add_parser("prepare")
    for name in ("old-account", "target-uin", "profile", "ticket"):
        prepare_command.add_argument("--" + name, required=True)
    _add_apply_flag(prepare_command)

    final = commands.add_parser("finalize")
    final.add_argument("--ticket", required=True)
    final.add_argument("--settings", required=True)
    final.add_argument("--confirm-psm-cutover", action="store_true")
    _add_apply_flag(final)

    restore = commands.add_parser("restore-old")
    restore.add_argument("--ticket", required=True)
    _add_apply_flag(restore)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    _add_read_commands(commands)
    _add_write_commands(commands)
    _add_lifecycle_commands(commands)
    return parser


def _refuse_unconfirmed_write(command: str) -> bool:
    print(
        json.dumps(
            {
                "status": "no-write",
                "operation": command,
                "next": "Review configuration, then explicitly supply --apply",
            }
        )
    )
    return True


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command in WRITE_COMMANDS and not args.apply:
        _refuse_unconfirmed_write(args.command)
        return
    try:
        result = HANDLERS[args.command](args)
    except Exception:  # noqa: BLE001 - never emit secrets, URLs or raw API errors
        parser.exit(
            2,
            "Operation failed. No secrets or raw API errors are emitted. Reconcile uncertain "
            "write outcomes before retry.\n",
        )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.command == "preflight" and not result["scope_binding_ready"]:
        parser.exit(
            3,
            "Preflight account scope or caller binding failed. Native acceptance remains required.\n",
        )


if __name__ == "__main__":
    main()
