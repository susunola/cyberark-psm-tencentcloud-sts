"""Scheduler-neutral, scoped one-shot maintenance; never auto-finalize a rotation."""

import copy
import os
import re
import uuid
from pathlib import Path
from typing import Any

from federation import assume_role
from pam.cloud import uin
from pam.files import private_output, save_json
from pam.lifecycle import prepare

JOB_FIELDS = {"id", "action", "account", "target_uin", "profile", "safe", "platform"}
JOB_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,80}")
RESERVED_NAME_PATTERN = re.compile(r"(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])")
ACCOUNT_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,128}")
PROFILE_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,80}")
MAX_SCOPE_LENGTH = 1024
MIN_JOBS = 1
MAX_JOBS = 100
ALLOWED_ACTIONS = ("verify-cam", "prepare-key")
LOCK_NAME = ".maintenance.lock"


def validate_jobs(configuration: Any) -> list[dict[str, str]]:
    if not isinstance(configuration, dict) or set(configuration) != {"jobs"}:
        raise ValueError("Expected maintenance jobs only")
    jobs = copy.deepcopy(configuration["jobs"])
    if not isinstance(jobs, list) or not MIN_JOBS <= len(jobs) <= MAX_JOBS:
        raise ValueError("Configure 1..100 jobs")
    identifiers: set[str] = set()
    targets: set[str] = set()
    for job in jobs:
        if not isinstance(job, dict) or set(job) != JOB_FIELDS:
            raise ValueError("Invalid maintenance job fields")
        if not all(isinstance(value, str) and value for value in job.values()):
            raise ValueError("Maintenance fields must be nonempty strings")
        if (
            not re.fullmatch(JOB_ID_PATTERN, job["id"])
            or job["id"].casefold() in identifiers
            or re.fullmatch(RESERVED_NAME_PATTERN, job["id"])
        ):
            raise ValueError("Use distinct safe job IDs")
        job["target_uin"] = str(uin(job["target_uin"]))
        if not re.fullmatch(ACCOUNT_PATTERN, job["account"]) or not re.fullmatch(
            PROFILE_PATTERN, job["profile"]
        ):
            raise ValueError("Invalid maintenance account/profile")
        if any(
            len(job[k]) > MAX_SCOPE_LENGTH or not job[k].strip() or any(ord(c) < 32 for c in job[k])
            for k in ("safe", "platform")
        ):
            raise ValueError("Invalid maintenance scope")
        if job["action"] not in ALLOWED_ACTIONS:
            raise ValueError("Maintenance cannot finalize, delete, approve or reset credentials")
        if job["action"] == "prepare-key" and job["target_uin"] in targets:
            raise ValueError("One preparation per target UIN per run")
        if job["action"] == "prepare-key":
            targets.add(job["target_uin"])
        identifiers.add(job["id"].casefold())
    return jobs


def run(
    configuration: Any,
    settings: dict[str, Any],
    state_dir: str | Path,
    cloud: Any,
    vault: Any,
    role_verifier: Any = assume_role,
) -> list[dict[str, str]]:
    jobs = validate_jobs(configuration)
    state = Path(state_dir)
    if not state.is_dir():
        raise ValueError("Pre-create a protected maintenance state directory")
    lock_path = state / LOCK_NAME
    # Fail if another runner or a crash journal exists; do not steal potentially active locks.
    with private_output(lock_path) as lock:
        save_json(lock, {"pid": os.getpid()})
    try:
        results: list[dict[str, str]] = []
        for job in jobs:
            old = vault.account(job["account"])
            props = old.get("platformAccountProperties", {})
            sid = props.get("TencentSecretId")
            profile = settings["profiles"].get(job["profile"])
            if (
                old.get("safeName") != job["safe"]
                or old.get("platformId") != job["platform"]
                or props.get("TencentRoleProfile") != job["profile"]
            ):
                raise ValueError("Maintenance account outside approved scope")
            if not profile or not sid or sid not in profile["allowed_secret_ids"]:
                raise ValueError("Maintenance caller not authorized in bridge profile")
            if job["action"] == "verify-cam":
                secret = vault.secret(
                    job["account"], "Scheduled Tencent credential verification " + job["id"]
                )
                try:
                    cloud.verify(sid, secret, job["target_uin"])
                    role_verifier(
                        sid,
                        secret,
                        profile["role_arn"],
                        "verify-" + uuid.uuid4().hex,
                        profile["duration_seconds"],
                        profile["region"],
                    )
                finally:
                    secret = None
                results.append({"job": job["id"], "status": "identity-and-role-verified"})
            else:
                ticket_path = state / (job["id"] + ".json")
                operation = uuid.uuid4().hex
                with private_output(ticket_path) as journal:
                    save_json(
                        journal,
                        {
                            "operation": operation,
                            "status": "preparing",
                            "target_uin": job["target_uin"],
                            "old_account": job["account"],
                            "profile": job["profile"],
                        },
                    )
                ticket = prepare(cloud, vault, job["account"], job["target_uin"], job["profile"], operation)
                temporary = state / (job["id"] + ".json.tmp")
                with private_output(temporary) as sink:
                    save_json(sink, ticket.public())
                os.replace(temporary, ticket_path)
                results.append(
                    {
                        "job": job["id"],
                        "status": "prepared-awaiting-tested-cutover",
                        "ticket": str(ticket_path),
                    }
                )
        return results
    finally:
        lock_path.unlink()
