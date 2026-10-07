"""Verify that the test suite actually enforces the security-critical guards.

Coverage says a line ran; it does not say a test would notice if the line
disappeared. This script disables one guard at a time and requires the suite to
fail. A guard whose removal nothing notices is a guard nothing protects - the
common way a security control is lost during a refactor.

Usage:

    python scripts/check_guard_mutations.py            # all guards
    python scripts/check_guard_mutations.py --list     # show the table only

Safety: each target file must match git HEAD before and after, so a run can never
hide or overwrite uncommitted work. Files are restored from memory in a `finally`
block even when a run is interrupted.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = "tests"
SUITE_TIMEOUT_SECONDS = 900
EXIT_SURVIVED = 1
EXIT_UNSAFE = 2

# (description, file, exact source to replace, replacement that disables the guard)
MUTATIONS: tuple[tuple[str, str, str, str], ...] = (
    (
        "lifecycle: the target must hold exactly the rotation pair",
        "pam/lifecycle.py",
        "    if set(states) != {ticket.old_secret_id, ticket.new_secret_id}:",
        "    if False:",
    ),
    (
        "lifecycle: an explicit tested cutover confirmation is required",
        "pam/lifecycle.py",
        "    if not confirmed_cutover:",
        "    if False:",
    ),
    (
        "lifecycle: target key state is checked before verification",
        "pam/lifecycle.py",
        "    if states[ticket.new_secret_id] != 'Active' or states[ticket.old_secret_id] not in KEY_STATUSES:",
        "    if False:",
    ),
    (
        "lifecycle: the bridge must authorize the replacement key",
        "pam/lifecycle.py",
        "    if not profile or ticket.new_secret_id not in profile['allowed_secret_ids']:",
        "    if False:",
    ),
    (
        "lifecycle: the bridge must authorize the key being restored",
        "pam/lifecycle.py",
        "    if not profile or ticket.old_secret_id not in profile['allowed_secret_ids']:",
        "    if False:",
    ),
    (
        "vault: an empty query or fragment in the base URL is rejected",
        "pam/vault.py",
        "            or '?' in api_url",
        "            or False",
    ),
    (
        "vault: dot segments cannot escape the API prefix",
        "pam/vault.py",
        "            or _has_dot_segment(path)",
        "            or False",
    ),
    (
        "vault: a non-string account id is refused",
        "pam/vault.py",
        "        if not isinstance(account_id, str) or not re.fullmatch",
        "        if not re.fullmatch",
    ),
    (
        "cloud: a repeated CAM key record is refused",
        "pam/cloud.py",
        "                or identifier in seen\n",
        "                or False\n",
    ),
    (
        "cloud: vendor text cannot carry control characters",
        "pam/cloud.py",
        "    if len(value) > MAX_VENDOR_TEXT or any(ord(c) < 32 or ord(c) == 127 for c in value):",
        "    if len(value) > MAX_VENDOR_TEXT:",
    ),
    (
        "security: one identity cannot exhaust the shared token pool",
        "security.py",
        "        while len(mine) >= self.identity_capacity:",
        "        while False:",
    ),
    (
        "bridge: a comma-joined identity is refused",
        "app.py",
        "        if identity != identity.strip() or ',' in identity:",
        "        if False:",
    ),
    (
        "bridge: the admission slot count is bounded",
        "app.py",
        "    if type(issuance_slots) is not int or not 1 <= issuance_slots <= MAX_ISSUANCE_SLOTS:",
        "    if False:",
    ),
    (
        "security: the per-identity token bound is validated",
        "security.py",
        "    return 1 <= identity_capacity <= capacity",
        "    return True",
    ),
    (
        "cloud: the CAM sub-user bound is enforced",
        "pam/cloud.py",
        "        if not isinstance(users, list) or len(users) > self.max_users:",
        "        if not isinstance(users, list):",
    ),
    (
        "bridge: a refusal records its reason for triage",
        "app.py",
        "        if response.status_code >= 400:",
        "        if False:",
    ),
    (
        "files: a private output is created owner-only",
        "pam/files.py",
        "    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)",
        "    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)",
    ),
    (
        "lifecycle: prepare re-checks the binding instead of trusting the validator",
        "pam/lifecycle.py",
        "    if not old_sid or props.get('TencentRoleProfile') != profile:",
        "    if False:",
    ),
)


def tracked_and_clean(path: Path) -> bool:
    """True when the file is committed and has no uncommitted modification."""
    relative = path.relative_to(ROOT).as_posix()
    inside = subprocess.run(
        ["git", "ls-files", "--error-unmatch", relative],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if inside.returncode != 0:
        return False
    dirty = subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--", relative],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return dirty.returncode == 0


def run_suite() -> tuple[bool, str]:
    run = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", TESTS],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=SUITE_TIMEOUT_SECONDS,
        check=False,
    )
    summary = [line for line in run.stderr.splitlines() if line.startswith(("FAILED", "OK", "Ran "))]
    return run.returncode == 0, summary[-1] if summary else ""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print the mutation table and exit")
    args = parser.parse_args()

    if args.list:
        for description, path, _, _ in MUTATIONS:
            print(f"{path:20} {description}")
        return

    paths = sorted({path for _, path, _, _ in MUTATIONS})
    unsafe = [path for path in paths if not tracked_and_clean(ROOT / path)]
    if unsafe:
        print(
            "Refusing to run: these files differ from HEAD, so a run would hide or overwrite "
            "uncommitted work:\n  " + "\n  ".join(unsafe),
            file=sys.stderr,
        )
        raise SystemExit(EXIT_UNSAFE)

    originals = {path: (ROOT / path).read_text(encoding="utf-8") for path in paths}
    baseline_ok, baseline_summary = run_suite()
    if not baseline_ok:
        print(f"The suite fails before any mutation ({baseline_summary}); fix that first.", file=sys.stderr)
        raise SystemExit(EXIT_UNSAFE)

    survived: list[str] = []
    missing: list[str] = []
    try:
        for description, path, old, new in MUTATIONS:
            source = originals[path]
            if old not in source:
                missing.append(f"{description} ({path})")
                print(f"{'pattern not found':24} {description}")
                continue
            (ROOT / path).write_text(source.replace(old, new, 1), encoding="utf-8")
            try:
                passed, _summary = run_suite()
            finally:
                (ROOT / path).write_text(source, encoding="utf-8")
            if passed:
                survived.append(f"{description} ({path})")
                print(f"{'SURVIVED':24} {description}")
            else:
                print(f"{'caught':24} {description}")
    finally:
        for path, source in originals.items():
            (ROOT / path).write_text(source, encoding="utf-8")

    for path, source in originals.items():
        if (ROOT / path).read_text(encoding="utf-8") != source:
            print(f"Failed to restore {path}; restore it from git before continuing.", file=sys.stderr)
            raise SystemExit(EXIT_UNSAFE)

    caught = len(MUTATIONS) - len(survived) - len(missing)
    print(f"\nEnforced guards: {caught}/{len(MUTATIONS)}")
    if missing:
        print("Patterns that no longer match (update this table):", file=sys.stderr)
        for entry in missing:
            print(f"  {entry}", file=sys.stderr)
        raise SystemExit(EXIT_UNSAFE)
    if survived:
        print("Guards no test enforces:", file=sys.stderr)
        for entry in survived:
            print(f"  {entry}", file=sys.stderr)
        raise SystemExit(EXIT_SURVIVED)


if __name__ == "__main__":
    main()
