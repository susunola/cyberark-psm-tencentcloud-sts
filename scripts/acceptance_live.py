"""Live acceptance checks against real Tencent Cloud STS. Read-only.

Two risks cannot be settled offline:

1. whether the international endpoint accepts the bridge's signing inputs, and
2. whether a 300-second AssumeRole duration is accepted at all - the bridge's
   configuration floor is 31..300 because federation requires credentials that
   expire no sooner than 30 seconds, but nothing local can prove the API agrees.

This script calls only ``GetCallerIdentity`` and ``AssumeRole``. It prints nothing
that could serve as a credential: no AK/SK, no temporary credentials, and never the
generated login URL. SDK failures are reduced to their error code, because vendor
messages can echo request parameters.

Usage:

    set -a; source ~/wbenv; set +a
    python scripts/acceptance_live.py --role-arn qcs::cam::uin/<uin>:roleName/<name>

    # or point at a credentials file; its contents are never printed
    python scripts/acceptance_live.py --credentials-file ~/wbenv --role-arn ...

Exit codes: 0 all checks passed, 2 a check failed, 3 credentials or arguments
were unusable.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from federation import login_url  # noqa: E402 - the project root is added above

SECRET_ID_NAMES = (
    'TENCENTCLOUD_SECRET_ID',
    'TENCENTCLOUD_SECRETID',
    'TENCENT_SECRET_ID',
    'SECRET_ID',
    'SECRETID',
)
SECRET_KEY_NAMES = (
    'TENCENTCLOUD_SECRET_KEY',
    'TENCENTCLOUD_SECRETKEY',
    'TENCENT_SECRET_KEY',
    'SECRET_KEY',
    'SECRETKEY',
)
DURATION_CANDIDATES = (300, 900, 7200)
STS_ENDPOINT = 'sts.intl.tencentcloudapi.com'
REQUEST_TIMEOUT_SECONDS = 15
EXIT_FAILED = 2
EXIT_UNUSABLE = 3


def parse_credentials_file(path: Path) -> dict[str, str]:
    """Read KEY=VALUE lines or a JSON object. Only the names are ever reported."""
    raw = path.read_text(encoding='utf-8')
    text = raw.lstrip()
    if text.startswith('{'):
        try:
            parsed = json.loads(raw)
        except ValueError:
            raise SystemExit(f'{path.name} looks like JSON but does not parse.') from None
        if not isinstance(parsed, dict):
            raise SystemExit(f'{path.name} must contain a JSON object.')
        return {str(key): str(value) for key, value in parsed.items()}
    found: dict[str, str] = {}
    for line in raw.splitlines():
        entry = line.strip()
        if not entry or entry.startswith('#'):
            continue
        if entry.lower().startswith('export '):
            entry = entry[7:].strip()
        name, separator, value = entry.partition('=')
        if separator:
            found[name.strip()] = value.strip().strip('\'"')
    return found


def pick(values: dict[str, str], names: tuple[str, ...]) -> tuple[str | None, str | None]:
    for name in names:
        if values.get(name):
            return values[name], name
    return None, None


def resolve_credentials(source: dict[str, str], origin: str) -> tuple[str, str]:
    secret_id, id_name = pick(source, SECRET_ID_NAMES)
    secret_key, key_name = pick(source, SECRET_KEY_NAMES)
    if not secret_id or not secret_key:
        raise SystemExit(
            f'No caller credential found in {origin}. Expected one of {SECRET_ID_NAMES} '
            f'and one of {SECRET_KEY_NAMES} (names only are reported, values never are).'
        )
    # Names, not values: this is what confirms the right variables were picked up.
    print(f'  credential source : {origin}  ({id_name} + {key_name})')
    return secret_id, secret_key


def error_code(error: BaseException) -> str:
    """Return the SDK error code only; messages can echo request parameters."""
    for attribute in ('code', 'Code'):
        value = getattr(error, attribute, None)
        if isinstance(value, str) and value:
            return value
    return type(error).__name__


def sts_client(secret_id: str, secret_key: str, region: str) -> Any:
    from tencentcloud.common.credential import Credential
    from tencentcloud.common.profile.client_profile import ClientProfile
    from tencentcloud.common.profile.http_profile import HttpProfile
    from tencentcloud.sts.v20180813 import sts_client as client_module

    http = HttpProfile(endpoint=STS_ENDPOINT, reqTimeout=REQUEST_TIMEOUT_SECONDS)
    profile = ClientProfile(httpProfile=http)
    return client_module.StsClient(Credential(secret_id, secret_key), region, profile)


def check_caller(client: Any) -> bool:
    from tencentcloud.sts.v20180813 import models

    try:
        identity = client.GetCallerIdentity(models.GetCallerIdentityRequest())
    except Exception as error:  # noqa: BLE001 - reported as a code, never as text
        print(f'  GetCallerIdentity : FAILED ({error_code(error)})')
        return False
    # Report whatever identity fields this endpoint actually returns rather than
    # assuming a mainland shape; these are account identifiers, not credentials.
    fields = {
        name.lstrip('_'): value
        for name, value in vars(identity).items()
        if name.startswith('_') and isinstance(value, str) and value
    }
    rendered = ' '.join(f'{name}={value}' for name, value in sorted(fields.items()))
    print(f'  caller            : {rendered or "(no identity fields returned)"}')
    return True


def try_assume_role(
    client: Any, role_arn: str, duration: int
) -> tuple[bool, int | None, dict[str, str], str]:
    """Assume the role once. Returns (ok, seconds remaining, credentials, error code).

    The returned credentials are handed straight to the login-URL check and are
    never printed.
    """
    from tencentcloud.sts.v20180813 import models

    request = models.AssumeRoleRequest()
    request.RoleArn = role_arn
    request.RoleSessionName = f'psm-acceptance-{os.urandom(4).hex()}'
    request.DurationSeconds = duration
    try:
        response = client.AssumeRole(request)
    except Exception as error:  # noqa: BLE001 - reported as a code, never as text
        return False, None, {}, error_code(error)
    credentials = {
        name: getattr(response.Credentials, name)
        for name in ('TmpSecretId', 'TmpSecretKey', 'Token')
    }
    return True, int(response.ExpiredTime) - int(time.time()), credentials, ''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    # Optional: without it only the caller identity is checked, which still proves
    # the credential works and that the international endpoint is reachable.
    parser.add_argument('--role-arn', default='', help='role the caller may assume')
    parser.add_argument('--region', default='ap-singapore')
    parser.add_argument('--credentials-file', type=Path, help='file holding the caller AK/SK')
    parser.add_argument('--destination', default='https://console.tencentcloud.com/')
    args = parser.parse_args()

    print('Tencent Cloud acceptance (read-only: GetCallerIdentity and AssumeRole)')
    if args.credentials_file is not None:
        if not args.credentials_file.is_file():
            raise SystemExit(f'{args.credentials_file} is not a readable file.')
        source = parse_credentials_file(args.credentials_file)
        origin = str(args.credentials_file)
    else:
        source = dict(os.environ)
        origin = 'environment'
    secret_id, secret_key = resolve_credentials(source, origin)
    print(f'  endpoint          : {STS_ENDPOINT} ({args.region})')

    client = sts_client(secret_id, secret_key, args.region)
    if not check_caller(client):
        raise SystemExit(EXIT_FAILED)

    if not args.role_arn:
        print('\nconclusion: caller credential works; pass --role-arn to check AssumeRole durations')
        raise SystemExit(0)

    print('  AssumeRole durations:')
    working: dict[str, str] | None = None
    working_duration: int | None = None
    for duration in DURATION_CANDIDATES:
        ok, remaining, credentials, code = try_assume_role(client, args.role_arn, duration)
        if ok and remaining is not None:
            print(f'    {duration:>6}s : accepted (expires in {remaining}s)')
            working, working_duration = credentials, duration
            break
        print(f'    {duration:>6}s : refused ({code})')
        if duration == DURATION_CANDIDATES[0] and not code.startswith(
            ('InvalidParameter', 'FailedOperation.Duration', 'UnsupportedOperation')
        ):
            # Not a duration problem, so trying other values cannot help.
            break

    if working is None:
        print('\nconclusion: FAILED - no duration was accepted; the bridge cannot assume this role')
        raise SystemExit(EXIT_FAILED)
    if working_duration != DURATION_CANDIDATES[0]:
        print(
            f'    note: the bridge default of {DURATION_CANDIDATES[0]}s is NOT accepted by this API; '
            f'the smallest accepted value tried was {working_duration}s'
        )

    # Exercise the real signing path with real temporary credentials. The URL carries
    # credentials, so only its shape is reported.
    try:
        url = login_url(working, args.destination)
    except Exception as error:  # noqa: BLE001 - reported as a code, never as text
        print(f'  login URL         : FAILED ({error_code(error)})')
        raise SystemExit(EXIT_FAILED) from None
    parsed = urlsplit(url)
    signed = 'signature=' in parsed.query and 'secretId=' in parsed.query
    print(f'  login URL         : host={parsed.hostname} signature_present={signed} (URL not printed)')
    if parsed.hostname != 'www.tencentcloud.com' or not signed:
        raise SystemExit(EXIT_FAILED)

    print('\nconclusion: all checks passed (the URL itself must still be opened in a browser)')
    raise SystemExit(0)


if __name__ == "__main__":
    main()
