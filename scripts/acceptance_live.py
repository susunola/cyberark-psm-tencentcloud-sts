"""Live acceptance checks against real Tencent Cloud. Read-only by default.

Settles the questions no offline test can:

1. whether the international endpoint accepts the project's request construction,
2. whether AssumeRole accepts the duration the bridge is configured to request,
3. whether Tencent's role-login callback accepts the signature the project builds,
4. what shape a role needs (console login, session duration) for that flow.

With ``--provision`` it also creates a throwaway role so (2) and (3) can run
without depending on a role you already have, then deletes it again unless
``--keep-role`` is given. Creating and deleting a role are the only mutations, and
both are announced on stdout.

The script prints credential NAMES and SDK error CODES, never values: no AK/SK,
no temporary credentials, and never the generated login URL even though it builds
and uses one. For (3) it requests the callback twice - once with the real signature
and once with a tampered copy - so a rejection can be attributed to the signature
rather than to a non-browser client.

Usage:

    set -a; source ~/wbenv; set +a
    python scripts/acceptance_live.py --provision
    python scripts/acceptance_live.py --role-arn qcs::cam::uin/<uin>:roleName/<name>

Exit codes: 0 all checks passed, 2 a check failed, 3 credentials or arguments were
unusable.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

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
CAM_ENDPOINT = 'cam.intl.tencentcloudapi.com'
CALLBACK_HOST = 'www.tencentcloud.com'
REQUEST_TIMEOUT_SECONDS = 15
BROWSER_USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/124.0 Safari/537.36'
)
PROBE_ROLE = 'PSMAcceptanceProbe'
DURATION_PARAMETER_ERRORS = ('InvalidParameter', 'FailedOperation.Duration', 'UnsupportedOperation')
EXIT_FAILED = 2
EXIT_UNUSABLE = 3


# ---------------------------------------------------------------- credentials


def parse_credentials_file(path: Path) -> dict[str, str]:
    """Read KEY=VALUE lines or a JSON object. Only the names are ever reported."""
    raw = path.read_text(encoding='utf-8')
    if raw.lstrip().startswith('{'):
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
    print(f'  credential source  : {origin}  ({id_name} + {key_name})')
    return secret_id, secret_key


# ------------------------------------------------------------------- clients


def error_code(error: BaseException) -> str:
    """Return the SDK error code only; messages can echo request parameters."""
    for attribute in ('code', 'Code'):
        value = getattr(error, attribute, None)
        if isinstance(value, str) and value:
            return value
    return type(error).__name__


def build_client(module_name: str, class_name: str, secret_id: str, secret_key: str, region: str) -> Any:
    from tencentcloud.common.credential import Credential
    from tencentcloud.common.profile.client_profile import ClientProfile
    from tencentcloud.common.profile.http_profile import HttpProfile

    endpoint = STS_ENDPOINT if class_name == 'StsClient' else CAM_ENDPOINT
    http = HttpProfile(endpoint=endpoint, reqTimeout=REQUEST_TIMEOUT_SECONDS)
    profile = ClientProfile(httpProfile=http)
    credential = Credential(secret_id, secret_key)
    if class_name == 'StsClient':
        from tencentcloud.sts.v20180813 import sts_client

        return sts_client.StsClient(credential, region, profile)
    from tencentcloud.cam.v20190116 import cam_client

    return cam_client.CamClient(credential, region, profile)


# ------------------------------------------------------------------- checks


def check_caller(sts: Any) -> dict[str, str]:
    from tencentcloud.sts.v20180813 import models

    try:
        identity = sts.GetCallerIdentity(models.GetCallerIdentityRequest())
    except Exception as error:  # noqa: BLE001 - reported as a code, never as text
        print(f'  GetCallerIdentity  : FAILED ({error_code(error)})')
        raise SystemExit(EXIT_FAILED) from None
    # Account identifiers, not credentials, and needed to confirm the right caller.
    fields = {
        name.lstrip('_'): value
        for name, value in vars(identity).items()
        if name.startswith('_') and isinstance(value, str) and value
    }
    print('  caller             : ' + ' '.join(f'{k}={v}' for k, v in sorted(fields.items())))
    return fields


def trust_document(principal_qcs: str) -> str:
    return json.dumps(
        {
            'version': '2.0',
            'statement': [
                {'action': 'name/sts:AssumeRole', 'effect': 'allow', 'principal': {'qcs': [principal_qcs]}}
            ],
        }
    )


def trust_candidates(account: str, principal: str) -> list[tuple[str, str]]:
    """Least privilege first, then the account scope the API actually accepts.

    The per-sub-user form is tried first. On this international account it is
    rejected as a non-existent principal even for a sub-user that ListUsers reports,
    in which case the probe falls back to the account scope that existing roles in
    the same account use. The probe role carries no policies, so the wider trust
    confers no permissions on anything; the scope used is always reported.
    """
    return [
        (f'qcs::cam::uin/{account}:uin/{principal}', 'this sub-user only'),
        (f'qcs::cam::uin/{account}:root', 'account scope (probe role has no policies)'),
    ]


def sleep_to_respect_rate_limit() -> None:
    """CAM allows about two calls per second; a probe must not trip that limit."""
    time.sleep(0.7)


def describe_role(cam: Any, name: str) -> dict[str, Any] | None:
    from tencentcloud.cam.v20190116 import models

    request = models.GetRoleRequest()
    request.RoleName = name
    try:
        info = cam.GetRole(request).RoleInfo
    except Exception as error:  # noqa: BLE001 - a missing role is an expected answer
        code = error_code(error)
        if 'NotFound' in code or 'NotExist' in code:
            return None
        print(f'  GetRole            : FAILED ({code})')
        raise SystemExit(EXIT_FAILED) from None
    return {
        'RoleName': info.RoleName,
        'RoleArn': info.RoleArn,
        'ConsoleLogin': info.ConsoleLogin,
        'SessionDuration': info.SessionDuration,
        'RoleId': info.RoleId,
    }


def create_probe_role(cam: Any, account: str, principal: str) -> dict[str, Any]:
    from tencentcloud.cam.v20190116 import models

    last_code = ''
    for principal_qcs, note in trust_candidates(account, principal):
        request = models.CreateRoleRequest()
        request.RoleName = PROBE_ROLE
        request.PolicyDocument = trust_document(principal_qcs)
        request.ConsoleLogin = 1  # the bridge's whole purpose is console login
        request.SessionDuration = 7200  # the API minimum; the AssumeRole test probes lower
        request.Description = 'Temporary role created by scripts/acceptance_live.py; safe to delete.'
        print(f'  MUTATION           : creating role {PROBE_ROLE} trusting {note}')
        sleep_to_respect_rate_limit()
        try:
            cam.CreateRole(request)
        except Exception as error:  # noqa: BLE001 - reported as a code, never as text
            last_code = error_code(error)
            print(f'    rejected         : {last_code}')
            continue
        role = describe_role(cam, PROBE_ROLE)
        if role is None:
            raise SystemExit(EXIT_FAILED)
        role['TrustQcs'] = principal_qcs
        role['TrustNote'] = note
        return role
    print(f'  CreateRole         : FAILED ({last_code or "no candidate accepted"})')
    raise SystemExit(EXIT_FAILED)


def delete_probe_role(cam: Any, name: str) -> bool:
    from tencentcloud.cam.v20190116 import models

    request = models.DeleteRoleRequest()
    request.RoleName = name
    print(f'  MUTATION           : deleting role {name}')
    try:
        cam.DeleteRole(request)
    except Exception as error:  # noqa: BLE001 - reported as a code, never as text
        print(f'  DeleteRole         : FAILED ({error_code(error)}) - remove it by hand')
        return False
    return True


def assume(
    sts: Any, role_arn: str, duration: int
) -> tuple[bool, int | None, dict[str, str], str]:
    """Assume the role once. Credentials are used downstream and never printed."""
    from tencentcloud.sts.v20180813 import models

    request = models.AssumeRoleRequest()
    request.RoleArn = role_arn
    request.RoleSessionName = f'psm-acceptance-{os.urandom(4).hex()}'
    request.DurationSeconds = duration
    try:
        response = sts.AssumeRole(request)
    except Exception as error:  # noqa: BLE001 - reported as a code, never as text
        return False, None, {}, error_code(error)
    credentials = {
        name: getattr(response.Credentials, name)
        for name in ('TmpSecretId', 'TmpSecretKey', 'Token')
    }
    return True, int(response.ExpiredTime) - int(time.time()), credentials, ''


def tamper(url: str) -> str:
    """Corrupt the signature, keeping the URL otherwise identical."""
    parts = urlsplit(url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    flipped = [
        (key, (value[:-1] + ('A' if value.endswith('B') else 'B')) if key == 'signature' else value)
        for key, value in query
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(flipped), parts.fragment))


def probe_callback(url: str) -> tuple[int | None, str]:
    """Request the callback without following it. Returns (status, location host)."""
    try:
        response = requests.get(
            url,
            allow_redirects=False,
            timeout=REQUEST_TIMEOUT_SECONDS,
            headers={'User-Agent': BROWSER_USER_AGENT},
        )
    except requests.RequestException as error:
        return None, type(error).__name__
    location = response.headers.get('Location', '')
    return response.status_code, urlsplit(location).hostname or ''


# --------------------------------------------------------------------- main


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role-arn', default='', help='role to assume; default is the probe role')
    parser.add_argument('--region', default='ap-singapore')
    parser.add_argument('--credentials-file', type=Path, help='file holding the caller AK/SK')
    parser.add_argument('--destination', default='https://console.tencentcloud.com/')
    parser.add_argument('--site', default='intl', choices=('intl', 'china'))
    parser.add_argument(
        '--provision',
        action='store_true',
        help=f'create the throwaway {PROBE_ROLE} role, then delete it again',
    )
    parser.add_argument('--keep-role', action='store_true', help='do not delete a created role')
    args = parser.parse_args()

    print('Tencent Cloud live acceptance')
    if args.credentials_file is not None:
        if not args.credentials_file.is_file():
            raise SystemExit(f'{args.credentials_file} is not a readable file.')
        source = parse_credentials_file(args.credentials_file)
        origin = str(args.credentials_file)
    else:
        source, origin = dict(os.environ), 'environment'
    secret_id, secret_key = resolve_credentials(source, origin)
    print(f'  endpoint           : {STS_ENDPOINT} ({args.region})')

    sts = build_client('sts', 'StsClient', secret_id, secret_key, args.region)
    fields = check_caller(sts)

    created_here = False
    role_arn = args.role_arn
    try:
        if args.provision:
            cam = build_client('cam', 'CamClient', secret_id, secret_key, args.region)
            existing = describe_role(cam, PROBE_ROLE)
            if existing is None:
                account = fields.get('AccountId', '')
                principal = fields.get('PrincipalId', '')
                if not account or not principal:
                    raise SystemExit('GetCallerIdentity did not return AccountId/PrincipalId.')
                existing = create_probe_role(cam, account, principal)
                created_here = True
            else:
                print(f'  reusing existing   : {PROBE_ROLE} (not created by this run)')
            role_arn = existing['RoleArn']
            print(
                f'  probe role         : ConsoleLogin={existing["ConsoleLogin"]} '
                f'SessionDuration={existing["SessionDuration"]}s'
            )
            if existing.get('TrustNote'):
                print(f'  probe role trust   : {existing["TrustNote"]} ({existing["TrustQcs"]})')
        if not role_arn:
            print('\nconclusion: caller credential works; pass --provision or --role-arn for the rest')
            return

        print('  AssumeRole durations:')
        working: dict[str, str] | None = None
        accepted: int | None = None
        for duration in DURATION_CANDIDATES:
            ok, remaining, credentials, code = assume(sts, role_arn, duration)
            if ok and remaining is not None:
                print(f'    {duration:>6}s : accepted (expires in {remaining}s)')
                working, accepted = credentials, duration
                break
            print(f'    {duration:>6}s : refused ({code})')
            if duration == DURATION_CANDIDATES[0] and not code.startswith(DURATION_PARAMETER_ERRORS):
                break  # not a duration problem, so other values cannot help

        if working is None or accepted is None:
            print('\nconclusion: FAILED - no duration accepted; the bridge cannot assume this role')
            raise SystemExit(EXIT_FAILED)
        if accepted != DURATION_CANDIDATES[0]:
            print(
                f'    FINDING: the bridge default of {DURATION_CANDIDATES[0]}s is refused by this API; '
                f'the smallest accepted value tried was {accepted}s'
            )

        # Exercise the real signing path with real temporary credentials.
        real_url = login_url(working, args.destination, site=args.site)
        print(f'  login URL          : host={urlsplit(real_url).hostname} (URL never printed)')
        status, location = probe_callback(real_url)
        bad_status, bad_location = probe_callback(tamper(real_url))
        print(f'    correct signature : HTTP {status} -> {location or "(no redirect)"}')
        print(f'    tampered signature: HTTP {bad_status} -> {bad_location or "(no redirect)"}')
        if status is None or bad_status is None:
            print('  NOTE: a network failure prevents attributing the result to the signature')
        elif (status, location) == (bad_status, bad_location):
            print(
                '  NOTE: both requests answered identically, so the callback did not validate the '
                'signature for this client; the signing scheme stays unproven here'
            )
        else:
            print('    the callback distinguishes a valid signature from a tampered one')
    finally:
        if created_here and not args.keep_role:
            cam = build_client('cam', 'CamClient', secret_id, secret_key, args.region)
            delete_probe_role(cam, PROBE_ROLE)
        elif created_here:
            print(f'  probe role kept    : delete {PROBE_ROLE} when you are done')

    print('\nconclusion: checks completed; browser-side console login still needs a human')


if __name__ == '__main__':
    main()
