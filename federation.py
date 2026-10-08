"""Tencent Cloud role-console federation for the international and China sites."""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

from validate import MAX_NONCE, MAX_SECRET_ID_LEN, MIN_NONCE, is_identifier


class FederationError(Exception):
    pass


# Credentials that expire within this window are unusable for a console session,
# so they are refused rather than handed to the browser. configuration.py derives
# its minimum duration from this value.
MIN_CREDENTIAL_MARGIN_SECONDS = 30

# Site is a matching set: console host, signed callback host and API endpoints.
# Never mix them — a China destination signed with the international callback
# host is rejected by the console.
DEFAULT_SITE = 'intl'


@dataclass(frozen=True)
class Site:
    name: str
    console_host: str
    login_host: str
    sts_endpoint: str
    cam_endpoint: str
    cvm_endpoint: str


SITES: dict[str, Site] = {
    'intl': Site(
        name='intl',
        console_host='console.tencentcloud.com',
        login_host='www.tencentcloud.com',
        sts_endpoint='sts.intl.tencentcloudapi.com',
        cam_endpoint='cam.intl.tencentcloudapi.com',
        cvm_endpoint='cvm.intl.tencentcloudapi.com',
    ),
    'china': Site(
        name='china',
        console_host='console.cloud.tencent.com',
        login_host='cloud.tencent.com',
        sts_endpoint='sts.tencentcloudapi.com',
        cam_endpoint='cam.tencentcloudapi.com',
        cvm_endpoint='cvm.tencentcloudapi.com',
    ),
}


def validate_site(site: object) -> Site:
    if not isinstance(site, str) or site not in SITES:
        raise ValueError("Site must be 'intl' or 'china'")
    return SITES[site]


def validate_region(region: str) -> str:
    # Validate syntax without pretending to maintain a cloud availability catalogue.
    if not isinstance(region, str) or len(region) > 64 or not re.fullmatch(r'[a-z]{2}-[a-z]+(?:-[a-z0-9]+)*', region):
        raise ValueError('Invalid cloud region')
    return region


def validate_destination(url: str, site: str = DEFAULT_SITE) -> str:
    console_host = validate_site(site).console_host
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise FederationError('Invalid console destination')
    try:
        p = urlsplit(url)
        valid = (p.scheme == 'https' and p.hostname == console_host
                 and p.port in (None, 443) and not p.username and not p.password)
    except (ValueError, TypeError):
        valid = False
    if not valid or any(ord(c) < 33 for c in url) or '\\' in url:
        raise FederationError('Invalid console destination')
    return url


def login_url(
    credentials: Mapping[str, str],
    destination: str,
    *,
    site: str = DEFAULT_SITE,
    now: int | None = None,
    nonce: int | None = None,
) -> str:
    chosen = validate_site(site)
    validate_destination(destination, site)
    now = int(time.time()) if now is None else now
    nonce = secrets.randbelow(MAX_NONCE - MIN_NONCE + 1) + MIN_NONCE if nonce is None else nonce
    if type(nonce) is not int or not MIN_NONCE <= nonce <= MAX_NONCE:
        raise FederationError('Invalid nonce')
    if type(now) is not int or now <= 0:
        raise FederationError('Invalid timestamp')
    sid, key, token = (credentials.get(n) for n in ('TmpSecretId', 'TmpSecretKey', 'Token'))
    if not all(isinstance(x, str) and x for x in (sid, key, token)):
        raise FederationError('Missing temporary credentials')
    if not is_identifier(sid or '', 1, MAX_SECRET_ID_LEN):
        raise FederationError('Invalid temporary SecretId')
    # Tencent's callback signs only these four unencoded parameters, in this order.
    canonical = (f'GET{chosen.login_host}/login/roleAccessCallback?action=roleLogin'
                 f'&nonce={nonce}&secretId={sid}&timestamp={now}')
    signature = base64.b64encode(hmac.new((key or '').encode(), canonical.encode(), hashlib.sha256).digest()).decode()
    return f'https://{chosen.login_host}/login/roleAccessCallback?' + urlencode({
        'algorithm': 'sha256', 'secretId': sid, 'token': token,
        'nonce': nonce, 'timestamp': now, 'signature': signature, 's_url': destination})


def assume_role(
    secret_id: str,
    secret_key: str,
    role_arn: str,
    session_name: str,
    duration: int,
    region: str,
    site: str = DEFAULT_SITE,
) -> dict[str, str]:
    chosen = validate_site(site)
    validate_region(region)
    # Explicit credentials: no environment credential fallback or debug logging.
    from tencentcloud.common import credential
    from tencentcloud.common.profile.client_profile import ClientProfile
    from tencentcloud.common.profile.http_profile import HttpProfile
    from tencentcloud.sts.v20180813 import models, sts_client

    http = HttpProfile(endpoint=chosen.sts_endpoint, reqTimeout=15)
    profile = ClientProfile(httpProfile=http)
    client = sts_client.StsClient(credential.Credential(secret_id, secret_key), region, profile)
    req = models.AssumeRoleRequest()
    req.RoleArn, req.RoleSessionName, req.DurationSeconds = role_arn, session_name, duration
    try:
        response = client.AssumeRole(req)
        credentials: dict[str, Any] = {name: getattr(response.Credentials, name) for name in ('TmpSecretId', 'TmpSecretKey', 'Token')}
        expired_at = response.ExpiredTime
    except Exception:  # noqa: BLE001 - never forward error text
        # SDK exception text may contain sensitive request material; never forward it.
        raise FederationError('STS request failed') from None
    # Checked outside the sanitizing handler so the operator sees the real cause
    # instead of a generic STS failure.
    if type(expired_at) is not int or expired_at <= int(time.time()) + MIN_CREDENTIAL_MARGIN_SECONDS:
        raise FederationError('Temporary credentials expire too soon')
    return credentials
