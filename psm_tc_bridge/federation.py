"""Tencent Cloud mainland role-console federation. No credential logging.

Signing follows the documented roleAccessCallback string. Parameters are sorted,
unencoded, and covered by HMAC-SHA256 of the temporary SecretKey:

    GETcloud.tencent.com/login/roleAccessCallback?action=roleLogin&nonce=...&secretId=...&timestamp=...

The token is a request parameter, not part of the signature. Official reference:
https://cloud.tencent.com/document/product/598/45529
"""

import base64
import hashlib
import hmac
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit


class FederationError(Exception):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def validate_destination(url):
    try:
        parsed = urlsplit(url)
        valid = (
            parsed.scheme == 'https'
            and parsed.hostname == 'console.cloud.tencent.com'
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password
            and parsed.hostname == parsed.netloc
        )
    except (ValueError, TypeError, AttributeError):
        valid = False
    if not valid or not isinstance(url, str) or any(ord(char) < 33 for char in url) or '\\' in url or '%' in url:
        raise FederationError('Invalid console destination')
    return url


def login_request(credentials, destination, *, now=None, nonce=None, login_host='cloud.tencent.com'):
    validate_destination(destination)
    if login_host != 'cloud.tencent.com':
        raise FederationError('Unsupported login host')
    now = int(time.time()) if now is None else now
    nonce = secrets.randbelow(99990001) + 10000 if nonce is None else nonce
    if type(nonce) is not int or not 10000 <= nonce <= 100000000:
        raise FederationError('Invalid nonce')
    if type(now) is not int or now <= 0:
        raise FederationError('Invalid timestamp')
    secret_id, secret_key, token = (credentials.get(name) for name in ('TmpSecretId', 'TmpSecretKey', 'Token'))
    if not all(isinstance(value, str) and value for value in (secret_id, secret_key, token)):
        raise FederationError('Missing temporary credentials')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', secret_id):
        raise FederationError('Invalid temporary SecretId')
    signed = {'action': 'roleLogin', 'nonce': nonce, 'secretId': secret_id, 'timestamp': now}
    canonical_query = '&'.join(f'{key}={signed[key]}' for key in sorted(signed))
    canonical = f'GET{login_host}/login/roleAccessCallback?{canonical_query}'
    signature = base64.b64encode(
        hmac.new(secret_key.encode(), canonical.encode(), hashlib.sha256).digest()
    ).decode()
    fields = {
        'algorithm': 'sha256',
        'secretId': secret_id,
        'token': token,
        'nonce': str(nonce),
        'timestamp': str(now),
        'signature': signature,
        's_url': destination,
    }
    return f'https://{login_host}/login/roleAccessCallback', fields


def login_url(credentials, destination, *, now=None, nonce=None, login_host='cloud.tencent.com'):
    endpoint, fields = login_request(
        credentials, destination, now=now, nonce=nonce, login_host=login_host
    )
    return endpoint + '?' + urlencode(fields)


def assume_role(secret_id, secret_key, role_arn, session_name, duration, region, *,
                endpoint='sts.tencentcloudapi.com', external_id=None, session_policy=None):
    # Explicit credentials: no environment credential fallback or debug logging.
    from tencentcloud.common import credential
    from tencentcloud.common.profile.client_profile import ClientProfile
    from tencentcloud.common.profile.http_profile import HttpProfile
    from tencentcloud.sts.v20180813 import models, sts_client

    http = HttpProfile(endpoint=endpoint, reqTimeout=15)
    profile = ClientProfile(httpProfile=http)
    client = sts_client.StsClient(credential.Credential(secret_id, secret_key), region, profile)
    request = models.AssumeRoleRequest()
    request.RoleArn = role_arn
    request.RoleSessionName = session_name
    request.DurationSeconds = duration
    if external_id:
        request.ExternalId = external_id
    if session_policy:
        request.Policy = session_policy
    try:
        response = client.AssumeRole(request)
        expired = getattr(response, 'ExpiredTime', 0) or 0
        if expired <= int(time.time()) + 30:
            raise FederationError('Temporary credentials expire too soon')
        values = {name: getattr(response.Credentials, name) for name in ('TmpSecretId', 'TmpSecretKey', 'Token')}
        if not all(isinstance(value, str) and value for value in values.values()):
            raise FederationError('Missing temporary credentials')
        return values
    except FederationError:
        raise
    except Exception as exc:
        code = getattr(exc, 'code', None) or type(exc).__name__
        raise FederationError('STS request failed', code=code) from None
