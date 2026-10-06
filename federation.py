"""Tencent Cloud international role-console federation. No credential logging."""
import base64
import hashlib
import hmac
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit


class FederationError(Exception):
    pass


def validate_destination(url):
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise FederationError('Invalid console destination')
    try:
        p = urlsplit(url)
        valid = (p.scheme == 'https' and p.hostname == 'console.tencentcloud.com'
                 and p.port in (None, 443) and not p.username and not p.password)
    except (ValueError, TypeError):
        valid = False
    if not valid or any(ord(c) < 33 for c in url) or '\\' in url:
        raise FederationError('Invalid console destination')
    return url


def login_url(credentials, destination, *, now=None, nonce=None):
    validate_destination(destination)
    now = int(time.time()) if now is None else now
    nonce = secrets.randbelow(99990001) + 10000 if nonce is None else nonce
    if type(nonce) is not int or not 10000 <= nonce <= 100000000:
        raise FederationError('Invalid nonce')
    if type(now) is not int or now <= 0:
        raise FederationError('Invalid timestamp')
    sid, key, token = (credentials.get(n) for n in ('TmpSecretId', 'TmpSecretKey', 'Token'))
    if not all(isinstance(x, str) and x for x in (sid, key, token)):
        raise FederationError('Missing temporary credentials')
    if not re.fullmatch(r'[A-Za-z0-9_-]+', sid):
        raise FederationError('Invalid temporary SecretId')
    # Tencent's callback signs only these four unencoded parameters, in this order.
    canonical = (f'GETwww.tencentcloud.com/login/roleAccessCallback?action=roleLogin'
                 f'&nonce={nonce}&secretId={sid}&timestamp={now}')
    signature = base64.b64encode(hmac.new(key.encode(), canonical.encode(), hashlib.sha256).digest()).decode()
    return 'https://www.tencentcloud.com/login/roleAccessCallback?' + urlencode({
        'algorithm': 'sha256', 'secretId': sid, 'token': token,
        'nonce': nonce, 'timestamp': now, 'signature': signature, 's_url': destination})


def assume_role(secret_id, secret_key, role_arn, session_name, duration, region):
    # Explicit credentials: no environment credential fallback or debug logging.
    from tencentcloud.common import credential
    from tencentcloud.common.profile.client_profile import ClientProfile
    from tencentcloud.common.profile.http_profile import HttpProfile
    from tencentcloud.sts.v20180813 import sts_client, models
    http = HttpProfile(endpoint='sts.intl.tencentcloudapi.com', reqTimeout=15)
    profile = ClientProfile(httpProfile=http)
    client = sts_client.StsClient(credential.Credential(secret_id, secret_key), region, profile)
    req = models.AssumeRoleRequest()
    req.RoleArn, req.RoleSessionName, req.DurationSeconds = role_arn, session_name, duration
    try:
        response = client.AssumeRole(req)
        if response.ExpiredTime <= int(time.time()) + 30:
            raise FederationError('Temporary credentials expire too soon')
        return {name: getattr(response.Credentials, name) for name in ('TmpSecretId', 'TmpSecretKey', 'Token')}
    except Exception:
        # SDK exception text may contain sensitive request material; never forward it.
        raise FederationError('STS request failed') from None
