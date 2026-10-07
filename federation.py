"""Tencent Cloud international role-console federation. No credential logging."""

import base64
import hashlib
import hmac
import re
import secrets
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

MAX_DESTINATION_LENGTH = 2048
MAX_REGION_LENGTH = 64
REGION_PATTERN = re.compile(r"[a-z]{2}-[a-z]+(?:-[a-z0-9]+)*")
MIN_NONCE = 10000
MAX_NONCE = 100000000
FEDERATION_HOST = "www.tencentcloud.com"
LOGIN_PATH = "/login/roleAccessCallback"
ACTION = "roleLogin"
ALGORITHM = "sha256"


class FederationError(Exception):
    """Raised when federation input or STS interaction is invalid."""


def validate_region(region: str) -> str:
    """Validate region syntax without pretending to own a cloud availability catalogue."""
    if (
        not isinstance(region, str)
        or len(region) > MAX_REGION_LENGTH
        or not re.fullmatch(REGION_PATTERN, region)
    ):
        raise ValueError("Invalid cloud region")
    return region


def validate_destination(url: str) -> str:
    if not isinstance(url, str) or not url or len(url) > MAX_DESTINATION_LENGTH:
        raise FederationError("Invalid console destination")
    try:
        parsed = urlsplit(url)
        valid = (
            parsed.scheme == "https"
            and parsed.hostname == "console.tencentcloud.com"
            and parsed.port in (None, 443)
            and not parsed.username
            and not parsed.password
        )
    except (ValueError, TypeError):
        valid = False
    if not valid or any(ord(c) < 33 for c in url) or "\\" in url:
        raise FederationError("Invalid console destination")
    return url


def _required_credential(credentials: dict[str, Any], name: str) -> str:
    value = credentials.get(name)
    if not isinstance(value, str) or not value:
        raise FederationError("Missing temporary credentials")
    return value


def login_url(
    credentials: dict[str, Any],
    destination: str,
    *,
    now: int | None = None,
    nonce: int | None = None,
) -> str:
    validate_destination(destination)
    now = int(time.time()) if now is None else now
    nonce = secrets.randbelow(MAX_NONCE - MIN_NONCE + 1) + MIN_NONCE if nonce is None else nonce
    if type(nonce) is not int or not MIN_NONCE <= nonce <= MAX_NONCE:
        raise FederationError("Invalid nonce")
    if type(now) is not int or now <= 0:
        raise FederationError("Invalid timestamp")
    sid = _required_credential(credentials, "TmpSecretId")
    key = _required_credential(credentials, "TmpSecretKey")
    token = _required_credential(credentials, "Token")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", sid):
        raise FederationError("Invalid temporary SecretId")
    # Tencent's callback signs only these four unencoded parameters, in this order.
    canonical = (
        f"GET{FEDERATION_HOST}{LOGIN_PATH}?action={ACTION}&nonce={nonce}&secretId={sid}&timestamp={now}"
    )
    signature = base64.b64encode(hmac.new(key.encode(), canonical.encode(), hashlib.sha256).digest()).decode()
    return (
        "https://"
        + FEDERATION_HOST
        + LOGIN_PATH
        + "?"
        + urlencode(
            {
                "algorithm": ALGORITHM,
                "secretId": sid,
                "token": token,
                "nonce": nonce,
                "timestamp": now,
                "signature": signature,
                "s_url": destination,
            }
        )
    )


def assume_role(
    secret_id: str,
    secret_key: str,
    role_arn: str,
    session_name: str,
    duration: int,
    region: str,
) -> dict[str, str]:
    validate_region(region)
    # Explicit credentials: no environment credential fallback or debug logging.
    from tencentcloud.common import credential
    from tencentcloud.common.profile.client_profile import ClientProfile
    from tencentcloud.common.profile.http_profile import HttpProfile
    from tencentcloud.sts.v20180813 import models, sts_client

    http = HttpProfile(endpoint="sts.intl.tencentcloudapi.com", reqTimeout=15)
    profile = ClientProfile(httpProfile=http)
    client = sts_client.StsClient(credential.Credential(secret_id, secret_key), region, profile)
    req = models.AssumeRoleRequest()
    req.RoleArn, req.RoleSessionName, req.DurationSeconds = role_arn, session_name, duration
    try:
        response = client.AssumeRole(req)
        if response.ExpiredTime <= int(time.time()) + 30:
            raise FederationError("Temporary credentials expire too soon")
        return {
            name: getattr(response.Credentials, name) for name in ("TmpSecretId", "TmpSecretKey", "Token")
        }
    except Exception:  # noqa: BLE001 - SDK text may echo request credentials
        # SDK exception text may contain sensitive request material; never forward it.
        raise FederationError("STS request failed") from None
