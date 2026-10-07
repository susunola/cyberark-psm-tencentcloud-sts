"""Tencent Cloud CAM/CVM administrative adapter. No credential logging."""
from __future__ import annotations

import re
from typing import Any

from federation import FederationError, validate_region
from validate import (
    MAX_CREDENTIAL_ID_LEN,
    MAX_INVENTORY_INSTANCES,
    MAX_INVENTORY_PAGE_SIZE,
    MAX_INVENTORY_PAGES,
    MAX_INVENTORY_USERS,
    is_identifier,
)

KEY_STATUSES = ('Active', 'Inactive')
# Vendor-controlled strings are echoed into operator output; bound and sanitise them.
MAX_VENDOR_TEXT = 1024
VENDOR_HOST_PATTERN = re.compile(r'[0-9A-Fa-f:.]{1,64}')
KEY_ID_PATTERN = re.compile(r'[A-Za-z0-9_-]{1,256}')
MAX_CAM_KEYS = 10
# CAM's ListUsers has no pagination fields in v20190116 and returns every sub-user
# in one response, so this is a bound on an unbounded reply rather than a page size.
# An organisation above it must raise the bound deliberately and accept the larger
# response: assert_subuser runs before every key mutation and has no narrower API.
DEFAULT_MAX_CAM_USERS = MAX_INVENTORY_USERS
MAX_CAM_USERS_CEILING = 100000


def uin(value: object) -> int:
    if not re.fullmatch(r'[0-9]{1,20}', str(value)) or int(str(value)) <= 0:
        raise ValueError('Explicit positive target UIN required')
    return int(str(value))


def display_text(value: object) -> str:
    """Return a bounded, control-character-free vendor string for operator output."""
    if not isinstance(value, str):
        return ''
    if len(value) > MAX_VENDOR_TEXT or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise FederationError('Unexpected vendor text in inventory')
    return value


def display_flag(value: object) -> int:
    """Return the CAM console-login flag; the vendor field is numeric, not text."""
    if type(value) is not int or value not in (0, 1):
        raise FederationError('Unexpected vendor flag in inventory')
    return value


def display_hosts(value: object) -> list[str]:
    """Return a bounded list of address literals from a cloud inventory record."""
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_VENDOR_TEXT:
        raise FederationError('Unexpected vendor address list in inventory')
    hosts: list[str] = []
    for item in value:
        if not isinstance(item, str) or not re.fullmatch(VENDOR_HOST_PATTERN, item):
            raise FederationError('Unexpected vendor address in inventory')
        hosts.append(item)
    return hosts


class Cloud:
    def __init__(
        self,
        secret_id: str,
        secret_key: str,
        region: str = 'ap-singapore',
        max_users: int = DEFAULT_MAX_CAM_USERS,
    ) -> None:
        from tencentcloud.cam.v20190116.cam_client import CamClient
        from tencentcloud.common.credential import Credential
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile

        validate_region(region)
        if isinstance(max_users, bool) or not isinstance(max_users, int):
            raise ValueError('CAM sub-user bound must be an integer')
        if not 1 <= max_users <= MAX_CAM_USERS_CEILING:
            raise ValueError(f'CAM sub-user bound must be 1..{MAX_CAM_USERS_CEILING}')
        self.max_users = max_users
        self.credential = Credential(secret_id, secret_key)
        self.region = region
        self.cam = CamClient(self.credential, region, ClientProfile(httpProfile=HttpProfile(endpoint='cam.intl.tencentcloudapi.com', reqTimeout=15)))

    @staticmethod
    def call(function: Any, request: Any) -> Any:
        try:
            return function(request)
        except Exception:  # noqa: BLE001 - never forward error text
            # SDK error text may echo request or credential material; never forward it.
            raise FederationError('Cloud operation failed; inspect permissions and sanitized audit records') from None

    def keys(self, target: object) -> list[dict[str, str]]:
        """Return a validated, duplicate-free CAM access-key inventory.

        Retirement decisions read this list, so a malformed or repeated record must
        fail loudly rather than collapse into a wrong key state.
        """
        from tencentcloud.cam.v20190116.models import ListAccessKeysRequest

        req = ListAccessKeysRequest()
        req.TargetUin = uin(target)
        result = self.call(self.cam.ListAccessKeys, req)
        records = getattr(result, 'AccessKeys', None) or []
        if not isinstance(records, list) or len(records) > MAX_CAM_KEYS:
            raise FederationError('Invalid or oversized CAM key inventory')
        inventory: list[dict[str, str]] = []
        seen: set[str] = set()
        for record in records:
            identifier = getattr(record, 'AccessKeyId', None)
            status = getattr(record, 'Status', None)
            description = getattr(record, 'Description', None)
            if (
                not isinstance(identifier, str)
                or not re.fullmatch(KEY_ID_PATTERN, identifier)
                or status not in KEY_STATUSES
                or identifier in seen
                or not isinstance(description, (str, type(None)))
            ):
                raise FederationError('Invalid or repeated CAM key record')
            seen.add(identifier)
            inventory.append({'id': identifier, 'status': status, 'description': description or ''})
        return inventory

    def create_key(self, target: object, operation: str) -> tuple[str, str]:
        if not isinstance(operation, str) or not re.fullmatch(r'[a-f0-9]{32}', operation):
            raise ValueError('Invalid rotation operation')
        self.assert_subuser(target)
        from tencentcloud.cam.v20190116.models import CreateAccessKeyRequest

        req = CreateAccessKeyRequest()
        req.TargetUin = uin(target)
        req.Description = 'psm-rotation:' + operation
        key = self.call(self.cam.CreateAccessKey, req).AccessKey
        if not key or not key.AccessKeyId or not key.SecretAccessKey:
            raise FederationError('Invalid key creation response; reconcile cloud inventory before retry')
        return key.AccessKeyId, key.SecretAccessKey

    def set_key_status(self, target: object, secret_id: str, status: str) -> None:
        if status not in ('Active', 'Inactive') or not is_identifier(secret_id, 1, MAX_CREDENTIAL_ID_LEN):
            raise ValueError('Invalid key transition')
        self.assert_subuser(target)
        from tencentcloud.cam.v20190116.models import UpdateAccessKeyRequest

        req = UpdateAccessKeyRequest()
        req.TargetUin = uin(target)
        req.AccessKeyId = secret_id
        req.Status = status
        self.call(self.cam.UpdateAccessKey, req)

    def users(self) -> list[Any]:
        from tencentcloud.cam.v20190116.models import ListUsersRequest

        users = self.call(self.cam.ListUsers, ListUsersRequest()).Data
        if not isinstance(users, list) or len(users) > self.max_users:
            # Naming the bound and the knob makes this actionable rather than a dead end.
            raise FederationError(
                f'CAM inventory exceeds the configured bound of {self.max_users} sub-users; '
                'raise PSM_TC_MAX_CAM_USERS deliberately and expect a larger response'
            )
        seen: set[str] = set()
        for user in users:
            target = str(uin(user.Uin))
            if target in seen:
                raise FederationError('Duplicate CAM inventory identity')
            seen.add(target)
        return users

    def assert_subuser(self, target: object) -> None:
        target = str(uin(target))
        users = self.users()
        if target not in {str(uin(user.Uin)) for user in users}:
            raise FederationError('Target must be a listed CAM sub-user; root keys are not managed')

    def verify(self, secret_id: str, secret_key: str, target: object) -> bool:
        target = str(uin(target))
        from tencentcloud.common.credential import Credential
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile
        from tencentcloud.sts.v20180813 import models, sts_client

        client = sts_client.StsClient(Credential(secret_id, secret_key), self.region,
            ClientProfile(httpProfile=HttpProfile(endpoint='sts.intl.tencentcloudapi.com', reqTimeout=15)))
        identity = self.call(client.GetCallerIdentity, models.GetCallerIdentityRequest())
        if str(identity.UserId) != target:
            raise FederationError('Credential belongs to a different identity')
        return True

    def discover(self, regions: list[str] | tuple[str, ...]) -> dict[str, list[dict[str, Any]]]:
        # Preflight every region before any inventory request.
        if not isinstance(regions, (list, tuple)) or not 1 <= len(regions) <= 20:
            raise ValueError('Supply 1..20 explicit regions')
        for region in regions:
            validate_region(region)
        if len(set(regions)) != len(regions):
            raise ValueError('Duplicate inventory region')
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile
        from tencentcloud.cvm.v20170312 import cvm_client, models

        users = self.users()
        inventory: dict[str, list[dict[str, Any]]] = {'users': [], 'instances': []}
        for user in users:
            inventory['users'].append({'uin': str(user.Uin), 'name': display_text(user.Name),
                'console_login': display_flag(user.ConsoleLogin), 'keys': self.keys(user.Uin)})
        for region in regions:
            client = cvm_client.CvmClient(self.credential, region,
                ClientProfile(httpProfile=HttpProfile(endpoint='cvm.intl.tencentcloudapi.com', reqTimeout=15)))
            offset, expected = 0, None
            seen: set[str] = set()
            for _page in range(MAX_INVENTORY_PAGES):
                req = models.DescribeInstancesRequest()
                req.Offset = offset
                req.Limit = 100
                result = self.call(client.DescribeInstances, req)
                total = result.TotalCount
                batch = result.InstanceSet
                if batch is None and total == 0:
                    batch = []
                if type(total) is not int or not 0 <= total <= MAX_INVENTORY_INSTANCES or not isinstance(batch, list) or len(batch) > MAX_INVENTORY_PAGE_SIZE:
                    raise FederationError('Invalid or oversized inventory page')
                if expected is not None and total != expected:
                    raise FederationError('Inventory changed during pagination; restart discovery')
                expected = total
                if offset + len(batch) > total or (not batch and offset < total):
                    raise FederationError('Incomplete inventory page')
                if len(inventory['instances']) + len(batch) > MAX_INVENTORY_INSTANCES:
                    raise FederationError('Inventory exceeds total record bound')
                for instance in batch:
                    identifier = instance.InstanceId
                    if not isinstance(identifier, str) or not re.fullmatch(r'ins-[A-Za-z0-9]+', identifier) or identifier in seen:
                        raise FederationError('Invalid or repeated inventory instance')
                    seen.add(identifier)
                    inventory['instances'].append({'id': identifier, 'region': region,
                        'name': display_text(instance.InstanceName), 'os': display_text(instance.OsName),
                        'private_ips': display_hosts(instance.PrivateIpAddresses),
                        'public_ips': display_hosts(instance.PublicIpAddresses),
                        'state': display_text(instance.InstanceState)})
                offset += len(batch)
                if offset == total:
                    break
            else:
                raise FederationError('Inventory exceeds page bound')
        return inventory
