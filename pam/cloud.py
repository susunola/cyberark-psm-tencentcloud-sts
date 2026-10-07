"""Tencent Cloud CAM/CVM helpers with explicit credentials and no debug logging."""

import re
from typing import Any

from federation import FederationError, validate_region

UIN_PATTERN = re.compile(r"[0-9]{1,20}")
OPERATION_PATTERN = re.compile(r"[a-f0-9]{32}")
SECRET_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,256}")
INSTANCE_ID_PATTERN = re.compile(r"ins-[A-Za-z0-9]+")
CAM_ENDPOINT = "cam.intl.tencentcloudapi.com"
STS_ENDPOINT = "sts.intl.tencentcloudapi.com"
CVM_ENDPOINT = "cvm.intl.tencentcloudapi.com"
REQUEST_TIMEOUT = 15
MAX_CAM_USERS = 1000
MIN_DISCOVERY_REGIONS = 1
MAX_DISCOVERY_REGIONS = 20
CVM_PAGE_LIMIT = 100
MAX_CVM_PAGES = 100
MAX_INSTANCE_RECORDS = 10000
KEY_STATUSES = ("Active", "Inactive")


def uin(value: Any) -> int:
    if not re.fullmatch(UIN_PATTERN, str(value)) or int(value) <= 0:
        raise ValueError("Explicit positive target UIN required")
    return int(value)


class Cloud:
    def __init__(self, secret_id: str, secret_key: str, region: str = "ap-singapore"):
        from tencentcloud.cam.v20190116.cam_client import CamClient
        from tencentcloud.common.credential import Credential
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile

        validate_region(region)
        self.credential = Credential(secret_id, secret_key)
        self.region = region
        self.cam = CamClient(
            self.credential,
            region,
            ClientProfile(httpProfile=HttpProfile(endpoint=CAM_ENDPOINT, reqTimeout=REQUEST_TIMEOUT)),
        )

    @staticmethod
    def call(function: Any, request: Any) -> Any:
        try:
            return function(request)
        except Exception:  # noqa: BLE001 - SDK text may echo request credentials
            raise FederationError(
                "Cloud operation failed; inspect permissions and sanitized audit records"
            ) from None

    def keys(self, target: Any) -> list[dict[str, str]]:
        from tencentcloud.cam.v20190116.models import ListAccessKeysRequest

        req = ListAccessKeysRequest()
        req.TargetUin = uin(target)
        result = self.call(self.cam.ListAccessKeys, req)
        return [
            {"id": k.AccessKeyId, "status": k.Status, "description": k.Description or ""}
            for k in result.AccessKeys or []
        ]

    def create_key(self, target: Any, operation: str) -> tuple[str, str]:
        from tencentcloud.cam.v20190116.models import CreateAccessKeyRequest

        # Validate before any cloud call: invalid input must never reach CAM.
        if not isinstance(operation, str) or not re.fullmatch(OPERATION_PATTERN, operation):
            raise ValueError("Invalid rotation operation")
        self.assert_subuser(target)
        req = CreateAccessKeyRequest()
        req.TargetUin = uin(target)
        req.Description = "psm-rotation:" + operation
        key = self.call(self.cam.CreateAccessKey, req).AccessKey
        if not key or not key.AccessKeyId or not key.SecretAccessKey:
            raise FederationError("Invalid key creation response; reconcile cloud inventory before retry")
        return key.AccessKeyId, key.SecretAccessKey

    def set_key_status(self, target: Any, secret_id: str, status: str) -> None:
        from tencentcloud.cam.v20190116.models import UpdateAccessKeyRequest

        # Validate before any cloud call: invalid input must never reach CAM.
        if (
            status not in KEY_STATUSES
            or not isinstance(secret_id, str)
            or not re.fullmatch(SECRET_ID_PATTERN, secret_id)
        ):
            raise ValueError("Invalid key transition")
        self.assert_subuser(target)
        req = UpdateAccessKeyRequest()
        req.TargetUin = uin(target)
        req.AccessKeyId = secret_id
        req.Status = status
        self.call(self.cam.UpdateAccessKey, req)

    def users(self) -> list[Any]:
        """Return a bounded, duplicate-free CAM user inventory."""
        from tencentcloud.cam.v20190116.models import ListUsersRequest

        users = self.call(self.cam.ListUsers, ListUsersRequest()).Data
        if not isinstance(users, list) or len(users) > MAX_CAM_USERS:
            raise FederationError("Invalid or oversized CAM inventory")
        seen: set[str] = set()
        for user in users:
            target = str(uin(user.Uin))
            if target in seen:
                raise FederationError("Duplicate CAM inventory identity")
            seen.add(target)
        return users

    def assert_subuser(self, target: Any) -> None:
        target = str(uin(target))
        users = self.users()
        if target not in {str(uin(user.Uin)) for user in users}:
            raise FederationError("Target must be a listed CAM sub-user; root keys are not managed")

    def verify(self, secret_id: str, secret_key: str, target: Any) -> bool:
        target = str(uin(target))
        from tencentcloud.common.credential import Credential
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile
        from tencentcloud.sts.v20180813 import models, sts_client

        client = sts_client.StsClient(
            Credential(secret_id, secret_key),
            self.region,
            ClientProfile(httpProfile=HttpProfile(endpoint=STS_ENDPOINT, reqTimeout=REQUEST_TIMEOUT)),
        )
        identity = self.call(client.GetCallerIdentity, models.GetCallerIdentityRequest())
        if str(identity.UserId) != target:
            raise FederationError("Credential belongs to a different identity")
        return True

    @staticmethod
    def _inventory_page(result: Any) -> tuple[int, list[Any]]:
        """Return a validated (total, batch) pair for one CVM inventory page."""
        total = result.TotalCount
        batch = result.InstanceSet
        if batch is None and total == 0:
            batch = []
        if (
            type(total) is not int
            or not 0 <= total <= MAX_INSTANCE_RECORDS
            or not isinstance(batch, list)
            or len(batch) > CVM_PAGE_LIMIT
        ):
            raise FederationError("Invalid or oversized inventory page")
        return total, batch

    @staticmethod
    def _instance_entry(instance: Any, region: str, seen: set[str]) -> dict[str, Any]:
        """Map one instance to an inventory record, rejecting bad or repeated IDs."""
        identifier = instance.InstanceId
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(INSTANCE_ID_PATTERN, identifier)
            or identifier in seen
        ):
            raise FederationError("Invalid or repeated inventory instance")
        seen.add(identifier)
        return {
            "id": identifier,
            "region": region,
            "name": instance.InstanceName,
            "os": instance.OsName,
            "private_ips": instance.PrivateIpAddresses or [],
            "public_ips": instance.PublicIpAddresses or [],
            "state": instance.InstanceState,
        }

    def discover(self, regions: list[str]) -> dict[str, list[dict[str, Any]]]:
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile
        from tencentcloud.cvm.v20170312 import cvm_client, models

        # Preflight every region before any inventory request.
        if (
            not isinstance(regions, (list, tuple))
            or not MIN_DISCOVERY_REGIONS <= len(regions) <= MAX_DISCOVERY_REGIONS
        ):
            raise ValueError("Supply 1..20 explicit regions")
        for region in regions:
            validate_region(region)
        if len(set(regions)) != len(regions):
            raise ValueError("Duplicate inventory region")
        users = self.users()
        inventory: dict[str, list[dict[str, Any]]] = {"users": [], "instances": []}
        for user in users:
            inventory["users"].append(
                {
                    "uin": str(user.Uin),
                    "name": user.Name,
                    "console_login": user.ConsoleLogin,
                    "keys": self.keys(user.Uin),
                }
            )
        for region in regions:
            client = cvm_client.CvmClient(
                self.credential,
                region,
                ClientProfile(httpProfile=HttpProfile(endpoint=CVM_ENDPOINT, reqTimeout=REQUEST_TIMEOUT)),
            )
            offset = 0
            expected: int | None = None
            seen: set[str] = set()
            for _page in range(MAX_CVM_PAGES):
                req = models.DescribeInstancesRequest()
                req.Offset = offset
                req.Limit = CVM_PAGE_LIMIT
                total, batch = self._inventory_page(self.call(client.DescribeInstances, req))
                if expected is not None and total != expected:
                    raise FederationError("Inventory changed during pagination; restart discovery")
                expected = total
                if offset + len(batch) > total or (not batch and offset < total):
                    raise FederationError("Incomplete inventory page")
                if len(inventory["instances"]) + len(batch) > MAX_INSTANCE_RECORDS:
                    raise FederationError("Inventory exceeds total record bound")
                for instance in batch:
                    inventory["instances"].append(self._instance_entry(instance, region, seen))
                offset += len(batch)
                if offset == total:
                    break
            else:
                raise FederationError("Inventory exceeds page bound")
        return inventory
