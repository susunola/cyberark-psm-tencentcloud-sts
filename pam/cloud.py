"""Tencent Cloud CAM/CVM helpers with explicit credentials and no debug logging."""

import re
from typing import Any

from federation import FederationError

UIN_PATTERN = re.compile(r"[0-9]{1,20}")
REGION_PATTERN = re.compile(r"[a-z]+-[a-z]+")
CAM_ENDPOINT = "cam.intl.tencentcloudapi.com"
STS_ENDPOINT = "sts.intl.tencentcloudapi.com"
CVM_ENDPOINT = "cvm.intl.tencentcloudapi.com"
REQUEST_TIMEOUT = 15
CVM_PAGE_LIMIT = 100


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
        if status not in ("Active", "Inactive") or not isinstance(secret_id, str) or not secret_id:
            raise ValueError("Invalid key transition")
        self.assert_subuser(target)
        req = UpdateAccessKeyRequest()
        req.TargetUin = uin(target)
        req.AccessKeyId = secret_id
        req.Status = status
        self.call(self.cam.UpdateAccessKey, req)

    def assert_subuser(self, target: Any) -> None:
        from tencentcloud.cam.v20190116.models import ListUsersRequest

        users = self.call(self.cam.ListUsers, ListUsersRequest()).Data or []
        if str(uin(target)) not in {str(user.Uin) for user in users}:
            raise FederationError("Target must be a listed CAM sub-user; root keys are not managed")

    def verify(self, secret_id: str, secret_key: str, target: Any) -> bool:
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
        if str(identity.UserId) != str(uin(target)):
            raise FederationError("Credential belongs to a different identity")
        return True

    def discover(self, regions: list[str]) -> dict[str, list[dict[str, Any]]]:
        from tencentcloud.cam.v20190116.models import ListUsersRequest
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile
        from tencentcloud.cvm.v20170312 import cvm_client, models

        # Validate every region before the first cloud call.
        if not isinstance(regions, list) or any(
            not isinstance(region, str) or not re.fullmatch(REGION_PATTERN, region) for region in regions
        ):
            raise ValueError("Invalid region")
        users = self.call(self.cam.ListUsers, ListUsersRequest()).Data or []
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
            while True:
                req = models.DescribeInstancesRequest()
                req.Offset = offset
                req.Limit = CVM_PAGE_LIMIT
                result = self.call(client.DescribeInstances, req)
                batch = result.InstanceSet or []
                if not batch and offset < result.TotalCount:
                    raise FederationError("Incomplete inventory page")
                for instance in batch:
                    inventory["instances"].append(
                        {
                            "id": instance.InstanceId,
                            "region": region,
                            "name": instance.InstanceName,
                            "os": instance.OsName,
                            "private_ips": instance.PrivateIpAddresses or [],
                            "public_ips": instance.PublicIpAddresses or [],
                            "state": instance.InstanceState,
                        }
                    )
                offset += len(batch)
                if offset >= result.TotalCount:
                    break
        return inventory
