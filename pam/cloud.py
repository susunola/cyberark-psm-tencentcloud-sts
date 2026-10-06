import re
from federation import FederationError


def uin(value):
    if not re.fullmatch(r'[0-9]{1,20}', str(value)) or int(value) <= 0:
        raise ValueError('Explicit positive target UIN required')
    return int(value)


class Cloud:
    def __init__(self, secret_id, secret_key, region='ap-singapore'):
        from tencentcloud.common.credential import Credential
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile
        from tencentcloud.cam.v20190116.cam_client import CamClient
        self.credential = Credential(secret_id, secret_key)
        self.region = region
        self.cam = CamClient(self.credential, region, ClientProfile(httpProfile=HttpProfile(endpoint='cam.intl.tencentcloudapi.com', reqTimeout=15)))

    @staticmethod
    def call(function, request):
        try:
            return function(request)
        except Exception:
            raise FederationError('Cloud operation failed; inspect permissions and sanitized audit records') from None

    def keys(self, target):
        from tencentcloud.cam.v20190116.models import ListAccessKeysRequest
        req = ListAccessKeysRequest(); req.TargetUin = uin(target)
        result = self.call(self.cam.ListAccessKeys, req)
        return [{'id': k.AccessKeyId, 'status': k.Status, 'description': k.Description or ''} for k in result.AccessKeys or []]

    def create_key(self, target, operation):
        self.assert_subuser(target)
        from tencentcloud.cam.v20190116.models import CreateAccessKeyRequest
        req = CreateAccessKeyRequest(); req.TargetUin = uin(target); req.Description = 'psm-rotation:' + operation
        key = self.call(self.cam.CreateAccessKey, req).AccessKey
        if not key or not key.AccessKeyId or not key.SecretAccessKey:
            raise FederationError('Invalid key creation response; reconcile cloud inventory before retry')
        return key.AccessKeyId, key.SecretAccessKey

    def set_key_status(self, target, secret_id, status):
        self.assert_subuser(target)
        from tencentcloud.cam.v20190116.models import UpdateAccessKeyRequest
        if status not in ('Active', 'Inactive') or not secret_id:
            raise ValueError('Invalid key transition')
        req = UpdateAccessKeyRequest(); req.TargetUin = uin(target); req.AccessKeyId = secret_id; req.Status = status
        self.call(self.cam.UpdateAccessKey, req)

    def assert_subuser(self, target):
        from tencentcloud.cam.v20190116.models import ListUsersRequest
        users = self.call(self.cam.ListUsers, ListUsersRequest()).Data or []
        if str(uin(target)) not in {str(user.Uin) for user in users}:
            raise FederationError('Target must be a listed CAM sub-user; root keys are not managed')

    def verify(self, secret_id, secret_key, target):
        from tencentcloud.common.credential import Credential
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile
        from tencentcloud.sts.v20180813 import sts_client, models
        client = sts_client.StsClient(Credential(secret_id, secret_key), self.region,
            ClientProfile(httpProfile=HttpProfile(endpoint='sts.intl.tencentcloudapi.com', reqTimeout=15)))
        identity = self.call(client.GetCallerIdentity, models.GetCallerIdentityRequest())
        if str(identity.UserId) != str(uin(target)):
            raise FederationError('Credential belongs to a different identity')
        return True

    def discover(self, regions):
        from tencentcloud.cam.v20190116.models import ListUsersRequest
        from tencentcloud.cvm.v20170312 import cvm_client, models
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile
        users = self.call(self.cam.ListUsers, ListUsersRequest()).Data or []
        inventory = {'users': [], 'instances': []}
        for user in users:
            inventory['users'].append({'uin': str(user.Uin), 'name': user.Name,
                'console_login': user.ConsoleLogin, 'keys': self.keys(user.Uin)})
        for region in regions:
            if not re.fullmatch(r'[a-z]+-[a-z]+', region):
                raise ValueError('Invalid region')
            client = cvm_client.CvmClient(self.credential, region,
                ClientProfile(httpProfile=HttpProfile(endpoint='cvm.intl.tencentcloudapi.com', reqTimeout=15)))
            offset = 0
            while True:
                req = models.DescribeInstancesRequest(); req.Offset = offset; req.Limit = 100
                result = self.call(client.DescribeInstances, req)
                batch = result.InstanceSet or []
                if not batch and offset < result.TotalCount:
                    raise FederationError('Incomplete inventory page')
                for instance in batch:
                    inventory['instances'].append({'id': instance.InstanceId, 'region': region,
                        'name': instance.InstanceName, 'os': instance.OsName,
                        'private_ips': instance.PrivateIpAddresses or [],
                        'public_ips': instance.PublicIpAddresses or [], 'state': instance.InstanceState})
                offset += len(batch)
                if offset >= result.TotalCount:
                    break
        return inventory
