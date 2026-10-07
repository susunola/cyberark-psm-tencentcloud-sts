import re
from federation import FederationError, validate_region


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
        validate_region(region)
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
        if not isinstance(operation, str) or not re.fullmatch(r'[a-f0-9]{32}', operation):
            raise ValueError('Invalid rotation operation')
        self.assert_subuser(target)
        from tencentcloud.cam.v20190116.models import CreateAccessKeyRequest
        req = CreateAccessKeyRequest(); req.TargetUin = uin(target); req.Description = 'psm-rotation:' + operation
        key = self.call(self.cam.CreateAccessKey, req).AccessKey
        if not key or not key.AccessKeyId or not key.SecretAccessKey:
            raise FederationError('Invalid key creation response; reconcile cloud inventory before retry')
        return key.AccessKeyId, key.SecretAccessKey

    def set_key_status(self, target, secret_id, status):
        if status not in ('Active', 'Inactive') or not isinstance(secret_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,256}', secret_id):
            raise ValueError('Invalid key transition')
        self.assert_subuser(target)
        from tencentcloud.cam.v20190116.models import UpdateAccessKeyRequest
        req = UpdateAccessKeyRequest(); req.TargetUin = uin(target); req.AccessKeyId = secret_id; req.Status = status
        self.call(self.cam.UpdateAccessKey, req)

    def users(self):
        from tencentcloud.cam.v20190116.models import ListUsersRequest
        users = self.call(self.cam.ListUsers, ListUsersRequest()).Data
        if not isinstance(users, list) or len(users) > 1000:
            raise FederationError('Invalid or oversized CAM inventory')
        seen = set()
        for user in users:
            target = str(uin(user.Uin))
            if target in seen:
                raise FederationError('Duplicate CAM inventory identity')
            seen.add(target)
        return users

    def assert_subuser(self, target):
        target = str(uin(target))
        users = self.users()
        if target not in {str(uin(user.Uin)) for user in users}:
            raise FederationError('Target must be a listed CAM sub-user; root keys are not managed')

    def verify(self, secret_id, secret_key, target):
        target = str(uin(target))
        from tencentcloud.common.credential import Credential
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile
        from tencentcloud.sts.v20180813 import sts_client, models
        client = sts_client.StsClient(Credential(secret_id, secret_key), self.region,
            ClientProfile(httpProfile=HttpProfile(endpoint='sts.intl.tencentcloudapi.com', reqTimeout=15)))
        identity = self.call(client.GetCallerIdentity, models.GetCallerIdentityRequest())
        if str(identity.UserId) != target:
            raise FederationError('Credential belongs to a different identity')
        return True

    def discover(self, regions):
        # Preflight every region before any inventory request.
        if not isinstance(regions, (list, tuple)) or not 1 <= len(regions) <= 20:
            raise ValueError('Supply 1..20 explicit regions')
        for region in regions:
            validate_region(region)
        if len(set(regions)) != len(regions):
            raise ValueError('Duplicate inventory region')
        from tencentcloud.cvm.v20170312 import cvm_client, models
        from tencentcloud.common.profile.client_profile import ClientProfile
        from tencentcloud.common.profile.http_profile import HttpProfile
        users = self.users()
        inventory = {'users': [], 'instances': []}
        for user in users:
            inventory['users'].append({'uin': str(user.Uin), 'name': user.Name,
                'console_login': user.ConsoleLogin, 'keys': self.keys(user.Uin)})
        for region in regions:
            client = cvm_client.CvmClient(self.credential, region,
                ClientProfile(httpProfile=HttpProfile(endpoint='cvm.intl.tencentcloudapi.com', reqTimeout=15)))
            offset, expected = 0, None
            seen = set()
            for page in range(100):
                req = models.DescribeInstancesRequest(); req.Offset = offset; req.Limit = 100
                result = self.call(client.DescribeInstances, req)
                total = result.TotalCount
                batch = result.InstanceSet
                if batch is None and total == 0:
                    batch = []
                if type(total) is not int or not 0 <= total <= 10000 or not isinstance(batch, list) or len(batch) > 100:
                    raise FederationError('Invalid or oversized inventory page')
                if expected is not None and total != expected:
                    raise FederationError('Inventory changed during pagination; restart discovery')
                expected = total
                if offset + len(batch) > total or (not batch and offset < total):
                    raise FederationError('Incomplete inventory page')
                if len(inventory['instances']) + len(batch) > 10000:
                    raise FederationError('Inventory exceeds total record bound')
                for instance in batch:
                    identifier = instance.InstanceId
                    if not isinstance(identifier, str) or not re.fullmatch(r'ins-[A-Za-z0-9]+', identifier) or identifier in seen:
                        raise FederationError('Invalid or repeated inventory instance')
                    seen.add(identifier)
                    inventory['instances'].append({'id': instance.InstanceId, 'region': region,
                        'name': instance.InstanceName, 'os': instance.OsName,
                        'private_ips': instance.PrivateIpAddresses or [],
                        'public_ips': instance.PublicIpAddresses or [], 'state': instance.InstanceState})
                offset += len(batch)
                if offset == total:
                    break
            else:
                raise FederationError('Inventory exceeds page bound')
        return inventory
