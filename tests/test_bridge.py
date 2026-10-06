import base64
import hashlib
import hmac
import re
import unittest
from unittest.mock import patch, MagicMock
import time
from urllib.parse import parse_qs, urlsplit
from app import create_app
from federation import FederationError, assume_role, login_url, validate_destination


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.creds = dict(TmpSecretId='AKID-TEST', TmpSecretKey='fake-test-secret', Token='test+/=&token')
        self.calls = []
        def sts(*args):
            self.calls.append(args)
            return self.creds
        self.settings = {'profiles': {'readonly': dict(role_arn='qcs::cam::uin/123:roleName/ReadOnly',
            allowed_secret_ids=['broker-id'], destination='https://console.cloud.tencent.com/',
            duration_seconds=300, region='ap-guangzhou')}}
        self.app = create_app(self.settings, proxy_key='p' * 32, session_key='s' * 32, sts=sts)
        self.client = self.app.test_client()
        self.headers = {'X-PSM-Bridge-Key': 'p' * 32, 'X-PSM-Authenticated-User': 'PSMConnect'}

    def form(self):
        r = self.client.get('/', headers=self.headers, base_url='https://bridge.local')
        self.assertEqual(r.status_code, 200)
        csrf = re.search(r'name="csrf" value="([^"]+)"', r.text).group(1)
        return dict(csrf=csrf, secret_id='broker-id', secret_key='fake-broker-key', profile='readonly', audit_label='alice')

    def post(self, data):
        return self.client.post('/connect', data=data, headers=self.headers, base_url='https://bridge.local')

    def test_signature_and_encoding(self):
        url = login_url(self.creds, 'https://console.cloud.tencent.com/cvm?x=1&y=2', now=1700000000, nonce=67439)
        q = parse_qs(urlsplit(url).query)
        canonical = 'GETcloud.tencent.com/login/roleAccessCallback?action=roleLogin&nonce=67439&secretId=AKID-TEST&timestamp=1700000000'
        expected = base64.b64encode(hmac.new(b'fake-test-secret', canonical.encode(), hashlib.sha256).digest()).decode()
        self.assertEqual(q['signature'], [expected])
        self.assertEqual(q['token'], [self.creds['Token']])
        self.assertEqual(q['s_url'], ['https://console.cloud.tencent.com/cvm?x=1&y=2'])
        self.assertNotIn(self.creds['TmpSecretKey'], url)

    def test_open_redirect_rejected(self):
        for u in ['http://console.cloud.tencent.com/', 'https://console.cloud.tencent.com.evil.test/',
                  'https://evil.test/', 'https://user@console.cloud.tencent.com/', 'https://console.cloud.tencent.com:444/']:
            with self.assertRaises(FederationError):
                validate_destination(u)

    def test_requires_authenticated_proxy(self):
        self.assertEqual(self.client.get('/').status_code, 403)
        self.assertEqual(self.client.get('/', headers=self.headers, environ_overrides={'REMOTE_ADDR': '192.0.2.1'}).status_code, 403)

    def test_success(self):
        r = self.post(self.form())
        self.assertEqual(r.status_code, 303)
        self.assertTrue(r.headers['Location'].startswith('https://cloud.tencent.com/login/roleAccessCallback?'))
        self.assertEqual(self.calls[0][2], self.settings['profiles']['readonly']['role_arn'])
        self.assertEqual(self.calls[0][4], 300)
        self.assertEqual(r.headers['Cache-Control'], 'no-store')

    def test_csrf_replay(self):
        data = self.form()
        cookie = self.client.get_cookie('session', domain='bridge.local').value
        self.assertEqual(self.post(data).status_code, 303)
        self.client.set_cookie('session', cookie, domain='bridge.local')
        self.assertEqual(self.post(data).status_code, 403)
        self.assertEqual(len(self.calls), 1)

    def test_csrf_wrong(self):
        data = self.form(); data['csrf'] = 'wrong'
        self.assertEqual(self.post(data).status_code, 403)
        self.assertFalse(self.calls)

    def test_profile_and_key_allowlist(self):
        for name, value in [('profile', 'administrator'), ('secret_id', 'unapproved-id'), ('audit_label', 'bad/name')]:
            data = self.form(); data[name] = value
            self.assertEqual(self.post(data).status_code, 400)
        self.assertFalse(self.calls)

    def test_sts_error_redacted(self):
        def failure(*args):
            raise FederationError('SENSITIVE-SECRET')
        app = create_app(self.settings, proxy_key='p'*32, session_key='s'*32, sts=failure)
        self.client = app.test_client()
        r = self.post(self.form())
        self.assertEqual(r.status_code, 502)
        self.assertNotIn('SENSITIVE-SECRET', r.text)

    def test_actual_sdk_request_shape(self):
        response = MagicMock()
        response.ExpiredTime = int(time.time()) + 300
        for field, value in self.creds.items():
            setattr(response.Credentials, field, value)
        with patch('tencentcloud.sts.v20180813.sts_client.StsClient') as factory:
            factory.return_value.AssumeRole.return_value = response
            result = assume_role('broker-id', 'fake-key', 'qcs::cam::uin/123:roleName/ReadOnly', 'psm-alice-123', 300, 'ap-guangzhou')
            req = factory.return_value.AssumeRole.call_args.args[0]
            self.assertEqual(req.DurationSeconds, 300)
            self.assertEqual(req.RoleSessionName, 'psm-alice-123')
            self.assertEqual(result, self.creds)

    def test_sdk_errors_do_not_leak(self):
        with patch('tencentcloud.sts.v20180813.sts_client.StsClient') as factory:
            factory.return_value.AssumeRole.side_effect = Exception('FAKE-SENSITIVE-REQUEST')
            with self.assertRaisesRegex(FederationError, '^STS request failed$'):
                assume_role('broker-id', 'fake-key', 'role', 'test', 300, 'ap-guangzhou')

    def test_expiring_credentials_rejected(self):
        with patch('tencentcloud.sts.v20180813.sts_client.StsClient') as factory:
            factory.return_value.AssumeRole.return_value.ExpiredTime = int(time.time())
            with self.assertRaises(FederationError):
                assume_role('broker-id', 'fake-key', 'role', 'test', 300, 'ap-guangzhou')


if __name__ == '__main__':
    unittest.main()
