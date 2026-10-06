import base64
import hashlib
import hmac
import html
import io
import re
import time
import unittest
from contextlib import redirect_stderr
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

from app import create_app
from federation import FederationError, assume_role, login_url, validate_destination


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.creds = dict(TmpSecretId='AKID-TEST', TmpSecretKey='fake-test-secret', Token='test+/=&token')
        self.calls = []

        def sts(*args, **kwargs):
            self.calls.append((args, kwargs))
            return self.creds

        self.settings = {'profiles': {'readonly': dict(
            role_arn='qcs::cam::uin/123:roleName/ReadOnly',
            allowed_secret_ids=['broker-id'],
            destination='https://console.cloud.tencent.com/',
            duration_seconds=300,
            region='ap-guangzhou',
        )}}
        self.events = []

        def record(event, **fields):
            fields['event'] = event
            self.events.append(fields)

        self.app = create_app(
            self.settings, proxy_key='p' * 32, session_key='s' * 32, sts=sts, auditor=record
        )
        self.client = self.app.test_client()
        self.headers = {'X-PSM-Bridge-Key': 'p' * 32, 'X-PSM-Authenticated-User': 'PSMConnect'}

    def form(self):
        response = self.client.get('/', headers=self.headers, base_url='https://bridge.local')
        self.assertEqual(response.status_code, 200)
        csrf = re.search(r'name="csrf" value="([^"]+)"', response.text).group(1)
        return dict(csrf=csrf, secret_id='broker-id', secret_key='fake-broker-key', profile='readonly', audit_label='alice')

    def post(self, data):
        return self.client.post('/connect', data=data, headers=self.headers, base_url='https://bridge.local')

    def test_signature_and_encoding(self):
        url = login_url(self.creds, 'https://console.cloud.tencent.com/cvm?x=1&y=2', now=1700000000, nonce=67439)
        query = parse_qs(urlsplit(url).query)
        canonical = 'GETcloud.tencent.com/login/roleAccessCallback?action=roleLogin&nonce=67439&secretId=AKID-TEST&timestamp=1700000000'
        expected = base64.b64encode(hmac.new(b'fake-test-secret', canonical.encode(), hashlib.sha256).digest()).decode()
        self.assertEqual(query['signature'], [expected])
        self.assertEqual(query['algorithm'], ['sha256'])
        self.assertEqual(query['token'], [self.creds['Token']])
        self.assertEqual(query['s_url'], ['https://console.cloud.tencent.com/cvm?x=1&y=2'])
        self.assertNotIn(self.creds['TmpSecretKey'], url)
        self.assertNotIn('token=', canonical)

    def test_open_redirect_rejected(self):
        for url in [
            'http://console.cloud.tencent.com/',
            'https://console.cloud.tencent.com.evil.test/',
            'https://evil.test/',
            'https://user@console.cloud.tencent.com/',
            'https://console.cloud.tencent.com:444/',
            'https://console.cloud.tencent.com%2eevil.test/',
            'https://console.cloud.tencent.com/\\evil',
        ]:
            with self.assertRaises(FederationError):
                validate_destination(url)

    def test_requires_authenticated_proxy(self):
        self.assertEqual(self.client.get('/').status_code, 403)
        self.assertEqual(self.client.get('/', headers=self.headers, environ_overrides={'REMOTE_ADDR': '192.0.2.1'}).status_code, 403)
        self.assertEqual(self.client.get('/healthz', headers={'X-PSM-Bridge-Key': 'p' * 32}).status_code, 200)

    def test_success_posts_credentials_instead_of_location(self):
        response = self.post(self.form())
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('Location', response.headers)
        self.assertIn('https://cloud.tencent.com/login/roleAccessCallback', response.text)
        self.assertIn('name="token"', response.text)
        self.assertIn(self.creds['Token'], html.unescape(response.text))
        self.assertNotIn(self.creds['TmpSecretKey'], response.text)
        self.assertEqual(self.calls[0][0][2], self.settings['profiles']['readonly']['role_arn'])
        self.assertEqual(self.calls[0][0][4], 300)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
        self.assertIn("form-action https://cloud.tencent.com/login/roleAccessCallback", response.headers['Content-Security-Policy'])
        self.assertEqual(self.events[-1]['event'], 'connect_ok')
        self.assertNotIn('fake-broker-key', str(self.events))
        self.assertNotIn(self.creds['Token'], str(self.events))

    def test_get_compatibility_redirect(self):
        settings = {'submit_method': 'get', 'profiles': self.settings['profiles']}

        def sts(*args, **kwargs):
            return self.creds
        app = create_app(settings, proxy_key='p' * 32, session_key='s' * 32, sts=sts, auditor=lambda *a, **k: None)
        self.client = app.test_client()
        response = self.post(self.form())
        self.assertEqual(response.status_code, 303)
        self.assertTrue(response.headers['Location'].startswith('https://cloud.tencent.com/login/roleAccessCallback?'))
        self.assertNotIn(self.creds['TmpSecretKey'], response.headers['Location'])

    def test_csrf_replay(self):
        data = self.form()
        cookie = self.client.get_cookie('psm_tc_sid', domain='bridge.local').value
        self.assertEqual(self.post(data).status_code, 200)
        self.client.set_cookie('psm_tc_sid', cookie, domain='bridge.local')
        self.assertEqual(self.post(data).status_code, 403)
        self.assertEqual(len(self.calls), 1)

    def test_csrf_wrong(self):
        data = self.form()
        data['csrf'] = 'wrong'
        self.assertEqual(self.post(data).status_code, 403)
        self.assertFalse(self.calls)

    def test_profile_and_key_allowlist(self):
        for name, value in [('profile', 'administrator'), ('secret_id', 'unapproved-id'), ('audit_label', 'bad/name')]:
            data = self.form()
            data[name] = value
            self.assertEqual(self.post(data).status_code, 400)
        self.assertFalse(self.calls)

    def test_sts_error_redacted(self):
        def failure(*args, **kwargs):
            raise FederationError('SENSITIVE-SECRET', code='AuthFailure')

        def record(event, **fields):
            fields['event'] = event
            self.events.append(fields)

        app = create_app(self.settings, proxy_key='p' * 32, session_key='s' * 32, sts=failure, auditor=record)
        self.client = app.test_client()
        response = self.post(self.form())
        self.assertEqual(response.status_code, 502)
        self.assertNotIn('SENSITIVE-SECRET', response.text)
        self.assertEqual(self.events[-1]['error_code'], 'AuthFailure')
        self.assertNotIn('SENSITIVE-SECRET', str(self.events))

    def test_actual_sdk_request_shape(self):
        response = MagicMock()
        response.ExpiredTime = int(time.time()) + 300
        for field, value in self.creds.items():
            setattr(response.Credentials, field, value)
        with patch('tencentcloud.sts.v20180813.sts_client.StsClient') as factory:
            factory.return_value.AssumeRole.return_value = response
            result = assume_role(
                'broker-id', 'fake-key', 'qcs::cam::uin/123:roleName/ReadOnly', 'psm-alice-123', 300, 'ap-guangzhou',
                external_id='ext-id', session_policy='{"version":"2.0"}',
            )
            request = factory.return_value.AssumeRole.call_args.args[0]
            self.assertEqual(request.DurationSeconds, 300)
            self.assertEqual(request.RoleSessionName, 'psm-alice-123')
            self.assertEqual(request.ExternalId, 'ext-id')
            self.assertEqual(request.Policy, '{"version":"2.0"}')
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

    def test_keys_must_differ(self):
        with self.assertRaises(ValueError):
            create_app(self.settings, proxy_key='k' * 32, session_key='k' * 32)

    def test_audit_stream_has_no_secrets(self):
        def sts(*args, **kwargs):
            return self.creds
        app = create_app(self.settings, proxy_key='p' * 32, session_key='s' * 32, sts=sts)
        self.client = app.test_client()
        stream = io.StringIO()
        with redirect_stderr(stream):
            self.post(self.form())
        text = stream.getvalue()
        self.assertIn('connect_ok', text)
        self.assertNotIn('fake-broker-key', text)
        self.assertNotIn(self.creds['Token'], text)
        self.assertNotIn(self.creds['TmpSecretKey'], text)


if __name__ == '__main__':
    unittest.main()
