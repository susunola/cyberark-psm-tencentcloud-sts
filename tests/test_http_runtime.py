"""Real loopback HTTP tests. The TLS proxy and cloud response remain untested here."""
import re
import tempfile
import threading
import unittest
from pathlib import Path

import requests

from app import create_app
from configuration import load_settings
from runtime import make_server


class HttpRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        settings = {'profiles': {'readonly': {'role_arn':'qcs::cam::uin/123:roleName/ReadOnly',
            'allowed_secret_ids':['broker-id'], 'destination':'https://console.tencentcloud.com/',
            'duration_seconds':300, 'region':'ap-guangzhou'}}}
        def mock_sts(*args):
            return {'TmpSecretId':'AKID-TEST','TmpSecretKey':'fake-key','Token':'fake-token'}
        cls.app = create_app(settings, proxy_key='p'*32, session_key='s'*32, sts=mock_sts)
        cls.server = make_server(cls.app, port=0)
        cls.url = f'http://127.0.0.1:{cls.server.effective_port}'
        cls.stopping = threading.Event()
        cls.server_errors = []
        def run():
            try:
                while not cls.stopping.is_set():
                    cls.server.asyncore.loop(timeout=0.1, map=cls.server._map, count=1)
            except Exception as error:  # noqa: BLE001 - never forward error text
                cls.server_errors.append(error)
        cls.thread = threading.Thread(target=run, daemon=True)
        cls.thread.start()
        cls.headers = {'X-PSM-Bridge-Key':'p'*32,'X-PSM-Authenticated-User':'test-user'}

    @classmethod
    def tearDownClass(cls):
        cls.stopping.set()
        cls.thread.join(timeout=3)
        if cls.thread.is_alive():
            raise AssertionError('HTTP test server did not stop')
        cls.server.task_dispatcher.shutdown()
        cls.server.close()
        if cls.server_errors:
            raise AssertionError('HTTP test server failed') from cls.server_errors[0]

    def test_authentication_over_socket(self):
        denied = requests.get(self.url+'/healthz', timeout=3)
        self.assertEqual(denied.status_code,403)
        accepted = requests.get(self.url+'/healthz',headers=self.headers,timeout=3)
        self.assertEqual(accepted.status_code,200)
        self.assertEqual(accepted.json()['status'],'ok')

    def test_real_form_and_redirect(self):
        form = requests.get(self.url+'/', headers=self.headers, timeout=3)
        csrf = re.search(r'name="csrf" value="([^"]+)"',form.text).group(1)
        # Simulate forwarding from the TLS-terminating proxy. Secure cookies are never
        # automatically sent over HTTP; this manually forwards the test cookie to backend.
        cookie = form.cookies.get('session')
        headers = {**self.headers, 'Cookie':f'session={cookie}'}
        result = requests.post(self.url+'/connect', headers=headers, timeout=3,
            allow_redirects=False, data={'csrf':csrf,'profile':'readonly','secret_id':'broker-id',
            'secret_key':'fake-key','audit_label':'test-user'})
        self.assertEqual(result.status_code,303)
        self.assertTrue(result.headers['Location'].startswith('https://www.tencentcloud.com/login/roleAccessCallback?'))
        replay = requests.post(self.url+'/connect', headers=headers, timeout=3,
            allow_redirects=False, data={'csrf':csrf,'profile':'readonly','secret_id':'broker-id',
            'secret_key':'fake-key','audit_label':'test-user'})
        self.assertEqual(replay.status_code,403)

    def test_server_body_limit(self):
        result = requests.post(self.url+'/connect',headers=self.headers,data=b'x'*9000,timeout=3)
        self.assertEqual(result.status_code,413)


class ConfigurationLoadingTests(unittest.TestCase):
    def test_duplicate_fields_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'settings.json'
            path.write_text('{"profiles":{},"profiles":{}}')
            with self.assertRaisesRegex(ValueError,'Duplicate'):
                load_settings(path)

    def test_oversized_file_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'settings.json'
            path.write_bytes(b' '*(1024*1024+1))
            with self.assertRaisesRegex(ValueError,'size limit'):
                load_settings(path)


if __name__ == '__main__':
    unittest.main()
