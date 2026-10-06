from concurrent.futures import ThreadPoolExecutor
import re
import threading
import unittest
from app import create_app
from security import TokenStore


class TokenTests(unittest.TestCase):
    def test_replay_race_has_one_winner(self):
        tokens = TokenStore()
        token = tokens.issue('alice')
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: tokens.consume(token, 'alice'), range(100)))
        self.assertEqual(sum(results), 1)

    def test_identity_binding_preserves_original_owner(self):
        tokens = TokenStore()
        token = tokens.issue('alice')
        self.assertFalse(tokens.consume(token, 'bob'))
        self.assertTrue(tokens.consume(token, 'alice'))

    def test_capacity_and_expiration(self):
        now = [0]
        tokens = TokenStore(capacity=2, ttl=120, clock=lambda: now[0])
        a = tokens.issue('a'); tokens.issue('b')
        self.assertIsNone(tokens.issue('c'))
        now[0] = 120
        self.assertFalse(tokens.consume(a, 'a'))
        self.assertIsNotNone(tokens.issue('c'))

    def test_slow_sts_does_not_exhaust_health_workers(self):
        started = threading.Barrier(3)
        finish = threading.Event()
        settings = {'profiles': {'readonly': {'role_arn':'qcs::cam::uin/123:roleName/ReadOnly',
            'allowed_secret_ids':['broker-id'], 'destination':'https://console.tencentcloud.com/',
            'duration_seconds':300, 'region':'ap-guangzhou'}}}
        def slow_sts(*args):
            started.wait(timeout=5)
            finish.wait(timeout=5)
            return {'TmpSecretId':'AKID-TEST','TmpSecretKey':'fake-key','Token':'fake-token'}
        app = create_app(settings, proxy_key='p'*32, session_key='s'*32, sts=slow_sts)
        headers = {'X-PSM-Bridge-Key':'p'*32, 'X-PSM-Authenticated-User':'alice'}
        def connect():
            client = app.test_client()
            response = client.get('/', headers=headers, base_url='https://bridge.local')
            csrf = re.search(r'name="csrf" value="([^"]+)"',response.text).group(1)
            return client.post('/connect', headers=headers, base_url='https://bridge.local',data={
                'csrf':csrf,'profile':'readonly','secret_id':'broker-id','secret_key':'fake-key','audit_label':'alice'})
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = [pool.submit(connect) for _ in range(2)]
            try:
                started.wait(timeout=5)
                overloaded = connect()
                self.assertEqual(overloaded.status_code, 503)
                self.assertEqual(overloaded.headers['Retry-After'], '5')
                self.assertEqual(app.test_client().get('/healthz', headers=headers).status_code, 200)
            finally:
                finish.set()
            self.assertEqual([future.result(timeout=5).status_code for future in pending], [303,303])


if __name__ == '__main__':
    unittest.main()
