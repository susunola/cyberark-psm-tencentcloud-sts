"""Cover remaining validation and failure-closed branches for core modules."""
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app import create_app, normalize_audit_label
from configuration import load_settings, validate_settings
from federation import FederationError, login_url, validate_destination
from security import (
    RedisTokenStore,
    TokenStore,
    TokenStoreError,
    configured_token_store,
    shared_environment,
)

SETTINGS = {
    'profiles': {
        'readonly': {
            'role_arn': 'qcs::cam::uin/123:roleName/ReadOnly',
            'allowed_secret_ids': ['broker-id'],
            'destination': 'https://console.tencentcloud.com/',
            'duration_seconds': 300,
            'region': 'ap-guangzhou',
        }
    }
}

HEADERS = {'X-PSM-Bridge-Key': 'p' * 32, 'X-PSM-Authenticated-User': 'tester'}


class ConfigurationCoverage(unittest.TestCase):
    def test_rejects_non_dict_and_wrong_top_keys(self):
        with self.assertRaises(ValueError):
            validate_settings([])
        with self.assertRaises(ValueError):
            validate_settings({'profiles': {}, 'extra': 1})
        with self.assertRaises(ValueError):
            validate_settings({'profiles': {}})

    def test_rejects_bad_profile_shapes(self):
        cases = [
            {'profiles': {'bad name!': SETTINGS['profiles']['readonly']}},
            {'profiles': {'ok': {'role_arn': 'x'}}},
            {'profiles': {'ok': {**SETTINGS['profiles']['readonly'], 'role_arn': 'not-an-arn'}}},
            {'profiles': {'ok': {**SETTINGS['profiles']['readonly'], 'duration_seconds': '300'}}},
            {'profiles': {'ok': {**SETTINGS['profiles']['readonly'], 'allowed_secret_ids': ['REPLACE']}}},
        ]
        for settings in cases:
            with self.subTest(settings=settings):
                with self.assertRaises(ValueError):
                    validate_settings(settings)

    def test_load_settings_rejects_oversize(self, tmp_path=None):
        root = Path(__file__).resolve().parent
        big = root / '_big_config.json'
        try:
            big.write_bytes(b'{"profiles":' + b'x' * (1024 * 1024 + 10) + b'}')
            with self.assertRaises(ValueError):
                load_settings(big)
        finally:
            if big.exists():
                big.unlink()


class FederationCoverage(unittest.TestCase):
    def test_destination_rejects_http_and_foreign_hosts(self):
        for url in ('http://console.tencentcloud.com/', 'https://evil.example.com/', 'https://console.tencentcloud.com@evil/', 'not-a-url'):
            with self.subTest(url=url):
                with self.assertRaises(FederationError):
                    validate_destination(url)

    def test_login_url_rejects_bad_nonce_timestamp(self):
        creds = {'TmpSecretId': 'AKID-x', 'TmpSecretKey': 'k', 'Token': 't'}
        dest = 'https://console.tencentcloud.com/'
        with self.assertRaises(FederationError):
            login_url(creds, dest, now=1, nonce=5)
        with self.assertRaises(FederationError):
            login_url(creds, dest, now=-1, nonce=10000)
        with self.assertRaises(FederationError):
            login_url({'TmpSecretId': '!', 'TmpSecretKey': 'k', 'Token': 't'}, dest, now=1, nonce=10000)


class SecurityCoverage(unittest.TestCase):
    def test_token_store_capacity_and_identity_binding(self):
        store = TokenStore(capacity=2, ttl=120, clock=lambda: 0.0)
        a = store.issue('alice')
        b = store.issue('bob')
        self.assertIsNotNone(a)
        self.assertIsNotNone(b)
        self.assertIsNone(store.issue('carol'))
        self.assertFalse(store.consume(a, 'bob'))
        self.assertTrue(store.consume(a, 'alice'))
        self.assertFalse(store.consume(a, 'alice'))

    def test_redis_store_validates_and_fails_closed(self):
        with self.assertRaises(ValueError):
            RedisTokenStore(MagicMock(), namespace='bad namespace!')
        with self.assertRaises(ValueError):
            RedisTokenStore(MagicMock(), capacity=0)
        client = MagicMock()
        client.eval.side_effect = RuntimeError('boom')
        store = RedisTokenStore(client)
        with self.assertRaises(TokenStoreError):
            store.issue('id')
        with self.assertRaises(TokenStoreError):
            store.consume('t', 'id')
        client.ping.side_effect = RuntimeError('down')
        with self.assertRaises(TokenStoreError):
            store.check()

    def test_configured_token_store_forwards_identity_capacity(self):
        store = configured_token_store({}, identity_capacity=5)
        self.assertIsInstance(store, TokenStore)
        self.assertEqual(store.identity_capacity, 5)
        # In-memory default still derives a bound when unset.
        self.assertEqual(configured_token_store({}).identity_capacity, min(3, 1000))

    def test_configured_token_store_requires_tls(self):
        self.assertIsInstance(configured_token_store({}), TokenStore)
        with self.assertRaises(ValueError):
            configured_token_store({'PSM_TC_REDIS_URL': 'redis://localhost:6379/0'})
        with self.assertRaises(ValueError):
            configured_token_store({'PSM_TC_REDIS_URL': 'rediss://localhost:6379/0?x=1'})

    def test_shared_environment_rejects_bad_json(self):
        root = Path(__file__).resolve().parent
        path = root / '_shared_bad.json'
        try:
            path.write_text('{"redis_url": "r", "namespace": "n", "session_key": "short", "ca_bundle": ""}')
            with self.assertRaises(ValueError):
                shared_environment({'PSM_TC_SHARED_CONFIG': str(path)})
            path.write_text('{"redis_url": "r", "namespace": "n"}')
            with self.assertRaises(ValueError):
                shared_environment({'PSM_TC_SHARED_CONFIG': str(path)})
        finally:
            if path.exists():
                path.unlink()


class AppCoverage(unittest.TestCase):
    def setUp(self):
        self.app = create_app(SETTINGS, proxy_key='p' * 32, session_key='s' * 32)
        self.client = self.app.test_client()

    def test_health_reports_unavailable_when_store_down(self):
        with patch('security.TokenStore.check', side_effect=TokenStoreError):
            response = self.client.get('/healthz', headers=HEADERS)
        self.assertEqual(response.status_code, 503)

    def test_identity_control_characters_rejected(self):
        headers = {**HEADERS, 'X-PSM-Authenticated-User': 'bad\x01user'}
        self.assertEqual(self.client.get('/', headers=headers).status_code, 403)

    def test_normalize_audit_label_bounds(self):
        with self.assertRaises(ValueError):
            normalize_audit_label('x')
        with self.assertRaises(ValueError):
            normalize_audit_label('x' * 300)
        self.assertEqual(normalize_audit_label('ok-user'), 'ok-user')
        self.assertRegex(normalize_audit_label('display name!'), r'^display-name-[0-9a-f]{16}$')

    def test_connect_rejects_invalid_label(self):
        response = self.client.get('/', headers=HEADERS)
        token = response.text.split('value="')[1].split('"')[0]
        data = {
            'csrf': token, 'secret_id': 'broker-id', 'secret_key': 'k',
            'profile': 'readonly', 'audit_label': 'x',
        }
        self.assertEqual(self.client.post('/connect', data=data, headers=HEADERS).status_code, 400)


if __name__ == '__main__':
    unittest.main()
