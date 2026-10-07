"""Regressions for the bridge identity guard and the issuance admission order."""

import re
import threading
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

from app import create_app
from security import TokenStore

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
KEY = 'p' * 32
CREDENTIALS = {'TmpSecretId': 'AKID-TEMP', 'TmpSecretKey': 'fake-temp-key', 'Token': 'fake-token'}
FORM_FIELDS = ('csrf', 'profile', 'secret_id', 'secret_key', 'audit_label')


def headers(identity='alice', key=KEY):
    return {'X-PSM-Bridge-Key': key, 'X-PSM-Authenticated-User': identity}


def load_form(client, identity='alice'):
    page = client.get('/', headers=headers(identity), base_url='https://bridge.local')
    assert page.status_code == 200, page.status_code
    return re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)


def submitted_form(csrf):
    return {
        'csrf': csrf,
        'profile': 'readonly',
        'secret_id': 'broker-id',
        'secret_key': 'fake-broker-key',
        'audit_label': 'alice',
    }


class IdentityGuardTests(unittest.TestCase):
    def setUp(self):
        self.app = create_app(SETTINGS, proxy_key=KEY, session_key='s' * 32, sts=MagicMock(return_value=CREDENTIALS))
        self.client = self.app.test_client()

    def test_a_comma_joined_identity_is_refused(self):
        # waitress joins repeated headers with ", ", so an appended value would
        # otherwise enter the audit identity and the token binding key at once.
        for identity in ('mallory, alice', 'mallory,alice', 'alice,', ',alice'):
            with self.subTest(identity=identity):
                response = self.client.get('/', headers=headers(identity), base_url='https://bridge.local')
                self.assertEqual(response.status_code, 403)

    def test_surrounding_whitespace_is_not_a_valid_identity(self):
        for identity in (' alice', 'alice ', '\talice'):
            with self.subTest(identity=identity):
                response = self.client.get('/', headers=headers(identity), base_url='https://bridge.local')
                self.assertEqual(response.status_code, 403)

    def test_an_identity_with_an_inner_space_is_still_accepted(self):
        # Spaces are legal in Windows account names and are not a join artefact.
        response = self.client.get(
            '/', headers=headers(r'DOMAIN\Alice Smith'), base_url='https://bridge.local'
        )
        self.assertEqual(response.status_code, 200)


class RefusingIssuanceSlots:
    """Stand-in for the issuance semaphore that is always out of capacity."""

    def acquire(self, blocking=False):
        return False

    def release(self):  # pragma: no cover - a refused request must never release
        raise AssertionError('release() called without a matching acquire()')


class AdmissionOrderTests(unittest.TestCase):
    def test_a_busy_bridge_does_not_consume_the_token_or_the_session_cookie(self):
        """A 503 must leave the submitted form usable.

        The regression: the token was burned before admission control, so a busy
        bridge forced a form reload and re-entry of the SecretKey for no reason.
        """
        store = TokenStore()
        with patch.object(threading, 'BoundedSemaphore', return_value=RefusingIssuanceSlots()):
            busy_app = create_app(
                SETTINGS,
                proxy_key=KEY,
                session_key='s' * 32,
                sts=MagicMock(return_value=CREDENTIALS),
                token_store=store,
            )
        busy_client = busy_app.test_client()
        csrf = load_form(busy_client)
        refused = busy_client.post(
            '/connect', data=submitted_form(csrf), headers=headers(), base_url='https://bridge.local'
        )
        self.assertEqual(refused.status_code, 503)
        self.assertEqual(refused.headers['Retry-After'], '5')

        # A second node sharing the same token store, carrying the same session.
        ready_app = create_app(
            SETTINGS,
            proxy_key=KEY,
            session_key='s' * 32,
            sts=MagicMock(return_value=CREDENTIALS),
            token_store=store,
        )
        ready_client = ready_app.test_client()
        ready_client.set_cookie('session', busy_client.get_cookie('session', domain='bridge.local').value, domain='bridge.local')
        retry = ready_client.post(
            '/connect', data=submitted_form(csrf), headers=headers(), base_url='https://bridge.local'
        )
        self.assertEqual(retry.status_code, 303, retry.data)
        self.assertEqual(urlsplit(retry.headers['Location']).hostname, 'www.tencentcloud.com')
        self.assertNotIn('fake-broker-key', retry.headers['Location'])
        # The single-use token really was still available to the retry.
        self.assertFalse(store.consume(csrf, 'alice'))


if __name__ == '__main__':
    unittest.main()
