"""Regressions for the bridge identity guard and the issuance admission order."""

import re
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

from app import DEFAULT_ISSUANCE_SLOTS, MAX_ISSUANCE_SLOTS, create_app
from runtime import THREADS
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


class AdmissionCapacityTests(unittest.TestCase):
    """H2: burst submissions must queue briefly instead of being refused."""

    def credentials(self):
        return {"TmpSecretId": "AKID-TEMP", "TmpSecretKey": "fake-temp-key", "Token": "fake-token"}

    def submit(self, app, who):
        client = app.test_client()
        csrf = load_form(client, who)
        return client.post(
            "/connect", data=submitted_form(csrf), headers=headers(who), base_url="https://bridge.local"
        )

    def test_a_burst_is_absorbed_by_the_bounded_wait(self):
        """One slot, a slow STS, two callers: the second waits instead of failing.

        The regression this guards: with a non-blocking acquire, every caller beyond
        the slot count received 503, which PSM's form submission cannot recover from.
        The first caller is provably inside STS before the second is submitted, so
        the second can only succeed by waiting for the slot.
        """
        entered = threading.Event()
        gate = threading.Event()

        def slow_sts(*args):
            entered.set()
            gate.wait(timeout=10)
            return self.credentials()

        app = create_app(
            SETTINGS, proxy_key=KEY, session_key="s" * 32, sts=slow_sts,
            issuance_slots=1, issuance_wait=8,
        )
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.submit, app, "alice")
            self.assertTrue(entered.wait(timeout=5), "the first submission never reached STS")
            second = pool.submit(self.submit, app, "bob")
            time.sleep(0.05)  # let the second caller reach the slot wait
            gate.set()
            codes = sorted(future.result(timeout=15).status_code for future in (first, second))
        self.assertEqual(codes, [303, 303])

    def test_waiting_past_the_timeout_still_reports_busy(self):
        entered = threading.Event()
        release = threading.Event()

        def blocked_sts(*args):
            entered.set()
            release.wait(timeout=10)
            return self.credentials()

        app = create_app(
            SETTINGS, proxy_key=KEY, session_key="s" * 32, sts=blocked_sts,
            issuance_slots=1, issuance_wait=0.2,
        )
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                first = pool.submit(self.submit, app, "alice")
                self.assertTrue(entered.wait(timeout=5), "the first submission never reached STS")
                second = self.submit(app, "bob")
                self.assertEqual(second.status_code, 503)
                self.assertEqual(second.headers["Retry-After"], "5")
                release.set()  # let the first submission finish before joining it
                self.assertEqual(first.result(timeout=15).status_code, 303)
        finally:
            release.set()

    def test_the_default_slot_count_leaves_a_thread_for_health_checks(self):
        """The two numbers are tuned together; this keeps them from drifting."""
        self.assertLess(DEFAULT_ISSUANCE_SLOTS, THREADS)

    def test_admission_parameters_are_validated(self):
        for slots in (0, -1, MAX_ISSUANCE_SLOTS + 1, True, "3", None):
            with self.subTest(slots=slots), self.assertRaises(ValueError):
                create_app(SETTINGS, proxy_key=KEY, session_key="s" * 32, issuance_slots=slots)
        for wait in (-1, 61, True, "5", None):
            with self.subTest(wait=wait), self.assertRaises(ValueError):
                create_app(SETTINGS, proxy_key=KEY, session_key="s" * 32, issuance_wait=wait)


class SharedIdentityCapacityTests(unittest.TestCase):
    """H1: the per-identity bound counts identities, so a shared one needs headroom."""

    def four_sessions(self, app):
        clients, tokens = [], []
        for _ in range(4):
            client = app.test_client()
            clients.append(client)
            tokens.append(load_form(client))
        return [
            client.post(
                "/connect",
                data=submitted_form(token),
                headers=headers(),  # every session presents the same identity
                base_url="https://bridge.local",
            )
            for client, token in zip(clients, tokens, strict=True)
        ]

    def test_the_default_bound_evicts_an_earlier_session_when_the_identity_is_shared(self):
        """Documents why one Windows identity per person is a deployment prerequisite."""
        app = create_app(
            SETTINGS, proxy_key=KEY, session_key="s" * 32, sts=MagicMock(return_value=CREDENTIALS)
        )
        codes = [response.status_code for response in self.four_sessions(app)]
        self.assertEqual(codes, [403, 303, 303, 303])

    def test_a_raised_bound_supports_a_shared_identity(self):
        """The bound is configurable, so a shared-identity deployment can size it."""
        app = create_app(
            SETTINGS, proxy_key=KEY, session_key="s" * 32, sts=MagicMock(return_value=CREDENTIALS),
            identity_capacity=8,
        )
        codes = [response.status_code for response in self.four_sessions(app)]
        self.assertEqual(codes, [303, 303, 303, 303])


class RefusingIssuanceSlots:
    """Stand-in for the issuance semaphore that is always out of capacity."""

    def acquire(self, blocking=True, timeout=None):
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
