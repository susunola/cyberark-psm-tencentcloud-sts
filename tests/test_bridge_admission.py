"""Regressions for the bridge identity guard and the issuance admission order."""

import io
import json
import logging
import re
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch
from urllib.parse import urlsplit

from app import DEFAULT_ISSUANCE_SLOTS, MAX_ISSUANCE_SLOTS, create_app
from federation import FederationError
from runtime import THREADS, worker_threads
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
        # slots + one waiter + /livez
        self.assertEqual(worker_threads(DEFAULT_ISSUANCE_SLOTS), DEFAULT_ISSUANCE_SLOTS + 2)
        self.assertEqual(worker_threads(20), 22)
        self.assertGreaterEqual(THREADS, DEFAULT_ISSUANCE_SLOTS + 2)

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


class RejectionAuditTests(unittest.TestCase):
    """M2: a refused request must say why, and who presented which identity."""

    def events(self, action):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        audit = logging.getLogger('psm_tencent.audit')
        audit.addHandler(handler)
        previous = audit.level
        audit.setLevel(logging.INFO)
        try:
            client = create_app(
                SETTINGS, proxy_key=KEY, session_key='s' * 32, sts=MagicMock(return_value=CREDENTIALS)
            ).test_client()
            action(client)
        finally:
            audit.removeHandler(handler)
            audit.setLevel(previous)
        return [json.loads(line) for line in stream.getvalue().splitlines()]

    def csrf_token(self, client, who='alice'):
        return load_form(client, who)

    def test_each_refusal_carries_a_fixed_reason_code(self):
        def wrong_key(client):
            client.get('/', headers=headers(key='p' * 31), base_url='https://bridge.local')

        def smuggled_identity(client):
            client.get('/', headers=headers('mallory, alice'), base_url='https://bridge.local')

        def bad_csrf(client):
            client.post(
                '/connect', data=submitted_form('not-the-token'), headers=headers(), base_url='https://bridge.local'
            )

        def binding_mismatch(client):
            client.post(
                '/connect',
                data={**submitted_form(self.csrf_token(client)), 'profile': 'not-a-profile'},
                headers=headers(),
                base_url='https://bridge.local',
            )

        def oversized_form(client):
            client.post(
                '/connect',
                data={**submitted_form(self.csrf_token(client)), 'extra': '1'},
                headers=headers(),
                base_url='https://bridge.local',
            )

        for action, expected in (
            (wrong_key, 'proxy-key-rejected'),
            (smuggled_identity, 'identity-header-rejected'),
            (bad_csrf, 'csrf-rejected'),
            (binding_mismatch, 'binding-rejected'),
            (oversized_form, 'form-shape-rejected'),
        ):
            with self.subTest(expected=expected):
                failures = [row for row in self.events(action) if row.get('status', 0) >= 400]
                self.assertTrue(failures, 'no failed request was recorded')
                self.assertEqual(failures[-1]['reason'], expected)

    def test_a_smuggled_identity_is_recorded_but_a_malformed_one_is_not(self):
        # The smuggling value is printable and bounded, so triage needs to see it;
        # a control-character or oversized value is not echoed into the log.
        smuggled = [row for row in self.events(lambda c: c.get(
            '/', headers=headers('mallory, alice'), base_url='https://bridge.local'
        )) if row.get('status') == 403]
        self.assertEqual(smuggled[-1].get('proxy_identity'), 'mallory, alice')

        malformed = [row for row in self.events(lambda c: c.get(
            '/', headers=headers('x' * 300), base_url='https://bridge.local'
        )) if row.get('status') == 403]
        self.assertNotIn('proxy_identity', malformed[-1])

    def test_an_authenticated_refusal_names_the_identity_and_a_success_has_no_reason(self):
        def refused(client):
            client.post(
                '/connect', data=submitted_form('not-the-token'), headers=headers(), base_url='https://bridge.local'
            )

        failed = [row for row in self.events(refused) if row.get('status') >= 400]
        self.assertEqual(failed[-1]['proxy_identity'], 'alice')

        def succeeded(client):
            token = self.csrf_token(client)
            client.post(
                '/connect', data=submitted_form(token), headers=headers(), base_url='https://bridge.local'
            )

        rows = self.events(succeeded)
        issued = [row for row in rows if row.get('event') == 'role_session_issued']
        self.assertEqual(len(issued), 1)
        # A successful response carries no rejection reason.
        for row in rows:
            if row.get('event') == 'http_result':
                self.assertNotIn('reason', row)

    def test_the_audit_record_never_carries_the_credential(self):
        secret = 'fake-broker-key-' + 'x' * 20
        rows = self.events(lambda c: c.post(
            '/connect',
            data={
                'csrf': 'wrong',
                'profile': 'readonly',
                'secret_id': 'broker-id',
                'secret_key': secret,
                'audit_label': 'alice',
            },
            headers=headers(),
            base_url='https://bridge.local',
        ))
        rendered = json.dumps(rows)
        self.assertNotIn(secret, rendered)
        self.assertNotIn('broker-id', rendered)


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


class IssuanceMetricTests(unittest.TestCase):
    """The STS call is the slowest step of a login and the only one that leaves the host."""

    def rows(self, sts):
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        audit = logging.getLogger('psm_tencent.audit')
        audit.addHandler(handler)
        previous = audit.level
        audit.setLevel(logging.INFO)
        try:
            client = create_app(SETTINGS, proxy_key=KEY, session_key='s' * 32, sts=sts).test_client()
            client.post('/connect', data=submitted_form(load_form(client)), headers=headers(), base_url='https://bridge.local')
        finally:
            audit.removeHandler(handler)
            audit.setLevel(previous)
        return [json.loads(line) for line in stream.getvalue().splitlines()]

    def test_the_recorded_duration_is_the_measured_call(self):
        def slow(*_args):
            time.sleep(0.05)
            return CREDENTIALS

        rows = self.rows(slow)
        issued = [row for row in rows if row.get('event') == 'role_session_issued'][-1]
        self.assertGreaterEqual(issued['sts_ms'], 40)
        self.assertLess(issued['sts_ms'], 30000)
        result = [row for row in rows if row.get('event') == 'http_result'][-1]
        self.assertEqual(result['status'], 303)
        self.assertGreaterEqual(result['sts_ms'], 40)

    def test_a_failed_issuance_records_the_duration_and_a_fixed_reason(self):
        def failing(*_args):
            time.sleep(0.05)
            raise FederationError('STS request failed: ' + 'FAKE-SECRET-VENDOR-TEXT')

        rows = self.rows(failing)
        result = [row for row in rows if row.get('event') == 'http_result'][-1]
        self.assertEqual(result['status'], 502)
        self.assertEqual(result['reason'], 'issuance-failed')
        self.assertGreaterEqual(result['sts_ms'], 40)
        self.assertNotIn('FAKE-SECRET-VENDOR-TEXT', json.dumps(rows))


if __name__ == '__main__':
    unittest.main()
