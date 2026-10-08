"""Bridge tests whose failure branches the end-to-end HTTP suites do not reach.

test_bridge.py and test_hardening.py drive the happy path and the main refusal paths over the
Flask test client, so the proxy guard, the hardened response headers and the connect-form
refusals here are re-expressed through create_app() rather than through removed internals.
This module also pins the audit-label edge cases, the startup contract of main() and the
validation of modules that app.py depends on.
"""

import hashlib
import io
import os
import re
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

from flask import Flask
from werkzeug.datastructures import MultiDict

from app import DEFAULT_ISSUANCE_SLOTS, DEFAULT_ISSUANCE_WAIT_SECONDS, create_app, main, normalize_audit_label
from federation import FederationError, login_url, validate_destination
from pam.files import private_output, read_json, save_json
from pam.planning import cvm_plan
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
PROFILE = SETTINGS['profiles']['readonly']
DESTINATION = PROFILE['destination']
PROXY_KEY = 'p' * 32
SESSION_KEY = 's' * 32
HEADERS = {'X-PSM-Bridge-Key': PROXY_KEY, 'X-PSM-Authenticated-User': 'PSMConnect'}
BASE_URL = 'https://bridge.local'
NOW = 1700000000
NONCE = 67439
CREDENTIALS = {'TmpSecretId': 'AKID-TEST', 'TmpSecretKey': 'fake-test-key', 'Token': 'fake-test-token'}
SKIP_REASON = 'Need known OS, explicit guest username and private IP'
STARTUP_ENVIRONMENT = {
    'PSM_TC_CONFIG': '/fake/settings.json',
    'PSM_TC_PROXY_KEY': PROXY_KEY,
    'PSM_TC_SESSION_KEY': SESSION_KEY,
}
STARTUP_MESSAGE = 'Bridge startup configuration invalid. Check service environment and settings.'
# The full policy is pinned as a literal so a weakened CSP fails here.
CSP_VALUE = (
    "default-src 'none'; form-action 'self' "
    'https://www.tencentcloud.com https://console.tencentcloud.com; '
    "frame-ancestors 'none'; base-uri 'none'"
)
SECURITY_HEADERS = {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'Content-Security-Policy': CSP_VALUE,
}
FRAMEWORK_HEADERS = {'Content-Type', 'Content-Length', 'Set-Cookie', 'Vary'}


def label_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()[:16]


class AuditLabelTests(unittest.TestCase):
    def test_readable_labels_pass_through_unchanged(self):
        for label in ('alice', 'ab', 'DOMAIN_user.name@example.com', 'team=ops=', 'a-b_c.d'):
            with self.subTest(label=label):
                self.assertEqual(normalize_audit_label(label), label)

    def test_unsafe_label_gets_readable_prefix_and_hash_suffix(self):
        label = 'DOMAIN\\alice'
        value = normalize_audit_label(label)
        self.assertEqual(value, 'DOMAIN-alice-' + label_hash(label))
        self.assertEqual(len(value), len('DOMAIN-alice') + 1 + 16)
        self.assertRegex(value, r'^[A-Za-z0-9_.@=-]{2,64}$')

    def test_label_without_any_safe_character_falls_back_to_user(self):
        for label in ('\\/', '中文', '  '):
            with self.subTest(label=label):
                value = normalize_audit_label(label)
                self.assertEqual(value, 'user-' + label_hash(label))

    def test_boundary_lengths_two_and_two_hundred_fifty_six_are_accepted(self):
        self.assertEqual(normalize_audit_label('ab'), 'ab')
        longest = normalize_audit_label('a' * 256)
        self.assertEqual(longest, 'a' * 40 + '-' + label_hash('a' * 256))
        self.assertLessEqual(len(longest), 64)

    def test_lengths_one_and_two_hundred_fifty_seven_are_rejected(self):
        for label in ('a', 'a' * 257):
            with self.subTest(length=len(label)), self.assertRaises(ValueError):
                normalize_audit_label(label)

    def test_non_string_input_is_rejected(self):
        for value in (None, 123, 1.5, b'alice', ['alice'], {'label': 'alice'}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_audit_label(value)

    def test_control_characters_are_rejected(self):
        for label in ('bad\nlabel', 'bad\tlabel', 'bad\x00label', 'a' * 255 + '\n'):
            with self.subTest(label=label), self.assertRaises(ValueError):
                normalize_audit_label(label)

    def test_label_is_stable_and_distinguishes_different_input(self):
        first = normalize_audit_label('DOMAIN\\alice')
        self.assertEqual(first, normalize_audit_label('DOMAIN\\alice'))
        # Distinct inputs cannot collide even when their readable prefixes are identical.
        self.assertNotEqual(first, normalize_audit_label('DOMAIN/alice'))


class ProxyGuardTests(unittest.TestCase):
    """Bridge key and proxy identity refusals, driven through the real Flask client.

    test_bridge.test_requires_authenticated_proxy covers a request with no proxy headers and
    a non-loopback peer, and test_coverage_gaps covers one control character in the identity.
    The remaining key and identity boundaries are pinned here.
    """

    def setUp(self):
        self.app = create_app(SETTINGS, proxy_key=PROXY_KEY, session_key=SESSION_KEY)
        self.client = self.app.test_client()

    def test_missing_or_wrong_bridge_key_is_rejected(self):
        for key in (None, '', 'q' * 32, PROXY_KEY[:-1]):
            headers = {'X-PSM-Authenticated-User': 'PSMConnect'}
            if key is not None:
                headers['X-PSM-Bridge-Key'] = key
            with self.subTest(key=key):
                response = self.client.get('/', headers=headers, base_url=BASE_URL)
                self.assertEqual(response.status_code, 403)

    def test_blank_over_long_or_control_character_identity_is_rejected(self):
        for identity in ('', '   ', 'u' * 257, 'bad\x01user', 'bad\x7fuser'):
            with self.subTest(identity=repr(identity[:8])):
                response = self.client.get('/', headers={**HEADERS, 'X-PSM-Authenticated-User': identity}, base_url=BASE_URL)
                self.assertEqual(response.status_code, 403)

    def test_identity_at_the_length_boundary_is_accepted(self):
        response = self.client.get('/', headers={**HEADERS, 'X-PSM-Authenticated-User': 'u' * 256}, base_url=BASE_URL)
        self.assertEqual(response.status_code, 200)


class SecurityHeaderTests(unittest.TestCase):
    """Exact hardened header set on both the success and the refusal path."""

    def setUp(self):
        self.app = create_app(SETTINGS, proxy_key=PROXY_KEY, session_key=SESSION_KEY)
        self.client = self.app.test_client()

    def assert_hardened(self, response):
        self.assertEqual(set(response.headers.keys()) - FRAMEWORK_HEADERS, set(SECURITY_HEADERS) | {'X-Request-ID'})
        for name, value in SECURITY_HEADERS.items():
            self.assertEqual(response.headers[name], value)
        self.assertRegex(response.headers['X-Request-ID'], r'^[0-9a-f]{32}$')
        self.assertNotIn('*', response.headers['Content-Security-Policy'])

    def test_success_response_carries_exactly_the_hardened_headers(self):
        response = self.client.get('/', headers=HEADERS, base_url=BASE_URL)
        self.assertEqual(response.status_code, 200)
        self.assert_hardened(response)

    def test_refused_request_carries_the_same_hardened_headers(self):
        response = self.client.get('/', base_url=BASE_URL)
        self.assertEqual(response.status_code, 403)
        self.assert_hardened(response)


class ConnectFormTests(unittest.TestCase):
    """Exact-form, secret key bound and allowlist refusals over the real Flask client.

    test_hardening.test_duplicate_and_unknown_fields already covers an unknown field and a
    repeated field with a different value; test_bridge.test_profile_and_key_allowlist covers
    both allowlists and a rejected audit label. Only the gaps are re-expressed here.
    """

    def setUp(self):
        self.calls = []

        def sts(*args):
            self.calls.append(args)
            return CREDENTIALS

        self.app = create_app(SETTINGS, proxy_key=PROXY_KEY, session_key=SESSION_KEY, sts=sts)
        self.client = self.app.test_client()

    def form(self):
        response = self.client.get('/', headers=HEADERS, base_url=BASE_URL)
        self.assertEqual(response.status_code, 200)
        return {
            'csrf': re.search(r'name="csrf" value="([^"]+)"', response.text).group(1),
            'secret_id': 'broker-id',
            'secret_key': 'fake-key',
            'profile': 'readonly',
            'audit_label': 'alice',
        }

    def post(self, data):
        return self.client.post('/connect', data=data, headers=HEADERS, base_url=BASE_URL)

    def test_missing_field_is_rejected_before_any_sts_call(self):
        for name in ('csrf', 'profile', 'secret_id', 'secret_key', 'audit_label'):
            data = self.form()
            del data[name]
            with self.subTest(missing=name):
                self.assertEqual(self.post(data).status_code, 400)
        self.assertFalse(self.calls)

    def test_repeated_field_is_rejected_even_when_identical(self):
        for name in ('csrf', 'profile'):
            data = MultiDict(self.form())
            data.add(name, data[name])
            with self.subTest(repeated=name):
                self.assertEqual(self.post(data).status_code, 400)
        self.assertFalse(self.calls)

    def test_secret_key_bounds_one_and_five_hundred_twelve_are_accepted(self):
        for value in ('k', 'k' * 512):
            self.calls.clear()
            data = self.form()
            data['secret_key'] = value
            with self.subTest(length=len(value)):
                self.assertEqual(self.post(data).status_code, 303)
            self.assertEqual(self.calls[0][1], value)

    def test_secret_key_outside_the_bounds_is_rejected(self):
        for value in ('', 'k' * 513):
            data = self.form()
            data['secret_key'] = value
            with self.subTest(length=len(value)):
                self.assertEqual(self.post(data).status_code, 400)
        self.assertFalse(self.calls)


class StartupTests(unittest.TestCase):
    def setUp(self):
        # main() calls logging.basicConfig(); leaving the root logger configured makes
        # every later test print its audit events to stderr and buries real failures.
        patch('app.logging.basicConfig').start()
        self.addCleanup(patch.stopall)

    def test_short_proxy_or_session_key_is_rejected(self):
        for proxy_key, session_key in (('short-key', SESSION_KEY), (PROXY_KEY, 'short-key')):
            with self.subTest(proxy_key=proxy_key[:9]), self.assertRaisesRegex(ValueError, '32'):
                create_app(SETTINGS, proxy_key=proxy_key, session_key=session_key)

    def test_exhausted_issuance_capacity_returns_rate_limit(self):
        store = MagicMock()
        store.issue.return_value = None
        app = create_app(SETTINGS, proxy_key=PROXY_KEY, session_key=SESSION_KEY, token_store=store)
        client = app.test_client()
        response = client.get('/', headers=HEADERS, base_url=BASE_URL)
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers['Retry-After'], '120')
        self.assertIn('Too many pending connections', response.text)
        # No connect form, and therefore no CSRF token, is handed out on rejection.
        self.assertNotIn('name="csrf"', response.text)
        store.issue.assert_called_once_with('PSMConnect')

    def test_admission_and_identity_bounds_come_from_the_environment(self):
        """The two deployment-dependent numbers must be settable without a rebuild."""
        captured = {}

        def capture(settings, **kwargs):
            captured.update(kwargs)
            return MagicMock()

        environment = {
            'PSM_TC_CONFIG': 'settings.json',
            'PSM_TC_PROXY_KEY': PROXY_KEY,
            'PSM_TC_SESSION_KEY': SESSION_KEY,
            'PSM_TC_ISSUANCE_SLOTS': '8',
            'PSM_TC_ISSUANCE_WAIT_SECONDS': '12.5',
            'PSM_TC_IDENTITY_CAPACITY': '32',
        }
        with (
            patch('app.shared_environment', return_value=environment),
            patch('app.load_settings', return_value=SETTINGS),
            patch('app.configured_token_store', return_value=MagicMock()),
            patch('app.create_app', side_effect=capture),
            patch('runtime.make_server', return_value=MagicMock()),
        ):
            main()
        self.assertEqual(captured['issuance_slots'], 8)
        self.assertEqual(captured['issuance_wait'], 12.5)
        self.assertEqual(captured['identity_capacity'], 32)

    def test_unset_or_invalid_admission_overrides_behave_predictably(self):
        """Unset means 'use the default'; a malformed value must fail startup, sanitized."""
        captured = {}

        def capture(settings, **kwargs):
            captured.update(kwargs)
            return MagicMock()

        base = {
            'PSM_TC_CONFIG': 'settings.json',
            'PSM_TC_PROXY_KEY': PROXY_KEY,
            'PSM_TC_SESSION_KEY': SESSION_KEY,
        }
        with (
            patch('app.shared_environment', return_value=dict(base)),
            patch('app.load_settings', return_value=SETTINGS),
            patch('app.configured_token_store', return_value=MagicMock()),
            patch('app.create_app', side_effect=capture),
            patch('runtime.make_server', return_value=MagicMock()),
        ):
            main()
        self.assertEqual(captured['issuance_slots'], DEFAULT_ISSUANCE_SLOTS)
        self.assertEqual(captured['issuance_wait'], DEFAULT_ISSUANCE_WAIT_SECONDS)
        self.assertIsNone(captured['identity_capacity'])

        for name, value in (
            ('PSM_TC_ISSUANCE_SLOTS', 'many'),
            ('PSM_TC_ISSUANCE_WAIT_SECONDS', 'soon'),
            ('PSM_TC_IDENTITY_CAPACITY', 'lots'),
        ):
            with (
                self.subTest(override=f'{name}={value}'),
                patch('app.shared_environment', return_value={**base, name: value}),
                patch('app.load_settings', return_value=SETTINGS),
                patch('app.configured_token_store', return_value=MagicMock()),
                self.assertRaises(SystemExit) as raised,
            ):
                main()
            self.assertEqual(str(raised.exception), STARTUP_MESSAGE)
            self.assertNotIn(value, str(raised.exception))

    def test_startup_failure_hides_the_cause_and_its_values(self):
        for error in (RuntimeError('FAKE-ENVIRONMENT-SECRET'), ValueError('FAKE-CONFIG-SECRET')):
            with (
                self.subTest(error=str(error)),
                patch('app.shared_environment', side_effect=error),
                self.assertRaises(SystemExit) as raised,
            ):
                main()
            message = str(raised.exception)
            self.assertEqual(message, STARTUP_MESSAGE)
            self.assertNotIn(str(error), message)
            self.assertTrue(raised.exception.__suppress_context__)

    def test_a_missing_environment_variable_is_named_without_exposing_values(self):
        environment = {key: value for key, value in STARTUP_ENVIRONMENT.items() if key != 'PSM_TC_PROXY_KEY'}
        with (
            patch('app.shared_environment', return_value=environment),
            patch('app.load_settings', return_value=SETTINGS),
            self.assertRaises(SystemExit) as raised,
        ):
            main()
        message = str(raised.exception)
        self.assertEqual(message, 'Bridge startup requires environment variable PSM_TC_PROXY_KEY.')
        self.assertNotIn(SESSION_KEY, message)
        self.assertTrue(raised.exception.__suppress_context__)

    def test_configuration_values_never_reach_the_startup_error(self):
        with (
            patch('app.shared_environment', return_value=STARTUP_ENVIRONMENT),
            patch('app.load_settings', side_effect=ValueError('FAKE-CONFIG-SECRET')),
            self.assertRaises(SystemExit) as raised,
        ):
            main()
        message = str(raised.exception)
        self.assertEqual(message, STARTUP_MESSAGE)
        for value in (*STARTUP_ENVIRONMENT.values(), 'FAKE-CONFIG-SECRET'):
            self.assertNotIn(value, message)

    def test_startup_success_runs_the_configured_server(self):
        server = MagicMock()
        # main() imports make_server inside the function, so the factory is patched there.
        with (
            patch('app.shared_environment', return_value=STARTUP_ENVIRONMENT) as environment,
            patch('app.load_settings', return_value=SETTINGS) as loader,
            patch('app.configured_token_store', return_value=TokenStore()) as token_store,
            patch('runtime.make_server', return_value=server) as factory,
        ):
            main()
        environment.assert_called_once()
        loader.assert_called_once_with(STARTUP_ENVIRONMENT['PSM_TC_CONFIG'])
        token_store.assert_called_once_with(STARTUP_ENVIRONMENT)
        factory.assert_called_once()
        self.assertIsInstance(factory.call_args.args[0], Flask)
        server.run.assert_called_once_with()


class FederationInputTests(unittest.TestCase):
    def test_bad_now_is_rejected(self):
        for now in ('1700000000', 0, -1, True, 1700000000.5):
            with (
                self.subTest(now=now),
                self.assertRaisesRegex(FederationError, 'Invalid timestamp'),
            ):
                login_url(CREDENTIALS, DESTINATION, now=now, nonce=NONCE)

    def test_bad_nonce_is_rejected(self):
        for nonce in (9999, 100000001, 0, -1, True, '67439', 67439.5):
            with (
                self.subTest(nonce=nonce),
                self.assertRaisesRegex(FederationError, 'Invalid nonce'),
            ):
                login_url(CREDENTIALS, DESTINATION, now=NOW, nonce=nonce)

    def test_nonce_bounds_are_inclusive(self):
        for nonce in (10000, 100000000):
            with self.subTest(nonce=nonce):
                url = login_url(CREDENTIALS, DESTINATION, now=NOW, nonce=nonce)
                self.assertEqual(parse_qs(urlsplit(url).query)['nonce'], [str(nonce)])

    def test_missing_credentials_are_rejected(self):
        for name in CREDENTIALS:
            creds = {key: value for key, value in CREDENTIALS.items() if key != name}
            with (
                self.subTest(missing=name),
                self.assertRaisesRegex(FederationError, 'Missing temporary credentials'),
            ):
                login_url(creds, DESTINATION, now=NOW, nonce=NONCE)

    def test_empty_or_non_string_credentials_are_rejected(self):
        for name in CREDENTIALS:
            for value in ('', None, 123, b'fake-bytes', [CREDENTIALS[name]]):
                with (
                    self.subTest(name=name, value=value),
                    self.assertRaisesRegex(FederationError, 'Missing temporary credentials'),
                ):
                    login_url({**CREDENTIALS, name: value}, DESTINATION, now=NOW, nonce=NONCE)

    def test_temporary_secret_id_outside_the_allowed_character_set_is_rejected(self):
        for secret_id in ('AKID&bad', 'AKID bad', 'AKID/bad', 'AKID+bad', 'AKID.bad'):
            creds = {**CREDENTIALS, 'TmpSecretId': secret_id}
            with (
                self.subTest(secret_id=secret_id),
                self.assertRaisesRegex(FederationError, 'Invalid temporary SecretId') as raised,
            ):
                login_url(creds, DESTINATION, now=NOW, nonce=NONCE)
            self.assertNotIn(secret_id, str(raised.exception))

    def test_destination_that_breaks_urlsplit_is_reported_as_federation_error(self):
        for url in ('https://[::1', 'https://[::1]:99999/', 'https://console.tencentcloud.com:abc/'):
            with self.subTest(url=url), self.assertRaises(FederationError) as raised:
                validate_destination(url)
            self.assertNotIsInstance(raised.exception, (ValueError, TypeError))


class JsonFileTests(unittest.TestCase):
    def test_neither_path_nor_stream_is_rejected(self):
        with self.assertRaisesRegex(ValueError, r'^Provide a JSON path or stream$'):
            read_json()

    def test_text_and_binary_streams_are_equivalent(self):
        self.assertEqual(read_json(stream=io.StringIO('{"a": 1}')), {'a': 1})
        self.assertEqual(read_json(stream=io.BytesIO(b'{"a": 1}')), {'a': 1})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'value.json'
            path.write_bytes(b'{"a": 1}')
            with path.open('rb') as handle:
                self.assertEqual(read_json(stream=handle), {'a': 1})

    def test_size_bound_accepts_the_limit_and_rejects_one_more(self):
        document = '{"a": 1}'
        self.assertEqual(read_json(stream=io.StringIO(document), limit=len(document)), {'a': 1})
        with self.assertRaisesRegex(ValueError, 'size bound'):
            read_json(stream=io.StringIO(document), limit=len(document) - 1)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'value.json'
            path.write_bytes(document.encode())
            self.assertEqual(read_json(path, limit=len(document)), {'a': 1})
            with self.assertRaisesRegex(ValueError, 'size bound'):
                read_json(path, limit=len(document) - 1)

    def test_utf8_bom_is_tolerated_for_paths_and_streams(self):
        document = b'\xef\xbb\xbf{"Bom": true}'
        self.assertEqual(read_json(stream=io.BytesIO(document)), {'Bom': True})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'bom.json'
            path.write_bytes(document)
            self.assertEqual(read_json(path), {'Bom': True})

    def test_duplicate_object_keys_are_rejected_from_a_path(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'duplicate.json'
            path.write_text('{"secret_key": "first", "secret_key": "second"}')
            with self.assertRaisesRegex(ValueError, 'Duplicate'):
                read_json(path)

    def test_private_output_is_owner_only_and_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'ticket.json'
            with private_output(path) as stream:
                save_json(stream, {'status': 'prepared', 'attempts': 1})
            if os.name == 'posix':
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            else:
                # Windows mode bits never carry an ACL, so 0600 expresses nothing there:
                # the documented control is a protected parent directory (SECURITY.md).
                # Exclusive creation and the surviving content are what the file itself
                # guarantees, and both are asserted here.
                self.assertGreater(path.stat().st_size, 0)
            self.assertEqual(read_json(path), {'status': 'prepared', 'attempts': 1})
            with self.assertRaises(FileExistsError):
                private_output(path)
            self.assertEqual(read_json(path), {'status': 'prepared', 'attempts': 1})


class CvmPlanTests(unittest.TestCase):
    def instance(self, **overrides):
        value = {
            'id': 'ins-1',
            'region': 'ap-guangzhou',
            'os': 'Ubuntu Linux',
            'private_ips': ['10.0.0.1'],
            'public_ips': [],
        }
        value.update(overrides)
        return value

    def plan(self, instances, usernames=None):
        return cvm_plan(
            {'instances': instances},
            'CloudSafe',
            'UnixPlatform',
            'WindowsPlatform',
            usernames if usernames is not None else {'ins-1': 'guest'},
        )

    def test_missing_safe_or_platform_is_rejected(self):
        inventory = {'instances': [self.instance()]}
        for args in (
            ('', 'UnixPlatform', 'WindowsPlatform'),
            ('CloudSafe', '', 'WindowsPlatform'),
            ('CloudSafe', 'UnixPlatform', ''),
        ):
            with self.subTest(missing=args.index('')), self.assertRaises(ValueError):
                cvm_plan(inventory, *args, {'ins-1': 'guest'})

    def test_unknown_os_missing_username_and_missing_private_ip_are_skipped(self):
        cases = {
            'unknown-os': (self.instance(os='FreeBSD 14.0'), {'ins-1': 'guest'}),
            'no-username': (self.instance(), {}),
            'no-private-ip': (self.instance(private_ips=[]), {'ins-1': 'guest'}),
            'no-os-field': (self.instance(os=None), {'ins-1': 'guest'}),
        }
        for name, (instance, usernames) in cases.items():
            with self.subTest(case=name):
                plan = self.plan([instance], usernames)
                self.assertEqual(plan['accounts'], [])
                self.assertEqual(plan['skipped'], [{'id': 'ins-1', 'reason': SKIP_REASON}])

    def test_windows_instance_uses_the_windows_platform_and_rdp(self):
        plan = self.plan([self.instance(os='Windows Server 2022')])
        account = plan['accounts'][0]
        self.assertEqual(account['platformId'], 'WindowsPlatform')
        self.assertEqual(account['connection_component'], 'PSM-RDP')
        self.assertEqual(plan['skipped'], [])

    def test_linux_instance_uses_the_linux_platform_and_ssh(self):
        for os_name in ('Ubuntu Linux', 'CentOS 7', 'Debian 12', 'Rocky Linux 9', 'SUSE Linux'):
            with self.subTest(os=os_name):
                account = self.plan([self.instance(os=os_name)])['accounts'][0]
                self.assertEqual(account['platformId'], 'UnixPlatform')
                self.assertEqual(account['connection_component'], 'PSM-SSH')

    def test_only_the_private_address_is_proposed(self):
        account = self.plan([self.instance(private_ips=['10.1.2.3'], public_ips=['203.0.113.9'])])
        self.assertEqual(account['accounts'][0]['address'], '10.1.2.3')
        self.assertNotIn('203.0.113.9', str(account))
        public_only = self.plan([self.instance(private_ips=[], public_ips=['203.0.113.9'])])
        self.assertEqual(public_only['accounts'], [])
        self.assertEqual(len(public_only['skipped']), 1)

    def test_first_private_address_that_is_not_an_ip_is_rejected(self):
        for address in ('not-an-ip', '10.0.0.999', '10.0.0.1/24'):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.plan([self.instance(private_ips=[address])])

    def test_account_name_is_region_plus_instance_id_and_scope_is_pinned(self):
        instance = self.instance(id='ins-9f2c', region='ap-singapore')
        account = self.plan([instance], {'ins-9f2c': 'guest'})['accounts'][0]
        self.assertEqual(account['name'], 'tc-ap-singapore-ins-9f2c')
        self.assertEqual(account['safeName'], 'CloudSafe')
        self.assertEqual(account['userName'], 'guest')
        self.assertEqual(account['secretType'], 'password')
        self.assertFalse(account['secretManagement']['automaticManagementEnabled'])


if __name__ == '__main__':
    unittest.main()
