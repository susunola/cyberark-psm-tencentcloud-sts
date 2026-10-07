"""Direct unit tests for bridge helpers whose failure branches HTTP tests cannot reach."""

import hashlib
import io
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlsplit

from flask import Flask, session
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import BadRequest, Forbidden

from app import (
    FORM_FIELDS,
    consume_session_token,
    create_app,
    issue_login_url,
    main,
    normalize_audit_label,
    read_form,
    resolve_request,
    security_headers,
    verify_proxy_peer,
)
from federation import FederationError, login_url, validate_destination
from pam.files import private_output, read_json, save_json
from pam.planning import cvm_plan
from security import TokenStore

SETTINGS = {
    "profiles": {
        "readonly": {
            "role_arn": "qcs::cam::uin/123:roleName/ReadOnly",
            "allowed_secret_ids": ["broker-id"],
            "destination": "https://console.tencentcloud.com/",
            "duration_seconds": 300,
            "region": "ap-guangzhou",
        }
    }
}
PROFILE = SETTINGS["profiles"]["readonly"]
DESTINATION = PROFILE["destination"]
PROXY_KEY = "p" * 32
NOW = 1700000000
NONCE = 67439
CREDENTIALS = {"TmpSecretId": "AKID-TEST", "TmpSecretKey": "fake-test-key", "Token": "fake-test-token"}
SKIP_REASON = "Need known OS, explicit guest username and private IP"
PEER_HEADERS = {"X-PSM-Bridge-Key": PROXY_KEY, "X-PSM-Authenticated-User": "PSMConnect"}
STARTUP_ENVIRONMENT = {
    "PSM_TC_CONFIG": "/fake/settings.json",
    "PSM_TC_PROXY_KEY": PROXY_KEY,
    "PSM_TC_SESSION_KEY": "s" * 32,
}

# Minimal real Flask app: request contexts need a secret key for session access.
CONTEXT_APP = Flask(__name__)
CONTEXT_APP.secret_key = "s" * 32


def context(*, remote_addr="127.0.0.1", **kwargs):
    """Open a request context; remote_addr=None mimics a request without REMOTE_ADDR."""
    overrides = {} if remote_addr is None else {"REMOTE_ADDR": remote_addr}
    return CONTEXT_APP.test_request_context("/", environ_overrides=overrides, **kwargs)


def raw_peer_context(identity, *, remote_addr="127.0.0.1", proxy_key=PROXY_KEY):
    """Open a context from a raw WSGI environ.

    Werkzeug's builder refuses to construct headers carrying CR/LF, so the peer
    guard is driven the way a forwarding proxy could deliver such a header.
    """
    environ = {
        "REQUEST_METHOD": "POST",
        "SCRIPT_NAME": "",
        "PATH_INFO": "/",
        "QUERY_STRING": "",
        "SERVER_NAME": "bridge.local",
        "SERVER_PORT": "443",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "REMOTE_ADDR": remote_addr,
        "wsgi.url_scheme": "https",
        "wsgi.input": io.BytesIO(b""),
        "wsgi.errors": io.StringIO(),
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
        "HTTP_X_PSM_BRIDGE_KEY": proxy_key,
        "HTTP_X_PSM_AUTHENTICATED_USER": identity,
    }
    return CONTEXT_APP.request_context(environ)


def label_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()[:16]


class AuditLabelTests(unittest.TestCase):
    def test_readable_labels_pass_through_unchanged(self):
        for label in ("alice", "ab", "DOMAIN_user.name@example.com", "team=ops=", "a-b_c.d"):
            with self.subTest(label=label):
                self.assertEqual(normalize_audit_label(label), label)

    def test_unsafe_label_gets_readable_prefix_and_hash_suffix(self):
        label = "DOMAIN\\alice"
        value = normalize_audit_label(label)
        self.assertEqual(value, "DOMAIN-alice-" + label_hash(label))
        self.assertEqual(len(value), len("DOMAIN-alice") + 1 + 16)
        self.assertRegex(value, r"^[A-Za-z0-9_.@=-]{2,64}$")

    def test_label_without_any_safe_character_falls_back_to_user(self):
        for label in ("\\/", "中文", "  "):
            with self.subTest(label=label):
                value = normalize_audit_label(label)
                self.assertEqual(value, "user-" + label_hash(label))

    def test_boundary_lengths_two_and_two_hundred_fifty_six_are_accepted(self):
        self.assertEqual(normalize_audit_label("ab"), "ab")
        longest = normalize_audit_label("a" * 256)
        self.assertEqual(longest, "a" * 40 + "-" + label_hash("a" * 256))
        self.assertLessEqual(len(longest), 64)

    def test_lengths_one_and_two_hundred_fifty_seven_are_rejected(self):
        for label in ("a", "a" * 257):
            with self.subTest(length=len(label)), self.assertRaises(ValueError):
                normalize_audit_label(label)

    def test_non_string_input_is_rejected(self):
        for value in (None, 123, 1.5, b"alice", ["alice"], {"label": "alice"}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_audit_label(value)

    def test_control_characters_are_rejected(self):
        for label in ("bad\nlabel", "bad\tlabel", "bad\x00label", "a" * 255 + "\n"):
            with self.subTest(label=label), self.assertRaises(ValueError):
                normalize_audit_label(label)

    def test_label_is_stable_and_distinguishes_different_input(self):
        first = normalize_audit_label("DOMAIN\\alice")
        self.assertEqual(first, normalize_audit_label("DOMAIN\\alice"))
        # Distinct inputs cannot collide even when their readable prefixes are identical.
        self.assertNotEqual(first, normalize_audit_label("DOMAIN/alice"))


class ProxyPeerTests(unittest.TestCase):
    def test_non_loopback_peer_is_rejected(self):
        for peer in ("192.0.2.1", "10.0.0.5", None):
            with (
                self.subTest(peer=peer),
                context(remote_addr=peer, headers=PEER_HEADERS),
                self.assertRaises(Forbidden),
            ):
                verify_proxy_peer(PROXY_KEY)

    def test_missing_or_wrong_bridge_key_is_rejected(self):
        for key in (None, "", "q" * 32, PROXY_KEY[:-1]):
            headers = {"X-PSM-Authenticated-User": "PSMConnect"}
            if key is not None:
                headers["X-PSM-Bridge-Key"] = key
            with (
                self.subTest(key=key),
                context(headers=headers),
                self.assertRaises(Forbidden),
            ):
                verify_proxy_peer(PROXY_KEY)

    def test_missing_blank_or_over_long_identity_is_rejected(self):
        for identity in (None, "", "   ", "u" * 257):
            headers = {"X-PSM-Bridge-Key": PROXY_KEY}
            if identity is not None:
                headers["X-PSM-Authenticated-User"] = identity
            with (
                self.subTest(identity=identity),
                context(headers=headers),
                self.assertRaises(Forbidden),
            ):
                verify_proxy_peer(PROXY_KEY)

    def test_identity_with_a_control_character_is_rejected(self):
        for identity in ("u\x01ser", "u\x7fser", "u\nser", "u\rser"):
            with (
                self.subTest(identity=repr(identity)),
                raw_peer_context(identity),
                self.assertRaises(Forbidden),
            ):
                verify_proxy_peer(PROXY_KEY)

    def test_loopback_peer_with_key_and_bounded_identity_passes(self):
        for peer in ("127.0.0.1", "::1"):
            with self.subTest(peer=peer), context(remote_addr=peer, headers=PEER_HEADERS):
                self.assertIsNone(verify_proxy_peer(PROXY_KEY))
        longest = {**PEER_HEADERS, "X-PSM-Authenticated-User": "u" * 256}
        with context(headers=longest):
            self.assertIsNone(verify_proxy_peer(PROXY_KEY))
        with raw_peer_context("u" * 256):
            self.assertIsNone(verify_proxy_peer(PROXY_KEY))


class SecurityHeaderTests(unittest.TestCase):
    def test_exact_header_set_and_content_security_policy(self):
        headers = security_headers("rid-1234")
        self.assertEqual(
            set(headers),
            {
                "Cache-Control",
                "Pragma",
                "Referrer-Policy",
                "X-Content-Type-Options",
                "X-Request-ID",
                "Content-Security-Policy",
            },
        )
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Pragma"], "no-cache")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Request-ID"], "rid-1234")
        policy = headers["Content-Security-Policy"]
        self.assertIn("default-src 'none'", policy)
        self.assertIn(
            "form-action 'self' https://www.tencentcloud.com https://console.tencentcloud.com", policy
        )
        self.assertIn("frame-ancestors 'none'", policy)
        self.assertIn("base-uri 'none'", policy)
        self.assertNotIn("*", policy)

    def test_request_id_is_echoed_verbatim(self):
        for request_id in ("", "0" * 32, "not-a-hex-id"):
            with self.subTest(request_id=request_id):
                self.assertEqual(security_headers(request_id)["X-Request-ID"], request_id)


class FormReadingTests(unittest.TestCase):
    def setUp(self):
        self.data = {
            "csrf": "fake-csrf",
            "profile": "readonly",
            "secret_id": "broker-id",
            "secret_key": "fake-key",
            "audit_label": "alice",
        }
        self.assertEqual(set(FORM_FIELDS), set(self.data))

    def test_exact_form_is_returned_verbatim(self):
        with context(method="POST", data=self.data):
            self.assertEqual(read_form(), self.data)

    def test_extra_or_missing_field_is_rejected(self):
        extra = {**self.data, "role_arn": "qcs::cam::uin/123:roleName/Admin"}
        missing = {name: value for name, value in self.data.items() if name != "csrf"}
        for data in (extra, missing):
            with (
                self.subTest(fields=sorted(data)),
                context(method="POST", data=data),
                self.assertRaises(BadRequest),
            ):
                read_form()

    def test_repeated_field_is_rejected_even_when_identical(self):
        repeated = MultiDict(self.data)
        repeated.add("profile", "administrator")
        with context(method="POST", data=repeated), self.assertRaises(BadRequest):
            read_form()
        doubled = MultiDict(self.data)
        doubled.add("csrf", "fake-csrf")
        with context(method="POST", data=doubled), self.assertRaises(BadRequest):
            read_form()


class SessionTokenTests(unittest.TestCase):
    def test_missing_session_token_or_mismatch_is_rejected(self):
        store = MagicMock()
        with context():
            session["csrf"] = "issued-token"
            with self.assertRaises(Forbidden):
                consume_session_token(store, "other-token", "PSMConnect")
        with context(), self.assertRaises(Forbidden):
            consume_session_token(store, "issued-token", "PSMConnect")
        store.consume.assert_not_called()

    def test_backend_refusal_is_rejected_and_the_session_token_is_burned(self):
        store = MagicMock()
        store.consume.return_value = False
        with context():
            session["csrf"] = "issued-token"
            with self.assertRaises(Forbidden):
                consume_session_token(store, "issued-token", "PSMConnect")
            store.consume.assert_called_once_with("issued-token", "PSMConnect")
            self.assertNotIn("csrf", session)

    def test_single_use_token_is_bound_and_burned(self):
        store = MagicMock()
        store.consume.return_value = True
        with context():
            session["csrf"] = "issued-token"
            self.assertIsNone(consume_session_token(store, "issued-token", "PSMConnect"))
            store.consume.assert_called_once_with("issued-token", "PSMConnect")
            self.assertNotIn("csrf", session)


class RequestResolutionTests(unittest.TestCase):
    def form(self, **overrides):
        data = {
            "csrf": "fake-csrf",
            "profile": "readonly",
            "secret_id": "broker-id",
            "secret_key": "fake-key",
            "audit_label": "alice",
        }
        data.update(overrides)
        return data

    def test_unknown_profile_and_unlisted_secret_id_are_rejected(self):
        for overrides in ({"profile": "administrator"}, {"secret_id": "unapproved-id"}):
            with (
                self.subTest(overrides=overrides),
                context(),
                self.assertRaises(BadRequest),
            ):
                resolve_request(SETTINGS["profiles"], self.form(**overrides))

    def test_empty_or_over_long_secret_key_is_rejected(self):
        for value in ("", "k" * 513):
            with self.subTest(length=len(value)), context(), self.assertRaises(BadRequest):
                resolve_request(SETTINGS["profiles"], self.form(secret_key=value))

    def test_invalid_audit_label_is_rejected(self):
        with context(), self.assertRaises(BadRequest):
            resolve_request(SETTINGS["profiles"], self.form(audit_label="bad\nlabel"))

    def test_secret_key_bounds_one_and_five_hundred_twelve_are_accepted(self):
        for value in ("k", "k" * 512):
            with self.subTest(length=len(value)), context():
                self.assertEqual(
                    resolve_request(SETTINGS["profiles"], self.form(secret_key=value)),
                    (PROFILE, "broker-id", value, "alice"),
                )

    def test_resolution_returns_profile_and_normalized_label(self):
        with context():
            profile, secret_id, secret_key, label = resolve_request(
                SETTINGS["profiles"], self.form(audit_label="DOMAIN\\alice")
            )
        self.assertEqual(profile, PROFILE)
        self.assertEqual((secret_id, secret_key), ("broker-id", "fake-key"))
        self.assertEqual(label, "DOMAIN-alice-" + label_hash("DOMAIN\\alice"))


class LoginUrlIssuanceTests(unittest.TestCase):
    def test_profile_values_reach_the_connector_and_the_callback(self):
        connect = MagicMock(return_value=CREDENTIALS)
        url = issue_login_url(connect, "broker-id", "fake-key", PROFILE, "psm-alice-rid")
        connect.assert_called_once_with(
            "broker-id",
            "fake-key",
            PROFILE["role_arn"],
            "psm-alice-rid",
            PROFILE["duration_seconds"],
            PROFILE["region"],
        )
        parsed = urlsplit(url)
        self.assertEqual(parsed.netloc, "www.tencentcloud.com")
        self.assertEqual(parsed.path, "/login/roleAccessCallback")
        query = parse_qs(parsed.query)
        self.assertEqual(query["s_url"], [DESTINATION])
        self.assertEqual(query["secretId"], ["AKID-TEST"])
        self.assertEqual(query["token"], ["fake-test-token"])
        self.assertNotIn("fake-key", url)

    def test_connector_failure_propagates_to_the_caller(self):
        connect = MagicMock(side_effect=FederationError("STS request failed"))
        with self.assertRaises(FederationError):
            issue_login_url(connect, "broker-id", "fake-key", PROFILE, "psm-alice-rid")


class StartupTests(unittest.TestCase):
    def test_short_proxy_or_session_key_is_rejected(self):
        for proxy_key, session_key in (("short-key", "s" * 32), (PROXY_KEY, "short-key")):
            with self.subTest(proxy_key=proxy_key[:9]), self.assertRaisesRegex(ValueError, "32"):
                create_app(SETTINGS, proxy_key=proxy_key, session_key=session_key)

    def test_exhausted_issuance_capacity_returns_rate_limit(self):
        store = MagicMock()
        store.issue.return_value = None
        app = create_app(SETTINGS, proxy_key=PROXY_KEY, session_key="s" * 32, token_store=store)
        client = app.test_client()
        response = client.get(
            "/",
            headers={"X-PSM-Bridge-Key": PROXY_KEY, "X-PSM-Authenticated-User": "PSMConnect"},
        )
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers["Retry-After"], "120")
        self.assertIn("Too many pending connections", response.text)
        # No connect form, and therefore no CSRF token, is handed out on rejection.
        self.assertNotIn('name="csrf"', response.text)
        store.issue.assert_called_once_with("PSMConnect")

    def test_startup_failure_hides_the_cause_and_its_values(self):
        for error in (RuntimeError("FAKE-ENVIRONMENT-SECRET"), ValueError("FAKE-CONFIG-SECRET")):
            with (
                self.subTest(error=str(error)),
                patch("app.shared_environment", side_effect=error),
                self.assertRaises(SystemExit) as raised,
            ):
                main()
            message = str(raised.exception)
            self.assertEqual(
                message,
                "Bridge startup configuration invalid. Check service environment and settings.",
            )
            self.assertNotIn(str(error), message)
            self.assertTrue(raised.exception.__suppress_context__)

    def test_configuration_values_never_reach_the_startup_error(self):
        with (
            patch("app.shared_environment", return_value=STARTUP_ENVIRONMENT),
            patch("app.load_settings", side_effect=ValueError("FAKE-CONFIG-SECRET")),
            self.assertRaises(SystemExit) as raised,
        ):
            main()
        message = str(raised.exception)
        for value in (*STARTUP_ENVIRONMENT.values(), "FAKE-CONFIG-SECRET"):
            self.assertNotIn(value, message)

    def test_startup_success_runs_the_configured_server(self):
        server = MagicMock()
        with (
            patch("app.shared_environment", return_value=STARTUP_ENVIRONMENT) as environment,
            patch("app.load_settings", return_value=SETTINGS) as loader,
            patch("app.configured_token_store", return_value=TokenStore()) as token_store,
            patch("runtime.make_server", return_value=server) as factory,
        ):
            main()
        environment.assert_called_once()
        loader.assert_called_once_with(STARTUP_ENVIRONMENT["PSM_TC_CONFIG"])
        token_store.assert_called_once_with(STARTUP_ENVIRONMENT)
        factory.assert_called_once()
        self.assertIsInstance(factory.call_args.args[0], Flask)
        server.run.assert_called_once_with()


class FederationInputTests(unittest.TestCase):
    def test_bad_now_is_rejected(self):
        for now in ("1700000000", 0, -1, True, 1700000000.5):
            with (
                self.subTest(now=now),
                self.assertRaisesRegex(FederationError, "Invalid timestamp"),
            ):
                login_url(CREDENTIALS, DESTINATION, now=now, nonce=NONCE)

    def test_bad_nonce_is_rejected(self):
        for nonce in (9999, 100000001, 0, -1, True, "67439", 67439.5):
            with (
                self.subTest(nonce=nonce),
                self.assertRaisesRegex(FederationError, "Invalid nonce"),
            ):
                login_url(CREDENTIALS, DESTINATION, now=NOW, nonce=nonce)

    def test_nonce_bounds_are_inclusive(self):
        for nonce in (10000, 100000000):
            with self.subTest(nonce=nonce):
                url = login_url(CREDENTIALS, DESTINATION, now=NOW, nonce=nonce)
                self.assertEqual(parse_qs(urlsplit(url).query)["nonce"], [str(nonce)])

    def test_missing_credentials_are_rejected(self):
        for name in CREDENTIALS:
            creds = {key: value for key, value in CREDENTIALS.items() if key != name}
            with (
                self.subTest(missing=name),
                self.assertRaisesRegex(FederationError, "Missing temporary credentials"),
            ):
                login_url(creds, DESTINATION, now=NOW, nonce=NONCE)

    def test_empty_or_non_string_credentials_are_rejected(self):
        for name in CREDENTIALS:
            for value in ("", None, 123, b"fake-bytes", [CREDENTIALS[name]]):
                with (
                    self.subTest(name=name, value=value),
                    self.assertRaisesRegex(FederationError, "Missing temporary credentials"),
                ):
                    login_url({**CREDENTIALS, name: value}, DESTINATION, now=NOW, nonce=NONCE)

    def test_temporary_secret_id_outside_the_allowed_character_set_is_rejected(self):
        for secret_id in ("AKID&bad", "AKID bad", "AKID/bad", "AKID+bad", "AKID.bad"):
            creds = {**CREDENTIALS, "TmpSecretId": secret_id}
            with (
                self.subTest(secret_id=secret_id),
                self.assertRaisesRegex(FederationError, "Invalid temporary SecretId") as raised,
            ):
                login_url(creds, DESTINATION, now=NOW, nonce=NONCE)
            self.assertNotIn(secret_id, str(raised.exception))

    def test_destination_that_breaks_urlsplit_is_reported_as_federation_error(self):
        for url in ("https://[::1", "https://[::1]:99999/", "https://console.tencentcloud.com:abc/"):
            with self.subTest(url=url), self.assertRaises(FederationError) as raised:
                validate_destination(url)
            self.assertNotIsInstance(raised.exception, (ValueError, TypeError))


class JsonFileTests(unittest.TestCase):
    def test_neither_path_nor_stream_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "path or a stream"):
            read_json()

    def test_text_and_binary_streams_are_equivalent(self):
        self.assertEqual(read_json(stream=io.StringIO('{"a": 1}')), {"a": 1})
        self.assertEqual(read_json(stream=io.BytesIO(b'{"a": 1}')), {"a": 1})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "value.json"
            path.write_bytes(b'{"a": 1}')
            with path.open("rb") as handle:
                self.assertEqual(read_json(stream=handle), {"a": 1})

    def test_size_bound_accepts_the_limit_and_rejects_one_more(self):
        document = '{"a": 1}'
        self.assertEqual(read_json(stream=io.StringIO(document), limit=len(document)), {"a": 1})
        with self.assertRaisesRegex(ValueError, "size bound"):
            read_json(stream=io.StringIO(document), limit=len(document) - 1)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "value.json"
            path.write_bytes(document.encode())
            self.assertEqual(read_json(path, limit=len(document)), {"a": 1})
            with self.assertRaisesRegex(ValueError, "size bound"):
                read_json(path, limit=len(document) - 1)

    def test_utf8_bom_is_tolerated_for_paths_and_streams(self):
        document = b'\xef\xbb\xbf{"Bom": true}'
        self.assertEqual(read_json(stream=io.BytesIO(document)), {"Bom": True})
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bom.json"
            path.write_bytes(document)
            self.assertEqual(read_json(path), {"Bom": True})

    def test_duplicate_object_keys_are_rejected_from_a_path(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "duplicate.json"
            path.write_text('{"secret_key": "first", "secret_key": "second"}')
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                read_json(path)

    def test_private_output_is_owner_only_and_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ticket.json"
            with private_output(path) as stream:
                save_json(stream, {"status": "prepared", "attempts": 1})
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(read_json(path), {"status": "prepared", "attempts": 1})
            with self.assertRaises(FileExistsError):
                private_output(path)
            self.assertEqual(read_json(path), {"status": "prepared", "attempts": 1})


class CvmPlanTests(unittest.TestCase):
    def instance(self, **overrides):
        value = {
            "id": "ins-1",
            "region": "ap-guangzhou",
            "os": "Ubuntu Linux",
            "private_ips": ["10.0.0.1"],
            "public_ips": [],
        }
        value.update(overrides)
        return value

    def plan(self, instances, usernames=None):
        return cvm_plan(
            {"instances": instances},
            "CloudSafe",
            "UnixPlatform",
            "WindowsPlatform",
            usernames if usernames is not None else {"ins-1": "guest"},
        )

    def test_missing_safe_or_platform_is_rejected(self):
        inventory = {"instances": [self.instance()]}
        for args in (
            ("", "UnixPlatform", "WindowsPlatform"),
            ("CloudSafe", "", "WindowsPlatform"),
            ("CloudSafe", "UnixPlatform", ""),
        ):
            with self.subTest(missing=args.index("")), self.assertRaises(ValueError):
                cvm_plan(inventory, *args, {"ins-1": "guest"})

    def test_unknown_os_missing_username_and_missing_private_ip_are_skipped(self):
        cases = {
            "unknown-os": (self.instance(os="FreeBSD 14.0"), {"ins-1": "guest"}),
            "no-username": (self.instance(), {}),
            "no-private-ip": (self.instance(private_ips=[]), {"ins-1": "guest"}),
            "no-os-field": (self.instance(os=None), {"ins-1": "guest"}),
        }
        for name, (instance, usernames) in cases.items():
            with self.subTest(case=name):
                plan = self.plan([instance], usernames)
                self.assertEqual(plan["accounts"], [])
                self.assertEqual(plan["skipped"], [{"id": "ins-1", "reason": SKIP_REASON}])

    def test_windows_instance_uses_the_windows_platform_and_rdp(self):
        plan = self.plan([self.instance(os="Windows Server 2022")])
        account = plan["accounts"][0]
        self.assertEqual(account["platformId"], "WindowsPlatform")
        self.assertEqual(account["connection_component"], "PSM-RDP")
        self.assertEqual(plan["skipped"], [])

    def test_linux_instance_uses_the_linux_platform_and_ssh(self):
        for os_name in ("Ubuntu Linux", "CentOS 7", "Debian 12", "Rocky Linux 9", "SUSE Linux"):
            with self.subTest(os=os_name):
                account = self.plan([self.instance(os=os_name)])["accounts"][0]
                self.assertEqual(account["platformId"], "UnixPlatform")
                self.assertEqual(account["connection_component"], "PSM-SSH")

    def test_only_the_private_address_is_proposed(self):
        account = self.plan([self.instance(private_ips=["10.1.2.3"], public_ips=["203.0.113.9"])])
        self.assertEqual(account["accounts"][0]["address"], "10.1.2.3")
        self.assertNotIn("203.0.113.9", str(account))
        public_only = self.plan([self.instance(private_ips=[], public_ips=["203.0.113.9"])])
        self.assertEqual(public_only["accounts"], [])
        self.assertEqual(len(public_only["skipped"]), 1)

    def test_first_private_address_that_is_not_an_ip_is_rejected(self):
        for address in ("not-an-ip", "10.0.0.999", "10.0.0.1/24"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.plan([self.instance(private_ips=[address])])

    def test_account_name_is_region_plus_instance_id_and_scope_is_pinned(self):
        instance = self.instance(id="ins-9f2c", region="ap-singapore")
        account = self.plan([instance], {"ins-9f2c": "guest"})["accounts"][0]
        self.assertEqual(account["name"], "tc-ap-singapore-ins-9f2c")
        self.assertEqual(account["safeName"], "CloudSafe")
        self.assertEqual(account["userName"], "guest")
        self.assertEqual(account["secretType"], "password")
        self.assertFalse(account["secretManagement"]["automaticManagementEnabled"])


if __name__ == "__main__":
    unittest.main()
