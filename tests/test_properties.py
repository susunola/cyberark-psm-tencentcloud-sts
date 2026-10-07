"""Property-based tests for the security-critical validators.

Example-based tests pin the cases we thought of. These pin the *invariants* that
must hold for every input: a destination is never accepted for a foreign host, a
normalized audit label is always log-safe, a route can never escape the API
prefix, a size bound is never exceeded, and no failure message ever echoes the
credential material it was given.

The deadline is disabled: these run on shared CI runners where a 200 ms per-example
limit turns scheduler jitter into a false failure.
"""

import io
import json
import re
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import unquote, urlsplit

try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st
except ModuleNotFoundError:  # pragma: no cover - a runtime-only install carries no test tooling
    raise unittest.SkipTest("install requirements-dev.txt to run the property suite") from None

from app import normalize_audit_label
from configuration import validate_settings
from federation import FederationError, login_url, validate_destination, validate_region
from pam.files import read_json
from pam.vault import Vault

settings.register_profile(
    "ci",
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile("ci")

LOG_SAFE_LABEL = re.compile(r"[A-Za-z0-9_.@=-]{2,64}")
ACCOUNT_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
ROLE_ARN = "qcs::cam::uin/123:roleName/ReadOnly"
DESTINATION = "https://console.tencentcloud.com/"
CONSOLE_HOST = "console.tencentcloud.com"
LONG_SECRET = st.text(alphabet=st.characters(codec="ascii", categories=["L", "N", "P"]), min_size=16, max_size=64)


def valid_settings(role_arn=ROLE_ARN, destination=DESTINATION, duration=300, region="ap-guangzhou"):
    return {
        "profiles": {
            "readonly": {
                "role_arn": role_arn,
                "allowed_secret_ids": ["broker-id"],
                "destination": destination,
                "duration_seconds": duration,
                "region": region,
            }
        }
    }


class DestinationProperties(unittest.TestCase):
    @given(st.text())
    def test_no_text_can_redirect_the_console_handoff(self, candidate):
        """Whatever the config says, an accepted destination is the console host."""
        try:
            accepted = validate_destination(candidate)
        except (FederationError, ValueError, TypeError):
            return
        parsed = urlsplit(accepted)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.hostname, CONSOLE_HOST)
        self.assertIn(parsed.port, (None, 443))
        self.assertFalse(parsed.username)
        self.assertFalse(parsed.password)
        self.assertFalse(any(ord(c) < 33 for c in accepted))
        self.assertNotIn("\\", accepted)

    @given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-.", min_size=1, max_size=60))
    def test_no_generated_lookalike_host_is_accepted(self, label):
        for prefix in ("", "https://", "https://www.", "https://evil."):
            for suffix in ("", ".evil.test", ".test", "%00"):
                candidate = f"{prefix}{label}{suffix}"
                with self.subTest(candidate=candidate):
                    try:
                        validate_destination(candidate)
                    except (FederationError, ValueError, TypeError):
                        continue
                    self.assertEqual(urlsplit(candidate).hostname, CONSOLE_HOST)


class RegionProperties(unittest.TestCase):
    @given(st.text())
    def test_an_accepted_region_is_lowercase_and_bounded(self, candidate):
        try:
            accepted = validate_region(candidate)
        except (ValueError, TypeError):
            return
        self.assertRegex(accepted, r"[a-z]{2}-[a-z]+(?:-[a-z0-9]+)*")
        self.assertLessEqual(len(accepted), 64)


class AuditLabelProperties(unittest.TestCase):
    @given(st.text())
    def test_a_normalized_label_is_always_log_safe(self, candidate):
        """Accepted labels are ASCII-safe, bounded, and free of control characters."""
        try:
            normalized = normalize_audit_label(candidate)
        except ValueError:
            return
        self.assertRegex(normalized, LOG_SAFE_LABEL.pattern)
        self.assertLessEqual(len(normalized), 64)
        self.assertFalse(any(ord(c) < 32 or ord(c) == 127 for c in normalized))

    @given(st.text(min_size=2, max_size=256).filter(lambda value: not any(ord(c) < 32 for c in value)))
    def test_normalization_is_deterministic_and_distinguishes_inputs(self, candidate):
        first = normalize_audit_label(candidate)
        self.assertEqual(first, normalize_audit_label(candidate))
        # Distinct inputs must not collide onto one label.
        other = candidate + "x" if any(ord(c) >= 32 for c in candidate + "x") else None
        if other is not None and len(other) <= 256:
            self.assertNotEqual(first, normalize_audit_label(other))


class RouteProperties(unittest.TestCase):
    @given(st.text())
    def test_an_accepted_route_cannot_escape_the_api_prefix(self, candidate):
        session = MagicMock()
        response = MagicMock(status_code=200, content=b"{}")
        response.json.return_value = {}
        session.request.return_value = response
        vault = Vault("https://pvwa.test/PasswordVault/API", "fake-token", session=session)
        try:
            vault.request("GET", candidate)
        except (ValueError, TypeError):
            return
        self.assertTrue(candidate.startswith("/"))
        self.assertFalse(candidate.startswith("//"))
        self.assertNotIn("#", candidate)
        self.assertNotIn("\\", candidate)
        self.assertFalse(any(ord(c) < 33 for c in candidate))
        for segment in candidate.split("?", 1)[0].split("/"):
            self.assertNotIn(segment.lower().replace("%2e", "."), (".", ".."))

    @given(st.text(alphabet=st.characters(codec="ascii"), min_size=1, max_size=200))
    def test_a_rejected_route_never_reaches_the_transport(self, candidate):
        """A route rejected by validation must be refused before any transport call."""
        session = MagicMock()
        response = MagicMock(status_code=200, content=b"{}")
        response.json.return_value = {}
        session.request.return_value = response
        vault = Vault("https://pvwa.test/PasswordVault/API", "fake-token", session=session)
        try:
            vault.request("GET", candidate)
        except ValueError:
            session.request.assert_not_called()
        except Exception:  # noqa: BLE001 - the route was accepted; a transport fault is out of scope
            self.assertTrue(candidate.startswith("/"))


class JsonBoundProperties(unittest.TestCase):
    @given(st.binary(max_size=200), st.integers(min_value=1, max_value=100))
    def test_the_size_bound_is_never_exceeded(self, payload, limit):
        """Oversized input is refused; anything that parses was inside the bound."""
        try:
            read_json(stream=io.BytesIO(payload), limit=limit)
        except Exception:  # noqa: BLE001 - malformed JSON is expected and irrelevant here
            return
        self.assertLessEqual(len(payload), limit)

    @given(st.binary(min_size=2, max_size=200), st.integers(min_value=1, max_value=100))
    def test_an_oversized_document_is_always_refused(self, payload, limit):
        if len(payload) <= limit:
            return
        with self.assertRaises(ValueError):
            read_json(stream=io.BytesIO(payload), limit=limit)

    @given(st.dictionaries(st.text(min_size=1, max_size=8), st.integers(), max_size=6))
    def test_valid_objects_round_trip_within_the_bound(self, payload):
        raw = json.dumps(payload).encode()
        self.assertEqual(read_json(stream=io.BytesIO(raw), limit=len(raw)), payload)


class SettingsIsolationProperties(unittest.TestCase):
    @given(st.integers(min_value=31, max_value=300))
    def test_validation_never_aliases_caller_state(self, duration):
        source = valid_settings(duration=duration)
        validated = validate_settings(source)
        self.assertEqual(validated, source)
        self.assertIsNot(validated, source)
        validated["profiles"]["readonly"]["allowed_secret_ids"].append("injected-id")
        self.assertEqual(source["profiles"]["readonly"]["allowed_secret_ids"], ["broker-id"])


class CredentialLeakageProperties(unittest.TestCase):
    @given(key=LONG_SECRET, token=LONG_SECRET)
    def test_the_long_term_key_never_reaches_the_callback_url(self, key, token):
        # Distinct markers: the token legitimately appears in the URL, the key must not.
        key, token = "KEY" + key, "TOKEN" + token
        url = login_url(
            {"TmpSecretId": "AKID-TEMP", "TmpSecretKey": key, "Token": token}, DESTINATION, now=1700000000, nonce=67439
        )
        # Checked against the decoded URL as well, so an encoded key cannot slip past.
        self.assertNotIn(key, url)
        self.assertNotIn(key, unquote(url))
        self.assertIn("secretId=AKID-TEMP", url)
        self.assertEqual(urlsplit(url).hostname, "www.tencentcloud.com")

    @given(
        credentials=st.fixed_dictionaries(
            {},
            optional={
                "TmpSecretId": st.one_of(st.none(), LONG_SECRET, st.just("bad&id")),
                "TmpSecretKey": st.one_of(st.none(), LONG_SECRET),
                "Token": st.one_of(st.none(), LONG_SECRET),
            },
        )
    )
    def test_a_rejected_credential_is_never_echoed_in_the_error(self, credentials):
        secrets = [v for v in credentials.values() if isinstance(v, str) and len(v) >= 16]
        try:
            login_url(credentials, DESTINATION, now=1700000000, nonce=67439)
        except FederationError as error:
            for secret in secrets:
                self.assertNotIn(secret, str(error))
            self.assertLess(len(str(error)), 200)


class SigningStringProperties(unittest.TestCase):
    @given(sid=st.text(alphabet="ABCabc0123456789_-", min_size=1, max_size=64))
    def test_only_the_four_documented_parameters_are_signed(self, sid):
        captured = []
        real_hmac = __import__("hmac").new

        def capture(key, message, *args, **kwargs):
            captured.append(message)
            return real_hmac(key, message, *args, **kwargs)

        with patch("federation.hmac.new", side_effect=capture):
            login_url(
                {"TmpSecretId": sid, "TmpSecretKey": "fake-key", "Token": "fake-token"},
                DESTINATION,
                now=1700000000,
                nonce=67439,
            )
        self.assertEqual(
            captured,
            [
                (
                    "GETwww.tencentcloud.com/login/roleAccessCallback?action=roleLogin"
                    f"&nonce=67439&secretId={sid}&timestamp=1700000000"
                ).encode()
            ],
        )


if __name__ == "__main__":
    unittest.main()
