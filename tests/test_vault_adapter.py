"""Adapter tests for pam.vault: URL/TLS policy, sanitized errors and exact PVWA payloads.

Every transport in this module is a fake. No test requires credentials or network access.
"""

import json
import unittest
from unittest.mock import MagicMock

from pam.vault import Vault, VaultError
from validate import MAX_PVWA_RESPONSE_BYTES

API_URL = "https://pvwa.example/PasswordVault/API"
TOKEN = "FAKE-TOKEN"
VENDOR_TEXT = "FAKE-VENDOR-TEXT"


class VaultTestCase(unittest.TestCase):
    """Shared helpers: a stubbed request() and a Vault backed by a fake transport."""

    def setUp(self):
        self.vault = Vault(API_URL, TOKEN)
        self.vault.request = MagicMock(return_value={"ok": True})

    def transport_vault(self):
        """Return (vault, transport) so the real request() path runs against a MagicMock session."""
        transport = MagicMock()
        return Vault(API_URL, TOKEN, session=transport), transport

    @staticmethod
    def response(status_code=200, body=None, json_value=None):
        """Fake a streamed response; an omitted body defaults to the JSON value."""
        if body is None:
            body = json.dumps(json_value).encode() if json_value is not None else b""
        response = MagicMock()
        response.status_code = status_code
        response.headers = {"Content-Length": str(len(body))}
        response.iter_content.return_value = [body] if body else []
        return response

    @staticmethod
    def account_record(**overrides):
        record = {
            "id": "1_2",
            "safeName": "Guests",
            "platformId": "UnixSSH",
            "platformAccountProperties": {},
        }
        record.update(overrides)
        return record


class VaultConstructionTests(unittest.TestCase):
    def test_secure_base_url_is_accepted_and_normalised(self):
        vault = Vault(API_URL + "/", TOKEN)
        self.assertEqual(vault.url, API_URL)
        self.assertEqual(vault.token, TOKEN)
        self.assertIs(vault.ca, True)

    def test_non_https_and_malformed_base_urls_are_rejected(self):
        for url in ("http://pvwa.example/PasswordVault/API", "https:///PasswordVault/API", "https://"):
            with self.assertRaises(ValueError) as error:
                Vault(url, TOKEN)
            self.assertEqual(str(error.exception), "Use an explicit HTTPS PVWA API base URL")

    def test_userinfo_query_and_fragment_are_rejected(self):
        for url in (
            "https://user:FAKE-SECRET@pvwa.example/API",
            "https://user@pvwa.example/API",
            API_URL + "?limit=1",
            API_URL + "#fragment",
        ):
            with self.assertRaises(ValueError) as error:
                Vault(url, TOKEN)
            self.assertEqual(str(error.exception), "Use an explicit HTTPS PVWA API base URL")

    def test_a_trailing_query_or_fragment_delimiter_is_rejected(self):
        # An empty query/fragment parses as falsy but the raw delimiter would
        # survive into self.url and truncate every subsequent route.
        for suffix in ("#", "?", "#fragment", "?limit=1"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                Vault(API_URL + suffix, TOKEN)
        self.assertEqual(Vault(API_URL + "/", TOKEN).url, API_URL)

    def test_tls_verification_and_token_are_mandatory(self):
        with self.assertRaises(ValueError) as error:
            Vault(API_URL, TOKEN, ca=False)
        self.assertEqual(str(error.exception), "TLS verification and an authorized PVWA session are required")
        with self.assertRaises(ValueError):
            Vault(API_URL, "")

    def test_alternative_ca_bundle_is_allowed(self):
        vault = Vault(API_URL, TOKEN, ca="/opt/pvwa/FAKE-ca.pem")
        self.assertEqual(vault.ca, "/opt/pvwa/FAKE-ca.pem")

    def test_injected_session_is_used_and_environment_proxies_are_disabled(self):
        transport = MagicMock()
        vault = Vault(API_URL, TOKEN, session=transport)
        self.assertIs(vault.session, transport)
        self.assertFalse(transport.trust_env)


class VaultRequestTests(VaultTestCase):
    def test_dot_segments_are_rejected_before_the_client_can_normalise_them(self):
        # requests collapses '/../' client-side, which would escape the API prefix;
        # no internal caller builds such a route, so refuse it outright.
        vault, transport = self.transport_vault()
        transport.request.return_value = self.response(json_value={"ok": True})
        for path in ("/Platforms/..", "/../Secret", "/Accounts/%2e%2e/x", "/Accounts/./x"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                vault.request("GET", path)
        transport.request.assert_not_called()
        for path in ("/Accounts/1_2", "/Accounts?limit=1&offset=0", "/Recordings/x/Play"):
            with self.subTest(path=path):
                vault.request("GET", path)
        self.assertEqual(transport.request.call_count, 3)

    def test_successful_request_returns_json_and_pins_transport_arguments(self):
        vault, transport = self.transport_vault()
        transport.request.return_value = self.response(200, json_value={"id": "1_2"})
        self.assertEqual(vault.request("GET", "/Accounts/1_2"), {"id": "1_2"})
        args, kwargs = transport.request.call_args
        self.assertEqual(args, ("GET", API_URL + "/Accounts/1_2"))
        self.assertEqual(kwargs["headers"]["Authorization"], TOKEN)
        self.assertEqual(kwargs["headers"]["Content-Type"], "application/json")
        self.assertEqual(kwargs["headers"]["Accept"], "application/json")
        self.assertEqual(kwargs["timeout"], (5, 20))
        self.assertIs(kwargs["verify"], True)
        self.assertIs(kwargs["allow_redirects"], False)

    def test_empty_body_returns_none_without_parsing(self):
        vault, transport = self.transport_vault()
        response = self.response(204, b"", None)
        transport.request.return_value = response
        self.assertIsNone(vault.request("DELETE", "/MyRequests/request-123"))
        response.json.assert_not_called()

    def test_non_2xx_raises_vault_error_with_status_and_no_vendor_body(self):
        vault, transport = self.transport_vault()
        for status in (199, 300, 302, 400, 401, 403, 500, 503):
            transport.request.return_value = self.response(
                status, b'{"Message": "x"}', {"Message": VENDOR_TEXT}
            )
            with self.assertRaises(VaultError) as error:
                vault.request("GET", "/Accounts")
            self.assertEqual(error.exception.status, status)
            self.assertNotIn(VENDOR_TEXT, str(error.exception))

    def test_transport_failure_is_sanitized(self):
        vault, transport = self.transport_vault()
        transport.request.side_effect = OSError("FAKE-SECRET at " + API_URL)
        with self.assertRaises(VaultError) as error:
            vault.request("POST", "/Accounts", {"secret": "FAKE-SECRET"})
        message = str(error.exception)
        self.assertIn("PVWA request failed", message)
        self.assertNotIn("FAKE-SECRET", message)
        self.assertNotIn("pvwa.example", message)
        self.assertIsNone(error.exception.status)
        self.assertIsNone(error.exception.__cause__)
        self.assertTrue(error.exception.__suppress_context__)

    def test_existing_vault_error_is_re_raised_untouched(self):
        vault, transport = self.transport_vault()
        denied = VaultError("denied by PVWA", 503)
        transport.request.side_effect = denied
        with self.assertRaises(VaultError) as error:
            vault.request("GET", "/Accounts")
        self.assertIs(error.exception, denied)
        self.assertEqual(error.exception.status, 503)

    def test_malformed_json_is_sanitized(self):
        vault, transport = self.transport_vault()
        response = self.response(200, b"<html>not json</html>", None)
        transport.request.return_value = response
        with self.assertRaises(VaultError) as error:
            vault.request("GET", "/Accounts")
        # Sanitized: classifies the fault without echoing the body or stack.
        self.assertIn("PVWA response was not valid JSON", str(error.exception))
        self.assertNotIn("<html>", str(error.exception))

    def test_declared_oversized_response_is_rejected_before_the_body_is_read(self):
        vault, transport = self.transport_vault()
        response = self.response(200, json_value={"ok": True})
        response.headers = {"Content-Length": str(MAX_PVWA_RESPONSE_BYTES + 1)}
        transport.request.return_value = response
        with self.assertRaises(VaultError) as error:
            vault.request("GET", "/Accounts")
        self.assertEqual(str(error.exception), "PVWA response exceeded size limit")
        self.assertEqual(error.exception.status, 200)
        response.iter_content.assert_not_called()

    def test_a_non_numeric_content_length_is_rejected(self):
        vault, transport = self.transport_vault()
        response = self.response(200, json_value={"ok": True})
        response.headers = {"Content-Length": VENDOR_TEXT}
        transport.request.return_value = response
        with self.assertRaises(VaultError) as error:
            vault.request("GET", "/Accounts")
        self.assertEqual(str(error.exception), "PVWA response exceeded size limit")
        self.assertNotIn(VENDOR_TEXT, str(error.exception))

    def test_a_streamed_body_beyond_the_limit_is_rejected(self):
        vault, transport = self.transport_vault()
        response = self.response(200, json_value={"ok": True})
        del response.headers["Content-Length"]
        response.iter_content.return_value = [b"x" * 65536] * (MAX_PVWA_RESPONSE_BYTES // 65536 + 1)
        transport.request.return_value = response
        with self.assertRaises(VaultError) as error:
            vault.request("GET", "/Accounts")
        self.assertEqual(str(error.exception), "PVWA response exceeded size limit")

    def test_a_chunked_body_at_the_limit_is_accepted(self):
        vault, transport = self.transport_vault()
        body = json.dumps({"value": ["x" * 65530]}).encode()
        response = self.response(200, body)
        response.headers = {"Content-Length": str(len(body))}
        response.iter_content.return_value = [body[i : i + 65536] for i in range(0, len(body), 65536)]
        transport.request.return_value = response
        self.assertEqual(vault.request("GET", "/Accounts"), {"value": ["x" * 65530]})

    def test_request_headers_payload_and_accept_override(self):
        vault, transport = self.transport_vault()
        transport.request.return_value = self.response(200, json_value={"ok": True})
        vault.request("POST", "/Accounts", {"name": "FAKE-ACCOUNT"}, accept="text/plain")
        kwargs = transport.request.call_args.kwargs
        self.assertEqual(kwargs["json"], {"name": "FAKE-ACCOUNT"})
        self.assertEqual(kwargs["headers"]["Accept"], "text/plain")


class CapabilityProbeTests(VaultTestCase):
    def probe(self, plan):
        """Run the real probe; plan maps a request path to (status, json body)."""
        vault, transport = self.transport_vault()

        def dispatch(method, url, **kwargs):
            status, body = plan.get(url[len(API_URL) :], (200, {"value": []}))
            return self.response(status, json_value=body)

        transport.request.side_effect = dispatch
        self.probe_transport = transport
        return vault.capability_probe()

    def test_probe_rejects_unsupported_account_listing(self):
        for body in ({"value": {}}, {}, [], None, VENDOR_TEXT):
            with self.assertRaises(VaultError) as error:
                self.probe({"/Accounts?limit=1": (200, body)})
            self.assertEqual(str(error.exception), "Unsupported account-list response")

    def test_probe_maps_denials_to_coarse_labels(self):
        result = self.probe(
            {
                "/LiveSessions?limit=1&offset=0": (401, None),
                "/Recordings?limit=1&offset=0": (403, None),
                "/IncomingRequests": (404, None),
                "/MyRequests": (405, None),
            }
        )
        self.assertEqual(
            result["resources"],
            {
                "Accounts": "available-read",
                "LiveSessions": "authentication-required",
                "Recordings": "permission-denied",
                "IncomingRequests": "unsupported-or-hidden",
                "MyRequests": "method-unsupported",
            },
        )
        self.assertNotIn("PVWA request denied", str(result))

    def test_probe_reports_unknown_status_as_probe_failed(self):
        # The label mapping is inlined in capability_probe; a missing status reaches it as -1.
        for status in (302, 429, 500, 503, None):
            result = self.probe({"/Recordings?limit=1&offset=0": (status, None)})
            self.assertEqual(result["resources"]["Recordings"], "probe-failed")
            self.assertNotIn("PVWA request", str(result))

    def test_probe_flags_unexpected_read_shape(self):
        result = self.probe({"/MyRequests": (200, VENDOR_TEXT)})
        self.assertEqual(result["resources"]["MyRequests"], "unexpected-response")
        self.assertNotIn(VENDOR_TEXT, str(result))

    def test_probe_is_read_only_and_declares_scope(self):
        result = self.probe({})
        self.assertTrue(result["account_list"])
        self.assertEqual(result["resources"]["Accounts"], "available-read")
        self.assertEqual(result["resources"]["LiveSessions"], "available-read")
        self.assertEqual(result["resources"]["Recordings"], "available-read")
        self.assertEqual(result["writes"], "not probed")
        self.assertEqual(result["native_cpm"], "requires an installed platform")
        self.assertEqual(result["session_recording"], "provided by PSM")
        self.assertTrue(all(call.args[0] == "GET" for call in self.probe_transport.request.call_args_list))


class AccountOperationTests(VaultTestCase):
    def test_account_path_rejects_traversal_and_oversized_identifiers(self):
        for value in (
            "../Accounts",
            "..%2fAccounts",
            "1_2/3",
            "1 2",
            "1.2",
            "1;2",
            "",
            "a" * 129,
            None,
            123,
        ):
            with self.assertRaises(ValueError) as error:
                Vault.account_path(value)
            self.assertEqual(str(error.exception), "Invalid Vault account ID")
        self.assertEqual(Vault.account_path("1_2"), "/Accounts/1_2")
        self.assertEqual(Vault.account_path("a" * 128), "/Accounts/" + "a" * 128)

    def test_account_returns_matching_account_only(self):
        self.vault.request.return_value = {"id": "1_2", "safeName": "Guests"}
        self.assertEqual(self.vault.account("1_2"), {"id": "1_2", "safeName": "Guests"})
        self.vault.request.assert_called_once_with("GET", "/Accounts/1_2")
        for body in ({"id": "9_9"}, {"id": None}, [{"id": "1_2"}], None, "1_2"):
            self.vault.request.return_value = body
            with self.assertRaises(VaultError) as error:
                self.vault.account("1_2")
            self.assertEqual(str(error.exception), "Unexpected account response")

    def test_secret_retrieval_path_and_payload(self):
        self.vault.request.return_value = "FAKE-SECRET"
        self.assertEqual(self.vault.secret("1_2", "Approved maintenance"), "FAKE-SECRET")
        self.vault.request.assert_called_once_with(
            "POST", "/Accounts/1_2/Password/Retrieve", {"reason": "Approved maintenance"}
        )

    def test_secret_response_must_be_a_non_empty_string(self):
        for body in ("", None, 0, {"Password": "FAKE-SECRET"}, ["FAKE-SECRET"], True):
            self.vault.request.return_value = body
            with self.assertRaises(VaultError) as error:
                self.vault.secret("1_2", "Approved maintenance")
            self.assertEqual(str(error.exception), "Unexpected secret response")
            self.assertNotIn("FAKE-SECRET", str(error.exception))

    def test_create_returns_server_identifier(self):
        self.vault.request.return_value = {"id": "12_34", "name": "FAKE-ACCOUNT"}
        self.assertEqual(self.vault.create({"name": "FAKE-ACCOUNT"}), "12_34")
        self.vault.request.assert_called_once_with("POST", "/Accounts", {"name": "FAKE-ACCOUNT"})

    def test_create_requires_certain_identifier(self):
        for body in ({}, {"id": ""}, {"id": 0}, {"id": None}, [], None, "12_34"):
            self.vault.request.return_value = body
            with self.assertRaises(VaultError) as error:
                self.vault.create({"name": "FAKE-ACCOUNT"})
            self.assertEqual(
                str(error.exception), "Account creation result is uncertain; reconcile before retry"
            )

    def test_paginated_resources_send_native_page_bounds(self):
        for resource, limit, offset in (("Accounts", 1, 0), ("LiveSessions", 100, 7), ("Recordings", 20, 40)):
            self.vault.list_operations(resource, limit, offset)
            self.vault.request.assert_called_with("GET", f"/{resource}?limit={limit}&offset={offset}")

    def test_approval_lists_are_never_paginated(self):
        for resource in ("IncomingRequests", "MyRequests"):
            self.vault.list_operations(resource, 100, 0)
            self.vault.request.assert_called_with("GET", "/" + resource)

    def test_list_operations_rejects_unknown_resource_and_page_bounds(self):
        with self.assertRaises(ValueError) as resource_error:
            self.vault.list_operations("Secrets", 1, 0)
        self.assertEqual(str(resource_error.exception), "Unsupported operational resource")
        for args in (("Recordings", 0, 0), ("Recordings", 101, 0), ("Recordings", 100, -1)):
            with self.assertRaises(ValueError) as bounds_error:
                self.vault.list_operations(*args)
            self.assertEqual(str(bounds_error.exception), "Invalid page bounds")
        self.vault.request.assert_not_called()


class SessionAndRequestTests(VaultTestCase):
    def test_session_action_paths_and_acceptance(self):
        for action in ("suspend", "resume", "terminate"):
            result = self.vault.session_action("session-123", action)
            self.vault.request.assert_called_with("POST", "/LiveSessions/session-123/" + action)
            self.assertEqual(
                result, {"session_id": "session-123", "action": action, "status": "accepted-by-PVWA"}
            )

    def test_session_action_rejects_unknown_action_and_identifier(self):
        with self.assertRaises(ValueError) as action_error:
            self.vault.session_action("session-123", "delete")
        self.assertEqual(str(action_error.exception), "Unsupported session action")
        for session_id in ("../Accounts", ""):
            with self.assertRaises(ValueError) as id_error:
                self.vault.session_action(session_id, "terminate")
            self.assertEqual(str(id_error.exception), "Invalid Vault account ID")
        self.vault.request.assert_not_called()

    def test_session_details_sections(self):
        for section, suffix in (
            ("details", ""),
            ("activities", "/activities"),
            ("properties", "/properties"),
        ):
            self.vault.session_details("session-123", section)
            self.vault.request.assert_called_with("GET", "/LiveSessions/session-123" + suffix)
        self.vault.session_details("session-123")
        self.vault.request.assert_called_with("GET", "/LiveSessions/session-123")
        with self.assertRaises(ValueError) as error:
            self.vault.session_details("session-123", "valid")
        self.assertEqual(str(error.exception), "Unsupported session detail")

    def test_recording_sections_and_playback(self):
        for section, suffix in (
            ("details", ""),
            ("activities", "/activities"),
            ("properties", "/properties"),
            ("valid", "/valid"),
            ("play", "/Play"),
        ):
            self.vault.recording("recording-123", section)
            self.vault.request.assert_called_with("GET", "/Recordings/recording-123" + suffix)
        with self.assertRaises(ValueError) as section_error:
            self.vault.recording("recording-123", "delete")
        self.assertEqual(str(section_error.exception), "Unsupported recording operation")
        with self.assertRaises(ValueError):
            self.vault.recording("../Secrets", "play")

    def test_request_details_incoming_and_outgoing_paths(self):
        self.vault.request_details("request-123")
        self.vault.request.assert_called_with("GET", "/MyRequests/request-123")
        self.vault.request_details("request-123", incoming=True)
        self.vault.request.assert_called_with("GET", "/IncomingRequests/request-123")
        for request_id in ("../MyRequests", ""):
            with self.assertRaises(ValueError) as error:
                self.vault.request_details(request_id)
            self.assertEqual(str(error.exception), "Invalid Vault account ID")

    def test_request_decision_path_and_reason_bounds(self):
        result = self.vault.request_decision("request-123", "confirm", "Approved maintenance")
        self.vault.request.assert_called_once_with(
            "POST", "/IncomingRequests/request-123/confirm", {"Reason": "Approved maintenance"}
        )
        self.assertEqual(
            result, {"request_id": "request-123", "decision": "confirm", "status": "accepted-by-PVWA"}
        )
        self.vault.request.reset_mock()
        self.vault.request_decision("request-123", "reject", "x" * 1024)
        for decision, reason in (
            ("bulk-confirm", "Approved maintenance"),
            ("confirm", ""),
            ("confirm", "   "),
            ("confirm", "x" * 1025),
            ("confirm", 12345),
        ):
            with self.assertRaises(ValueError) as error:
                self.vault.request_decision("request-123", decision, reason)
            self.assertEqual(str(error.exception), "Explicit decision and reason required")
        self.assertEqual(self.vault.request.call_count, 1)

    def test_cancel_request_is_removal_only(self):
        result = self.vault.cancel_request("request-123")
        self.vault.request.assert_called_once_with("DELETE", "/MyRequests/request-123")
        self.assertEqual(result["request_id"], "request-123")
        self.assertEqual(result["status"], "request-removal-accepted")
        self.assertIn("not revoked", result["note"])
        with self.assertRaises(ValueError):
            self.vault.cancel_request("request-123/../Secrets")


class AccessRequestTests(VaultTestCase):
    def test_access_request_minimal_payload(self):
        self.vault.access_request("1_2", "Approved maintenance", "PSM-SSH")
        self.vault.request.assert_called_once_with(
            "POST",
            "/MyRequests",
            {
                "AccountID": "1_2",
                "Reason": "Approved maintenance",
                "UseConnect": True,
                "ConnectionComponent": "PSM-SSH",
            },
        )

    def test_access_request_happy_path_with_tickets_and_window(self):
        self.vault.access_request(
            "1_2",
            "Approved maintenance",
            "PSM-SSH",
            ticket_id="CHG1",
            ticket_system="ServiceNow",
            from_date=0,
            to_date=253402300799,
        )
        self.vault.request.assert_called_once_with(
            "POST",
            "/MyRequests",
            {
                "AccountID": "1_2",
                "Reason": "Approved maintenance",
                "UseConnect": True,
                "ConnectionComponent": "PSM-SSH",
                "TicketID": "CHG1",
                "TicketingSystem": "ServiceNow",
                "FromDate": 0,
                "ToDate": 253402300799,
            },
        )

    def test_access_request_ticket_pairing_and_bounds(self):
        for options in ({"ticket_id": "CHG1"}, {"ticket_system": "ServiceNow"}):
            with self.assertRaises(ValueError) as error:
                self.vault.access_request("1_2", "Approved maintenance", "PSM-SSH", **options)
            self.assertEqual(str(error.exception), "Supply ticket ID and system together")
        for ticket_id, ticket_system in (
            ("x" * 257, "ServiceNow"),
            ("CHG1", "x" * 257),
            (12345, "ServiceNow"),
        ):
            with self.assertRaises(ValueError) as error:
                self.vault.access_request(
                    "1_2",
                    "Approved maintenance",
                    "PSM-SSH",
                    ticket_id=ticket_id,
                    ticket_system=ticket_system,
                )
            self.assertEqual(str(error.exception), "Invalid ticket fields")
        self.vault.request.reset_mock()
        self.vault.access_request(
            "1_2",
            "Approved maintenance",
            "PSM-SSH",
            ticket_id="x" * 256,
            ticket_system="ServiceNow",
        )
        payload = self.vault.request.call_args.args[2]
        self.assertEqual(len(payload["TicketID"]), 256)
        self.vault.request.assert_called_once()

    def test_access_request_window_validation(self):
        for options in (
            {"from_date": 100},
            {"to_date": 200},
            {"from_date": 200, "to_date": 100},
            {"from_date": 100, "to_date": 100},
            {"from_date": True, "to_date": 200},
            {"from_date": "100", "to_date": 200},
            {"from_date": 100.0, "to_date": 200},
            {"from_date": -1, "to_date": 200},
            {"from_date": 100, "to_date": 253402300800},
        ):
            with self.assertRaises(ValueError) as error:
                self.vault.access_request("1_2", "Approved maintenance", "PSM-SSH", **options)
            self.assertEqual(str(error.exception), "Explicit ordered Unix-second request window required")
        self.vault.request.assert_not_called()

    def test_access_request_reason_and_component_validation(self):
        for reason in ("", "   ", 12345, "x" * 1025):
            with self.assertRaises(ValueError) as error:
                self.vault.access_request("1_2", reason, "PSM-SSH")
            self.assertEqual(str(error.exception), "A bounded request reason is required")
        for component in ("", "PSM SSH", "../PSM", "PSM/RDP"):
            with self.assertRaises(ValueError) as error:
                self.vault.access_request("1_2", "Approved maintenance", component)
            self.assertEqual(str(error.exception), "Explicit connection component required")
        with self.assertRaises(ValueError):
            self.vault.access_request("../Accounts", "Approved maintenance", "PSM-SSH")
        self.vault.request.assert_not_called()
        self.vault.access_request("1_2", "x" * 1024, "PSM-SSH")
        self.vault.request.assert_called_once()


class NativeCpmTests(VaultTestCase):
    def test_native_cpm_actions_and_payloads(self):
        self.vault.account = MagicMock(return_value=self.account_record())
        for action in ("Verify", "Reconcile"):
            result = self.vault.native_cpm("1_2", action, "Guests", "UnixSSH")
            self.vault.request.assert_called_once_with("POST", "/Accounts/1_2/" + action, None)
            self.assertEqual(result["action"], action)
            self.assertEqual(result["status"], "submitted-to-CPM")
            self.assertIn("not success", result["completion"])
            self.vault.request.reset_mock()
        self.vault.native_cpm("1_2", "Change", "Guests", "UnixSSH")
        self.vault.request.assert_called_once_with(
            "POST", "/Accounts/1_2/Change", {"changeImmediately": True}
        )

    def test_native_cpm_rejects_unknown_action_and_scope(self):
        self.vault.account = MagicMock(return_value=self.account_record())
        for action in ("Delete", "change", ""):
            with self.assertRaises(ValueError) as error:
                self.vault.native_cpm("1_2", action, "Guests", "UnixSSH")
            self.assertEqual(str(error.exception), "Explicit native CPM action and scope required")
        for safe, platform in (("", "UnixSSH"), ("Guests", "")):
            with self.assertRaises(ValueError):
                self.vault.native_cpm("1_2", "Verify", safe, platform)
        for safe, platform in (("OtherSafe", "UnixSSH"), ("Guests", "UnixAccounts")):
            with self.assertRaises(ValueError) as error:
                self.vault.native_cpm("1_2", "Verify", safe, platform)
            self.assertEqual(str(error.exception), "Account is outside the approved CPM scope")
        self.vault.request.assert_not_called()

    def test_native_cpm_refuses_cam_key_pair(self):
        self.vault.account = MagicMock(
            return_value=self.account_record(platformAccountProperties={"TencentSecretId": "FAKE-ID"})
        )
        with self.assertRaises(ValueError) as error:
            self.vault.native_cpm("1_2", "Change", "Guests", "UnixSSH")
        self.assertEqual(
            str(error.exception),
            "CAM key pairs require staged rotation, not guest password CPM actions",
        )
        self.vault.request.assert_not_called()

    def test_account_status_whitelists_management_fields(self):
        self.vault.account = MagicMock(
            return_value=self.account_record(
                secretManagement={
                    "automaticManagementEnabled": True,
                    "status": "success",
                    "lastModifiedTime": 1700000000,
                    "lastReconciledTime": 1700000001,
                    "extendedStatus": VENDOR_TEXT,
                    "error": VENDOR_TEXT,
                    "unexpected": VENDOR_TEXT,
                },
                secret="FAKE-SECRET",
            )
        )
        result = self.vault.account_status("1_2")
        self.assertEqual(
            result,
            {
                "account_id": "1_2",
                "safe": "Guests",
                "platform": "UnixSSH",
                "management": {
                    "automaticManagementEnabled": True,
                    "status": "success",
                    "lastModifiedTime": 1700000000,
                    "lastReconciledTime": 1700000001,
                },
            },
        )
        self.assertNotIn(VENDOR_TEXT, repr(result))
        self.assertNotIn("FAKE-SECRET", repr(result))

    def test_account_status_without_management_block(self):
        self.vault.account = MagicMock(return_value={"id": "1_2", "safeName": "Guests"})
        result = self.vault.account_status("1_2")
        self.assertEqual(result["management"], {})
        self.assertIsNone(result["platform"])
        self.vault.account = MagicMock(
            return_value=self.account_record(secretManagement={"automaticManagementEnabled": False})
        )
        self.assertEqual(
            self.vault.account_status("1_2")["management"], {"automaticManagementEnabled": False}
        )


class ConnectTests(VaultTestCase):
    def test_connect_payload_without_tickets(self):
        self.vault.request.return_value = {"PSMConnectResponse": "FAKE-SESSION"}
        self.assertEqual(
            self.vault.connect("1_2", "PSM-SSH", "Approved maintenance"),
            {"PSMConnectResponse": "FAKE-SESSION"},
        )
        self.vault.request.assert_called_once_with(
            "POST",
            "/Accounts/1_2/PSMConnect",
            {"ConnectionComponent": "PSM-SSH", "reason": "Approved maintenance"},
        )
        self.vault.request.return_value = "https://pvwa.example/PSM/FAKE-SESSION"
        self.assertEqual(
            self.vault.connect("1_2", "PSM-SSH", "Approved maintenance"),
            "https://pvwa.example/PSM/FAKE-SESSION",
        )

    def test_connect_ticket_pairing_and_size_bounds(self):
        self.vault.connect("1_2", "PSM-RDP", "Approved maintenance", "x" * 256, "ServiceNow")
        payload = self.vault.request.call_args.args[2]
        self.assertEqual(set(payload), {"ConnectionComponent", "reason", "TicketId", "TicketingSystemName"})
        self.assertEqual(len(payload["TicketId"]), 256)
        self.vault.request.reset_mock()
        for ticket_id, ticket_system in (
            ("x" * 257, "ServiceNow"),
            ("CHG1", "x" * 257),
        ):
            with self.assertRaises(ValueError) as error:
                self.vault.connect("1_2", "PSM-RDP", "Approved maintenance", ticket_id, ticket_system)
            self.assertEqual(str(error.exception), "Ticket fields exceed size bounds")
        for ticket_id, ticket_system in (("CHG1", None), (None, "ServiceNow")):
            with self.assertRaises(ValueError) as error:
                self.vault.connect("1_2", "PSM-RDP", "Approved maintenance", ticket_id, ticket_system)
            self.assertEqual(str(error.exception), "Supply ticket ID and system together")
        self.vault.request.assert_not_called()

    def test_connect_requires_component_and_bounded_reason(self):
        for component, reason in (
            ("PSM SSH", "Approved maintenance"),
            ("", "Approved maintenance"),
            ("../PSM", "Approved maintenance"),
            ("PSM-SSH", ""),
            ("PSM-SSH", "   "),
            ("PSM-SSH", 12345),
            ("PSM-SSH", "x" * 1025),
        ):
            with self.assertRaises(ValueError) as error:
                self.vault.connect("1_2", component, reason)
            self.assertEqual(str(error.exception), "Explicit component and bounded reason required")
        with self.assertRaises(ValueError):
            self.vault.connect("../Accounts", "PSM-SSH", "Approved maintenance")
        self.vault.request.assert_not_called()

    def test_connect_rejects_unsupported_response(self):
        for body in ({}, "", [], 0, None, ["FAKE-SESSION"]):
            self.vault.request.return_value = body
            with self.assertRaises(VaultError) as error:
                self.vault.connect("1_2", "PSM-SSH", "Approved maintenance")
            self.assertEqual(str(error.exception), "Unsupported native PSM response")


class AccountLookupTests(VaultTestCase):
    def test_find_rotation_accounts_filters_by_exact_name(self):
        operation = "a" * 32
        name = "tc-rotation-" + operation
        self.vault.request.return_value = {
            "value": [
                {"id": "1_2", "name": name},
                {"id": "3_4", "name": name + "-copy"},
                {"id": "5_6", "name": "FAKE-OTHER"},
                None,
                VENDOR_TEXT,
            ],
            "count": 5,
        }
        self.assertEqual(self.vault.find_rotation_accounts(operation), [{"id": "1_2", "name": name}])
        self.vault.request.assert_called_once_with("GET", "/Accounts?search=" + name + "&limit=1000")

    def test_find_rotation_accounts_accepts_absent_count(self):
        operation = "b" * 32
        record = {"id": "1_2", "name": "tc-rotation-" + operation}
        self.vault.request.return_value = {"value": [record]}
        self.assertEqual(self.vault.find_rotation_accounts(operation), [record])

    def test_find_rotation_accounts_rejects_bad_operation_and_response(self):
        for operation in ("", "abc", "A" * 32, "g" * 32, "a" * 31, "a" * 33):
            with self.assertRaises(ValueError) as error:
                self.vault.find_rotation_accounts(operation)
            self.assertEqual(str(error.exception), "Invalid rotation operation")
        operation = "a" * 32
        for body in ([], {"value": {}}, None, VENDOR_TEXT):
            self.vault.request.return_value = body
            with self.assertRaises(VaultError) as error:
                self.vault.find_rotation_accounts(operation)
            self.assertEqual(str(error.exception), "Unsupported account search response")
        self.vault.request.return_value = {
            "value": [{"id": "1_2", "name": "tc-rotation-" + operation}],
            "count": 2,
        }
        with self.assertRaises(VaultError) as error:
            self.vault.find_rotation_accounts(operation)
        self.assertEqual(str(error.exception), "Incomplete recovery search; inspect PVWA inventory")

    def test_rotation_recovery_refuses_a_next_page_even_without_count(self):
        # A partial inventory must never authorize recovery cleanup or a retry.
        operation = "a" * 32
        for count in (None, 0, 1):
            body = {"value": [{"id": "1_2", "name": "tc-rotation-" + operation}],
                    "nextLink": "https://untrusted.invalid/next"}
            if count is not None:
                body["count"] = count
            self.vault.request.return_value = body
            with self.subTest(count=count), self.assertRaises(VaultError):
                self.vault.find_rotation_accounts(operation)
        self.assertEqual(self.vault.request.call_count, 3)
        self.vault.request.assert_called_with("GET", "/Accounts?search=tc-rotation-" + operation + "&limit=1000")

    def test_find_accounts_by_name_filters_name_and_safe(self):
        value = [
            {"id": "1_2", "name": "host-1", "safeName": "Guests"},
            {"id": "3_4", "name": "host-1", "safeName": "OtherSafe"},
            {"id": "5_6", "name": "host-2", "safeName": "Guests"},
            None,
            VENDOR_TEXT,
        ]
        self.vault.request.return_value = {"value": value, "count": len(value)}
        self.assertEqual(self.vault.find_accounts_by_name("host-1", "Guests"), [value[0]])
        self.vault.request.assert_called_once_with("GET", "/Accounts?search=host-1&limit=1000")
        self.assertEqual(self.vault.find_accounts_by_name("host-1", "FAKE-MISSING-SAFE"), [])
        self.vault.request.reset_mock()
        self.vault.find_accounts_by_name("host 1/../2", "Guests")
        self.vault.request.assert_called_once_with("GET", "/Accounts?search=host%201%2F..%2F2&limit=1000")

    def test_find_accounts_by_name_rejects_incomplete_lookup(self):
        for body in ([], {"value": {}}, None, VENDOR_TEXT):
            self.vault.request.return_value = body
            with self.assertRaises(VaultError) as error:
                self.vault.find_accounts_by_name("host-1", "Guests")
            self.assertEqual(str(error.exception), "Unsupported account lookup")
        self.vault.request.return_value = {
            "value": [{"id": "1_2", "name": "host-1", "safeName": "Guests"}],
            "nextLink": "https://untrusted.invalid/next",
        }
        with self.assertRaises(VaultError) as error:
            self.vault.find_accounts_by_name("host-1", "Guests")
        self.assertEqual(str(error.exception), "Incomplete account lookup; reconcile before onboarding")
        self.vault.request.return_value = {"value": [], "count": 5}
        with self.assertRaises(VaultError):
            self.vault.find_accounts_by_name("host-1", "Guests")


if __name__ == "__main__":
    unittest.main()
