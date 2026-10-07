"""Boundary and branch coverage for pam.delivery exports, journals and preflight."""

import io
import json
import tempfile
import unittest
from typing import Any
from unittest.mock import MagicMock, patch

from pam.delivery import append_record, export_records, onboard_batch, preflight
from pam.vault import VaultError


def fake_account(name):
    """One schema-valid account payload for the Guests/UnixSSH scope."""
    return {
        "name": name,
        "address": "10.0.0.1",
        "userName": "admin",
        "platformId": "UnixSSH",
        "safeName": "Guests",
        "secretType": "password",
        "secret": "FAKE-SECRET",
    }


class ExportRecordsBoundsTests(unittest.TestCase):
    """export_records refuses to claim completeness for unverifiable pages."""

    def test_unsupported_resource_or_unbounded_page_bounds_are_rejected(self):
        vault = MagicMock()
        cases: list[tuple[Any, Any, Any]] = [
            ("Passwords", 1, 1),
            ("accounts", 1, 1),
            ("Accounts", 0, 1),
            ("Accounts", 101, 1),
            ("Accounts", True, 1),
            ("Accounts", 1.0, 1),
            ("Accounts", "1", 1),
            ("Accounts", 1, 0),
            ("Accounts", 1, 101),
            ("Accounts", 1, False),
            ("Accounts", 1, 1.0),
        ]
        for resource, limit, max_pages in cases:
            with (
                self.subTest(resource=resource, limit=limit, max_pages=max_pages),
                self.assertRaisesRegex(ValueError, "Use a bounded paginated resource"),
            ):
                list(export_records(vault, resource, limit, max_pages))
        vault.list_operations.assert_not_called()

    def test_page_response_must_be_a_dict_carrying_the_resource_list(self):
        vault = MagicMock()
        cases = [
            ("Accounts", []),
            ("Accounts", "value"),
            ("Accounts", {"Total": 1}),
            ("Accounts", {"value": {"id": "1"}}),
            ("Accounts", {"value": None}),
            ("LiveSessions", {"LiveSessions": {"id": "1"}}),
        ]
        for resource, response in cases:
            with self.subTest(resource=resource, response=response):
                vault.list_operations.return_value = response
                with self.assertRaisesRegex(ValueError, "Unsupported page response"):
                    list(export_records(vault, resource, limit=2))
        vault.list_operations.return_value = {"Recordings": [{"id": "1"}]}
        self.assertEqual(list(export_records(vault, "Recordings", limit=2)), [{"id": "1"}])

    def test_page_must_respect_limit_and_contain_only_records(self):
        vault = MagicMock()
        vault.list_operations.return_value = {"value": [{"id": "1"}, {"id": "2"}]}
        with self.assertRaisesRegex(ValueError, "Invalid page bounds or record schema"):
            list(export_records(vault, "Accounts", limit=1))
        vault.list_operations.return_value = {"value": [{"id": "1"}, "raw-record"]}
        with self.assertRaisesRegex(ValueError, "Invalid page bounds or record schema"):
            list(export_records(vault, "Accounts", limit=2))

    def test_page_total_must_be_a_non_negative_integer(self):
        vault = MagicMock()
        for total in (-1, "2", True, 1.5):
            with self.subTest(total=total):
                vault.list_operations.return_value = {"value": [{"id": "1"}], "Total": total}
                with self.assertRaisesRegex(ValueError, "Invalid page total"):
                    list(export_records(vault, "Accounts", limit=2))

    def test_empty_page_is_complete_only_without_nextlink_or_remaining_total(self):
        vault = MagicMock()
        for response in ({"value": [], "nextLink": "https://untrusted.invalid/"}, {"value": [], "Total": 3}):
            with self.subTest(response=response):
                vault.list_operations.return_value = response
                with self.assertRaisesRegex(ValueError, "Incomplete empty page"):
                    list(export_records(vault, "Accounts", limit=2))
        for response in ({"value": []}, {"value": [], "Total": 0}, {"value": [], "nextLink": "", "Total": 0}):
            with self.subTest(response=response):
                vault.list_operations.return_value = response
                self.assertEqual(list(export_records(vault, "Accounts", limit=2)), [])
        vault.list_operations.assert_called_with("Accounts", 2, 0)

    def test_full_final_page_stops_on_total_without_a_nextlink(self):
        vault = MagicMock()
        vault.list_operations.return_value = {"value": [{"id": "1"}, {"id": "2"}], "Total": 2}
        self.assertEqual([r["id"] for r in export_records(vault, "Accounts", limit=2)], ["1", "2"])
        vault.list_operations.assert_called_once_with("Accounts", 2, 0)

    def test_native_count_controls_short_page_continuation(self):
        # count is compared against the offset already advanced by this page, so a
        # short page keeps the export going only while count exceeds that offset.
        vault = MagicMock()
        vault.list_operations.side_effect = [
            {"LiveSessions": [{"id": "1"}], "count": 3},
            {"LiveSessions": [{"id": "2"}], "count": 3},
            {"LiveSessions": [{"id": "3"}], "count": 3},
        ]
        self.assertEqual([r["id"] for r in export_records(vault, "LiveSessions", limit=3)], ["1", "2", "3"])
        self.assertEqual(
            [call.args for call in vault.list_operations.call_args_list],
            [("LiveSessions", 3, 0), ("LiveSessions", 3, 1), ("LiveSessions", 3, 2)],
        )

    def test_invalid_native_count_is_rejected(self):
        vault = MagicMock()
        for count in (-1, "2", True, 1.5):
            with self.subTest(count=count):
                vault.list_operations.return_value = {"LiveSessions": [{"id": "1"}], "count": count}
                with self.assertRaisesRegex(ValueError, "Invalid account count"):
                    list(export_records(vault, "LiveSessions", limit=3))


class DurableJournalWriteTests(unittest.TestCase):
    """append_record keeps one JSONL line per attempt and only fsyncs on demand."""

    def test_record_is_written_as_a_single_utf8_preserving_line(self):
        stream = io.StringIO()
        append_record(stream, {"event": "create_attempt", "name": "运维账号"}, durable=False)
        raw = stream.getvalue()
        self.assertTrue(raw.endswith("\n"))
        self.assertEqual(len(raw.splitlines()), 1)
        self.assertEqual(json.loads(raw), {"event": "create_attempt", "name": "运维账号"})
        self.assertIn("运维账号", raw)
        self.assertNotIn("\\u", raw)

    def test_durable_write_flushes_and_fsyncs_the_stream(self):
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stream, patch("os.fsync") as fsync:
            append_record(stream, {"event": "batch_started"})
            fsync.assert_called_once_with(stream.fileno())
            stream.seek(0)
            self.assertEqual(json.loads(stream.read()), {"event": "batch_started"})

    def test_best_effort_write_never_calls_fsync(self):
        stream = io.StringIO()
        with patch("os.fsync") as fsync:
            append_record(stream, {"event": "batch_started"}, durable=False)
        fsync.assert_not_called()
        self.assertEqual(json.loads(stream.getvalue()), {"event": "batch_started"})


class BatchJournalTests(unittest.TestCase):
    """onboard_batch journals an ordered, resumable attempt log."""

    def test_batch_size_bounds_and_duplicate_names_are_rejected(self):
        vault = MagicMock()
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as journal:
            payloads: list[Any] = [[], [fake_account("only")] * 101]
            for batch in payloads:
                with (
                    self.subTest(size=len(batch)),
                    self.assertRaisesRegex(ValueError, "Provide 1..100 complete accounts through stdin"),
                ):
                    onboard_batch(batch, "Guests", "UnixSSH", vault, journal)
            with self.assertRaisesRegex(ValueError, "Duplicate account names in batch"):
                onboard_batch(
                    [fake_account("Team"), fake_account("team")], "Guests", "UnixSSH", vault, journal
                )
            journal.seek(0)
            self.assertEqual(journal.read(), "")
        vault.find_accounts_by_name.assert_not_called()
        vault.create.assert_not_called()

    def test_journal_records_ordered_events_and_returns_operation_summary(self):
        vault = MagicMock()
        vault.find_accounts_by_name.return_value = []
        vault.create.side_effect = ["1_2", "3_4"]
        with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as journal:
            result = onboard_batch(
                [fake_account("first"), fake_account("second")], "Guests", "UnixSSH", vault, journal
            )
            journal.seek(0)
            rows = [json.loads(line) for line in journal]
        self.assertEqual(
            [row["event"] for row in rows],
            [
                "batch_started",
                "create_attempt",
                "create_confirmed",
                "create_attempt",
                "create_confirmed",
                "batch_completed",
            ],
        )
        self.assertEqual(result["account_ids"], ["1_2", "3_4"])
        self.assertEqual(result["status"], "batch-completed")
        self.assertEqual(len(result["operation"]), 32)
        self.assertEqual({row["operation"] for row in rows}, {result["operation"]})
        self.assertEqual([row.get("index") for row in rows[1:5]], [0, 0, 1, 1])
        self.assertEqual([row["account_id"] for row in rows[2:5:2]], ["1_2", "3_4"])
        self.assertEqual(rows[0]["count"], 2)
        self.assertEqual(rows[-1]["count"], 2)
        self.assertEqual(rows[1]["name"], "first")
        self.assertEqual(rows[1]["safe"], "Guests")
        self.assertEqual(rows[1]["platform"], "UnixSSH")
        vault.find_accounts_by_name.assert_any_call("first", "Guests")
        self.assertEqual([call.args[0]["name"] for call in vault.create.call_args_list], ["first", "second"])


class PreflightScopeTests(unittest.TestCase):
    """preflight binds the requested scope to the account and Tencent caller."""

    def setUp(self):
        self.vault = MagicMock()
        account = fake_account("first")
        account["id"] = "1_2"
        self.vault.account.return_value = account
        self.vault.request.return_value = {}

    def test_component_and_scope_must_be_explicit(self):
        bad_components: list[Any] = [None, 42, "", "bad component", "PSM.SSH", "x" * 129]
        for component in bad_components:
            with (
                self.subTest(component=component),
                self.assertRaisesRegex(ValueError, "Explicit preflight scope and component required"),
            ):
                preflight(self.vault, {"profiles": {}}, "1_2", "Guests", "UnixSSH", component)
        for safe, platform in (("", "UnixSSH"), ("Guests", "")):
            with (
                self.subTest(safe=safe, platform=platform),
                self.assertRaisesRegex(ValueError, "Explicit preflight scope and component required"),
            ):
                preflight(self.vault, {"profiles": {}}, "1_2", safe, platform, "PSM-SSH")
        self.vault.account.assert_not_called()
        self.vault.request.assert_not_called()

    def test_account_scope_requires_exact_safe_and_platform(self):
        for field, value in (("safeName", "OtherSafe"), ("platformId", "WindowsRDP")):
            with self.subTest(field=field):
                account = fake_account("first")
                account[field] = value
                self.vault.account.return_value = account
                result = preflight(self.vault, {"profiles": {}}, "1_2", "Guests", "UnixSSH", "PSM-SSH")
                self.assertEqual(result["checks"], {"account_scope": False})
                self.assertFalse(result["scope_binding_ready"])
                self.assertEqual(
                    result["probes"],
                    {"platform_read": "available-read", "connector_list_read": "available-read"},
                )

    def test_caller_profile_binding_is_absent_without_tencent_properties(self):
        result = preflight(self.vault, {"profiles": {}}, "1_2", "Guests", "UnixSSH", "PSM-SSH")
        self.assertEqual(result["checks"], {"account_scope": True})
        self.assertNotIn("caller_profile_binding", result["checks"])

    def test_caller_profile_binding_requires_an_allowlisted_secret_id(self):
        settings = {"profiles": {"readonly": {"allowed_secret_ids": ["AKIDfake"]}}}
        account = fake_account("first")
        account["platformAccountProperties"] = {
            "TencentRoleProfile": "readonly",
            "TencentSecretId": "AKIDfake",
        }
        self.vault.account.return_value = account
        result = preflight(self.vault, settings, "1_2", "Guests", "UnixSSH", "PSM-SSH")
        self.assertIs(result["checks"]["caller_profile_binding"], True)
        self.assertTrue(result["scope_binding_ready"])

        for properties in (
            {"TencentRoleProfile": "readonly", "TencentSecretId": "AKIDother"},
            {"TencentRoleProfile": "missing", "TencentSecretId": "AKIDfake"},
            {"TencentSecretId": "AKIDfake"},
        ):
            with self.subTest(properties=properties):
                account["platformAccountProperties"] = properties
                result = preflight(self.vault, settings, "1_2", "Guests", "UnixSSH", "PSM-SSH")
                self.assertIs(result["checks"]["caller_profile_binding"], False)
                self.assertFalse(result["scope_binding_ready"])

    def test_platform_identifier_is_path_quoted(self):
        account = fake_account("first")
        account["platformId"] = "Unix/SSH"
        self.vault.account.return_value = account
        result = preflight(self.vault, {"profiles": {}}, "1_2", "Guests", "Unix/SSH", "PSM-SSH")
        self.assertTrue(result["checks"]["account_scope"])
        self.assertEqual(self.vault.request.call_args_list[0].args, ("GET", "/Platforms/Unix%2FSSH"))


class PreflightProbeTests(unittest.TestCase):
    """Probe labels stay coarse and never leak vendor text or credentials."""

    def setUp(self):
        self.vault = MagicMock()
        account = fake_account("first")
        account["id"] = "1_2"
        self.vault.account.return_value = account

    def preflight(self):
        return preflight(self.vault, {"profiles": {}}, "1_2", "Guests", "UnixSSH", "PSM-SSH")

    def test_probes_report_read_availability_and_unexpected_shapes(self):
        self.vault.request.side_effect = [{"id": "Platforms"}, "not-json"]
        result = self.preflight()
        self.assertEqual(
            result["probes"],
            {"platform_read": "available-read", "connector_list_read": "unexpected-response"},
        )
        self.assertEqual(
            [call.args for call in self.vault.request.call_args_list],
            [("GET", "/Platforms/UnixSSH"), ("GET", "/PSM/Connectors")],
        )

        self.vault.request.side_effect = [[], None]
        result = self.preflight()
        self.assertEqual(
            result["probes"],
            {"platform_read": "available-read", "connector_list_read": "unexpected-response"},
        )

    def test_vault_denials_map_to_coarse_probe_labels(self):
        for status, label in (
            (401, "authentication-required"),
            (403, "permission-denied"),
            (404, "unsupported-or-hidden"),
            (500, "probe-failed"),
            (None, "probe-failed"),
        ):
            with self.subTest(status=status):
                self.vault.request.side_effect = VaultError("PVWA request denied or failed", status)
                result = self.preflight()
                self.assertEqual(result["probes"], {"platform_read": label, "connector_list_read": label})

    def test_preflight_reports_scope_binding_and_unverified_guarantees(self):
        self.vault.request.return_value = {}
        result = self.preflight()
        self.assertEqual(result["account_id"], "1_2")
        self.assertEqual(result["requested_component"], "PSM-SSH")
        self.assertTrue(result["scope_binding_ready"])
        self.assertEqual(
            result["not_verified"],
            [
                "component assignment",
                "native CPM engine",
                "live console/SSH/RDP",
                "approval/recording",
                "write permissions",
                "production compatibility",
            ],
        )
        self.vault.secret.assert_not_called()


if __name__ == "__main__":
    unittest.main()
