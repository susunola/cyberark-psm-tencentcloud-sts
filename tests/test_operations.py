import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from pam.vault import Vault, VaultError


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.vault = Vault("https://pvwa.example/PasswordVault/API", "FAKE-TOKEN")
        self.vault.request = MagicMock(return_value={"ok": True})

    def test_read_page_bounds(self):
        self.vault.list_operations("Recordings", 20, 40)
        self.vault.request.assert_called_once_with("GET", "/Recordings?limit=20&offset=40")
        for args in [("Secrets", 20, 0), ("Recordings", 101, 0), ("LiveSessions", 20, -1)]:
            with self.assertRaises(ValueError):
                self.vault.list_operations(*args)

    def test_session_actions(self):
        for action in ("suspend", "resume", "terminate"):
            self.vault.session_action("session-123", action)
            self.vault.request.assert_called_with("POST", "/LiveSessions/session-123/" + action)
        with self.assertRaises(ValueError):
            self.vault.session_action("../Accounts", "terminate")
        with self.assertRaises(ValueError):
            self.vault.session_action("123", "delete")

    def test_connect_request_preserves_native_approval(self):
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
        with self.assertRaises(ValueError):
            self.vault.access_request("1_2", "", "PSM-SSH")

    def test_single_explicit_decision(self):
        self.vault.request_decision("request-123", "reject", "Wrong scope")
        self.vault.request.assert_called_once_with(
            "POST", "/IncomingRequests/request-123/reject", {"Reason": "Wrong scope"}
        )
        with self.assertRaises(ValueError):
            self.vault.request_decision("request-123", "bulk-confirm", "Wrong scope")

    def test_native_cpm_scope_and_async_status(self):
        self.vault.account = MagicMock(
            return_value={"safeName": "Guests", "platformId": "UnixSSH", "platformAccountProperties": {}}
        )
        result = self.vault.native_cpm("1_2", "Change", "Guests", "UnixSSH")
        self.assertEqual(result["status"], "submitted-to-CPM")
        self.vault.request.assert_called_once_with(
            "POST", "/Accounts/1_2/Change", {"changeImmediately": True}
        )
        self.vault.request.reset_mock()
        with self.assertRaises(ValueError):
            self.vault.native_cpm("1_2", "Reconcile", "OtherSafe", "UnixSSH")
        self.vault.request.assert_not_called()

    def test_native_guest_cpm_cannot_rotate_cam_pair(self):
        self.vault.account = MagicMock(
            return_value={
                "safeName": "Guests",
                "platformId": "UnixSSH",
                "platformAccountProperties": {"TencentSecretId": "fake-id"},
            }
        )
        with self.assertRaises(ValueError):
            self.vault.native_cpm("1_2", "Change", "Guests", "UnixSSH")
        self.vault.request.assert_not_called()

    def test_connect_request_keeps_native_ticket_policy(self):
        self.vault.connect("1_2", "PSM-RDP", "Maintenance", "CHG1", "ServiceNow")
        self.vault.request.assert_called_once_with(
            "POST",
            "/Accounts/1_2/PSMConnect",
            {
                "ConnectionComponent": "PSM-RDP",
                "reason": "Maintenance",
                "TicketId": "CHG1",
                "TicketingSystemName": "ServiceNow",
            },
        )
        self.vault.request.reset_mock()
        with self.assertRaises(ValueError):
            self.vault.connect("1_2", "PSM-RDP", "Maintenance", "CHG1")
        self.vault.request.assert_not_called()

    def test_status_does_not_emit_vendor_error_text(self):
        self.vault.account = MagicMock(
            return_value={
                "safeName": "Guests",
                "platformId": "UnixSSH",
                "secretManagement": {
                    "status": "failure",
                    "extendedStatus": "FAKE-SECRET",
                    "automaticManagementEnabled": True,
                },
            }
        )
        self.assertNotIn("FAKE-SECRET", repr(self.vault.account_status("1_2")))

    def test_capability_probe_is_read_only_and_distinguishes_denial(self):
        self.vault.request.side_effect = [
            {"value": []},
            {"LiveSessions": []},
            VaultError("denied", 403),
            VaultError("missing", 404),
            {"requests": []},
        ]
        result = self.vault.capability_probe()
        self.assertEqual(result["resources"]["Recordings"], "permission-denied")
        self.assertEqual(result["resources"]["IncomingRequests"], "unsupported-or-hidden")
        self.assertTrue(all(call.args[0] == "GET" for call in self.vault.request.call_args_list))

    def test_recording_endpoints_and_playback_do_not_download_video(self):
        for section, suffix in [
            ("details", ""),
            ("activities", "/activities"),
            ("properties", "/properties"),
            ("valid", "/valid"),
            ("play", "/Play"),
        ]:
            self.vault.recording("recording-123", section)
            self.vault.request.assert_called_with("GET", "/Recordings/recording-123" + suffix)
        with self.assertRaises(ValueError):
            self.vault.recording("../Secrets", "play")
        with self.assertRaises(ValueError):
            self.vault.recording("recording-123", "delete")

    def test_control_commands_default_no_write_without_credentials(self):
        script = Path(__file__).resolve().parents[1] / "scripts/pamctl.py"
        for args in [
            ["session", "--id", "123", "--action", "terminate"],
            ["request", "--account", "1_2", "--reason", "Maintenance", "--component", "PSM-SSH"],
            ["decision", "--id", "123", "--decision", "confirm", "--reason", "Maintenance"],
            ["cpm", "--account", "1_2", "--action", "Change", "--safe", "Guests", "--platform", "UnixSSH"],
            [
                "connect",
                "--account",
                "1_2",
                "--component",
                "PSM-SSH",
                "--reason",
                "Maintenance",
                "--out",
                "unused.json",
            ],
            ["recover-ticket", "--journal", "unused.json", "--ticket", "recovered.json"],
            ["playback", "--id", "recording-123", "--out", "unused.json"],
        ]:
            result = subprocess.run(
                [sys.executable, str(script), *args], capture_output=True, text=True, check=False
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("no-write", result.stdout)


if __name__ == "__main__":
    unittest.main()
