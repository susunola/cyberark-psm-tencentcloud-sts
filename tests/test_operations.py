import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock
from pam.vault import Vault


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.vault = Vault('https://pvwa.example/PasswordVault/API', 'FAKE-TOKEN')
        self.vault.request = MagicMock(return_value={'ok': True})

    def test_read_page_bounds(self):
        self.vault.list_operations('Recordings', 20, 40)
        self.vault.request.assert_called_once_with('GET', '/Recordings?limit=20&offset=40')
        for args in [('Secrets', 20, 0), ('Recordings', 101, 0), ('LiveSessions', 20, -1)]:
            with self.assertRaises(ValueError):
                self.vault.list_operations(*args)

    def test_session_actions(self):
        for action in ('suspend', 'resume', 'terminate'):
            self.vault.session_action('session-123', action)
            self.vault.request.assert_called_with('POST', '/LiveSessions/session-123/' + action)
        with self.assertRaises(ValueError):
            self.vault.session_action('../Accounts', 'terminate')
        with self.assertRaises(ValueError):
            self.vault.session_action('123', 'delete')

    def test_connect_request_preserves_native_approval(self):
        self.vault.access_request('1_2', 'Approved maintenance', 'PSM-SSH')
        self.vault.request.assert_called_once_with('POST', '/MyRequests', {
            'AccountID': '1_2', 'Reason': 'Approved maintenance',
            'UseConnect': True, 'ConnectionComponent': 'PSM-SSH'})
        with self.assertRaises(ValueError):
            self.vault.access_request('1_2', '', 'PSM-SSH')

    def test_single_explicit_decision(self):
        self.vault.request_decision('request-123', 'reject', 'Wrong scope')
        self.vault.request.assert_called_once_with('POST', '/IncomingRequests/request-123/reject', {'Reason': 'Wrong scope'})
        with self.assertRaises(ValueError):
            self.vault.request_decision('request-123', 'bulk-confirm', 'Wrong scope')

    def test_control_commands_default_no_write_without_credentials(self):
        script = Path(__file__).resolve().parents[1] / 'scripts/pamctl.py'
        for args in [ ['session', '--id', '123', '--action', 'terminate'],
                      ['request', '--account', '1_2', '--reason', 'Maintenance', '--component', 'PSM-SSH'],
                      ['decision', '--id', '123', '--decision', 'confirm', '--reason', 'Maintenance'] ]:
            result = subprocess.run([sys.executable, str(script), *args], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('no-write', result.stdout)


if __name__ == '__main__':
    unittest.main()
