"""Real TLS/HTTP PVWA adapter contract; synthetic responses, never a PAM emulator.

Exercises requests serialization, CA/hostname checks, response handling and write
retry behavior over a real socket. Passing does not certify a CyberArk release.
"""
import json
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from pam.vault import Vault, VaultError


@unittest.skipUnless(shutil.which("openssl"), "openssl required for the temporary test certificate")
class PvwaHttpsContractTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        certificate, key = root / "server.crt", root / "server.key"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(certificate), "-days", "1",
            "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
        ], check=True, capture_output=True)
        self.calls = []
        self.status = 200
        self.body = {"value": []}
        self.extra_headers = {}
        scenario = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                # The default access log can contain account paths and tokens.
                pass

            def respond(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length) if length else b""
                scenario.calls.append({
                    "method": self.command, "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "payload": json.loads(body) if body else None,
                })
                encoded = json.dumps(scenario.body).encode()
                self.send_response(scenario.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                for name, value in scenario.extra_headers.items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(encoded)

            do_GET = respond
            do_POST = respond

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())

        self.addCleanup(stop)
        self.url = f"https://localhost:{server.server_port}/PasswordVault/API"
        self.ca = str(certificate)
        self.vault = Vault(self.url, "FAKE-PVWA-TOKEN", ca=self.ca)
        self.addCleanup(self.vault.session.close)

    def test_account_and_approval_payload_cross_real_tls(self):
        self.body = {"id": "1_2", "safeName": "TestSafe"}
        self.assertEqual(self.vault.account("1_2")["safeName"], "TestSafe")
        self.body = {"RequestID": "req-1"}
        self.vault.access_request("1_2", "Integration acceptance", "PSM-TencentCloud",
                                  ticket_id="CHG-1", ticket_system="TestTickets", from_date=10, to_date=20)
        self.assertEqual([call["method"] for call in self.calls], ["GET", "POST"])
        self.assertTrue(all(call["authorization"] == "FAKE-PVWA-TOKEN" for call in self.calls))
        self.assertEqual(self.calls[1]["path"], "/PasswordVault/API/MyRequests")
        self.assertEqual(self.calls[1]["payload"], {
            "AccountID": "1_2", "Reason": "Integration acceptance", "UseConnect": True,
            "ConnectionComponent": "PSM-TencentCloud", "TicketID": "CHG-1",
            "TicketingSystem": "TestTickets", "FromDate": 10, "ToDate": 20,
        })

    def test_denial_redirect_and_uncertain_write_are_not_retried(self):
        for status in (401, 403, 302, 500):
            self.calls.clear()
            self.status = status
            self.body = {"Message": "FAKE-SENSITIVE-VENDOR-TEXT"}
            self.extra_headers = {"Location": "/PasswordVault/API/Accounts?redirected=1"}
            with self.subTest(status=status), self.assertRaises(VaultError) as error:
                self.vault.create({"name": "synthetic", "secret": "FAKE-SECRET"})
            self.assertEqual(error.exception.status, status)
            self.assertNotIn("FAKE-SENSITIVE", str(error.exception))
            self.assertEqual(len(self.calls), 1)
            self.assertEqual(self.calls[0]["path"], "/PasswordVault/API/Accounts")

    def test_untrusted_certificate_and_hostname_mismatch_send_no_authorization(self):
        for url, ca in ((self.url, True), (self.url.replace("localhost", "127.0.0.1"), self.ca)):
            vault = Vault(url, "FAKE-PVWA-TOKEN", ca=ca)
            with vault.session, self.subTest(url=url), self.assertRaises(VaultError):
                vault.request("GET", "/Accounts")
        self.assertEqual(self.calls, [])

    def test_partial_recovery_inventory_is_refused_over_real_transport(self):
        self.body = {"value": [], "nextLink": "/PasswordVault/API/Accounts?offset=1000"}
        with self.assertRaises(VaultError):
            self.vault.find_rotation_accounts("a" * 32)
        self.assertEqual(len(self.calls), 1)
