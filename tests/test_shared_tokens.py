import concurrent.futures
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

from app import create_app
from security import RedisTokenStore, TokenStoreError, configured_token_store, shared_environment

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
HEADERS = {"X-PSM-Bridge-Key": "p" * 32, "X-PSM-Authenticated-User": "PSMConnect"}


class SharedTokenUnitTests(unittest.TestCase):
    def test_backend_errors_are_redacted(self):
        backend = MagicMock()
        backend.eval.side_effect = RuntimeError("FAKE-CONNECTION-SECRET")
        store = RedisTokenStore(backend)
        with self.assertRaises(TokenStoreError) as error:
            store.issue("alice")
        self.assertNotIn("FAKE-CONNECTION-SECRET", str(error.exception))

    def test_production_tls_and_query_overrides(self):
        for url in (
            "redis://localhost:6379",
            "rediss://localhost:6379?ssl_cert_reqs=none",
            "rediss://localhost:6379/#bad",
        ):
            with self.assertRaises(ValueError):
                configured_token_store({"PSM_TC_REDIS_URL": url})
        with patch("redis.Redis.from_url") as factory:
            factory.return_value.ping.return_value = True
            configured_token_store({"PSM_TC_REDIS_URL": "rediss://redis.example:6379/0"})
            self.assertEqual(factory.call_args.kwargs["ssl_cert_reqs"], "required")
            self.assertTrue(factory.call_args.kwargs["ssl_check_hostname"])
            self.assertEqual(factory.call_args.kwargs["retry_on_error"], [])

    def test_shared_settings_no_duplicate_fields(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "shared.json"
            data = {
                "redis_url": "rediss://redis.example/0",
                "session_key": "s" * 32,
                "namespace": "production",
                "ca_bundle": "",
            }
            path.write_text(json.dumps(data))
            env = shared_environment({"PSM_TC_SHARED_CONFIG": str(path), "PSM_TC_PROXY_KEY": "p" * 32})
            self.assertEqual(env["PSM_TC_SESSION_KEY"], "s" * 32)
            path.write_text('{"session_key":"fake","session_key":"different"}')
            with self.assertRaises(ValueError):
                shared_environment({"PSM_TC_SHARED_CONFIG": str(path)})

    def test_bridge_outage_does_not_issue_credentials(self):
        store = MagicMock()
        store.issue.side_effect = TokenStoreError("unavailable")
        sts = MagicMock()
        app = create_app(SETTINGS, proxy_key="p" * 32, session_key="s" * 32, sts=sts, token_store=store)
        client = app.test_client()
        self.assertEqual(client.get("/", headers=HEADERS, base_url="https://bridge.local").status_code, 503)
        store.check.side_effect = TokenStoreError("unavailable")
        self.assertEqual(
            client.get("/healthz", headers=HEADERS, base_url="https://bridge.local").status_code, 503
        )
        store.issue.side_effect = None
        store.issue.return_value = "fake-token"
        client.get("/", headers=HEADERS, base_url="https://bridge.local")
        store.consume.side_effect = TokenStoreError("unavailable")
        response = client.post(
            "/connect",
            headers=HEADERS,
            base_url="https://bridge.local",
            data={
                "csrf": "fake-token",
                "profile": "readonly",
                "secret_id": "broker-id",
                "secret_key": "fake-key",
                "audit_label": "alice",
            },
        )
        self.assertEqual(response.status_code, 503)
        sts.assert_not_called()


@unittest.skipUnless(
    os.environ.get("PSM_TEST_REDIS_URL"), "Real Redis integration runs in the dedicated CI job"
)
class RealRedisTests(unittest.TestCase):
    def setUp(self):
        import redis

        self.client = redis.Redis.from_url(os.environ["PSM_TEST_REDIS_URL"], decode_responses=True)
        self.namespace = "test-" + uuid.uuid4().hex
        self.store = RedisTokenStore(self.client, namespace=self.namespace)

    def tearDown(self):
        # Includes the per-identity index keys created by the issue script. Redis drops
        # an empty collection itself, so the pattern can legitimately match nothing and
        # DEL with no keys is an error.
        stale = self.client.keys(self.store.prefix + ":*")
        if stale:
            self.client.delete(*stale)
        self.client.close()

    def test_cross_node_atomic_replay(self):
        token = self.store.issue("alice")
        other = RedisTokenStore(self.client, namespace=self.namespace)
        self.assertFalse(other.consume(token, "bob"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
            outcomes = list(workers.map(lambda _: other.consume(token, "alice"), range(16)))
        self.assertEqual(sum(outcomes), 1)
        self.assertFalse(self.store.consume(token, "alice"))

    def test_capacity_and_server_expiry(self):
        store = RedisTokenStore(self.client, namespace=self.namespace, capacity=1, ttl=0.05)
        token = store.issue("alice")
        self.assertIsNone(store.issue("bob"))
        time.sleep(0.08)
        self.assertFalse(store.consume(token, "alice"))
        self.assertIsNotNone(store.issue("bob"))

    def test_one_identity_cannot_exhaust_the_shared_pool(self):
        store = RedisTokenStore(self.client, namespace=self.namespace, capacity=6)
        for _ in range(50):
            self.assertIsNotNone(store.issue("mallory"))
        self.assertIsNotNone(store.issue("alice"))
        self.assertLessEqual(self.client.zcard(store.owner_key("mallory")), 3)

    def test_records_do_not_contain_raw_tokens_or_identity(self):
        token = self.store.issue("private-identity")
        records = self.client.hgetall(self.store.keys[1])
        self.assertNotIn(token, records)
        self.assertNotIn("private-identity", records.values())

    def test_browser_cookie_cross_node(self):
        sts = MagicMock(
            return_value={"TmpSecretId": "AKID-TEST", "TmpSecretKey": "fake-secret", "Token": "fake-token"}
        )
        app1 = create_app(SETTINGS, proxy_key="p" * 32, session_key="s" * 32, sts=sts, token_store=self.store)
        app2 = create_app(
            SETTINGS,
            proxy_key="p" * 32,
            session_key="s" * 32,
            sts=sts,
            token_store=RedisTokenStore(self.client, namespace=self.namespace),
        )
        first, second = app1.test_client(), app2.test_client()
        page = first.get("/", headers=HEADERS, base_url="https://bridge.local")
        token = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        cookie = first.get_cookie("session", domain="bridge.local").value
        second.set_cookie("session", cookie, domain="bridge.local")
        data = {
            "csrf": token,
            "profile": "readonly",
            "secret_id": "broker-id",
            "secret_key": "fake-key",
            "audit_label": "alice",
        }
        self.assertEqual(
            second.post("/connect", data=data, headers=HEADERS, base_url="https://bridge.local").status_code,
            303,
        )
        self.assertEqual(
            first.post("/connect", data=data, headers=HEADERS, base_url="https://bridge.local").status_code,
            403,
        )
        sts.assert_called_once()


# Minimal RESP3 HELLO reply; redis-py 5 negotiates protocol 3 on every connect.
_HELLO3_REPLY = (
    b"%7\r\n"
    b"$6\r\nserver\r\n$5\r\nredis\r\n"
    b"$7\r\nversion\r\n$5\r\n7.2.5\r\n"
    b"$5\r\nproto\r\n:3\r\n"
    b"$2\r\nid\r\n:1\r\n"
    b"$4\r\nmode\r\n$10\r\nstandalone\r\n"
    b"$4\r\nrole\r\n$6\r\nmaster\r\n"
    b"$7\r\nmodules\r\n*0\r\n"
)


def _read_line(connection, buffer):
    """Minimal RESP line reader for the fake TLS Redis endpoint."""
    while b"\r\n" not in buffer:
        data = connection.recv(4096)
        if not data:
            return None, buffer
        buffer += data
    line, buffer = buffer.split(b"\r\n", 1)
    return line, buffer


def _read_command(connection, buffer):
    """Parse one RESP array (or inline command); return (parts, buffer)."""
    line, buffer = _read_line(connection, buffer)
    if line is None:
        return None, buffer
    if not line.startswith(b"*"):
        return line.split(), buffer
    parts = []
    for _ in range(int(line[1:])):
        header, buffer = _read_line(connection, buffer)
        if header is None:
            return None, buffer
        length = int(header[1:])
        while len(buffer) < length + 2:
            data = connection.recv(4096)
            if not data:
                return None, buffer
            buffer += data
        parts.append(buffer[:length])
        buffer = buffer[length + 2 :]
    return parts, buffer


@unittest.skipUnless(shutil.which("openssl"), "openssl is required to mint a throwaway CA")
class TlsRedisTests(unittest.TestCase):
    """End-to-end rediss:// handshake against a self-signed local endpoint.

    The unit tests pin the ssl_* client options; this class proves the whole path —
    CA pinning, hostname verification and the check() ping — against a real TLS socket.
    """

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        for name in ("server", "other"):
            subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(self.directory / f"{name}.key"),
                    "-out", str(self.directory / f"{name}.crt"),
                    "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost",
                ],
                check=True,
                capture_output=True,
            )

    def start_server(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.directory / "server.crt", self.directory / "server.key")
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        self.addCleanup(listener.close)

        def serve():
            while True:
                try:
                    raw, _ = listener.accept()
                except OSError:
                    return
                threading.Thread(target=handle, args=(raw,), daemon=True).start()

        def handle(raw):
            try:
                connection = context.wrap_socket(raw, server_side=True)
                buffer = b""
                while True:
                    parts, buffer = _read_command(connection, buffer)
                    if parts is None:
                        return
                    verb = parts[0].upper() if parts else b""
                    if verb == b"PING":
                        connection.sendall(b"+PONG\r\n")
                    elif verb == b"HELLO":
                        connection.sendall(_HELLO3_REPLY)
                    else:
                        connection.sendall(b"+OK\r\n")
            except (OSError, ssl.SSLError):
                return
            finally:
                raw.close()

        threading.Thread(target=serve, daemon=True).start()
        return listener.getsockname()[1]

    def test_rediss_handshake_and_check_succeed_with_the_pinned_ca(self):
        port = self.start_server()
        store = configured_token_store(
            {
                "PSM_TC_REDIS_URL": f"rediss://localhost:{port}/0",
                "PSM_TC_REDIS_CA_BUNDLE": str(self.directory / "server.crt"),
            }
        )
        self.assertTrue(store.check())

    def test_rediss_with_an_untrusted_ca_fails_closed(self):
        port = self.start_server()
        with self.assertRaises(TokenStoreError) as error:
            configured_token_store(
                {
                    "PSM_TC_REDIS_URL": f"rediss://localhost:{port}/0",
                    "PSM_TC_REDIS_CA_BUNDLE": str(self.directory / "other.crt"),
                }
            )
        self.assertEqual(str(error.exception), "Token backend unavailable")


if __name__ == "__main__":
    unittest.main()
