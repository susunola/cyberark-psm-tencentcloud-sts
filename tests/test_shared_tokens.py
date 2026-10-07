import concurrent.futures
import json
import os
import re
import tempfile
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
        self.client.delete(*self.store.keys)
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


if __name__ == "__main__":
    unittest.main()
