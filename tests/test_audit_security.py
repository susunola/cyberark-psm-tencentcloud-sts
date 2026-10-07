"""Focused coverage for the audit aggregator and the single-use token stores."""

import hashlib
import io
import json
import tempfile
import unittest
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from unittest.mock import MagicMock, patch

from redis.backoff import NoBackoff
from redis.retry import Retry

from pam.audit import event, summarize
from security import (
    CONSUME_SCRIPT,
    ISSUE_SCRIPT,
    RedisTokenStore,
    TokenStore,
    TokenStoreError,
    configured_token_store,
    shared_environment,
)

REQUEST_ID = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
SCOPE = "local bridge aggregates; not native PAM threat analytics"
REDIS_URL = "rediss://redis.example:6379/0"
REPORT_KEYS = {
    "input_lines",
    "ignored_lines",
    "unique_http_events",
    "unique_role_events",
    "http_status_counts",
    "role_profile_counts",
    "scope",
}


def bridge_row(**overrides):
    row = {"event": "http_result", "request_id": REQUEST_ID, "status": 200}
    row.update(overrides)
    return row


def role_row(**overrides):
    row = {"event": "role_session_issued", "request_id": REQUEST_ID, "profile": "readonly-1"}
    row.update(overrides)
    return row


def stream(*rows):
    return io.StringIO("\n".join(rows) + "\n")


def recursion_deep_document():
    """Return a JSON document deep enough to exhaust the parser, or None when unsupported."""
    for depth in (100_000, 200_000, 400_000, 800_000):
        text = "[" * depth + "]" * depth
        try:
            json.loads(text)
        except RecursionError:
            return text
    return None


def shared_payload(**overrides):
    payload = {
        "redis_url": "rediss://shared.example:6379/2",
        "namespace": "shared-cluster",
        "session_key": "k" * 48,
        "ca_bundle": "/etc/ssl/shared-ca.pem",
    }
    payload.update(overrides)
    return payload


def write_shared_config(folder, payload):
    path = Path(folder) / "shared-config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


class AuditEventTests(unittest.TestCase):
    def test_event_emits_schema_version_and_utc_millisecond_timestamp(self):
        payload = json.loads(event({"event": "http_result", "request_id": REQUEST_ID}))
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["event"], "http_result")
        self.assertEqual(payload["request_id"], REQUEST_ID)
        stamp = payload["timestamp"]
        self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00$")
        parsed = datetime.fromisoformat(stamp)
        self.assertEqual(parsed.tzinfo, UTC)
        self.assertLess(abs((datetime.now(UTC) - parsed).total_seconds()), 5)

    def test_event_reserved_keys_cannot_be_clobbered_by_callers(self):
        # The schema tag and timestamp are owned by the emitter, so a caller
        # payload can never forge them; every other field is merged through.
        payload = json.loads(
            event({"schema_version": 99, "timestamp": "caller-supplied", "audit_label": "PSM-user"})
        )
        self.assertEqual(set(payload), {"schema_version", "timestamp", "audit_label"})
        self.assertEqual(payload["schema_version"], 1)
        self.assertNotEqual(payload["timestamp"], "caller-supplied")
        self.assertRegex(payload["timestamp"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00$")
        self.assertEqual(payload["audit_label"], "PSM-user")


class AuditSummarizeBoundsTests(unittest.TestCase):
    def test_invalid_max_lines_is_rejected(self):
        for value in (0, -1, 1.5, "10", None, True, 100001, 200000):
            with self.subTest(max_lines=value), self.assertRaises(ValueError):
                summarize(io.StringIO(""), max_lines=value)

    def test_line_count_bound_is_inclusive_and_fails_closed_past_it(self):
        self.assertEqual(summarize(io.StringIO(""), max_lines=1)["input_lines"], 0)
        two = [json.dumps(bridge_row()), json.dumps(bridge_row(request_id="b" * 32))]
        self.assertEqual(summarize(stream(*two), max_lines=2)["input_lines"], 2)
        with self.assertRaises(ValueError) as error:
            summarize(stream(*two), max_lines=1)
        self.assertIn("exceeds bound", str(error.exception))

    def test_line_byte_bound_is_inclusive_and_fails_closed_past_it(self):
        encoded = json.dumps(bridge_row())
        padded = encoded + " " * (8192 - len(encoded))
        self.assertEqual(len(padded), 8192)
        accepted = summarize(io.StringIO(padded))
        self.assertEqual((accepted["input_lines"], accepted["ignored_lines"]), (1, 0))
        self.assertEqual(accepted["unique_http_events"], 1)
        junk = summarize(io.StringIO("x" * 8192))
        self.assertEqual((junk["input_lines"], junk["ignored_lines"]), (1, 1))
        with self.assertRaises(ValueError) as error:
            summarize(io.StringIO(padded + "  "))
        self.assertIn("exceeds bound", str(error.exception))

    def test_recursion_deep_document_is_rejected_by_the_byte_bound(self):
        document = recursion_deep_document()
        if document is None:
            self.skipTest("interpreter parses arbitrary nesting depth")
        with self.assertRaises(ValueError) as error:
            summarize(io.StringIO(document))
        self.assertIn("exceeds bound", str(error.exception))


class AuditSummarizeFilterTests(unittest.TestCase):
    def test_malformed_rows_and_bad_request_ids_are_ignored_and_counted(self):
        rows = [
            "",
            "not json at all",
            "[1, 2]",
            json.dumps({"event": "http_result", "status": 200}),
            json.dumps(bridge_row(request_id="abc")),
            json.dumps(bridge_row(request_id="a" * 33)),
            json.dumps(bridge_row(request_id="z" * 32)),
            json.dumps(bridge_row(request_id="A" * 32)),
            json.dumps(bridge_row(request_id=1234)),
            json.dumps(bridge_row()),
        ]
        result = summarize(stream(*rows))
        self.assertEqual(set(result), REPORT_KEYS)
        self.assertEqual(result["scope"], SCOPE)
        self.assertEqual(result["input_lines"], 10)
        self.assertEqual(result["ignored_lines"], 9)
        self.assertEqual(result["unique_http_events"], 1)
        self.assertEqual(result["unique_role_events"], 0)
        self.assertEqual(result["http_status_counts"], {"200": 1})
        self.assertEqual(result["role_profile_counts"], {})

    def test_rows_with_unusable_event_status_or_profile_are_ignored(self):
        rows = [
            json.dumps(bridge_row(status="200")),
            json.dumps(bridge_row(status=99)),
            json.dumps(bridge_row(status=600)),
            json.dumps(bridge_row(status=True)),
            json.dumps(bridge_row(status=None)),
            json.dumps({"event": "http_result", "request_id": REQUEST_ID}),
            json.dumps({"event": "connect_started", "request_id": REQUEST_ID}),
            json.dumps({"request_id": REQUEST_ID}),
            json.dumps(role_row(profile="bad profile!")),
            json.dumps(role_row(profile="p" * 81)),
            json.dumps(role_row(profile=1234)),
            json.dumps({"event": "role_session_issued", "request_id": REQUEST_ID}),
            json.dumps(role_row()),
        ]
        result = summarize(stream(*rows))
        self.assertEqual(result["input_lines"], 13)
        self.assertEqual(result["ignored_lines"], 12)
        self.assertEqual(result["unique_http_events"], 0)
        self.assertEqual(result["unique_role_events"], 1)
        self.assertEqual(result["http_status_counts"], {})
        self.assertEqual(result["role_profile_counts"], {"readonly-1": 1})

    def test_duplicate_request_ids_are_deduplicated_per_event_type(self):
        first, second = "b" * 32, "c" * 32
        rows = [
            json.dumps(bridge_row(request_id=first, status=200)),
            json.dumps(bridge_row(request_id=first, status=500)),
            json.dumps(role_row(request_id=first, profile="readonly")),
            json.dumps(role_row(request_id=first, profile="admin")),
            json.dumps(bridge_row(request_id=second, status=500)),
            json.dumps(role_row(request_id=second, profile="admin")),
        ]
        result = summarize(stream(*rows))
        self.assertEqual(result["input_lines"], 6)
        self.assertEqual(result["ignored_lines"], 0)
        self.assertEqual(result["unique_http_events"], 2)
        self.assertEqual(result["unique_role_events"], 2)
        self.assertEqual(result["http_status_counts"], {"200": 1, "500": 1})
        self.assertEqual(result["role_profile_counts"], {"readonly": 1, "admin": 1})

    def test_utf8_bom_is_tolerated_only_on_the_first_line(self):
        first, second = "d" * 32, "e" * 32
        rows = [
            "\ufeff" + json.dumps(bridge_row(request_id=first)),
            "\ufeff" + json.dumps(bridge_row(request_id=second)),
        ]
        result = summarize(stream(*rows))
        self.assertEqual(result["input_lines"], 2)
        self.assertEqual(result["ignored_lines"], 1)
        self.assertEqual(result["unique_http_events"], 1)
        self.assertEqual(result["http_status_counts"], {"200": 1})

    def test_empty_stream_reports_the_exact_report_contract(self):
        self.assertEqual(
            summarize(io.StringIO("")),
            {
                "input_lines": 0,
                "ignored_lines": 0,
                "unique_http_events": 0,
                "unique_role_events": 0,
                "http_status_counts": {},
                "role_profile_counts": {},
                "scope": SCOPE,
            },
        )
        self.assertEqual(set(summarize(stream(json.dumps(bridge_row())))), REPORT_KEYS)


class InProcessTokenStoreTests(unittest.TestCase):
    def test_issue_and_consume_are_single_use_and_bound_to_the_identity(self):
        store = TokenStore(capacity=5, ttl=60)
        token = store.issue("alice")
        self.assertIsInstance(token, str)
        self.assertGreaterEqual(len(token), 32)
        self.assertIn(token, store.tokens)
        self.assertTrue(store.check())
        self.assertTrue(store.consume(token, "alice"))
        self.assertNotIn(token, store.tokens)
        self.assertFalse(store.consume(token, "alice"))

    def test_unknown_token_and_wrong_identity_leave_the_store_untouched(self):
        store = TokenStore()
        token = store.issue("alice")
        self.assertFalse(store.consume("unknown-token", "alice"))
        self.assertEqual(len(store.tokens), 1)
        self.assertFalse(store.consume(token, ""))
        self.assertFalse(store.consume(token, "alice "))
        self.assertIn(token, store.tokens)
        self.assertTrue(store.consume(token, "alice"))

    def test_expiry_comes_from_the_injected_clock(self):
        now = [100.0]
        store = TokenStore(ttl=10, clock=lambda: now[0])
        alive, doomed = store.issue("alice"), store.issue("bob")
        now[0] = 109.999
        self.assertTrue(store.consume(alive, "alice"))
        now[0] = 110.0
        self.assertFalse(store.consume(doomed, "bob"))
        self.assertNotIn(doomed, store.tokens)

    def test_default_clock_is_resolved_per_call_from_time_monotonic(self):
        store = TokenStore(ttl=30)
        with patch("security.time.monotonic", return_value=500.0) as clock:
            token = store.issue("alice")
            clock.return_value = 529.0
            self.assertTrue(store.consume(token, "alice"))
        with patch("security.time.monotonic", return_value=1000.0) as clock:
            token = store.issue("alice")
            clock.return_value = 1030.0
            self.assertFalse(store.consume(token, "alice"))
            self.assertGreaterEqual(clock.call_count, 2)

    def test_construction_rejects_a_bad_capacity_or_ttl(self):
        for overrides in (
            {"capacity": 0},
            {"capacity": -1},
            {"capacity": 1001},
            {"capacity": True},
            {"capacity": "10"},
            {"ttl": 0},
            {"ttl": -1},
            {"ttl": 121},
            {"ttl": "60"},
            {"ttl": None},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                TokenStore(**overrides)
        self.assertEqual(TokenStore(capacity=1, ttl=0.05).ttl, 0.05)

    def test_capacity_is_bounded_and_expired_tokens_are_pruned_on_issue(self):
        now = [0.0]
        store = TokenStore(capacity=2, ttl=60, clock=lambda: now[0])
        first = store.issue("alice")
        self.assertIsNotNone(store.issue("bob"))
        self.assertEqual(len(store.tokens), 2)
        self.assertIsNone(store.issue("carol"))
        self.assertEqual(len(store.tokens), 2)
        now[0] = 60.0
        replacement = store.issue("carol")
        self.assertIsNotNone(replacement)
        self.assertEqual(len(store.tokens), 1)
        self.assertNotIn(first, store.tokens)
        self.assertFalse(store.consume(first, "alice"))
        self.assertTrue(store.consume(replacement, "carol"))


class RedisTokenStoreTests(unittest.TestCase):
    def _assert_sanitized_failure(self, call):
        with self.assertRaises(TokenStoreError) as error:
            call()
        self.assertEqual(str(error.exception), "Token backend unavailable")
        self.assertIsNone(error.exception.__cause__)
        self.assertNotIn("FAKE-DSN", repr(error.exception))

    def test_construction_validation_and_key_layout(self):
        client = MagicMock()
        store = RedisTokenStore(client, namespace="prod", capacity=1, ttl=120)
        self.assertIs(store.client, client)
        self.assertEqual((store.capacity, store.ttl), (1, 120))
        self.assertEqual(store.keys, ("{prod}:expiry", "{prod}:owners"))
        RedisTokenStore(client, namespace="p" * 80, capacity=1000, ttl=1)
        for namespace in ("", "bad namespace", "x" * 81, "ns;drop", "ünïcode"):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                RedisTokenStore(client, namespace=namespace)
        for overrides in (
            {"capacity": 0},
            {"capacity": 1001},
            {"capacity": True},
            {"capacity": "10"},
            {"ttl": 0},
            {"ttl": 121},
            {"ttl": -1},
            {"ttl": True},
            {"ttl": "60"},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                RedisTokenStore(client, **overrides)
        client.eval.assert_not_called()
        client.ping.assert_not_called()

    def test_digest_is_a_stable_sha256_hex(self):
        self.assertEqual(RedisTokenStore.digest("alice"), hashlib.sha256(b"alice").hexdigest())
        self.assertEqual(RedisTokenStore.digest(""), hashlib.sha256(b"").hexdigest())
        self.assertRegex(RedisTokenStore.digest("alice"), r"^[0-9a-f]{64}$")
        self.assertEqual(RedisTokenStore.digest("alice"), RedisTokenStore.digest("alice"))
        self.assertNotEqual(RedisTokenStore.digest("alice"), RedisTokenStore.digest("bob"))

    def test_evaluate_returns_the_script_result_verbatim_and_sanitizes_every_driver_fault(self):
        client = MagicMock()
        store = RedisTokenStore(client)
        # evaluate hands the driver reply back untouched, so a reply that is not the
        # exact integer 1 must fail closed instead of being parsed into an authorization.
        client.eval.return_value = "1"
        self.assertEqual(store.evaluate(ISSUE_SCRIPT, "arg"), "1")
        self.assertIsNone(store.issue("alice"))
        client.eval.return_value = b"0"
        self.assertEqual(store.evaluate(ISSUE_SCRIPT, "arg"), b"0")
        self.assertIsNone(store.issue("alice"))
        client.eval.return_value = "not-a-number"
        self.assertEqual(store.evaluate(ISSUE_SCRIPT, "arg"), "not-a-number")
        self.assertIsNone(store.issue("alice"))
        for fault in (
            ConnectionError("FAKE-DSN redis://user:secret@private.invalid/0"),
            TimeoutError("FAKE-DSN"),
            ValueError("FAKE-DSN"),
            OSError("FAKE-DSN"),
            KeyError("FAKE-DSN"),
            TypeError("FAKE-DSN"),
            RuntimeError("FAKE-DSN"),
        ):
            with self.subTest(fault=type(fault).__name__):
                client = MagicMock()
                client.eval.side_effect = fault
                store = RedisTokenStore(client)
                for call in (
                    partial(store.evaluate, ISSUE_SCRIPT, "arg"),
                    partial(store.issue, "alice"),
                    partial(store.consume, "token-value", "alice"),
                ):
                    self._assert_sanitized_failure(call)

    def test_issue_only_accepts_a_script_result_of_one(self):
        client = MagicMock()
        store = RedisTokenStore(client, namespace="prod", capacity=7, ttl=45)
        client.eval.return_value = 1
        token = store.issue("alice")
        self.assertIsInstance(token, str)
        script, key_count, *extra = client.eval.call_args.args
        self.assertEqual(script, ISSUE_SCRIPT)
        self.assertEqual(key_count, 2)
        self.assertEqual(tuple(extra[:2]), store.keys)
        self.assertEqual(extra[2], RedisTokenStore.digest(token))
        self.assertEqual(extra[3], RedisTokenStore.digest("alice"))
        self.assertEqual(extra[4:], [7, 45_000])
        self.assertNotIn(token, str(client.eval.call_args))
        for result in (0, 2, -1, "1", b"1"):
            client.eval.return_value = result
            self.assertIsNone(store.issue("alice"))

    def test_consume_is_true_only_for_a_script_result_of_one(self):
        client = MagicMock()
        store = RedisTokenStore(client)
        client.eval.return_value = 1
        self.assertTrue(store.consume("token-value", "alice"))
        script, key_count, *extra = client.eval.call_args.args
        self.assertEqual(script, CONSUME_SCRIPT)
        self.assertEqual(key_count, 2)
        self.assertEqual(tuple(extra[:2]), store.keys)
        self.assertEqual(
            tuple(extra[2:]),
            (RedisTokenStore.digest("token-value"), RedisTokenStore.digest("alice")),
        )
        self.assertNotIn("token-value", str(client.eval.call_args))
        for result in (0, 2, -1, "0", b"0"):
            client.eval.return_value = result
            self.assertFalse(store.consume("token-value", "alice"))

    def test_check_requires_a_truthy_ping(self):
        for healthy in (True, 1, b"PONG", "PONG"):
            with self.subTest(ping=healthy):
                client = MagicMock()
                client.ping.return_value = healthy
                self.assertTrue(RedisTokenStore(client).check())
                client.ping.assert_called_once_with()
        for unhealthy in (None, False, 0, ""):
            with self.subTest(ping=unhealthy):
                client = MagicMock()
                client.ping.return_value = unhealthy
                with self.assertRaises(TokenStoreError) as error:
                    RedisTokenStore(client).check()
                self.assertEqual(str(error.exception), "Token backend unavailable")
        for fault in (ConnectionError("FAKE-DSN"), TimeoutError("FAKE-DSN"), TokenStoreError("FAKE-DSN")):
            with self.subTest(fault=type(fault).__name__):
                client = MagicMock()
                client.ping.side_effect = fault
                with self.assertRaises(TokenStoreError) as error:
                    RedisTokenStore(client).check()
                self.assertEqual(str(error.exception), "Token backend unavailable")
                self.assertIsNone(error.exception.__cause__)
                self.assertNotIn("FAKE-DSN", repr(error.exception))


class ConfiguredTokenStoreTests(unittest.TestCase):
    def test_absent_url_selects_the_in_process_store(self):
        for environment in ({}, {"PSM_TC_REDIS_URL": ""}, {"PSM_TC_REDIS_URL": None}):
            with self.subTest(environment=environment):
                store = configured_token_store(environment)
                self.assertIsInstance(store, TokenStore)
                self.assertTrue(store.check())

    def test_unsafe_redis_urls_are_rejected_before_a_client_is_built(self):
        with patch("redis.Redis.from_url") as factory:
            for url in (
                "redis://redis.example:6379/0",
                "http://redis.example/0",
                "rediss://redis.example:6379/0?ssl_cert_reqs=none",
                "rediss://redis.example:6379/0#fragment",
                "rediss://:6379/0",
                "rediss:///0",
                "rediss://redis.example:6379/primary",
                "rediss://redis.example:6379/0/1",
            ):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    configured_token_store({"PSM_TC_REDIS_URL": url})
            factory.assert_not_called()

    def test_tls_options_ca_bundle_and_eager_health_check(self):
        with patch("redis.Redis.from_url") as factory:
            factory.return_value.ping.return_value = True
            store = configured_token_store(
                {
                    "PSM_TC_REDIS_URL": REDIS_URL,
                    "PSM_TC_REDIS_NAMESPACE": "cluster-a",
                    "PSM_TC_REDIS_CA_BUNDLE": "/etc/ssl/fake-ca.pem",
                    "PSM_TC_PROXY_KEY": "p" * 32,
                }
            )
            self.assertEqual(factory.call_args.args, (REDIS_URL,))
            options = factory.call_args.kwargs
            self.assertEqual(options["socket_connect_timeout"], 2)
            self.assertEqual(options["socket_timeout"], 2)
            self.assertEqual(options["max_connections"], 10)
            self.assertIs(options["decode_responses"], True)
            self.assertEqual(options["ssl_cert_reqs"], "required")
            self.assertIs(options["ssl_check_hostname"], True)
            self.assertEqual(options["ssl_ca_certs"], "/etc/ssl/fake-ca.pem")
            self.assertEqual(options["retry_on_error"], [])
            self.assertIsInstance(options["retry"], Retry)
            self.assertEqual(options["retry"].get_retries(), 0)
            self.assertIsInstance(options["retry"]._backoff, NoBackoff)
            self.assertIsInstance(store, RedisTokenStore)
            self.assertEqual(store.keys, ("{cluster-a}:expiry", "{cluster-a}:owners"))
            factory.return_value.ping.assert_called_once_with()
            self.assertTrue(store.check())
            self.assertEqual(factory.return_value.ping.call_count, 2)

    def test_namespace_default_empty_ca_bundle_and_dead_backend(self):
        with patch("redis.Redis.from_url") as factory:
            factory.return_value.ping.return_value = True
            store = configured_token_store({"PSM_TC_REDIS_URL": REDIS_URL, "PSM_TC_REDIS_CA_BUNDLE": ""})
            self.assertIsNone(factory.call_args.kwargs["ssl_ca_certs"])
            self.assertEqual(store.keys, ("{psm-tencent}:expiry", "{psm-tencent}:owners"))
            implicit_default_db = configured_token_store({"PSM_TC_REDIS_URL": "rediss://redis.example:6379"})
            self.assertIsInstance(implicit_default_db, RedisTokenStore)
            factory.return_value.ping.return_value = None
            with self.assertRaises(TokenStoreError):
                configured_token_store({"PSM_TC_REDIS_URL": REDIS_URL})


class SharedEnvironmentTests(unittest.TestCase):
    def test_unset_shared_config_returns_the_input_mapping_unchanged(self):
        environment = {"PSM_TC_REDIS_URL": REDIS_URL, "PSM_TC_PROXY_KEY": "p" * 32}
        resolved = shared_environment(environment)
        # An unset shared config passes the environment through unchanged, as a copy.
        self.assertEqual(resolved, environment)
        self.assertIsNot(resolved, environment)
        self.assertEqual(shared_environment({}), {})

    def test_shared_config_overrides_cluster_settings(self):
        with tempfile.TemporaryDirectory() as folder:
            environment = {
                "PSM_TC_SHARED_CONFIG": write_shared_config(folder, shared_payload()),
                "PSM_TC_REDIS_URL": REDIS_URL,
                "PSM_TC_REDIS_NAMESPACE": "original",
                "PSM_TC_REDIS_CA_BUNDLE": "",
                "PSM_TC_SESSION_KEY": "o" * 32,
            }
            before = dict(environment)
            merged = shared_environment(environment)
            self.assertEqual(environment, before)
        self.assertIsNot(merged, environment)
        self.assertEqual(merged["PSM_TC_REDIS_URL"], "rediss://shared.example:6379/2")
        self.assertEqual(merged["PSM_TC_REDIS_NAMESPACE"], "shared-cluster")
        self.assertEqual(merged["PSM_TC_SESSION_KEY"], "k" * 48)
        self.assertEqual(merged["PSM_TC_REDIS_CA_BUNDLE"], "/etc/ssl/shared-ca.pem")
        self.assertEqual(merged["PSM_TC_SHARED_CONFIG"], before["PSM_TC_SHARED_CONFIG"])

    def test_shared_config_size_bound_is_enforced(self):
        with tempfile.TemporaryDirectory() as folder:
            oversized = Path(folder) / "oversized.json"
            oversized.write_text(json.dumps(shared_payload(ca_bundle="c" * 70_000)), encoding="utf-8")
            self.assertGreater(oversized.stat().st_size, 65_536)
            with self.assertRaises(ValueError) as error:
                shared_environment({"PSM_TC_SHARED_CONFIG": str(oversized)})
            self.assertIn("exceeds size limit", str(error.exception))

            padding = 65_536 - len(json.dumps(shared_payload(ca_bundle="")))
            raw = json.dumps(shared_payload(ca_bundle="c" * padding)).encode("utf-8")
            self.assertEqual(len(raw), 65_536)
            boundary = Path(folder) / "boundary.json"
            boundary.write_bytes(raw)
            merged = shared_environment({"PSM_TC_SHARED_CONFIG": str(boundary)})
            self.assertEqual(len(merged["PSM_TC_REDIS_CA_BUNDLE"]), padding)

    def test_shared_config_rejects_duplicate_keys_and_wrong_field_sets(self):
        duplicated = (
            '{"redis_url": "rediss://a.example/0", "redis_url": "rediss://b.example/0",'
            ' "namespace": "ns", "session_key": "' + "k" * 32 + '", "ca_bundle": ""}'
        )
        payload = shared_payload()
        cases = [
            duplicated,
            json.dumps({key: value for key, value in payload.items() if key != "ca_bundle"}),
            json.dumps({key: value for key, value in payload.items() if key != "session_key"}),
            json.dumps(shared_payload(extra="value")),
            json.dumps([payload]),
            "{}",
        ]
        with tempfile.TemporaryDirectory() as folder:
            for index, body in enumerate(cases):
                path = Path(folder) / f"case-{index}.json"
                path.write_text(body, encoding="utf-8")
                with self.subTest(case=index), self.assertRaises(ValueError):
                    shared_environment({"PSM_TC_SHARED_CONFIG": str(path)})

    def test_shared_config_rejects_weak_keys_non_strings_and_empty_values(self):
        cases = [
            shared_payload(session_key="short"),
            shared_payload(session_key="s" * 31),
            shared_payload(session_key="REPLACE" + "s" * 32),
            shared_payload(session_key=["k" * 32]),
            shared_payload(namespace=42),
            shared_payload(ca_bundle=7),
            shared_payload(redis_url=""),
            shared_payload(namespace=""),
        ]
        with tempfile.TemporaryDirectory() as folder:
            for index, payload in enumerate(cases):
                path = Path(folder) / f"weak-{index}.json"
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.subTest(case=index), self.assertRaises(ValueError):
                    shared_environment({"PSM_TC_SHARED_CONFIG": str(path)})
            accepted = write_shared_config(folder, shared_payload(session_key="k" * 32))
            merged = shared_environment({"PSM_TC_SHARED_CONFIG": accepted})
            self.assertEqual(merged["PSM_TC_SESSION_KEY"], "k" * 32)


if __name__ == "__main__":
    unittest.main()
