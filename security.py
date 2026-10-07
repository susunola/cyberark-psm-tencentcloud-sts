"""Bounded, identity-bound single-use tokens for a single bridge process."""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from validate import (
    DEFAULT_TOKEN_CAPACITY,
    DEFAULT_TOKEN_TTL_SECONDS,
    MAX_SHARED_CONFIG_BYTES,
    is_identifier,
    unique_json_object,
)


class TokenStoreError(Exception):
    """Backend failure; callers must fail closed without logging connection details."""


MAX_TOKEN_CAPACITY = 1000
MAX_TOKEN_TTL = 120
# A single proxy-authenticated caller may hold at most this many pending tokens;
# older ones are evicted so one identity cannot exhaust the shared pool.
DEFAULT_IDENTITY_CAPACITY = 3


def _valid_capacity(capacity: object) -> bool:
    # Booleans are rejected explicitly even though bool subclasses int.
    if isinstance(capacity, bool) or not isinstance(capacity, int):
        return False
    return 1 <= capacity <= MAX_TOKEN_CAPACITY


def _valid_identity_capacity(identity_capacity: object, capacity: int) -> bool:
    if isinstance(identity_capacity, bool) or not isinstance(identity_capacity, int):
        return False
    return 1 <= identity_capacity <= capacity


def _valid_ttl(ttl: object) -> bool:
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
        return False
    return 0 < ttl <= MAX_TOKEN_TTL


class TokenStore:
    def __init__(
        self,
        capacity: int = DEFAULT_TOKEN_CAPACITY,
        ttl: int = DEFAULT_TOKEN_TTL_SECONDS,
        clock: Callable[[], float] | None = None,
        identity_capacity: int | None = None,
    ) -> None:
        if not _valid_capacity(capacity) or not _valid_ttl(ttl):
            raise ValueError('Invalid token capacity/TTL')
        # Derived when unset so a small pool never rejects its own default; an
        # explicit value must still fit inside the pool.
        if identity_capacity is None:
            identity_capacity = min(DEFAULT_IDENTITY_CAPACITY, capacity)
        elif not _valid_identity_capacity(identity_capacity, capacity):
            raise ValueError('Invalid per-identity token capacity')
        self.capacity, self.ttl = capacity, ttl
        self.identity_capacity = identity_capacity
        # Late-bound lookup so tests can patch security.time.monotonic.
        self.clock = clock or (lambda: time.monotonic())  # noqa: PLW0108 - late binding for tests
        self.tokens: dict[str, tuple[float, str]] = {}
        self.lock = threading.Lock()

    def _evict_oldest_for(self, identity: str) -> None:
        """Keep one identity from monopolising the shared pool.

        Called with the lock held. Older tokens for the same identity are
        expendable because each form load replaces the caller's session token.
        """
        mine = sorted(
            (record for record, owner in self.tokens.items() if owner[1] == identity),
            key=lambda record: self.tokens[record][0],
        )
        while len(mine) >= self.identity_capacity:
            del self.tokens[mine.pop(0)]

    def issue(self, identity: str) -> str | None:
        now = self.clock()
        with self.lock:
            self.tokens = {k: v for k, v in self.tokens.items() if v[0] > now}
            self._evict_oldest_for(identity)
            if len(self.tokens) >= self.capacity:
                return None
            token = secrets.token_urlsafe(32)
            self.tokens[token] = (now + self.ttl, identity)
            return token

    def consume(self, token: str, identity: str) -> bool:
        now = self.clock()
        with self.lock:
            record = self.tokens.get(token)
            if not record:
                return False
            expiry, owner = record
            if expiry <= now:
                del self.tokens[token]
                return False
            if owner != identity:
                return False
            del self.tokens[token]
            return True

    def check(self) -> bool:
        return True


ISSUE_SCRIPT = """
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local expired = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now)
for _, token in ipairs(expired) do
    redis.call('HDEL', KEYS[2], token)
    redis.call('ZREM', KEYS[3], token)
end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
-- Bound this identity before the shared pool, so one caller cannot deny the rest.
while redis.call('ZCARD', KEYS[3]) >= tonumber(ARGV[5]) do
    local oldest = redis.call('ZRANGE', KEYS[3], 0, 0)[1]
    if not oldest then break end
    redis.call('ZREM', KEYS[3], oldest)
    redis.call('ZREM', KEYS[1], oldest)
    redis.call('HDEL', KEYS[2], oldest)
end
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then return 0 end
if redis.call('HEXISTS', KEYS[2], ARGV[1]) == 1 then return 0 end
redis.call('HSET', KEYS[2], ARGV[1], ARGV[2])
redis.call('ZADD', KEYS[1], now + tonumber(ARGV[4]), ARGV[1])
redis.call('ZADD', KEYS[3], now + tonumber(ARGV[4]), ARGV[1])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[4]) * 2)
redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[4]) * 2)
redis.call('PEXPIRE', KEYS[3], tonumber(ARGV[4]) * 2)
return 1
"""

CONSUME_SCRIPT = """
local expiry = redis.call('ZSCORE', KEYS[1], ARGV[1])
if not expiry then return 0 end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
if tonumber(expiry) <= now then
    redis.call('ZREM', KEYS[1], ARGV[1])
    redis.call('HDEL', KEYS[2], ARGV[1])
    redis.call('ZREM', KEYS[3], ARGV[1])
    return 0
end
if redis.call('HGET', KEYS[2], ARGV[1]) ~= ARGV[2] then return 0 end
redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('HDEL', KEYS[2], ARGV[1])
redis.call('ZREM', KEYS[3], ARGV[1])
return 1
"""


class RedisTokenStore:
    """Shared bounded tokens, consumed atomically on one Redis primary (Redis 7+).

    Every key is declared up front and shares the ``{namespace}`` hash tag, so the
    scripts stay single-slot on a cluster.
    """

    def __init__(
        self,
        client: Any,
        namespace: str = 'psm-tencent',
        capacity: int = DEFAULT_TOKEN_CAPACITY,
        ttl: int = DEFAULT_TOKEN_TTL_SECONDS,
        identity_capacity: int | None = None,
    ) -> None:
        if not is_identifier(namespace, 1, 80):
            raise ValueError('Invalid token namespace')
        if not _valid_capacity(capacity) or not _valid_ttl(ttl):
            raise ValueError('Invalid token capacity/TTL')
        if identity_capacity is None:
            identity_capacity = min(DEFAULT_IDENTITY_CAPACITY, capacity)
        elif not _valid_identity_capacity(identity_capacity, capacity):
            raise ValueError('Invalid per-identity token capacity')
        self.client, self.capacity, self.ttl = client, capacity, ttl
        self.identity_capacity = identity_capacity
        self.prefix = '{' + namespace + '}'
        self.keys = (self.prefix + ':expiry', self.prefix + ':owners')

    @staticmethod
    def digest(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    def owner_key(self, identity: str) -> str:
        return self.prefix + ':owner:' + self.digest(identity)

    def evaluate(self, script: str, keys: tuple[str, ...], *args: object) -> Any:
        try:
            return self.client.eval(script, len(keys), *keys, *args)
        except Exception:  # noqa: BLE001 - never forward error text
            # Never forward backend error text; it may echo connection or key material.
            raise TokenStoreError('Token backend unavailable') from None

    def issue(self, identity: str) -> str | None:
        token = secrets.token_urlsafe(32)
        keys = (*self.keys, self.owner_key(identity))
        result = self.evaluate(
            ISSUE_SCRIPT,
            keys,
            self.digest(token),
            self.digest(identity),
            self.capacity,
            int(self.ttl * 1000),
            self.identity_capacity,
        )
        return token if result == 1 else None

    def consume(self, token: str, identity: str) -> bool:
        keys = (*self.keys, self.owner_key(identity))
        return bool(self.evaluate(CONSUME_SCRIPT, keys, self.digest(token), self.digest(identity)) == 1)

    def check(self) -> bool:
        try:
            if not bool(self.client.ping()):
                raise TokenStoreError('Token backend unavailable')
            return True
        except Exception:  # noqa: BLE001 - never forward error text
            raise TokenStoreError('Token backend unavailable') from None


def configured_token_store(environment: Mapping[str, str]) -> TokenStore | RedisTokenStore:
    url = environment.get('PSM_TC_REDIS_URL')
    if not url:
        return TokenStore()
    parsed = urlsplit(url)
    if parsed.scheme != 'rediss' or not parsed.hostname or parsed.query or parsed.fragment or not re.fullmatch(r'/[0-9]+', parsed.path or '/0'):
        raise ValueError('Use a TLS Redis URL without query overrides')
    import redis
    from redis.backoff import NoBackoff
    from redis.retry import Retry

    # No automatic retry: an uncertain consume must never issue cloud credentials.
    client = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2,
        max_connections=10, decode_responses=True, ssl_cert_reqs='required', ssl_check_hostname=True,
        ssl_ca_certs=environment.get('PSM_TC_REDIS_CA_BUNDLE') or None,
        retry=Retry(NoBackoff(), 0), retry_on_error=[])
    store = RedisTokenStore(client, environment.get('PSM_TC_REDIS_NAMESPACE', 'psm-tencent'))
    store.check()
    return store


def shared_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """Optional ACL-protected cluster secrets file; never log its contents."""
    path = environment.get('PSM_TC_SHARED_CONFIG')
    if not path:
        return dict(environment)
    with Path(path).open('rb') as source:
        raw = source.read(MAX_SHARED_CONFIG_BYTES + 1)
    if len(raw) > MAX_SHARED_CONFIG_BYTES:
        raise ValueError('Shared configuration exceeds size limit')

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        return unique_json_object(pairs, message='Duplicate shared configuration field')

    config = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=unique)
    if not isinstance(config, dict) or set(config) != {'redis_url', 'namespace', 'session_key', 'ca_bundle'}:
        raise ValueError('Invalid shared configuration fields')
    if not isinstance(config['session_key'], str) or len(config['session_key']) < 32 or 'REPLACE' in config['session_key']:
        raise ValueError('Shared session key must have at least 32 characters')
    if not all(isinstance(config[k], str) for k in config):
        raise ValueError('Shared configuration fields must be strings')
    if not config['redis_url'] or not config['namespace']:
        raise ValueError('Shared Redis connection and namespace required')
    return {**environment, 'PSM_TC_REDIS_URL': config['redis_url'], 'PSM_TC_REDIS_NAMESPACE': config['namespace'],
            'PSM_TC_SESSION_KEY': config['session_key'], 'PSM_TC_REDIS_CA_BUNDLE': config['ca_bundle']}
