"""Bounded, identity-bound single-use tokens for a single bridge process."""
import secrets
import threading
import time
import hashlib
import re
import json
from pathlib import Path
from urllib.parse import urlsplit


class TokenStoreError(Exception):
    """Backend failure; callers must fail closed without logging connection details."""


class TokenStore:
    def __init__(self, capacity=1000, ttl=120, clock=None):
        self.capacity, self.ttl = capacity, ttl
        self.clock = clock or (lambda: time.monotonic())
        self.tokens = {}
        self.lock = threading.Lock()

    def issue(self, identity):
        now = self.clock()
        with self.lock:
            self.tokens = {k: v for k, v in self.tokens.items() if v[0] > now}
            if len(self.tokens) >= self.capacity:
                return None
            token = secrets.token_urlsafe(32)
            self.tokens[token] = (now + self.ttl, identity)
            return token

    def consume(self, token, identity):
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

    def check(self):
        return True


ISSUE_SCRIPT = '''
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local expired = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now)
for _, token in ipairs(expired) do redis.call('HDEL', KEYS[2], token) end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
if redis.call('ZCARD', KEYS[1]) >= tonumber(ARGV[3]) then return 0 end
if redis.call('HEXISTS', KEYS[2], ARGV[1]) == 1 then return 0 end
redis.call('HSET', KEYS[2], ARGV[1], ARGV[2])
redis.call('ZADD', KEYS[1], now + tonumber(ARGV[4]), ARGV[1])
redis.call('PEXPIRE', KEYS[1], tonumber(ARGV[4]) * 2)
redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[4]) * 2)
return 1
'''

CONSUME_SCRIPT = '''
local expiry = redis.call('ZSCORE', KEYS[1], ARGV[1])
if not expiry then return 0 end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
if tonumber(expiry) <= now then
    redis.call('ZREM', KEYS[1], ARGV[1])
    redis.call('HDEL', KEYS[2], ARGV[1])
    return 0
end
if redis.call('HGET', KEYS[2], ARGV[1]) ~= ARGV[2] then return 0 end
redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('HDEL', KEYS[2], ARGV[1])
return 1
'''


class RedisTokenStore:
    """Shared bounded tokens, consumed atomically on one Redis primary (Redis 7+)."""
    def __init__(self, client, namespace='psm-tencent', capacity=1000, ttl=120):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', namespace):
            raise ValueError('Invalid token namespace')
        if type(capacity) is not int or not 1 <= capacity <= 1000 or not 0 < ttl <= 120:
            raise ValueError('Invalid token capacity/TTL')
        self.client, self.capacity, self.ttl = client, capacity, ttl
        self.keys = ('{' + namespace + '}:expiry', '{' + namespace + '}:owners')

    @staticmethod
    def digest(value):
        return hashlib.sha256(value.encode()).hexdigest()

    def evaluate(self, script, *args):
        try:
            return self.client.eval(script, 2, *self.keys, *args)
        except Exception:
            raise TokenStoreError('Token backend unavailable') from None

    def issue(self, identity):
        token = secrets.token_urlsafe(32)
        result = self.evaluate(ISSUE_SCRIPT, self.digest(token), self.digest(identity), self.capacity, int(self.ttl * 1000))
        return token if result == 1 else None

    def consume(self, token, identity):
        return self.evaluate(CONSUME_SCRIPT, self.digest(token), self.digest(identity)) == 1

    def check(self):
        try:
            if not self.client.ping():
                raise TokenStoreError('Token backend unavailable')
            return True
        except Exception:
            raise TokenStoreError('Token backend unavailable') from None


def configured_token_store(environment):
    url = environment.get('PSM_TC_REDIS_URL')
    if not url:
        return TokenStore()
    parsed = urlsplit(url)
    if parsed.scheme != 'rediss' or not parsed.hostname or parsed.query or parsed.fragment or not re.fullmatch(r'/[0-9]+', parsed.path or '/0'):
        raise ValueError('Use a TLS Redis URL without query overrides')
    import redis
    from redis.retry import Retry
    from redis.backoff import NoBackoff
    # No automatic retry: an uncertain consume must never issue cloud credentials.
    client = redis.Redis.from_url(url, socket_connect_timeout=2, socket_timeout=2,
        max_connections=10, decode_responses=True, ssl_cert_reqs='required', ssl_check_hostname=True,
        ssl_ca_certs=environment.get('PSM_TC_REDIS_CA_BUNDLE') or None,
        retry=Retry(NoBackoff(), 0), retry_on_error=[])
    store = RedisTokenStore(client, environment.get('PSM_TC_REDIS_NAMESPACE', 'psm-tencent'))
    store.check()
    return store


def shared_environment(environment):
    """Optional ACL-protected cluster secrets file; never log its contents."""
    path = environment.get('PSM_TC_SHARED_CONFIG')
    if not path:
        return environment
    with Path(path).open('rb') as source:
        raw = source.read(65537)
    if len(raw) > 65536:
        raise ValueError('Shared configuration exceeds size limit')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate shared configuration field')
            result[key] = value
        return result
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
