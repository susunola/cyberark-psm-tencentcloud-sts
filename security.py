"""Bounded, identity-bound single-use tokens for a single bridge process."""
import secrets
import threading
import time


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
