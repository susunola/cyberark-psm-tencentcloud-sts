"""Internal bridge behind an authenticated HTTPS reverse proxy; not a public service."""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from typing import Any, NoReturn

from flask import Flask, Response, abort, g, redirect, render_template_string, request, session
from werkzeug.exceptions import HTTPException

from configuration import load_settings, validate_settings
from federation import assume_role, login_url
from pam.audit import event as audit_event
from security import (
    TokenStore,
    TokenStoreError,
    configured_token_store,
    shared_environment,
)
from validate import (
    MAX_AUDIT_LABEL_LEN,
    MAX_CREDENTIAL_ID_LEN,
    MAX_IDENTITY_LEN,
    MAX_PROFILE_NAME_LEN,
    MAX_REQUEST_BODY_BYTES,
    MAX_SECRET_KEY_LEN,
    MIN_PROXY_KEY_LEN,
    MIN_SESSION_KEY_LEN,
    is_credential_text,
)
from version import VERSION

FORM = f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>Tencent Cloud role connection</title>
<body><h1>Tencent Cloud role connection</h1><form method="post" action="/connect" autocomplete="off">
<input type="hidden" name="csrf" value="{{{{ csrf }}}}">
<label>SecretId <input id="secret_id" name="secret_id" required maxlength="{MAX_CREDENTIAL_ID_LEN}"></label><br>
<label>SecretKey <input id="secret_key" name="secret_key" type="password" required maxlength="{MAX_SECRET_KEY_LEN}"></label><br>
<label>Role profile <input id="profile" name="profile" required maxlength="{MAX_PROFILE_NAME_LEN}"></label><br>
<label>Audit label <input id="audit_label" name="audit_label" required maxlength="{MAX_AUDIT_LABEL_LEN}"></label><br>
<button id="connect_button" type="submit">Connect</button></form></body></html>"""

CSP = (
    "default-src 'none'; form-action 'self' "
    "https://www.tencentcloud.com https://console.tencentcloud.com; "
    "frame-ancestors 'none'; base-uri 'none'"
)

StsCallable = Callable[[str, str, str, str, int, str], Mapping[str, str]]
TokenStoreLike = Any

# Issuance admission. One worker thread is deliberately left free for health
# checks, so the default slot count tracks runtime.THREADS; the relationship is
# asserted by tests/test_bridge_admission.py so the two cannot drift apart.
# Machine-readable rejection reasons. Fixed codes only: vendor text, form values
# and credentials must never reach the audit log.
PROXY_PEER_REJECTED = 'proxy-peer-rejected'
PROXY_KEY_REJECTED = 'proxy-key-rejected'
IDENTITY_REJECTED = 'identity-header-rejected'
FORM_SHAPE_REJECTED = 'form-shape-rejected'
CSRF_REJECTED = 'csrf-rejected'
TOKEN_REJECTED = 'token-rejected'
BINDING_REJECTED = 'binding-rejected'
LABEL_REJECTED = 'label-rejected'
ADMISSION_BUSY = 'admission-busy'
CAPACITY_EXHAUSTED = 'token-capacity-exhausted'
# The one route a supervisor without a proxy key may call. It answers liveness and
# nothing else: no version, no dependency state, no identity. Every other endpoint,
# including an unknown one, still needs the key, and tests/test_hardening.py asserts
# that this set is exactly what is reachable without it.
PUBLIC_ROUTES = frozenset({'livez'})
BACKEND_UNAVAILABLE = 'token-backend-unavailable'
UNSPECIFIED_REASON = 'unspecified'
ISSUANCE_FAILED = 'issuance-failed'

DEFAULT_ISSUANCE_SLOTS = 3
MAX_ISSUANCE_SLOTS = 64
# How long a submission may wait for a slot before the bridge reports busy. The
# wait is bounded because a WSGI thread is held throughout, and PSM's form
# submission does not retry on its own.
DEFAULT_ISSUANCE_WAIT_SECONDS = 5.0
MAX_ISSUANCE_WAIT_SECONDS = 60.0
BUSY_RETRY_AFTER = '5'


def reject(reason: str, status: int = 403) -> NoReturn:
    """Record why a request was refused, then abort.

    Security monitoring needs to tell "someone is tampering with the form" apart
    from "the token backend is down", which a bare status code cannot express.
    """
    g.rejection_reason = reason
    abort(status)


def normalize_audit_label(label: str) -> str:
    if not isinstance(label, str) or not 2 <= len(label) <= MAX_AUDIT_LABEL_LEN or any(ord(c) < 32 for c in label):
        raise ValueError('Invalid audit label')
    if re.fullmatch(r'[A-Za-z0-9_.@=-]{2,64}', label):
        return label
    readable = re.sub(r'[^A-Za-z0-9_.@=-]', '-', label).strip('-')[:40] or 'user'
    return readable + '-' + hashlib.sha256(label.encode()).hexdigest()[:16]


def create_app(
    settings: Mapping[str, Any],
    *,
    proxy_key: str,
    session_key: str,
    sts: StsCallable = assume_role,
    token_store: TokenStoreLike | None = None,
    issuance_slots: int = DEFAULT_ISSUANCE_SLOTS,
    issuance_wait: float = DEFAULT_ISSUANCE_WAIT_SECONDS,
    identity_capacity: int | None = None,
) -> Flask:
    if len(proxy_key) < MIN_PROXY_KEY_LEN or len(session_key) < MIN_SESSION_KEY_LEN:
        raise ValueError(
            f'Proxy key must be at least {MIN_PROXY_KEY_LEN} characters; '
            f'session key at least {MIN_SESSION_KEY_LEN}'
        )
    if proxy_key == session_key:
        raise ValueError('Use independent proxy and session keys')
    if type(issuance_slots) is not int or not 1 <= issuance_slots <= MAX_ISSUANCE_SLOTS:
        raise ValueError(f'Issuance slots must be 1..{MAX_ISSUANCE_SLOTS}')
    if isinstance(issuance_wait, bool) or not isinstance(issuance_wait, (int, float)):
        raise ValueError('Issuance wait must be a number of seconds')
    if not 0 <= issuance_wait <= MAX_ISSUANCE_WAIT_SECONDS:
        raise ValueError(f'Issuance wait must be 0..{MAX_ISSUANCE_WAIT_SECONDS} seconds')
    profiles = validate_settings(settings)['profiles']
    app = Flask(__name__)
    tokens: TokenStoreLike = token_store if token_store is not None else TokenStore(identity_capacity=identity_capacity)
    slots = threading.BoundedSemaphore(issuance_slots)
    logger = logging.getLogger('psm_tencent.audit')
    app.config.update(
        SECRET_KEY=session_key,
        MAX_CONTENT_LENGTH=MAX_REQUEST_BODY_BYTES,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict',
    )

    @app.before_request
    def authenticate_proxy() -> Response | None:
        g.request_id = uuid.uuid4().hex
        # Never use ProxyFix/X-Forwarded-For to decide whether the peer is local.
        if request.remote_addr not in ('127.0.0.1', '::1'):
            reject(PROXY_PEER_REJECTED)
        if request.endpoint in PUBLIC_ROUTES:
            return None
        supplied = request.headers.get('X-PSM-Bridge-Key', '')
        if not hmac.compare_digest(supplied.encode(), proxy_key.encode()):
            reject(PROXY_KEY_REJECTED)
        identity = request.headers.get('X-PSM-Authenticated-User', '')
        if not identity or len(identity) > MAX_IDENTITY_LEN:
            reject(IDENTITY_REJECTED)
        if not identity.strip() or any(ord(c) < 32 or ord(c) == 127 for c in identity):
            reject(IDENTITY_REJECTED)
        # Printable and bounded, so worth recording: a rejected value here is either a
        # genuine identity or a smuggling attempt, and triage needs to tell which.
        g.claimed_identity = identity
        # waitress comma-joins repeated headers, so an appended value would land in
        # the identity, the token binding key and the audit record at once.
        if identity != identity.strip() or ',' in identity:
            reject(IDENTITY_REJECTED)
        return None

    @app.after_request
    def secure_response(response: Response) -> Response:
        response.headers.update({
            'Cache-Control': 'no-store',
            'Pragma': 'no-cache',
            'Referrer-Policy': 'no-referrer',
            'X-Content-Type-Options': 'nosniff',
            'X-Request-ID': g.request_id,
            'Content-Security-Policy': CSP,
        })
        # No form values, URL queries, cookies, Location headers or exception messages.
        fields = {
            'event': 'http_result',
            'request_id': g.request_id,
            'status': response.status_code,
        }
        if response.status_code >= 400:
            # Triage needs the reason and who presented which identity; a bare status
            # code cannot separate tampering attempts from an outage.
            fields['reason'] = getattr(g, 'rejection_reason', UNSPECIFIED_REASON)
            claimed = getattr(g, 'claimed_identity', None)
            if claimed:
                fields['proxy_identity'] = claimed
        # Integer milliseconds of the STS call, when one was made. Not a credential and not
        # vendor text, and without it the per-login TLS handshake is invisible.
        if getattr(g, 'sts_ms', None) is not None:
            fields['sts_ms'] = g.sts_ms
        logger.info(audit_event(fields))
        return response

    @app.get('/livez')
    def livez() -> dict[str, str]:
        # Deliberately says nothing but that the process answers. The proxy key and the
        # identity header are not checked here, so this must never report dependency
        # state: a probe that could reach Redis would also be a probe that reveals it.
        return {'status': 'ok'}

    # /healthz keeps its meaning for existing monitoring; /readyz is the name that says
    # what it does. Both check the token backend, because a bridge that cannot issue a
    # token cannot serve a connection, and neither checks the STS endpoint: a probe
    # interval would spend CAM's request budget for an answer the first login already gives.
    @app.get('/readyz')
    @app.get('/healthz')
    def readiness() -> tuple[dict[str, str], int] | dict[str, str]:
        try:
            tokens.check()
        except TokenStoreError:
            return {'status': 'unavailable', 'version': VERSION}, 503
        return {'status': 'ok', 'version': VERSION}

    @app.errorhandler(TokenStoreError)
    def token_backend_failure(error: TokenStoreError) -> tuple[str, int, dict[str, str]]:
        session.clear()
        g.rejection_reason = BACKEND_UNAVAILABLE
        return 'Connection service unavailable. Start a new connection later.', 503, {'Retry-After': '5'}

    @app.get('/')
    def index() -> tuple[str, int, dict[str, str]] | str:
        session.clear()
        token = tokens.issue(request.headers['X-PSM-Authenticated-User'])
        if token is None:
            g.rejection_reason = CAPACITY_EXHAUSTED
            return 'Too many pending connections. Retry later.', 429, {'Retry-After': '120'}
        session['csrf'] = token
        return render_template_string(FORM, csrf=session['csrf'])

    @app.post('/connect')
    def connect() -> Any:
        expected = {'csrf', 'profile', 'secret_id', 'secret_key', 'audit_label'}
        if set(request.form) != expected or any(len(request.form.getlist(k)) != 1 for k in expected):
            reject(FORM_SHAPE_REJECTED, 400)
        # Peek, do not pop: the session copy is only burned once the slot below is
        # reserved, so a 503 leaves the submitted form usable for a retry.
        csrf = session.get('csrf')
        if not csrf or not hmac.compare_digest(csrf.encode(), request.form.get('csrf', '').encode()):
            reject(CSRF_REJECTED)
        profile = profiles.get(request.form.get('profile', ''))
        sid = request.form.get('secret_id', '')
        key: str | None = request.form.get('secret_key', '')
        label = request.form.get('audit_label', '')
        if not profile or sid not in profile['allowed_secret_ids'] or not is_credential_text(key, MAX_SECRET_KEY_LEN):
            reject(BINDING_REJECTED, 400)
        secret_key = key or ''
        try:
            label = normalize_audit_label(label)
        except ValueError:
            reject(LABEL_REJECTED, 400)
        # Label is supplied by the form, not proof of human identity. A random suffix avoids collisions.
        name = f'psm-{label}-{g.request_id}'
        # Reserve the slot before consuming: returning 503 after burning the token
        # would force a form reload and re-entry of the SecretKey for nothing.
        # The wait is bounded so a slow STS cannot hold every worker thread
        # indefinitely; PSM's form submission does not retry by itself, so a short
        # queue absorbs normal shift-change bursts instead of failing them.
        if not slots.acquire(timeout=issuance_wait):
            g.rejection_reason = ADMISSION_BUSY
            return 'Connection service busy. Start a new connection later.', 503, {'Retry-After': BUSY_RETRY_AFTER}
        try:
            session.pop('csrf', None)
            if not tokens.consume(csrf, request.headers['X-PSM-Authenticated-User']):
                reject(TOKEN_REJECTED)
            started = time.monotonic()
            try:
                creds = sts(sid, secret_key, profile['role_arn'], name, profile['duration_seconds'], profile['region'])
            finally:
                # Timed even when the call raises: a failing STS is exactly when the
                # operator needs to know whether it was fast, slow or unreachable.
                g.sts_ms = int((time.monotonic() - started) * 1000)
            url = login_url(creds, profile['destination'])
        except (HTTPException, TokenStoreError):
            # A token-backend outage must keep its own 503/Retry-After contract.
            raise
        except Exception:  # noqa: BLE001 - never forward error text
            # Never allow exception text/tracebacks to include temporary or long-term secrets.
            g.rejection_reason = ISSUANCE_FAILED
            return f'Tencent Cloud connection failed. Reference: {g.request_id}', 502
        finally:
            slots.release()
            key = None
            secret_key = ''
        session.clear()
        logger.info(audit_event({
            'event': 'role_session_issued',
            'request_id': g.request_id,
            'profile': request.form['profile'],
            'proxy_identity': request.headers['X-PSM-Authenticated-User'],
            'role_session_name': name,
            'sts_ms': g.sts_ms,
        }))
        # Callback URL contains temporary credentials. Never log response headers or Location.
        return redirect(url, code=303)

    return app


def _environment_int(environment: Mapping[str, str], name: str, default: int) -> int:
    """Read an integer override, falling back to the documented default."""
    raw = environment.get(name, '')
    if not raw:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise ValueError(f'{name} must be an integer') from None


def _environment_optional_int(environment: Mapping[str, str], name: str) -> int | None:
    """Read an optional integer override; None leaves the decision to the store."""
    raw = environment.get(name, '')
    if not raw:
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise ValueError(f'{name} must be an integer') from None


def _environment_float(environment: Mapping[str, str], name: str, default: float) -> float:
    raw = environment.get(name, '')
    if not raw:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        raise ValueError(f'{name} must be a number of seconds') from None


def main() -> None:
    from runtime import make_server
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    try:
        environment = shared_environment(os.environ)
        settings = load_settings(environment['PSM_TC_CONFIG'])
        app = create_app(
            settings,
            proxy_key=environment['PSM_TC_PROXY_KEY'],
            session_key=environment['PSM_TC_SESSION_KEY'],
            token_store=configured_token_store(environment),
            issuance_slots=_environment_int(environment, 'PSM_TC_ISSUANCE_SLOTS', DEFAULT_ISSUANCE_SLOTS),
            issuance_wait=_environment_float(environment, 'PSM_TC_ISSUANCE_WAIT_SECONDS', DEFAULT_ISSUANCE_WAIT_SECONDS),
            identity_capacity=_environment_optional_int(environment, 'PSM_TC_IDENTITY_CAPACITY'),
        )
    except Exception:  # noqa: BLE001 - never forward error text
        raise SystemExit('Bridge startup configuration invalid. Check service environment and settings.') from None
    make_server(app).run()


if __name__ == '__main__':
    main()
