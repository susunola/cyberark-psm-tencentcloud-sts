"""Internal bridge behind an authenticated HTTPS reverse proxy; not a public service."""

import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import urlencode

from flask import Flask, abort, g, redirect, render_template_string, request, session

from psm_tc_bridge.audit import audit_event
from psm_tc_bridge.config import load_settings
from psm_tc_bridge.federation import FederationError, assume_role, login_request

FORM = '''<!doctype html><html lang="zh"><meta charset="utf-8"><title>腾讯云角色连接</title>
<body><h1>腾讯云角色连接</h1><form method="post" action="/connect" autocomplete="off">
<input type="hidden" name="csrf" value="{{ csrf }}">
<label>SecretId <input id="secret_id" name="secret_id" required maxlength="128" spellcheck="false" autocapitalize="off"></label><br>
<label>SecretKey <input id="secret_key" name="secret_key" type="password" required maxlength="512" spellcheck="false" autocomplete="off"></label><br>
<label>角色配置 <input id="profile" name="profile" required maxlength="80" spellcheck="false"></label><br>
<label>审计标签 <input id="audit_label" name="audit_label" required maxlength="64" spellcheck="false"></label><br>
<button id="connect_button" type="submit">连接</button></form></body></html>'''

HANDOFF = '''<!doctype html><html lang="zh"><meta charset="utf-8"><title>正在进入腾讯云控制台</title>
<body><p>正在进入腾讯云控制台…</p>
<form id="fed" method="post" action="{{ action }}" autocomplete="off">
{% for name, value in fields %}<input type="hidden" name="{{ name }}" value="{{ value }}">{% endfor %}
<noscript><button type="submit">继续</button></noscript></form>
<script nonce="{{ nonce }}">document.getElementById("fed").submit()</script></body></html>'''

LABEL = re.compile(r'[A-Za-z0-9_.@=-]{2,64}')
SECURITY_HEADERS = {
    'Cache-Control': 'no-store',
    'Pragma': 'no-cache',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Permissions-Policy': 'interest-cohort=()',
    'Cross-Origin-Resource-Policy': 'same-origin',
}


def _fingerprint(value):
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _allowlisted(value, candidates):
    matched = False
    for candidate in candidates:
        matched |= hmac.compare_digest(value.encode(), candidate.encode())
    return matched


def create_app(settings, *, proxy_key, session_key, sts=assume_role, auditor=audit_event):
    if not isinstance(proxy_key, str) or not isinstance(session_key, str) or len(proxy_key) < 32 or len(session_key) < 32:
        raise ValueError('Proxy and session keys must each be at least 32 characters')
    if hmac.compare_digest(proxy_key.encode(), session_key.encode()):
        raise ValueError('Proxy key and session key must differ')
    loaded = load_settings(settings)
    profiles = loaded['profiles']
    submit_method = loaded['submit_method']
    app = Flask(__name__)
    nonces = {}
    windows = {}
    lock = threading.Lock()
    app.config.update(
        SECRET_KEY=session_key,
        MAX_CONTENT_LENGTH=8192,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict',
        SESSION_COOKIE_NAME='psm_tc_sid',
    )

    def consume_nonce(token):
        now = time.time()
        with lock:
            expired = [item for item, expiry in nonces.items() if expiry <= now]
            for item in expired:
                del nonces[item]
            expiry = nonces.pop(token, 0)
        return expiry > now

    @app.before_request
    def authenticate_proxy():
        g.request_id = secrets.token_hex(8)
        # Never use ProxyFix or X-Forwarded-For to decide whether the peer is local.
        if request.remote_addr not in ('127.0.0.1', '::1'):
            abort(403)
        supplied = request.headers.get('X-PSM-Bridge-Key', '')
        if not hmac.compare_digest(supplied.encode(), proxy_key.encode()):
            abort(403)
        if request.path != '/healthz' and not request.headers.get('X-PSM-Authenticated-User'):
            abort(403)
        if request.path == '/connect':
            identity = request.headers.get('X-PSM-Authenticated-User', '')
            now = time.time()
            with lock:
                window = [stamp for stamp in windows.get(identity, []) if now - stamp < 60]
                if len(window) >= 12:
                    abort(429)
                window.append(now)
                windows[identity] = window
                if len(windows) > 200:
                    stale = [key for key, stamps in windows.items() if not stamps or now - stamps[-1] >= 60]
                    for key in stale:
                        del windows[key]

    @app.after_request
    def secure_response(response):
        response.headers.update(SECURITY_HEADERS)
        response.headers['X-Request-Id'] = getattr(g, 'request_id', '')
        if 'Content-Security-Policy' not in response.headers:
            response.headers['Content-Security-Policy'] = "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
        return response

    @app.get('/healthz')
    def healthz():
        return {'status': 'ok'}

    @app.get('/')
    def index():
        session.clear()
        token = secrets.token_urlsafe(32)
        with lock:
            expired = [item for item, expiry in nonces.items() if expiry <= time.time()]
            for item in expired:
                del nonces[item]
            if len(nonces) >= 1000:
                abort(429)
            nonces[token] = time.time() + 120
        session['csrf'] = token
        session['issued'] = time.time()
        return render_template_string(FORM, csrf=token)

    @app.post('/connect')
    def connect():
        csrf = session.pop('csrf', None)
        issued = session.pop('issued', 0)
        supplied = request.form.get('csrf', '')
        if (not csrf or not hmac.compare_digest(csrf.encode(), supplied.encode())
                or time.time() - issued > 120 or not consume_nonce(csrf)):
            abort(403)
        profile_name = request.form.get('profile', '')
        profile = profiles.get(profile_name)
        secret_id = request.form.get('secret_id', '')
        secret_key = request.form.get('secret_key', '')
        label = request.form.get('audit_label', '')
        if (not profile or not _allowlisted(secret_id, profile['allowed_secret_ids'])
                or not 1 <= len(secret_key) <= 512 or not LABEL.fullmatch(label)):
            auditor('connect_rejected', profile=profile_name[:80], label=label[:64], request_id=g.request_id, outcome='denied')
            abort(400)
        session_name = f'psm-{label}-{secrets.token_hex(8)}'
        try:
            credentials = sts(
                secret_id, secret_key, profile['role_arn'], session_name, profile['duration_seconds'], profile['region'],
                endpoint=profile['sts_endpoint'], external_id=profile.get('external_id'),
                session_policy=profile.get('session_policy'),
            )
            endpoint, fields = login_request(credentials, profile['destination'], login_host=profile['login_host'])
        except FederationError as exc:
            code = exc.code or 'federation'
            auditor('connect_failed', profile=profile_name, label=label, request_id=g.request_id,
                    outcome='error', error_code=str(code)[:64], secret_fingerprint=_fingerprint(secret_id))
            return 'Tencent Cloud connection failed. Consult restricted service diagnostics.', 502
        finally:
            secret_key = None
        session.clear()
        auditor('connect_ok', profile=profile_name, label=label, region=profile['region'],
                duration=profile['duration_seconds'], request_id=g.request_id, outcome='ok',
                secret_fingerprint=_fingerprint(secret_id))
        if submit_method == 'get':
            # Compatibility path. The Location header contains temporary credentials.
            return redirect(endpoint + '?' + urlencode(fields), code=303)
        nonce = secrets.token_urlsafe(16)
        response = app.response_class(
            render_template_string(HANDOFF, action=endpoint, fields=list(fields.items()), nonce=nonce)
        )
        response.headers['Content-Security-Policy'] = (
            f"default-src 'none'; script-src 'nonce-{nonce}'; form-action {endpoint}; base-uri 'none'; frame-ancestors 'none'"
        )
        return response

    return app


def main():
    from waitress import serve

    settings = load_settings(Path(os.environ['PSM_TC_CONFIG']))
    app = create_app(settings, proxy_key=os.environ['PSM_TC_PROXY_KEY'], session_key=os.environ['PSM_TC_SESSION_KEY'])
    serve(app, host='127.0.0.1', port=8765, threads=4, ident='psm-tc-bridge')


if __name__ == '__main__':
    main()
