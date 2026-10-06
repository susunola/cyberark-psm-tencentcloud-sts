"""Internal bridge behind an authenticated HTTPS reverse proxy; not a public service."""
import hmac
import json
import os
import re
import threading
import logging
import uuid
import hashlib

from flask import Flask, abort, g, redirect, render_template_string, request, session
from federation import assume_role, login_url
from configuration import load_settings, validate_settings
from security import TokenStore
from version import VERSION

FORM = '''<!doctype html><html lang="en"><meta charset="utf-8"><title>Tencent Cloud role connection</title>
<body><h1>Tencent Cloud role connection</h1><form method="post" action="/connect" autocomplete="off">
<input type="hidden" name="csrf" value="{{ csrf }}">
<label>SecretId <input id="secret_id" name="secret_id" required maxlength="256"></label><br>
<label>SecretKey <input id="secret_key" name="secret_key" type="password" required maxlength="512"></label><br>
<label>Role profile <input id="profile" name="profile" required maxlength="80"></label><br>
<label>Audit label <input id="audit_label" name="audit_label" required maxlength="256"></label><br>
<button id="connect_button" type="submit">Connect</button></form></body></html>'''


def normalize_audit_label(label):
    if not isinstance(label, str) or not 2 <= len(label) <= 256 or any(ord(c) < 32 for c in label):
        raise ValueError('Invalid audit label')
    if re.fullmatch(r'[A-Za-z0-9_.@=-]{2,64}', label):
        return label
    readable = re.sub(r'[^A-Za-z0-9_.@=-]', '-', label).strip('-')[:40] or 'user'
    return readable + '-' + hashlib.sha256(label.encode()).hexdigest()[:16]


def create_app(settings, *, proxy_key, session_key, sts=assume_role):
    if len(proxy_key) < 32 or len(session_key) < 32:
        raise ValueError('Proxy and session keys must each be at least 32 characters')
    if proxy_key == session_key:
        raise ValueError('Use independent proxy and session keys')
    profiles = validate_settings(settings)['profiles']
    app = Flask(__name__)
    tokens = TokenStore()
    issuance_slots = threading.BoundedSemaphore(2)
    logger = logging.getLogger('psm_tencent.audit')
    app.config.update(SECRET_KEY=session_key, MAX_CONTENT_LENGTH=8192,
                      SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE='Strict')

    @app.before_request
    def authenticate_proxy():
        g.request_id = uuid.uuid4().hex
        # Never use ProxyFix/X-Forwarded-For to decide whether the peer is local.
        if request.remote_addr not in ('127.0.0.1', '::1'):
            abort(403)
        supplied = request.headers.get('X-PSM-Bridge-Key', '')
        if not hmac.compare_digest(supplied.encode(), proxy_key.encode()):
            abort(403)
        if not request.headers.get('X-PSM-Authenticated-User'):
            abort(403)
        if len(request.headers['X-PSM-Authenticated-User']) > 256:
            abort(403)
        identity = request.headers['X-PSM-Authenticated-User']
        if not identity.strip() or any(ord(c) < 32 or ord(c) == 127 for c in identity):
            abort(403)

    @app.after_request
    def secure_response(response):
        response.headers.update({'Cache-Control': 'no-store', 'Pragma': 'no-cache',
            'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
            'X-Request-ID': g.request_id,
            'Content-Security-Policy': "default-src 'none'; form-action 'self' https://cloud.tencent.com https://console.cloud.tencent.com; frame-ancestors 'none'; base-uri 'none'"})
        # No form values, URL queries, cookies, Location headers or exception messages.
        logger.info(json.dumps({'event': 'http_result', 'request_id': g.request_id,
                              'status': response.status_code}))
        return response

    @app.get('/healthz')
    def health():
        return {'status': 'ok', 'version': VERSION}

    @app.get('/')
    def index():
        session.clear()
        token = tokens.issue(request.headers['X-PSM-Authenticated-User'])
        if token is None:
            return 'Too many pending connections. Retry later.', 429, {'Retry-After': '120'}
        session['csrf'] = token
        return render_template_string(FORM, csrf=session['csrf'])

    @app.post('/connect')
    def connect():
        expected = {'csrf', 'profile', 'secret_id', 'secret_key', 'audit_label'}
        if set(request.form) != expected or any(len(request.form.getlist(k)) != 1 for k in expected):
            abort(400)
        csrf = session.pop('csrf', None)
        if not csrf or not hmac.compare_digest(csrf.encode(), request.form.get('csrf', '').encode()):
            abort(403)
        if not tokens.consume(csrf, request.headers['X-PSM-Authenticated-User']):
            abort(403)
        profile = profiles.get(request.form.get('profile', ''))
        sid, key = request.form.get('secret_id', ''), request.form.get('secret_key', '')
        label = request.form.get('audit_label', '')
        if not profile or sid not in profile['allowed_secret_ids'] or not 1 <= len(key) <= 512:
            abort(400)
        try:
            label = normalize_audit_label(label)
        except ValueError:
            abort(400)
        # Label is supplied by the form, not proof of human identity. A random suffix avoids collisions.
        name = f'psm-{label}-{g.request_id}'
        if not issuance_slots.acquire(blocking=False):
            return 'Connection service busy. Start a new connection later.', 503, {'Retry-After': '5'}
        try:
            creds = sts(sid, key, profile['role_arn'], name, profile['duration_seconds'], profile['region'])
            url = login_url(creds, profile['destination'])
        except Exception:
            # Never allow exception text/tracebacks to include temporary or long-term secrets.
            return f'Tencent Cloud connection failed. Reference: {g.request_id}', 502
        finally:
            issuance_slots.release()
            key = None
        session.clear()
        logger.info(json.dumps({'event': 'role_session_issued', 'request_id': g.request_id,
                              'profile': request.form['profile'],
                              'proxy_identity': request.headers['X-PSM-Authenticated-User'],
                              'role_session_name': name}))
        # Callback URL contains temporary credentials. Never log response headers or Location.
        return redirect(url, code=303)

    return app


def main():
    from runtime import make_server
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    try:
        settings = load_settings(os.environ['PSM_TC_CONFIG'])
        app = create_app(settings, proxy_key=os.environ['PSM_TC_PROXY_KEY'], session_key=os.environ['PSM_TC_SESSION_KEY'])
    except (OSError, KeyError, ValueError):
        raise SystemExit('Bridge startup configuration invalid. Check service environment and settings.') from None
    make_server(app).run()


if __name__ == '__main__':
    main()
