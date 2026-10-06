"""Internal bridge behind an authenticated HTTPS reverse proxy; not a public service."""
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import time
import threading

from flask import Flask, abort, redirect, render_template_string, request, session
from federation import FederationError, assume_role, login_url, validate_destination

FORM = '''<!doctype html><html lang="zh"><meta charset="utf-8"><title>腾讯云角色连接</title>
<body><h1>腾讯云角色连接</h1><form method="post" action="/connect" autocomplete="off">
<input type="hidden" name="csrf" value="{{ csrf }}">
<label>SecretId <input id="secret_id" name="secret_id" required maxlength="256"></label><br>
<label>SecretKey <input id="secret_key" name="secret_key" type="password" required maxlength="512"></label><br>
<label>角色配置 <input id="profile" name="profile" required maxlength="80"></label><br>
<label>审计标签 <input id="audit_label" name="audit_label" required maxlength="64"></label><br>
<button id="connect_button" type="submit">连接</button></form></body></html>'''


def create_app(settings, *, proxy_key, session_key, sts=assume_role):
    if len(proxy_key) < 32 or len(session_key) < 32:
        raise ValueError('Proxy and session keys must each be at least 32 characters')
    profiles = settings['profiles']
    if not profiles:
        raise ValueError('At least one role profile required')
    for name, p in profiles.items():
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', name):
            raise ValueError('Invalid profile name')
        if not re.fullmatch(r'qcs::cam::uin/[0-9]+:role(?:Name)?/[A-Za-z0-9_-]+', p['role_arn']):
            raise ValueError('Invalid ordinary CAM role ARN')
        validate_destination(p['destination'])
        if type(p['duration_seconds']) is not int or not 1 <= p['duration_seconds'] <= 300:
            raise ValueError('Duration must be 1..300 seconds; confirm account/API minimum in staging')
        if not p['allowed_secret_ids'] or any('REPLACE' in s for s in p['allowed_secret_ids']):
            raise ValueError('Configure allowed broker SecretIds for each role')
        if not re.fullmatch(r'[a-z]+-[a-z]+', p['region']):
            raise ValueError('Invalid STS region')
    app = Flask(__name__)
    nonces = {}
    nonce_lock = threading.Lock()
    app.config.update(SECRET_KEY=session_key, MAX_CONTENT_LENGTH=8192,
                      SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE='Strict')

    @app.before_request
    def authenticate_proxy():
        # Never use ProxyFix/X-Forwarded-For to decide whether the peer is local.
        if request.remote_addr not in ('127.0.0.1', '::1'):
            abort(403)
        supplied = request.headers.get('X-PSM-Bridge-Key', '')
        if not hmac.compare_digest(supplied.encode(), proxy_key.encode()):
            abort(403)
        if not request.headers.get('X-PSM-Authenticated-User'):
            abort(403)

    @app.after_request
    def secure_response(response):
        response.headers.update({'Cache-Control': 'no-store', 'Pragma': 'no-cache',
            'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'"})
        return response

    @app.get('/')
    def index():
        session.clear()
        session['csrf'] = secrets.token_urlsafe(32)
        session['issued'] = time.time()
        with nonce_lock:
            expired = [n for n, expiry in nonces.items() if expiry <= time.time()]
            for n in expired:
                del nonces[n]
            if len(nonces) >= 1000:
                abort(429)
            nonces[session['csrf']] = time.time() + 120
        return render_template_string(FORM, csrf=session['csrf'])

    @app.post('/connect')
    def connect():
        csrf = session.pop('csrf', None)
        issued = session.pop('issued', 0)
        if not csrf or not hmac.compare_digest(csrf.encode(), request.form.get('csrf', '').encode()) or time.time() - issued > 120:
            abort(403)
        with nonce_lock:
            expiry = nonces.pop(csrf, 0)
        if expiry <= time.time():
            abort(403)
        profile = profiles.get(request.form.get('profile', ''))
        sid, key = request.form.get('secret_id', ''), request.form.get('secret_key', '')
        label = request.form.get('audit_label', '')
        if (not profile or sid not in profile['allowed_secret_ids'] or not 1 <= len(key) <= 512
                or not re.fullmatch(r'[A-Za-z0-9_.@=-]{2,64}', label)):
            abort(400)
        # Label is supplied by the form, not proof of human identity. A random suffix avoids collisions.
        name = f'psm-{label}-{secrets.token_hex(8)}'
        try:
            creds = sts(sid, key, profile['role_arn'], name, profile['duration_seconds'], profile['region'])
            url = login_url(creds, profile['destination'])
        except FederationError:
            return 'Tencent Cloud connection failed. Consult restricted service diagnostics.', 502
        finally:
            key = None
        session.clear()
        # Callback URL contains temporary credentials. Never log response headers or Location.
        return redirect(url, code=303)

    return app


def main():
    from waitress import serve
    settings = json.loads(Path(os.environ['PSM_TC_CONFIG']).read_text(encoding='utf-8'))
    app = create_app(settings, proxy_key=os.environ['PSM_TC_PROXY_KEY'], session_key=os.environ['PSM_TC_SESSION_KEY'])
    serve(app, host='127.0.0.1', port=8765, threads=4)


if __name__ == '__main__':
    main()
