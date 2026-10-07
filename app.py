"""Internal bridge behind an authenticated HTTPS reverse proxy; not a public service."""

import hashlib
import hmac
import logging
import os
import re
import threading
import uuid
from collections.abc import Callable
from typing import Any

from flask import Flask, Response, abort, g, redirect, render_template_string, request, session

from configuration import load_settings, validate_settings
from federation import assume_role, login_url
from pam.audit import event as audit_event
from security import (
    TokenStore,
    TokenStoreError,
    TokenStoreLike,
    configured_token_store,
    shared_environment,
)
from version import VERSION

AUDIT_LOGGER = "psm_tencent.audit"
ALLOWED_PROXY_ADDRS = frozenset({"127.0.0.1", "::1"})
FORM_FIELDS = ("csrf", "profile", "secret_id", "secret_key", "audit_label")
MIN_KEY_LENGTH = 32
MAX_CONTENT_LENGTH = 8192
MAX_IDENTITY_LENGTH = 256
MAX_SECRET_KEY_LENGTH = 512
MAX_AUDIT_LABEL_LENGTH = 256
ISSUANCE_SLOTS = 2
RATE_LIMIT_RETRY_AFTER = "120"
BUSY_RETRY_AFTER = "5"
READABLE_LABEL_PATTERN = re.compile(r"[A-Za-z0-9_.@=-]{2,64}")
UNSAFE_LABEL_CHARS = re.compile(r"[^A-Za-z0-9_.@=-]+")
SIMPLE_LABEL_FALLBACK = "user"

FORM = """<!doctype html><html lang="en"><meta charset="utf-8">
<title>Tencent Cloud role connection</title>
<body><h1>Tencent Cloud role connection</h1>
<form method="post" action="/connect" autocomplete="off">
<input type="hidden" name="csrf" value="{{ csrf }}">
<label>SecretId <input id="secret_id" name="secret_id" required maxlength="256"></label><br>
<label>SecretKey
<input id="secret_key" name="secret_key" type="password" required maxlength="512"></label><br>
<label>Role profile <input id="profile" name="profile" required maxlength="80"></label><br>
<label>Audit label <input id="audit_label" name="audit_label" required maxlength="256"></label><br>
<button id="connect_button" type="submit">Connect</button></form></body></html>"""

StsConnector = Callable[..., dict[str, Any]]
Profile = dict[str, Any]


def normalize_audit_label(label: str) -> str:
    """Return a log-safe label for a form-supplied audit string."""
    if (
        not isinstance(label, str)
        or not 2 <= len(label) <= MAX_AUDIT_LABEL_LENGTH
        or any(ord(c) < 32 for c in label)
    ):
        raise ValueError("Invalid audit label")
    if re.fullmatch(READABLE_LABEL_PATTERN, label):
        return label
    readable = UNSAFE_LABEL_CHARS.sub("-", label).strip("-")[:40] or SIMPLE_LABEL_FALLBACK
    return readable + "-" + hashlib.sha256(label.encode()).hexdigest()[:16]


def verify_proxy_peer(proxy_key: str) -> None:
    """Authenticate the reverse proxy peer and its identity assertion."""
    # Never use ProxyFix/X-Forwarded-For to decide whether the peer is local.
    if request.remote_addr not in ALLOWED_PROXY_ADDRS:
        abort(403)
    supplied = request.headers.get("X-PSM-Bridge-Key", "")
    if not hmac.compare_digest(supplied.encode(), proxy_key.encode()):
        abort(403)
    identity = request.headers.get("X-PSM-Authenticated-User", "")
    if not identity or len(identity) > MAX_IDENTITY_LENGTH:
        abort(403)
    if not identity.strip() or any(ord(c) < 32 or ord(c) == 127 for c in identity):
        abort(403)


def security_headers(request_id: str) -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Request-ID": request_id,
        "Content-Security-Policy": (
            "default-src 'none'; "
            "form-action 'self' https://www.tencentcloud.com https://console.tencentcloud.com; "
            "frame-ancestors 'none'; base-uri 'none'"
        ),
    }


def read_form() -> dict[str, str]:
    """Return the exact connect form, rejecting missing, extra or repeated fields."""
    if set(request.form) != set(FORM_FIELDS) or any(
        len(request.form.getlist(field)) != 1 for field in FORM_FIELDS
    ):
        abort(400)
    return {field: request.form[field] for field in FORM_FIELDS}


def consume_session_token(tokens: TokenStoreLike, supplied: str, identity: str) -> None:
    """Bind the single-use issued token to the authenticated identity and burn it."""
    stored = session.pop("csrf", None)
    if not stored or not hmac.compare_digest(stored.encode(), supplied.encode()):
        abort(403)
    if not tokens.consume(stored, identity):
        abort(403)


def resolve_request(profiles: dict[str, Profile], form: dict[str, str]) -> tuple[Profile, str, str, str]:
    """Resolve an authorized profile, caller SecretId and a normalized audit label."""
    profile = profiles.get(form["profile"])
    secret_id, secret_key = form["secret_id"], form["secret_key"]
    if (
        not profile
        or secret_id not in profile["allowed_secret_ids"]
        or not 1 <= len(secret_key) <= MAX_SECRET_KEY_LENGTH
    ):
        abort(400)
    try:
        label = normalize_audit_label(form["audit_label"])
    except ValueError:
        abort(400)
    return profile, secret_id, secret_key, label


def issue_login_url(
    connect: StsConnector, secret_id: str, secret_key: str, profile: Profile, session_name: str
) -> str:
    credentials = connect(
        secret_id,
        secret_key,
        profile["role_arn"],
        session_name,
        profile["duration_seconds"],
        profile["region"],
    )
    return login_url(credentials, profile["destination"])


def create_app(
    settings: dict[str, Any],
    *,
    proxy_key: str,
    session_key: str,
    sts: StsConnector = assume_role,
    token_store: TokenStoreLike | None = None,
) -> Flask:
    if len(proxy_key) < MIN_KEY_LENGTH or len(session_key) < MIN_KEY_LENGTH:
        raise ValueError("Proxy and session keys must each be at least 32 characters")
    if proxy_key == session_key:
        raise ValueError("Use independent proxy and session keys")
    profiles = validate_settings(settings)["profiles"]
    tokens: TokenStoreLike = token_store if token_store is not None else TokenStore()
    slots = threading.BoundedSemaphore(ISSUANCE_SLOTS)
    logger = logging.getLogger(AUDIT_LOGGER)

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=session_key,
        MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
    )

    @app.before_request
    def authenticate_proxy() -> None:
        g.request_id = uuid.uuid4().hex
        verify_proxy_peer(proxy_key)

    @app.after_request
    def secure_response(response: Response) -> Response:
        request_id: str = g.request_id
        response.headers.update(security_headers(request_id))
        # No form values, URL queries, cookies, Location headers or exception messages.
        logger.info(
            audit_event({"event": "http_result", "request_id": request_id, "status": response.status_code})
        )
        return response

    @app.errorhandler(TokenStoreError)
    def token_backend_failure(error: TokenStoreError) -> tuple[str, int, dict[str, str]]:
        del error
        session.clear()
        return (
            "Connection service unavailable. Start a new connection later.",
            503,
            {"Retry-After": BUSY_RETRY_AFTER},
        )

    @app.get("/healthz")
    def health() -> Any:
        try:
            tokens.check()
        except TokenStoreError:
            return {"status": "unavailable", "version": VERSION}, 503
        return {"status": "ok", "version": VERSION}

    @app.get("/")
    def index() -> Any:
        session.clear()
        token = tokens.issue(request.headers["X-PSM-Authenticated-User"])
        if token is None:
            return (
                "Too many pending connections. Retry later.",
                429,
                {"Retry-After": RATE_LIMIT_RETRY_AFTER},
            )
        session["csrf"] = token
        return render_template_string(FORM, csrf=token)

    @app.post("/connect")
    def connect() -> Any:
        form = read_form()
        identity = request.headers["X-PSM-Authenticated-User"]
        consume_session_token(tokens, form["csrf"], identity)
        profile, secret_id, secret_key, label = resolve_request(profiles, form)
        # Label is supplied by the form, not proof of human identity.
        # The request ID keeps concurrent sessions from colliding.
        session_name = f"psm-{label}-{g.request_id}"
        if not slots.acquire(blocking=False):
            return (
                "Connection service busy. Start a new connection later.",
                503,
                {"Retry-After": BUSY_RETRY_AFTER},
            )
        try:
            url = issue_login_url(sts, secret_id, secret_key, profile, session_name)
        except Exception:  # noqa: BLE001 - exception text must never carry any secret
            return f"Tencent Cloud connection failed. Reference: {g.request_id}", 502
        finally:
            slots.release()
            del secret_key
        session.clear()
        logger.info(
            audit_event(
                {
                    "event": "role_session_issued",
                    "request_id": g.request_id,
                    "profile": form["profile"],
                    "proxy_identity": identity,
                    "role_session_name": session_name,
                }
            )
        )
        # Callback URL contains temporary credentials. Never log response headers or Location.
        return redirect(url, code=303)

    return app


def main() -> None:
    from runtime import make_server

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        environment = shared_environment(os.environ)
        settings = load_settings(environment["PSM_TC_CONFIG"])
        app = create_app(
            settings,
            proxy_key=environment["PSM_TC_PROXY_KEY"],
            session_key=environment["PSM_TC_SESSION_KEY"],
            token_store=configured_token_store(environment),
        )
    except Exception:  # noqa: BLE001 - startup must never echo configuration values
        raise SystemExit(
            "Bridge startup configuration invalid. Check service environment and settings."
        ) from None
    make_server(app).run()


if __name__ == "__main__":
    main()
