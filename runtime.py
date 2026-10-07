"""Production HTTP server configuration, shared with socket-level integration tests.

Requests rejected by the server itself (oversized body or headers) are answered by
waitress before WSGI, so the application's security headers and request id do not
apply to them. The bodies are static and carry no request data; add proxy-level
error handling if that surface needs the same headers. See SECURITY.md.
"""
from __future__ import annotations

from typing import Any

from waitress import create_server


def make_server(app: Any, *, port: int = 8765) -> Any:
    return create_server(app, host='127.0.0.1', port=port, threads=4,
                         connection_limit=100, max_request_body_size=8192,
                         max_request_header_size=16384, channel_timeout=30)
