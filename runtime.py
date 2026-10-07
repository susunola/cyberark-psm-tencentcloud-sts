"""Production HTTP server configuration, shared with socket-level integration tests.

The transport ceiling sits above the application's own 8 KB contract so an
oversized body is rejected by the application and therefore carries the same
security headers as every other response. Requests with oversized *headers* are
still answered by the server before WSGI, because no application-level limit
exists for them; see SECURITY.md.
"""
from __future__ import annotations

from typing import Any

from waitress import create_server

from validate import MAX_REQUEST_HEADER_BYTES

# Hard transport ceiling. Kept above the application's MAX_CONTENT_LENGTH (8 KB)
# so the application produces the 413 with its hardening headers; this only bounds
# what the server is willing to buffer before handing the request over.
TRANSPORT_BODY_CEILING = 32768
MAX_REQUEST_HEADER_SIZE = MAX_REQUEST_HEADER_BYTES
THREADS = 4
CONNECTION_LIMIT = 100
CHANNEL_TIMEOUT = 30
DEFAULT_PORT = 8765


def make_server(app: Any, *, port: int = DEFAULT_PORT) -> Any:
    return create_server(app, host='127.0.0.1', port=port, threads=THREADS,
                         connection_limit=CONNECTION_LIMIT, max_request_body_size=TRANSPORT_BODY_CEILING,
                         max_request_header_size=MAX_REQUEST_HEADER_SIZE, channel_timeout=CHANNEL_TIMEOUT)
