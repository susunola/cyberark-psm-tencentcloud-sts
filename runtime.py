"""Production HTTP server configuration, shared with socket-level integration tests."""

from typing import Any

from waitress import create_server

DEFAULT_PORT = 8765
HOST = "127.0.0.1"
THREADS = 4
CONNECTION_LIMIT = 100
MAX_REQUEST_BODY_SIZE = 8192
MAX_REQUEST_HEADER_SIZE = 16384
CHANNEL_TIMEOUT = 30


def make_server(app: Any, *, port: int = DEFAULT_PORT) -> Any:
    return create_server(
        app,
        host=HOST,
        port=port,
        threads=THREADS,
        connection_limit=CONNECTION_LIMIT,
        max_request_body_size=MAX_REQUEST_BODY_SIZE,
        max_request_header_size=MAX_REQUEST_HEADER_SIZE,
        channel_timeout=CHANNEL_TIMEOUT,
    )
