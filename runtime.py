"""Production HTTP server configuration, shared with socket-level integration tests."""
from __future__ import annotations

from typing import Any

from waitress import create_server


def make_server(app: Any, *, port: int = 8765) -> Any:
    return create_server(app, host='127.0.0.1', port=port, threads=4,
                         connection_limit=100, max_request_body_size=8192,
                         max_request_header_size=16384, channel_timeout=30)
