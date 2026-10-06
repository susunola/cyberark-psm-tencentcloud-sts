"""Production HTTP server configuration, shared with socket-level integration tests."""
from waitress import create_server


def make_server(app, *, port=8765):
    return create_server(app, host='127.0.0.1', port=port, threads=4,
                         connection_limit=100, max_request_body_size=8192,
                         max_request_header_size=16384, channel_timeout=30)
