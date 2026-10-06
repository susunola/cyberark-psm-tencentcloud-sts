"""Structured audit events. Callers pass an explicit field set; this module never reads the request."""

import json
import logging
import sys
from datetime import datetime, timezone

_LOG = logging.getLogger('psm_tc_bridge.audit')
_FIELDS = ('profile', 'label', 'region', 'duration', 'request_id', 'outcome', 'error_code', 'secret_fingerprint')


def configure_logging():
    if _LOG.handlers:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter('%(message)s'))
    _LOG.addHandler(handler)
    _LOG.setLevel(logging.INFO)
    _LOG.propagate = False


def audit_event(event, **fields):
    configure_logging()
    payload = {
        'ts': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'event': event,
    }
    for key in _FIELDS:
        if key in fields and fields[key] is not None:
            payload[key] = fields[key]
    _LOG.info(json.dumps(payload, separators=(',', ':'), ensure_ascii=True))
