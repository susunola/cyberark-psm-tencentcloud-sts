"""Local aggregate reports: do not export identities, URLs or arbitrary log fields."""
from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, TextIO

from validate import MAX_AUDIT_LINE_BYTES, MAX_AUDIT_LINES, is_identifier


def event(fields: Mapping[str, Any]) -> str:
    """Serialize one audit record; schema_version and timestamp are never caller-overridable."""
    return json.dumps({**fields, 'schema_version': 1, 'timestamp': datetime.now(UTC).isoformat(timespec='milliseconds')})


def summarize(stream: TextIO, max_lines: int = MAX_AUDIT_LINES) -> dict[str, Any]:
    if type(max_lines) is not int or not 1 <= max_lines <= MAX_AUDIT_LINES:
        raise ValueError('Invalid audit line bound')
    statuses: Counter[str] = Counter()
    profiles: Counter[str] = Counter()
    seen_http: set[str] = set()
    seen_roles: set[str] = set()
    lines, ignored = 0, 0
    while True:
        line = stream.readline(8193)
        if not line:
            break
        lines += 1
        if lines > max_lines or len(line) > MAX_AUDIT_LINE_BYTES:
            raise ValueError('Audit input exceeds bound; report not complete')
        try:
            row = json.loads(line.lstrip('\ufeff') if lines == 1 else line)
        except (ValueError, RecursionError):
            ignored += 1
            continue
        if not isinstance(row, dict) or not isinstance(row.get('request_id'), str) or not re.fullmatch(r'[a-f0-9]{32}', row['request_id']):
            ignored += 1
            continue
        request_id = row['request_id']
        if row.get('event') == 'http_result' and type(row.get('status')) is int and 100 <= row['status'] <= 599:
            if request_id not in seen_http:
                statuses[str(row['status'])] += 1
                seen_http.add(request_id)
        elif row.get('event') == 'role_session_issued' and isinstance(row.get('profile'), str) and is_identifier(row['profile'], 1, 80):
            if request_id not in seen_roles:
                profiles[row['profile']] += 1
                seen_roles.add(request_id)
        else:
            ignored += 1
    return {'input_lines': lines, 'ignored_lines': ignored, 'unique_http_events': len(seen_http),
            'unique_role_events': len(seen_roles), 'http_status_counts': dict(statuses), 'role_profile_counts': dict(profiles),
            'scope': 'local bridge aggregates; not native PAM threat analytics'}
