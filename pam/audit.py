"""Local aggregate reports: do not export identities, URLs or arbitrary log fields."""
from collections import Counter
from datetime import datetime, timezone
import json
import re


def event(fields):
    return json.dumps({'schema_version':1, 'timestamp':datetime.now(timezone.utc).isoformat(timespec='milliseconds'), **fields})


def summarize(stream, max_lines=100000):
    if type(max_lines) is not int or not 1 <= max_lines <= 100000:
        raise ValueError('Invalid audit line bound')
    statuses, profiles = Counter(), Counter()
    seen_http, seen_roles = set(), set()
    lines, ignored = 0, 0
    while True:
        line = stream.readline(8193)
        if not line:
            break
        lines += 1
        if lines > max_lines or len(line) > 8192:
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
                statuses[str(row['status'])] += 1; seen_http.add(request_id)
        elif row.get('event') == 'role_session_issued' and isinstance(row.get('profile'), str) and re.fullmatch(r'[A-Za-z0-9_-]{1,80}', row['profile']):
            if request_id not in seen_roles:
                profiles[row['profile']] += 1; seen_roles.add(request_id)
        else:
            ignored += 1
    return {'input_lines':lines,'ignored_lines':ignored,'unique_http_events':len(seen_http),
            'unique_role_events':len(seen_roles),'http_status_counts':dict(statuses),'role_profile_counts':dict(profiles),
            'scope':'local bridge aggregates; not native PAM threat analytics'}
