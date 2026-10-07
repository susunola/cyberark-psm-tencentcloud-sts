"""Local aggregate reports: do not export identities, URLs or arbitrary log fields."""

import json
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, TextIO

REQUEST_ID_PATTERN = re.compile(r"[a-f0-9]{32}")
PROFILE_NAME_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,80}")
MAX_AUDIT_LINES = 100000
MAX_LINE_BYTES = 8192
SCHEMA_VERSION = 1


def event(fields: dict[str, Any]) -> str:
    """Serialize one audit record; the schema tag and timestamp are never caller-overridable."""
    return json.dumps(
        {
            **fields,
            "schema_version": SCHEMA_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        }
    )


def summarize(stream: TextIO, max_lines: int = MAX_AUDIT_LINES) -> dict[str, Any]:
    """Aggregate sanitized bridge events from a text log stream.

    Only the event name, HTTP status, profile name and request ID are retained;
    identities, URLs and arbitrary fields are dropped rather than echoed.
    """
    if type(max_lines) is not int or not 1 <= max_lines <= MAX_AUDIT_LINES:
        raise ValueError("Invalid audit line bound")
    statuses: Counter[str] = Counter()
    profiles: Counter[str] = Counter()
    seen_http: set[str] = set()
    seen_roles: set[str] = set()
    lines = 0
    ignored = 0
    while True:
        line = stream.readline(MAX_LINE_BYTES + 1)
        if not line:
            break
        lines += 1
        if lines > max_lines or len(line) > MAX_LINE_BYTES:
            raise ValueError("Audit input exceeds bound; report not complete")
        try:
            row = json.loads(line.lstrip("\ufeff") if lines == 1 else line)
        except (ValueError, RecursionError):
            ignored += 1
            continue
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("request_id"), str)
            or not re.fullmatch(REQUEST_ID_PATTERN, row["request_id"])
        ):
            ignored += 1
            continue
        request_id = row["request_id"]
        if (
            row.get("event") == "http_result"
            and type(row.get("status")) is int
            and 100 <= row["status"] <= 599
        ):
            if request_id not in seen_http:
                statuses[str(row["status"])] += 1
                seen_http.add(request_id)
        elif (
            row.get("event") == "role_session_issued"
            and isinstance(row.get("profile"), str)
            and re.fullmatch(PROFILE_NAME_PATTERN, row["profile"])
        ):
            if request_id not in seen_roles:
                profiles[row["profile"]] += 1
                seen_roles.add(request_id)
        else:
            ignored += 1
    return {
        "input_lines": lines,
        "ignored_lines": ignored,
        "unique_http_events": len(seen_http),
        "unique_role_events": len(seen_roles),
        "http_status_counts": dict(statuses),
        "role_profile_counts": dict(profiles),
        "scope": "local bridge aggregates; not native PAM threat analytics",
    }
