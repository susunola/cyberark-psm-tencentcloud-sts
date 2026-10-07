"""Shared input predicates and size bounds. Raise site-specific errors at call sites."""
from __future__ import annotations

import re
from typing import Any

# Size and capacity bounds (single source of truth for security limits).
MAX_CONFIG_BYTES = 1024 * 1024
MAX_SHARED_CONFIG_BYTES = 65536
MAX_JSON_INPUT_BYTES = 1024 * 1024
MAX_REQUEST_BODY_BYTES = 8192
MAX_REQUEST_HEADER_BYTES = 16384
MAX_IDENTITY_LEN = 256
MAX_AUDIT_LABEL_LEN = 256
MAX_SECRET_KEY_LEN = 512
MAX_FIELD_TEXT_LEN = 1024
MAX_PVWA_TOKEN_LEN = 16384
MAX_ACCOUNT_FIELD_LEN = 1024
MAX_DESCRIPTION_HASH = 16
MAX_PROFILE_NAME_LEN = 80
MAX_IDENTIFIER_LEN = 128
MAX_CREDENTIAL_ID_LEN = 256
MIN_PROXY_KEY_LEN = 32
MIN_SESSION_KEY_LEN = 32
CHANNEL_TIMEOUT_SECONDS = 30
MAX_ISSUANCE_SLOTS = 2
MAX_SECRET_MATERIAL_LEN = 4096
MAX_AUDIT_LINES = 100000
MAX_AUDIT_LINE_BYTES = 8192
MAX_INVENTORY_USERS = 1000
MAX_INVENTORY_INSTANCES = 10000
MAX_INVENTORY_PAGE_SIZE = 100
MAX_INVENTORY_PAGES = 100
MAX_CREDENTIAL_JSON_BYTES = 8192
MAX_ONBOARD_JSON_BYTES = 65536
MIN_NONCE = 10000
MAX_NONCE = 100000000
MAX_SECRET_ID_LEN = 4096
DEFAULT_TOKEN_CAPACITY = 1000
DEFAULT_TOKEN_TTL_SECONDS = 120

_IDENTIFIER = re.compile(r'[A-Za-z0-9_-]+')


def is_identifier(value: object, min_len: int = 1, max_len: int = 80) -> bool:
    """Token-like name: [A-Za-z0-9_-] within length bounds."""
    return (
        isinstance(value, str)
        and min_len <= len(value) <= max_len
        and bool(_IDENTIFIER.fullmatch(value))
    )


def is_readable_text(value: object, max_len: int = MAX_FIELD_TEXT_LEN, *, allow_empty: bool = False) -> bool:
    """Printable non-control text within a size bound."""
    if not isinstance(value, str) or len(value) > max_len:
        return False
    if not allow_empty and not value.strip():
        return False
    return not any(ord(c) < 32 for c in value)


def is_credential_text(value: object, max_len: int = MAX_SECRET_KEY_LEN) -> bool:
    """Non-empty credential string without control characters."""
    return (
        isinstance(value, str)
        and 1 <= len(value) <= max_len
        and not any(ord(c) < 32 or ord(c) == 127 for c in value)
    )


def unique_json_object(pairs: list[tuple[str, Any]], *, message: str = 'Duplicate JSON field') -> dict[str, Any]:
    """object_pairs_hook that rejects duplicate JSON keys."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(message)
        result[key] = value
    return result
