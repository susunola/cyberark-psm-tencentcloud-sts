"""Strict startup validation with errors that never echo configuration secrets."""

import copy
import json
import re
from pathlib import Path
from typing import Any

from federation import validate_destination, validate_region

MAX_CONFIG_BYTES = 1024 * 1024
MAX_PROFILES = 100
MIN_PROFILES = 1
MAX_SECRET_IDS = 10
MIN_SECRET_IDS = 1
MIN_DURATION_SECONDS = 1
MAX_DURATION_SECONDS = 300
PROFILE_NAME_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,80}")
SECRET_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{2,256}")
ROLE_ARN_PATTERN = re.compile(r"qcs::cam::uin/[0-9]+:role(?:Name)?/[A-Za-z0-9_-]+")


def load_settings(path: str | Path) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate configuration field")
            result[key] = value
        return result

    with Path(path).open("rb") as source:
        raw = source.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("Configuration exceeds size limit")
    return validate_settings(json.loads(raw.decode("utf-8-sig"), object_pairs_hook=unique_object))


def validate_settings(settings: Any) -> dict[str, Any]:
    if not isinstance(settings, dict) or set(settings) != {"profiles"}:
        raise ValueError("Expected a profiles object only")
    profiles = settings["profiles"]
    if not isinstance(profiles, dict) or not MIN_PROFILES <= len(profiles) <= MAX_PROFILES:
        raise ValueError("Configure 1..100 profiles")
    seen_ids: set[str] = set()
    required = {"role_arn", "allowed_secret_ids", "destination", "duration_seconds", "region"}
    for name, p in profiles.items():
        if not isinstance(name, str) or not re.fullmatch(PROFILE_NAME_PATTERN, name):
            raise ValueError("Invalid profile name")
        if not isinstance(p, dict) or set(p) != required:
            raise ValueError("Invalid profile fields")
        role_arn = p["role_arn"]
        if not isinstance(role_arn, str) or not re.fullmatch(ROLE_ARN_PATTERN, role_arn):
            raise ValueError("Invalid ordinary CAM role ARN")
        validate_destination(p["destination"])
        duration = p["duration_seconds"]
        if type(duration) is not int or not MIN_DURATION_SECONDS <= duration <= MAX_DURATION_SECONDS:
            raise ValueError("Duration must be 1..300 seconds")
        ids = p["allowed_secret_ids"]
        if not isinstance(ids, list) or not MIN_SECRET_IDS <= len(ids) <= MAX_SECRET_IDS:
            raise ValueError("Configure 1..10 caller SecretIds per profile")
        for sid in ids:
            if not isinstance(sid, str) or not re.fullmatch(SECRET_ID_PATTERN, sid) or "REPLACE" in sid:
                raise ValueError("Configure real caller SecretIds")
            if sid in seen_ids:
                raise ValueError("Each caller SecretId must belong to one profile only")
            seen_ids.add(sid)
        validate_region(p["region"])
    return copy.deepcopy(settings)
