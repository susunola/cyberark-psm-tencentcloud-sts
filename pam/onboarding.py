"""Validate complete account inputs before submitting a PVWA write."""

import copy
import re
from typing import Any

from pam.lifecycle import validate_identifier

REQUIRED_FIELDS = {"name", "address", "userName", "platformId", "safeName", "secretType", "secret"}
OPTIONAL_FIELDS = {"platformAccountProperties", "secretManagement"}
MANAGEMENT_FIELDS = {"automaticManagementEnabled", "manualManagementReason"}
MAX_METADATA_LENGTH = 1024
MAX_SECRET_LENGTH = 4096
MAX_PROPERTY_KEY_LENGTH = 128
PROFILE_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,80}")
CONNECTION_COMPONENTS = (None, "PSM-RDP", "PSM-SSH")
TENCENT_PROPERTIES = ("TencentSecretId", "TencentRoleProfile")


def _is_bounded_text(value: Any, *, allow_empty: bool = False) -> bool:
    if not isinstance(value, str) or len(value) > MAX_METADATA_LENGTH:
        return False
    if any(ord(c) < 32 for c in value):
        return False
    return allow_empty or bool(value.strip())


def _validate_scope(result: dict[str, Any], safe: str, platform: str) -> None:
    allowed = REQUIRED_FIELDS | OPTIONAL_FIELDS
    present = set(result)
    outside_schema = (REQUIRED_FIELDS - present) or (present - allowed)
    if outside_schema or result["safeName"] != safe or result["platformId"] != platform:
        raise ValueError("Account outside the approved schema or scope")
    for field in REQUIRED_FIELDS - {"secret"}:
        if not _is_bounded_text(result[field]):
            raise ValueError("Invalid account metadata")


def _validate_secret(result: dict[str, Any]) -> None:
    secret = result["secret"]
    if (
        result["secretType"] != "password"
        or not isinstance(secret, str)
        or not 1 <= len(secret) <= MAX_SECRET_LENGTH
    ):
        raise ValueError("Explicit bounded password credential required")


def _validate_properties(properties: Any) -> dict[str, Any]:
    if not isinstance(properties, dict):
        raise ValueError("Platform properties must be bounded strings")
    for key, value in properties.items():
        bounded_key = isinstance(key, str) and bool(key) and len(key) <= MAX_PROPERTY_KEY_LENGTH
        if not bounded_key or not isinstance(value, str) or len(value) > MAX_METADATA_LENGTH:
            raise ValueError("Platform properties must be bounded strings")
    if any(name in properties for name in TENCENT_PROPERTIES):
        validate_identifier(properties.get("TencentSecretId"))
        profile = properties.get("TencentRoleProfile")
        if not isinstance(profile, str) or not re.fullmatch(PROFILE_PATTERN, profile):
            raise ValueError("Complete Tencent caller/profile binding required")
    return properties


def _validate_management(management: Any, *, present: bool) -> dict[str, Any] | None:
    if not present:
        return None
    if (
        not isinstance(management, dict)
        or set(management) - MANAGEMENT_FIELDS
        or type(management.get("automaticManagementEnabled")) is not bool
    ):
        raise ValueError("Invalid management flags")
    reason = management.get("manualManagementReason")
    if "manualManagementReason" in management and (
        not isinstance(reason, str) or len(reason) > MAX_METADATA_LENGTH
    ):
        raise ValueError("Invalid management reason")
    return management


def validate_account(payload: Any, safe: str, platform: str) -> dict[str, Any]:
    """Return a deep-copied account payload that is safe to submit to PVWA."""
    if not isinstance(payload, dict):
        raise ValueError("Expected an account object")
    result = copy.deepcopy(payload)
    component = result.pop("connection_component", None)
    if component not in CONNECTION_COMPONENTS:
        raise ValueError("Unknown proposal component")
    _validate_scope(result, safe, platform)
    _validate_secret(result)
    properties = _validate_properties(result.get("platformAccountProperties", {}))
    management = _validate_management(result.get("secretManagement"), present="secretManagement" in result)
    if "TencentSecretId" in properties and (
        management is None or management.get("automaticManagementEnabled") is not False
    ):
        raise ValueError("CAM key accounts must explicitly disable native automatic management")
    return result
