"""Backward-compatible import path for the federation helpers."""

from psm_tc_bridge.federation import FederationError, assume_role, login_request, login_url, validate_destination

__all__ = ['FederationError', 'assume_role', 'login_request', 'login_url', 'validate_destination']
