# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Client and change planning for Vault auth method mounts (sys/auth)."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
import re
from typing import Any, Dict, Optional
from urllib.parse import quote

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultConfigurationError,
)

logger = logging.getLogger(__name__)

__all__ = [
    "VaultAuthMethods",
    "plan_auth_change",
    "resolve_auth_path",
    "vault_path",
]

_DURATION_RE = re.compile(r"^(\d+)(s|m|h)?$")
_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600}
_TUNE_LIST_FIELDS = {
    "audit_non_hmac_request_keys",
    "audit_non_hmac_response_keys",
    "passthrough_request_headers",
    "allowed_response_headers",
}
_TUNE_DURATION_FIELDS = {"default_lease_ttl", "max_lease_ttl"}


def vault_path(*parts: str) -> str:
    """Build a v1 API path, quoting each segment."""
    segments = []
    for part in parts:
        if not part:
            continue
        for segment in str(part).strip("/").split("/"):
            if segment:
                segments.append(quote(segment, safe=""))
    return "v1/" + "/".join(segments)


def resolve_auth_path(path: Optional[str], auth_type: Optional[str]) -> str:
    """Return the mount path, defaulting to the auth type as vault_auth_backend does."""
    resolved = (path or auth_type or "").strip("/")
    if not resolved:
        raise VaultConfigurationError("path or type is required")
    return resolved


def unwrap_data(response: Optional[dict]) -> dict:
    """Return the Vault data object, or the response itself when it is already unwrapped."""
    if not response:
        return {}
    data = response.get("data")
    if isinstance(data, dict):
        return data
    return response


def _duration_seconds(value: Any) -> Any:
    """Normalize integer seconds and simple duration strings (30s, 5m, 1h)."""
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return int(text)
        match = _DURATION_RE.match(text)
        if match:
            number = int(match.group(1))
            unit = match.group(2) or "s"
            return number * _DURATION_UNITS[unit]
    return value


def _tune_values(tune: Optional[dict]) -> Dict[str, Any]:
    if not tune:
        return {}
    return {key: value for key, value in tune.items() if value is not None}


def _values_match(field: str, desired: Any, existing: Any) -> bool:
    if field in _TUNE_LIST_FIELDS:
        return set(desired or []) == set(existing or [])
    if field in _TUNE_DURATION_FIELDS:
        return _duration_seconds(desired) == _duration_seconds(existing)
    return desired == existing


def plan_auth_change(
    existing: Optional[dict],
    desired: Dict[str, Any],
    current_tune: Optional[dict] = None,
) -> Dict[str, Any]:
    """
    Decide how to reconcile an auth mount.

    Enabling an existing mount of the same type is a no-op. A different type, or a
    different local flag, is rejected: both force a new mount in vault_auth_backend,
    and disabling here would drop every lease on that mount. Description and tune
    updates go to the tune endpoint. identity_token_key is sent when the mount is
    enabled; on an existing mount it is tuned only when Vault returns a different value.
    """
    path = desired["path"]
    if existing is None:
        return {"action": "enable", "tune": _tune_values(desired.get("tune"))}

    existing_type = existing.get("type")
    if existing_type != desired["type"]:
        raise VaultConfigurationError(
            f"Auth mount {path!r} is already enabled with type {existing_type!r}. "
            f"Disable it with state=absent before enabling type {desired['type']!r}."
        )

    if desired.get("local") is not None and bool(existing.get("local")) != bool(desired["local"]):
        raise VaultConfigurationError(
            f"Auth mount {path!r} is local={bool(existing.get('local'))}. "
            "Changing local requires disabling the mount first."
        )

    tune: Dict[str, Any] = {}
    if desired.get("description") is not None and (existing.get("description") or "") != desired["description"]:
        tune["description"] = desired["description"]

    if desired.get("identity_token_key") is not None:
        current_key = existing.get("identity_token_key")
        if current_key is not None and current_key != desired["identity_token_key"]:
            tune["identity_token_key"] = desired["identity_token_key"]

    current_tune = current_tune or {}
    for field, value in _tune_values(desired.get("tune")).items():
        if not _values_match(field, value, current_tune.get(field)):
            tune[field] = value

    if tune:
        return {"action": "tune", "tune": tune}
    return {"action": "unchanged", "tune": {}}


class VaultAuthMethods:
    """HTTP client for sys/auth and sys/mounts/auth/:path/tune."""

    def __init__(self, client):
        self._client = client

    def list_auth_methods(self) -> Dict[str, dict]:
        """Return enabled auth mounts keyed by path without a trailing slash."""
        raw = self._client._make_request("GET", "v1/sys/auth")
        payload = unwrap_data(raw)
        mounts = {}
        for key, value in payload.items():
            if isinstance(value, dict) and "type" in value:
                mounts[str(key).strip("/")] = value
        return mounts

    def read_auth_method(self, path: str) -> Optional[dict]:
        """Read one auth mount from the sys/auth catalog. Missing mounts return None."""
        normalized = path.strip("/")
        mount = self.list_auth_methods().get(normalized)
        if mount is None:
            return None
        config = mount.get("config") or {}
        return {
            "path": normalized,
            "type": mount.get("type"),
            "description": mount.get("description") or "",
            "local": bool(mount.get("local")),
            "accessor": mount.get("accessor"),
            "identity_token_key": config.get("identity_token_key"),
        }

    def read_auth_tune(self, path: str) -> dict:
        """Read mount tune at sys/mounts/auth/:path/tune."""
        raw = self._client._make_request("GET", vault_path("sys/mounts/auth", path, "tune"))
        return unwrap_data(raw)

    def enable_auth_method(
        self,
        path: str,
        auth_type: str,
        description: Optional[str] = None,
        local: Optional[bool] = None,
        identity_token_key: Optional[str] = None,
    ) -> dict:
        """Enable an auth mount. Vault errors if the path is already in use."""
        body: Dict[str, Any] = {"type": auth_type}
        if description is not None:
            body["description"] = description
        if local is not None:
            body["local"] = bool(local)
        if identity_token_key:
            body["config"] = {"identity_token_key": identity_token_key}
        logger.debug("POST enable auth mount %s type %s", path, auth_type)
        raw = self._client._make_request("POST", vault_path("sys/auth", path), json=body)
        return unwrap_data(raw)

    def tune_auth_method(self, path: str, tune: Dict[str, Any]) -> dict:
        """Update description, identity token key, or tune settings for an enabled mount."""
        logger.debug("POST tune auth mount %s keys %s", path, sorted(tune))
        raw = self._client._make_request("POST", vault_path("sys/mounts/auth", path, "tune"), json=tune)
        return unwrap_data(raw)

    def disable_auth_method(self, path: str) -> None:
        """Disable an auth mount."""
        logger.debug("DELETE auth mount %s", path)
        self._client._make_request("DELETE", vault_path("sys/auth", path))
