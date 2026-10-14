# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Client and comparison helpers for Vault TPM identity and TPM auth resources."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
from typing import Any, Dict, Optional

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_methods import unwrap_data, vault_path
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import VaultSecretNotFoundError

logger = logging.getLogger(__name__)

__all__ = [
    "VaultTpm",
    "decide_config_action",
    "decide_group_action",
    "decide_identity_action",
    "decide_role_action",
    "identity_result",
    "group_result",
    "normalize_pem",
    "record_matches",
    "role_result",
]

_SET_FIELDS = {
    "tpm_ids",
    "tpmgroup_ids",
    "member_tpm_ids",
    "token_policies",
    "token_bound_cidrs",
}
# Vault's provider treats a false/zero read of these as unset. Comparing them as
# booleans keeps a second run from rewriting a value Vault does not echo back.
_FALSE_MEANS_UNSET = {"token_no_default_policy", "disabled"}


def normalize_pem(value: Optional[str]) -> str:
    """
    Match Go's pem.EncodeToMemory, which is the form Vault stores.

    Surrounding whitespace is removed and a single trailing newline is added, so a
    missing newline does not force the identity record to be replaced.
    """
    return (value or "").strip() + "\n"


def _normalize_scalar(value: Any) -> Any:
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


def values_equal(field: str, desired: Any, existing: Any) -> bool:
    """Compare one desired field with the value Vault returned."""
    if field == "tpm_ek_public_key":
        return normalize_pem(desired) == normalize_pem(existing)
    if field in _SET_FIELDS:
        return set(desired or []) == set(existing or [])
    if field in _FALSE_MEANS_UNSET:
        return bool(desired) == bool(existing)
    if isinstance(desired, dict):
        return (existing or {}) == desired
    if isinstance(desired, int) and desired == 0 and existing in (None, "", 0, "0"):
        return True
    return _normalize_scalar(existing) == _normalize_scalar(desired)


def record_matches(existing: Optional[dict], desired: Dict[str, Any]) -> bool:
    """True when every set desired field already matches Vault. Unset fields are ignored."""
    if existing is None:
        return False
    for field, desired_value in desired.items():
        if desired_value is None:
            continue
        if not values_equal(field, desired_value, existing.get(field)):
            return False
    return True


def decide_config_action(existing: Optional[dict], desired: Dict[str, Any]) -> str:
    """Return write, unchanged, or missing for TPM auth backend config."""
    if not desired:
        return "unchanged" if existing is not None else "missing"
    if existing is not None and record_matches(existing, desired):
        return "unchanged"
    return "write"


def decide_role_action(existing: Optional[dict], desired: Dict[str, Any]) -> str:
    if existing is None:
        return "create"
    if record_matches(existing, desired):
        return "unchanged"
    return "update"


def decide_identity_action(existing: Optional[dict], desired: Dict[str, Any]) -> str:
    """
    Return create, update, replace, or unchanged.

    A PEM change replaces the record, matching RequiresReplaceIf on vault_identity_tpm.
    Whitespace-only PEM differences do not.
    """
    if existing is None:
        return "create"
    if not values_equal("tpm_ek_public_key", desired.get("tpm_ek_public_key"), existing.get("tpm_ek_public_key")):
        return "replace"
    if record_matches(existing, desired):
        return "unchanged"
    return "update"


def decide_group_action(existing: Optional[dict], desired: Dict[str, Any]) -> str:
    if existing is None:
        return "create"
    if record_matches(existing, desired):
        return "unchanged"
    return "update"


def identity_result(data: Optional[dict]) -> dict:
    """Shape an identity/tpm record for module return values."""
    if not data:
        return {}
    return {
        "name": data.get("name"),
        "tpm_ek_public_key": data.get("tpm_ek_public_key"),
        "disabled": bool(data.get("disabled")),
        "metadata": data.get("metadata") or {},
        "tpm_id": data.get("id") or data.get("tpm_id"),
    }


def group_result(data: Optional[dict]) -> dict:
    """Shape an identity/tpmgroup record for module return values."""
    if not data:
        return {}
    return {
        "name": data.get("name"),
        "member_tpm_ids": list(data.get("member_tpm_ids") or []),
        "metadata": data.get("metadata") or {},
        "tpm_group_id": data.get("id") or data.get("tpm_group_id"),
    }


def role_result(data: Optional[dict]) -> dict:
    if not data:
        return {}
    return dict(data)


def omit_none(values: Dict[str, Any]) -> Dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


class VaultTpm:
    """HTTP client for TPM auth config, TPM auth roles, and TPM identity records."""

    def __init__(self, client):
        self._client = client

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> Optional[dict]:
        kwargs = {}
        if body is not None:
            kwargs["json"] = body
        try:
            raw = self._client._make_request(method, path, **kwargs)
        except VaultSecretNotFoundError:
            if method == "GET":
                return None
            raise
        return unwrap_data(raw)

    def _delete(self, path: str) -> None:
        try:
            self._client._make_request("DELETE", path)
        except VaultSecretNotFoundError:
            return

    def read_config(self, mount: str) -> Optional[dict]:
        return self._request("GET", vault_path("auth", mount, "config"))

    def write_config(self, mount: str, body: Dict[str, Any]) -> Optional[dict]:
        logger.debug("POST TPM auth config at %s", mount)
        return self._request("POST", vault_path("auth", mount, "config"), body)

    def read_role(self, mount: str, name: str) -> Optional[dict]:
        return self._request("GET", vault_path("auth", mount, "role", name))

    def write_role(self, mount: str, name: str, body: Dict[str, Any]) -> Optional[dict]:
        logger.debug("POST TPM role %s at mount %s", name, mount)
        return self._request("POST", vault_path("auth", mount, "role", name), body)

    def delete_role(self, mount: str, name: str) -> None:
        logger.debug("DELETE TPM role %s at mount %s", name, mount)
        self._delete(vault_path("auth", mount, "role", name))

    def read_identity(self, name: Optional[str] = None, tpm_id: Optional[str] = None) -> Optional[dict]:
        """Read by id when one is known, otherwise by name. Create uses the collection path."""
        if tpm_id:
            return self._request("GET", vault_path("identity/tpm/id", tpm_id))
        if name:
            return self._request("GET", vault_path("identity/tpm/name", name))
        return None

    def create_identity(self, body: Dict[str, Any]) -> Optional[dict]:
        logger.debug("POST identity/tpm name=%s", body.get("name"))
        return self._request("POST", vault_path("identity/tpm"), body)

    def update_identity(
        self, body: Dict[str, Any], name: Optional[str] = None, tpm_id: Optional[str] = None
    ) -> Optional[dict]:
        if tpm_id:
            path = vault_path("identity/tpm/id", tpm_id)
        else:
            path = vault_path("identity/tpm/name", name)
        logger.debug("POST %s", path)
        return self._request("POST", path, body)

    def delete_identity(self, name: Optional[str] = None, tpm_id: Optional[str] = None) -> None:
        if tpm_id:
            path = vault_path("identity/tpm/id", tpm_id)
        else:
            path = vault_path("identity/tpm/name", name)
        logger.debug("DELETE %s", path)
        self._delete(path)

    def read_group(self, name: Optional[str] = None, tpm_group_id: Optional[str] = None) -> Optional[dict]:
        if tpm_group_id:
            return self._request("GET", vault_path("identity/tpmgroup/id", tpm_group_id))
        if name:
            return self._request("GET", vault_path("identity/tpmgroup/name", name))
        return None

    def create_group(self, body: Dict[str, Any]) -> Optional[dict]:
        logger.debug("POST identity/tpmgroup name=%s", body.get("name"))
        return self._request("POST", vault_path("identity/tpmgroup"), body)

    def update_group(
        self, body: Dict[str, Any], name: Optional[str] = None, tpm_group_id: Optional[str] = None
    ) -> Optional[dict]:
        if tpm_group_id:
            path = vault_path("identity/tpmgroup/id", tpm_group_id)
        else:
            path = vault_path("identity/tpmgroup/name", name)
        logger.debug("POST %s", path)
        return self._request("POST", path, body)

    def delete_group(self, name: Optional[str] = None, tpm_group_id: Optional[str] = None) -> None:
        if tpm_group_id:
            path = vault_path("identity/tpmgroup/id", tpm_group_id)
        else:
            path = vault_path("identity/tpmgroup/name", name)
        logger.debug("DELETE %s", path)
        self._delete(path)
