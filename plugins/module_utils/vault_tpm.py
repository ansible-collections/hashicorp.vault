# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import binascii
import hashlib
import logging
import re
from typing import Any, Dict, Optional, Tuple

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultSecretNotFoundError,
)

logger = logging.getLogger(__name__)

__all__ = ['VaultTpm', 'compute_tpm_id', 'MIN_VAULT_VERSION']

# Minimum Vault Enterprise version that provides the TPM identity API.
MIN_VAULT_VERSION = "2.2.0"

_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")
_PEM_RE = re.compile(r"^-----BEGIN (?P<label>[A-Z0-9 ]+)-----(?P<body>.*?)-----END (?P=label)-----$", re.DOTALL)


def _parse_version(version: str) -> Tuple[int, int, int]:
    """
    Parse the leading ``major.minor.patch`` of a Vault version string.

    Build metadata (``+ent``) and pre-release suffixes (``-beta``) are ignored.

    Args:
        version (str): The version string, e.g. ``"2.2.0+ent"``.

    Returns:
        tuple: ``(major, minor, patch)`` as integers.

    Raises:
        ValueError: If the string does not start with ``major.minor.patch``.
    """
    match = _VERSION_RE.match(version.strip())
    if not match:
        raise ValueError(f"Unrecognised Vault version: {version!r}")
    return tuple(int(part) for part in match.groups())


def compute_tpm_id(ek_pem: str) -> str:
    """
    Compute the Vault TPM ID for an endorsement key given as a PEM public key.

    The ID is ``"sha256-"`` followed by the hex SHA-256 of the DER bytes, which is how Vault derives it.
    Leading and trailing whitespace and CRLF line endings are accepted.

    Args:
        ek_pem (str): The endorsement key as a PKIX ``PUBLIC KEY`` PEM block.

    Returns:
        str: The TPM ID, e.g. ``"sha256-<64 hex characters>"``.

    Raises:
        TypeError: If ``ek_pem`` is not a string.
        ValueError: If the value is not a single ``PUBLIC KEY`` PEM block with valid base64 content.
    """
    if not isinstance(ek_pem, str):
        raise TypeError("ek_pem must be a string")

    match = _PEM_RE.match(ek_pem.strip())
    if not match:
        raise ValueError("ek_pem is not a PEM encoded block")
    if match.group("label") != "PUBLIC KEY":
        raise ValueError(f"ek_pem must be a PUBLIC KEY PEM block, got {match.group('label')}")

    body = re.sub(r"\s+", "", match.group("body"))
    try:
        der = base64.b64decode(body, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"ek_pem contains invalid base64 data: {e}") from e
    if not der:
        raise ValueError("ek_pem contains no key data")

    return "sha256-" + hashlib.sha256(der).hexdigest()


class VaultTpm:
    """
    Handles interactions with the Vault Enterprise TPM identity HTTP API (/identity/tpm, /identity/tpmgroup).

    Used by the TPM identity Ansible modules to enroll, read, update and delete TPM identities and to add
    them to TPM groups. Errors are not handled here: they propagate to the caller, except that the read
    methods return None when the record does not exist.
    """

    def __init__(self, client):
        """
        Initializes the Vault TPM API client.

        Args:
            client (VaultClient): An authenticated instance of the main VaultClient.
        """
        self._client = client

    def check_vault_version(self, min_version: str = MIN_VAULT_VERSION) -> None:
        """
        Check that the server is Vault Enterprise at or above a minimum version via GET /sys/health.

        The request sets ``sealedcode`` and ``standbycode`` so that a sealed or standby node still returns its
        payload with a success status. The endpoint does not need a token.

        Args:
            min_version (str): The minimum required version.

        Raises:
            VaultApiError: If the server is not Vault Enterprise or its version is lower than ``min_version``.
        """
        response = self._client._make_request("GET", "v1/sys/health", params={"sealedcode": 299, "standbycode": 299})
        version = str(response.get("version") or "")
        enterprise = bool(response.get("enterprise"))

        try:
            supported = enterprise and _parse_version(version) >= _parse_version(min_version)
        except ValueError:
            supported = False

        if not supported:
            raise VaultApiError(
                f"This module requires Vault Enterprise >= {min_version}. Found: {version or 'unknown'}."
            )

    def register_tpm(self, name: str, ek_pem: str, metadata: Optional[Dict[str, str]] = None) -> dict:
        """
        Enroll a TPM identity via POST /identity/tpm.

        Args:
            name (str): The name of the TPM identity.
            ek_pem (str): The endorsement key as a PEM public key.
            metadata (dict, optional): Metadata key-value pairs to store with the TPM.

        Returns:
            dict: The JSON response from Vault, with the TPM record under ``data``.

        Raises:
            TypeError: If metadata is not a dict.
        """
        if metadata is not None and not isinstance(metadata, dict):
            raise TypeError("metadata must be a dict")

        body: Dict[str, Any] = {"name": name, "tpm_ek_public_key": ek_pem}
        if metadata is not None:
            body["metadata"] = metadata

        logger.debug("POST TPM identity %s", name)
        return self._client._make_request("POST", "v1/identity/tpm", json=body)

    def read_tpm(self, name: str) -> Optional[dict]:
        """
        Read a TPM identity by name via GET /identity/tpm/name/:name.

        Args:
            name (str): The name of the TPM identity.

        Returns:
            dict: The TPM record (``id``, ``name``, ``metadata``, ``tpm_ek_public_key``, ``disabled``),
            or None if it does not exist.
        """
        return self._read(f"v1/identity/tpm/name/{name}")

    def read_tpm_by_id(self, tpm_id: str) -> Optional[dict]:
        """
        Read a TPM identity by ID via GET /identity/tpm/id/:id.

        Args:
            tpm_id (str): The TPM ID, e.g. ``"sha256-<hex>"``.

        Returns:
            dict: The TPM record, or None if it does not exist.
        """
        return self._read(f"v1/identity/tpm/id/{tpm_id}")

    def update_tpm(self, name: str, disabled: Optional[bool] = None, metadata: Optional[Dict[str, str]] = None) -> dict:
        """
        Update a TPM identity by name via POST /identity/tpm/name/:name.

        Only the fields that are not None are sent. The endorsement key is never sent because Vault does not
        allow it to be changed.

        Args:
            name (str): The name of the TPM identity.
            disabled (bool, optional): Whether the TPM is disabled.
            metadata (dict, optional): Metadata key-value pairs. Vault replaces the stored metadata.

        Returns:
            dict: The JSON response from Vault.

        Raises:
            TypeError: If metadata is not a dict.
        """
        if metadata is not None and not isinstance(metadata, dict):
            raise TypeError("metadata must be a dict")

        body: Dict[str, Any] = {}
        if disabled is not None:
            body["disabled"] = disabled
        if metadata is not None:
            body["metadata"] = metadata

        logger.debug("POST update TPM identity %s", name)
        return self._client._make_request("POST", f"v1/identity/tpm/name/{name}", json=body)

    def delete_tpm(self, name: str) -> None:
        """
        Delete a TPM identity by name via DELETE /identity/tpm/name/:name.

        Vault also removes the TPM from every TPM group, and succeeds if the TPM does not exist.

        Args:
            name (str): The name of the TPM identity.

        Returns:
            None
        """
        self._client._make_request("DELETE", f"v1/identity/tpm/name/{name}")

    def add_tpm_to_group(self, group_name: str, tpm_id: str) -> bool:
        """
        Add a TPM to a TPM group, keeping the existing members.

        Vault replaces ``member_tpm_ids`` on every write, so the current list is read first and posted back in
        full with the new ID appended. Nothing is written if the TPM is already a member. Two hosts adding
        themselves to the same group at the same time can overwrite each other.

        Args:
            group_name (str): The name of the TPM group.
            tpm_id (str): The TPM ID to add.

        Returns:
            bool: True if the group was updated, False if the TPM was already a member.

        Raises:
            VaultSecretNotFoundError: If the group does not exist.
        """
        path = f"v1/identity/tpmgroup/name/{group_name}"
        response = self._client._make_request("GET", path)
        members = list((response.get("data") or {}).get("member_tpm_ids") or [])
        if tpm_id in members:
            return False

        members.append(tpm_id)
        logger.debug("POST TPM group %s", group_name)
        self._client._make_request("POST", path, json={"member_tpm_ids": members})
        return True

    def _read(self, path: str) -> Optional[dict]:
        """
        GET a TPM record, returning its ``data`` or None if Vault answers 404.
        """
        try:
            response = self._client._make_request("GET", path)
        except VaultSecretNotFoundError:
            return None
        return response.get("data") or {}
