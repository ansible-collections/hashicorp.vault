# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = ['VaultNamespaces']


class VaultNamespaces:
    """
    Handles interactions with the Vault Namespaces API (/sys/namespaces).

    Provides operations for listing, reading, creating, patching, deleting,
    locking, and unlocking namespaces.
    """

    def __init__(self, client):
        """
        Initializes the Vault Namespaces API client.

        Args:
            client (VaultClient): An authenticated instance of the main VaultClient.
        """
        self._client = client

    def list_namespaces(self) -> List[Dict[str, Any]]:
        """
        List all Vault namespaces.

        Returns:
            List[Dict[str, Any]]: A single-element list containing the JSON ``data``
            object from the LIST response (typically ``keys`` and ``key_info``), so
            callers get Vault's structure unchanged.
        """
        path = "v1/sys/namespaces"
        response = self._client._make_request("LIST", path)
        return [response.get("data", {}) or {}]

    def read_namespace(self, namespace_path: str) -> dict:
        """
        Read a Vault namespace by path.

        Args:
            namespace_path (str): The path of the namespace to read.

        Returns:
            dict: Namespace data containing 'id', 'path', and 'custom_metadata'.

        Example response:
            {
                "id": "gsudz",
                "path": "ns1/",
                "custom_metadata": {"foo": "bar"}
            }
        """
        path = f"v1/sys/namespaces/{namespace_path}"
        response = self._client._make_request("GET", path)
        return response.get("data", {})

    def create_namespace(self, namespace_path: str, custom_metadata: Optional[Dict[str, str]] = None) -> dict:
        """
        Create a new Vault namespace.

        Args:
            namespace_path (str): The path for the new namespace.
            custom_metadata (dict, optional): Custom metadata key-value pairs for the namespace.

        Returns:
            dict: Response data from Vault containing the created namespace information.

        Raises:
            TypeError: If custom_metadata is not a dict.

        Example:
            namespaces.create_namespace(
                namespace_path="engineering",
                custom_metadata={"team": "platform", "environment": "prod"}
            )
        """
        if custom_metadata is not None and not isinstance(custom_metadata, dict):
            raise TypeError("custom_metadata must be a dict")

        path = f"v1/sys/namespaces/{namespace_path}"
        body: Dict[str, Any] = {}
        if custom_metadata:
            body["custom_metadata"] = custom_metadata

        logger.debug("POST namespace at %s", namespace_path)
        return self._client._make_request("POST", path, json=body)

    def patch_namespace(self, namespace_path: str, custom_metadata: Optional[Dict[str, str]] = None) -> dict:
        """
        Patch an existing Vault namespace's custom metadata.

        Args:
            namespace_path (str): The path of the namespace to patch.
            custom_metadata (dict, optional): Custom metadata key-value pairs to merge.

        Returns:
            dict: Response data from Vault.

        Raises:
            TypeError: If custom_metadata is not a dict.

        Example:
            namespaces.patch_namespace(
                namespace_path="engineering",
                custom_metadata={"owner": "alice"}
            )
        """
        if custom_metadata is not None and not isinstance(custom_metadata, dict):
            raise TypeError("custom_metadata must be a dict")

        path = f"v1/sys/namespaces/{namespace_path}"
        body: Dict[str, Any] = {}
        if custom_metadata:
            body["custom_metadata"] = custom_metadata

        headers = {"Content-Type": "application/merge-patch+json"}

        logger.debug("PATCH namespace at %s", namespace_path)
        return self._client._make_request("PATCH", path, json=body, headers=headers)

    def delete_namespace(self, namespace_path: str) -> None:
        """
        Delete a Vault namespace.

        Args:
            namespace_path (str): The path of the namespace to delete.

        Returns:
            None
        """
        path = f"v1/sys/namespaces/{namespace_path}"
        self._client._make_request("DELETE", path)

    def lock_namespace(self, subpath: Optional[str] = None) -> dict:
        """
        Lock a namespace to prevent API operations.

        Args:
            subpath (str, optional): Subpath within the namespace to lock. If None, locks the current namespace.

        Returns:
            dict: Response data from Vault containing lock information (e.g., unlock_key).

        Example:
            # Lock current namespace
            result = namespaces.lock_namespace()
            unlock_key = result.get("unlock_key")

            # Lock a subpath
            result = namespaces.lock_namespace(subpath="child")
        """
        if subpath:
            path = f"v1/sys/namespaces/api-lock/lock/{subpath}"
        else:
            path = "v1/sys/namespaces/api-lock/lock"

        logger.debug("POST lock namespace at %s", path)
        return self._client._make_request("POST", path, json={})

    def unlock_namespace(self, subpath: Optional[str] = None, unlock_key: Optional[str] = None) -> dict:
        """
        Unlock a namespace to restore API operations.

        Args:
            subpath (str, optional): Subpath within the namespace to unlock. If None, unlocks the current namespace.
            unlock_key (str, optional): The unlock key obtained from lock_namespace(). Root token holders can omit this.

        Returns:
            dict: Response data from Vault.

        Example:
            # Unlock with key
            namespaces.unlock_namespace(unlock_key="abc123...")

            # Unlock as root (no key needed)
            namespaces.unlock_namespace()

            # Unlock a subpath
            namespaces.unlock_namespace(subpath="child", unlock_key="abc123...")
        """
        if subpath:
            path = f"v1/sys/namespaces/api-lock/unlock/{subpath}"
        else:
            path = "v1/sys/namespaces/api-lock/unlock"

        body: Dict[str, Any] = {}
        if unlock_key:
            body["unlock_key"] = unlock_key

        logger.debug("POST unlock namespace at %s", path)
        return self._client._make_request("POST", path, json=body)
