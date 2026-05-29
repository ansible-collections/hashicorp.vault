# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

__all__ = ['VaultKv2Secrets']


class VaultKv2Secrets:
    """
    Handles interactions with the KV version 2 secrets engine.
    """

    def __init__(self, client):
        """
        Initializes the KV2 secrets client.

        Args:
            client (VaultClient): An authenticated instance of the main VaultClient.
        """
        self._client = client

    def read_secret(self, mount_path: str, secret_path: str, version: int = None) -> dict:
        """
        Reads a secret from the KV2 secrets engine.

        Args:
            mount_path (str): The mount path of the KV2 secrets engine.
            secret_path (str): The path to the secret.
            version (int, optional): The version to read. Defaults to the latest.

        Returns:
            dict: The secret's data and metadata.
        """
        path = f"v1/{mount_path}/data/{secret_path}"
        params = {}
        if version is not None:
            params["version"] = version

        response_data = self._client._make_request("GET", path, params=params)
        return response_data.get("data", {})

    def create_or_update_secret(
        self, mount_path: str, secret_path: str, secret_data: dict, cas: Optional[int] = None
    ) -> dict:
        """
        Creates or updates a secret in the KV2 secrets engine.

        Args:
            mount_path (str): The mount path of the KV2 secrets engine.
            secret_path (str): The path to the secret.
            secret_data (dict): The secret data to store.
            cas (int, optional): Check-and-Set value for conditional updates.
                                If provided, the update will only succeed if the current
                                version matches this value. Use 0 to ensure the secret
                                doesn't exist yet.

        Returns:
            dict: The response data containing metadata about the created/updated secret.

        Raises:
            TypeError: If secret_data is not a dictionary.

        Examples:
            # Create a new secret
            result = client.secrets.kv2.create_or_update_secret(
                mount_path="secret",
                secret_path="myapp/config",
                secret_data={"timeout": 60}
            )
        """
        if not isinstance(secret_data, dict):
            raise TypeError("secret_data must be a dict")

        path = f"v1/{mount_path}/data/{secret_path}"
        body: Dict[str, Any] = {"data": secret_data}
        if cas is not None:
            body["options"] = {"cas": cas}

        logger.debug("POST secret at %s with CAS: %s", secret_path, cas)
        return self._client._make_request("POST", path, json=body)

    def delete_secret(self, mount_path: str, secret_path: str, versions: Optional[List[int]] = None) -> None:
        """
        Deletes a secret from the KV2 secrets engine.
        If secret version is not provided, it will soft delete the latest version of the secret.
        If secret version is provided, it will delete the specified versions of the secret.
        This performs a soft delete (not a permanent destroy) of the secret version(s).

        Args:
            mount_path (str): The mount path of the KV2 secrets engine.
            secret_path (str): The path to the secret.
            versions (List[int], optional): The versions to delete. If not provided, deletes the latest version.

        Returns:
            None
        """
        if versions:
            # Delete specific versions using batch deletion
            path = f"v1/{mount_path}/delete/{secret_path}"
            self._client._make_request("POST", path, json={"versions": versions})
        else:
            # Delete latest version
            path = f"v1/{mount_path}/data/{secret_path}"
            self._client._make_request("DELETE", path)
