# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

__all__ = ['VaultKv1Secrets']


class VaultKv1Secrets:
    """
    Handles interactions with the KV version 1 secrets engine.
    """

    def __init__(self, client):
        """
        Initializes the KV1 secrets client.

        Args:
            client (VaultClient): An authenticated instance of the main VaultClient.
        """
        self._client = client

    def read_secret(self, mount_path: str, secret_path: str) -> dict:
        """
        Reads a secret from the KV1 secrets engine.

        Args:
            mount_path (str): The mount path of the KV1 secrets engine.
            secret_path (str): The path to the secret.

        Returns:
            dict: The secret's data and metadata.
        """
        path = f"v1/{mount_path}/{secret_path}"
        params = {}

        response_data = self._client._make_request("GET", path, params=params)
        return response_data.get("data", {})

    def create_or_update_secret(self, mount_path: str, secret_path: str, secret_data: dict) -> dict:
        """
        Creates or updates a secret in the KV1 secrets engine.

        Args:
            mount_path (str): The mount path of the KV1 secrets engine.
            secret_path (str): The path to the secret.
            secret_data (dict): The secret data to store.

        Returns:
            dict: The response data containing metadata about the created/updated secret.

        Raises:
            TypeError: If secret_data is not a dictionary.
        """
        if not isinstance(secret_data, dict):
            raise TypeError("secret_data must be a dict")

        path = f"v1/{mount_path}/{secret_path}"
        body: Dict[str, Any] = secret_data
        logger.debug("POST secret at %s", secret_path)
        return self._client._make_request("POST", path, json=body)

    def delete_secret(self, mount_path: str, secret_path: str) -> None:
        """
        Deletes the secret at the specified location.

        Args:
            mount_path (str): The mount path of the KV1 secrets engine.
            secret_path (str): The path to the secret.

        Returns:
            None
        """
        path = f"v1/{mount_path}/{secret_path}"
        self._client._make_request("DELETE", path)
