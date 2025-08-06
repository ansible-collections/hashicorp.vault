# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


import os
import requests
import json
import logging
import argparse

from .vault_exceptions import VaultClientError
from .vault_exceptions import VaultConnectionError
from .vault_exceptions import VaultApiError
from .vault_exceptions import VaultPermissionError
from .vault_exceptions import VaultSecretNotFoundError

log = logging.getLogger(__name__)


class VaultKv2Client:
    """
    Python client for interacting with Hashicorp Vault's KVv2 secrets engine.
    """

    def __init__(self, vault_addr: str, vault_token: str, vault_namespace: str = None):
        """
        Initializes the Vault KVv2 client.

        Args:
            vault_addr (str): Vault server address.
            vault_token (str): Vault token for authentication.
            vault_namespace (str, optional): Vault namespace to use.
        """

        if not vault_addr:
            raise ValueError("Vault address cannot be empty.")
        if not vault_token:
            raise ValueError("Vault token cannot be empty.")
            
        self.vault_addr = vault_addr.rstrip('/')
        self.session = requests.Session()
        headers = {'X-Vault-Token': vault_token}
        if vault_namespace:
            headers['X-Vault-Namespace'] = vault_namespace
    
        self.session.headers.update(headers)

    def _make_request(self, method: str, path: str, **kwargs) -> dict:
        """
        make requests to the Vault API.

        Args:
            method (str): The HTTP method.
            path (str): The API endpoint path.
            **kwargs: Additional arguments for the requests library.

        Returns:
            dict: The JSON response data.
        """

        url = f"{self.vault_addr}/v1/{path}"
        log.debug(f"Making {method} request to {url} with params: {kwargs.get('params')}")
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            errors = e.response.json().get('errors', [])
            msg = f"API request failed: {errors}"
            if status_code == 403:
                raise VaultPermissionError(msg, status_code, errors) from e
            elif status_code == 404:
                raise VaultSecretNotFoundError(msg, status_code, errors) from e
            else:
                raise VaultApiError(msg, status_code, errors) from e
        except requests.exceptions.RequestException as e:
            raise VaultConnectionError(f"Failed to connect to Vault at {self.vault_addr}. Error: {e}") from e

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

        path = f"{mount_path}/data/{secret_path}"
        params = {}
        if version is not None:
            params['version'] = version
        
        response_data = self._make_request('GET', path, params=params)
        return response_data.get('data', {})
