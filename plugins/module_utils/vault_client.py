# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import json  # noqa: F401
import logging

from typing import Any, Dict, List, Optional


try:
    import requests
except ImportError as imp_exc:
    REQUESTS_IMPORT_ERROR = imp_exc
else:
    REQUESTS_IMPORT_ERROR = None

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultConfigurationError,
    VaultConnectionError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)


logger = logging.getLogger(__name__)


class VaultClient:
    """
    A client for interacting with the HashiCorp Vault HTTP API.

    This client handles HTTP communication with Vault but does NOT handle
    authentication directly. Use an Authenticator to authenticate the client
    after instantiation.

    The separation of concerns allows for:
    - Creating clients before knowing the auth method
    - Easier unit testing with mock tokens
    - Cleaner plugin architecture

    Args:
        vault_address (str): The Vault server address (e.g., "https://vault.example.com:8200")
        vault_namespace (str): Vault Enterprise namespace (use "root" for OSS Vault)

    Example Usage:
        ```python
        # Step 1: Create an unauthenticated client
        client = VaultClient(
            vault_address="https://vault.example.com:8200",
            vault_namespace="my-namespace"
        )

        # Step 2: Authenticate using an Authenticator
        authenticator = TokenAuthenticator()
        authenticator.authenticate(client, token="hvs.abc123...")

        # Step 3: Client is now ready for API calls
        # (Use with VaultKV2Client or other secret engines)
        ```

    Attributes:
        vault_address (str): The Vault server address
        vault_namespace (str): The Vault namespace
        session (requests.Session): HTTP session with Vault headers configured
    """

    def __init__(self, vault_address: str, vault_namespace: str) -> None:
        """
        Initialize the Vault client.

        Creates an unauthenticated HTTP client with proper headers configured.
        You must use an Authenticator to authenticate before making API calls.

        Args:
            vault_address (str): The Vault server address (e.g., "https://vault.example.com:8200")
            vault_namespace (str): Vault Enterprise namespace (use "root" for OSS Vault)

        Raises:
            VaultConfigurationError: If vault_address or vault_namespace are empty/None
        """
        if REQUESTS_IMPORT_ERROR:
            raise ImportError(
                "The 'requests' library is required for VaultClient"
            ) from REQUESTS_IMPORT_ERROR

        if not vault_address:
            raise VaultConfigurationError("vault_address is required")
        if not vault_namespace:
            raise VaultConfigurationError("vault_namespace is required")

        self.vault_address = vault_address
        self.vault_namespace = vault_namespace

        # Set up HTTP session with namespace header
        self.session = requests.Session()
        self.session.headers.update({"X-Vault-Namespace": vault_namespace})

        logger.info("Initialized VaultClient for %s", vault_address)
        self.secrets = Secrets(self)

    def set_token(self, token: str) -> None:
        """
        Set or update the Vault token for the client.
        Args:
            token (str): The Vault client token (e.g., "hvs.abc123...")
        """
        self.session.headers.update({"X-Vault-Token": token})
        logger.debug("Token set for VaultClient")


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

    def _make_request(self, method: str, path: str, **kwargs) -> dict:
        """
        Make requests to the Vault API.

        Args:
            method (str): The HTTP method.
            path (str): The API endpoint path.
            **kwargs: Additional arguments for the requests library.

        Returns:
            dict: The JSON response data, or empty dict for successful operations with no content.
        """

        url = f"{self._client.vault_address}/v1/{path}"
        logger.debug("Making %s request to %s with params: %s", method, url, kwargs.get("params"))
        try:
            response = self._client.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.exceptions.HTTPError as e:
            status_code = e.response.status_code
            try:
                errors = e.response.json().get("errors", [])
            except json.JSONDecodeError:
                errors = [e.response.text]
            msg = f"API request failed: {errors}"
            if status_code == 403:
                raise VaultPermissionError(msg, status_code, errors) from e
            elif status_code == 404:
                raise VaultSecretNotFoundError(msg, status_code, errors) from e
            else:
                raise VaultApiError(msg, status_code, errors) from e
        except requests.exceptions.RequestException as e:
            raise VaultConnectionError(
                f"Failed to connect to Vault at {self._client.vault_address}. Error: {e}"
            ) from e

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
            params["version"] = version

        response_data = self._make_request("GET", path, params=params)
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
            VaultApiError: If the CAS check fails or other API errors occur.
            VaultPermissionError: If insufficient permissions.
            VaultConnectionError: If unable to connect to Vault.
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

        path = f"{mount_path}/data/{secret_path}"
        body: Dict[str, Any] = {"data": secret_data}
        if cas is not None:
            body["options"] = {"cas": cas}

        logger.debug("POST secret at %s with CAS: %s", secret_path, cas)
        return self._make_request("POST", path, json=body)

    def delete_secret(
        self, mount_path: str, secret_path: str, versions: Optional[List[int]] = None
    ) -> None:
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
            path = f"{mount_path}/delete/{secret_path}"
            self._make_request("POST", path, json={"versions": versions})
        else:
            # Delete latest version
            path = f"{mount_path}/data/{secret_path}"
            self._make_request("DELETE", path)


class Secrets:
    """A container class for different secrets engine clients."""

    def __init__(self, client):
        self.kv2 = VaultKv2Secrets(client)
