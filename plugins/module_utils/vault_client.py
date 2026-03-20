# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

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
            raise ImportError("The 'requests' library is required for VaultClient") from REQUESTS_IMPORT_ERROR

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
        self.acl_policies = VaultAclPolicies(self)
        self.namespaces = VaultNamespaces(self)

    def set_token(self, token: str) -> None:
        """
        Set or update the Vault token for the client.
        Args:
            token (str): The Vault client token (e.g., "hvs.abc123...")
        """
        self.session.headers.update({"X-Vault-Token": token})
        logger.debug("Token set for VaultClient")

    def _make_request(self, method: str, path: str, **kwargs) -> dict:
        """
        Make requests to the Vault API.

        Args:
            method (str): The HTTP method.
            path (str): The API endpoint path.
            **kwargs: Additional arguments for the requests library.

        Returns:
            dict: The JSON response data, or empty dict for successful operations with no content.

        Raises:
            VaultPermissionError: If Vault returns HTTP 403.
            VaultSecretNotFoundError: If Vault returns HTTP 404.
            VaultApiError: For other HTTP error responses from Vault.
            VaultConnectionError: If the HTTP request fails (network, timeout, etc.).
        """

        url = f"{self.vault_address}/{path}"
        logger.debug("Making %s request to %s with params: %s", method, url, kwargs.get("params"))
        try:
            response = self.session.request(method, url, **kwargs)
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
            raise VaultConnectionError(f"Failed to connect to Vault at {self.vault_address}. Error: {e}") from e


class VaultDatabaseConnection:
    """
    Handles interactions with the Vault Database Secrets Engine.
    """

    def __init__(self, client, mount_path="database"):
        """
        Initializes the Database connection client.

        Args:
            client (VaultClient): An authenticated instance of the main VaultClient.
            mount_path (str): The mount path of the database secrets engine. Defaults to "database".
        """
        self._client = client
        self._mount_path = (mount_path or "database").strip().strip("/")

    def list_connections(self) -> list:
        """
        List all available connections.

        Returns:
            List[str]: A list of connection names.
        """
        path = f"v1/{self._mount_path}/config"
        response_data = self._client._make_request("LIST", path)

        connections = response_data.get("data", {}).get("keys", [])

        return connections

    def read_connection(self, name: str) -> dict:
        """
        Read the configuration settings of a database connection.

        Args:
            name (str): The name of the connection to read.

        Returns:
            dict: The connection configuration data.
        """
        path = f"v1/{self._mount_path}/config/{name}"
        response_data = self._client._make_request("GET", path)

        return response_data.get("data", {})

    def create_or_update_connection(self, name: str, config: dict) -> dict:
        """
        Configure a database connection.

        Args:
            name (str): The name of the database connection
            config (dict): Connection configuration containing:
                - plugin_name (str, required): Database plugin type (e.g., 'postgresql-database-plugin')
                - plugin_version (str, optional): Semantic version of the plugin
                - allowed_roles (list, optional): Roles allowed to use this connection
                - verify_connection (bool, optional): Verify during setup (default: true)
                - root_rotation_statements (list, optional): Statements to execute during root rotation
                - password_policy (str, optional): Password policy to use for the connection
                - Other common fields (reference the individual plugin documentation to determine support)
                  - connection_url (str, optional): Database connection string
                  - username (str, optional): Database username
                  - password (str, optional): Database password
                  - disable_escaping (bool, optional): Disable escaping of special characters in the connection URL (default: false)

        Returns:
            dict: Response from Vault

        Raises:
            TypeError: If config is not a dict, or if config does not contain
                "plugin_name" with a string value.

        Example:
            db.create_or_update_connection(
              name="my-postgres-db",
              config={
                  "plugin_name": "postgresql-database-plugin",
                  "connection_url": "postgresql://{{username}}:{{password}}@localhost:5432/mydb",
                  "username": "vault",
                  "password": "secret",
                  "allowed_roles": ["readonly", "readwrite"]}
              )
        """
        if not isinstance(config, dict):
            raise TypeError("config must be a dict")
        if "plugin_name" not in config:
            raise TypeError('config must contain "plugin_name"')
        if not isinstance(config["plugin_name"], str):
            raise TypeError('config["plugin_name"] must be a str')

        path = f"v1/{self._mount_path}/config/{name}"
        return self._client._make_request("POST", path, json=config)

    def delete_connection(self, name: str) -> None:
        """
        Delete a database connection.

        Args:
            name (str): The name of the connection to delete.

        Returns:
            None
        """
        path = f"v1/{self._mount_path}/config/{name}"
        self._client._make_request("DELETE", path)

    def reset_connection(self, name: str) -> None:
        """
        Reset a database connection by closing the connection and its underlying plugin,
        then restarting it.

        Args:
            name (str): The name of the connection to reset.

        Returns:
            None
        """
        path = f"v1/{self._mount_path}/reset/{name}"
        self._client._make_request("POST", path, json={})


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


class VaultAclPolicies:
    """
    Handles interactions with the Vault ACL policy HTTP API (/sys/policy).

    Used by the ACL policy Ansible module and ACL policy _info module for
    create, update, delete, list, and read operations. Integrates with the
    collection's connection and authentication (base URL, token,
    X-Vault-Namespace).
    """

    def __init__(self, client):
        """
        Initializes the Vault ACL policies API client.

        Args:
            client (VaultClient): An authenticated instance of the main VaultClient.
        """
        self._client = client

    def list_acl_policies(self) -> List[str]:
        """
        List all Vault ACL policy names.

        Returns:
            list: ACL policy names (e.g. ["root", "deploy"]).
        """
        path = "v1/sys/policy"
        response = self._client._make_request("GET", path)
        return response.get("policies", [])

    def read_acl_policy(self, name: str) -> dict:
        """
        Read a Vault ACL policy by name.

        Args:
            name (str): The name of the ACL policy to read.

        Returns:
            dict: ACL policy data with "name" and "rules" keys.
        """
        path = f"v1/sys/policy/{name}"
        return self._client._make_request("GET", path)

    def create_or_update_acl_policy(self, name: str, acl_policy_rules: str) -> dict:
        """
        Create a new Vault ACL policy or update an existing one.

        Args:
            name (str): The name of the ACL policy (URL path segment).
            acl_policy_rules (str): The ACL policy rules string (request JSON field ``policy``).

        Returns:
            dict: The JSON response from Vault (often empty for success).

        Raises:
            TypeError: If the ACL policy rules are not a string.
        """
        if not isinstance(acl_policy_rules, str):
            raise TypeError("ACL policy rules must be a string")

        path = f"v1/sys/policy/{name}"
        body: Dict[str, Any] = {"policy": acl_policy_rules}
        logger.debug("POST ACL policy at %s", name)
        return self._client._make_request("POST", path, json=body)

    def delete_acl_policy(self, name: str) -> None:
        """
        Delete a Vault ACL policy by name.

        Args:
            name (str): The name of the ACL policy to delete.

        Returns:
            None
        """
        path = f"v1/sys/policy/{name}"
        self._client._make_request("DELETE", path)


class VaultNamespaces:
    """
    Handles interactions with the Vault Namespaces API (/sys/namespaces).

    Provides read-only operations for listing and reading namespace information.
    Used by the namespaces _info Ansible module.
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


class Secrets:
    """A container class for different secrets engine clients."""

    def __init__(self, client):
        self.kv2 = VaultKv2Secrets(client)
        self.kv1 = VaultKv1Secrets(client)
