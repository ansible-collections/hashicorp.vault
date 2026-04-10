# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json  # noqa: F401
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import quote

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

__all__ = [
    'VaultClient',
    'VaultKv2Secrets',
    'VaultKv1Secrets',
    'VaultAclPolicies',
    'VaultNamespaces',
    'Secrets',
]


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


class VaultPki:
    """
    Handles interactions with the Vault PKI secrets engine (certificate issue, sign, revoke, read, list).

    Supporting documentation (HashiCorp Developer, PKI secrets engine HTTP API):

    - Generate Certificate: https://developer.hashicorp.com/vault/api-docs/secret/pki#generate-certificate-and-key
    - Sign CSR: https://developer.hashicorp.com/vault/api-docs/secret/pki#sign-certificate
    - Revoke Certificate: https://developer.hashicorp.com/vault/api-docs/secret/pki#revoke-certificate
    - Read Certificate: https://developer.hashicorp.com/vault/api-docs/secret/pki#read-certificate
    - List Certificates: https://developer.hashicorp.com/vault/api-docs/secret/pki#list-certificates
    - PKI - Secrets Engines - HTTP API: https://developer.hashicorp.com/vault/api-docs/secret/pki
    """

    @staticmethod
    def _require_str(param: str, value: Any) -> None:
        """Raise TypeError if value is not a str (strict runtime check for API path/body inputs)."""
        if not isinstance(value, str):
            raise TypeError("{0} must be a str".format(param))

    @staticmethod
    def _require_optional_dict(param: str, value: Any) -> None:
        """Raise TypeError if value is provided and not a dict."""
        if value is not None and not isinstance(value, dict):
            raise TypeError("{0} must be a dict".format(param))

    @staticmethod
    def _require_pki_role_name(param: str, value: Any) -> None:
        """
        Validate a PKI role name before it is interpolated into a request path.

        Rejects values that would produce ambiguous or multi-segment paths (e.g. empty
        or containing ``/``).
        """
        VaultPki._require_str(param, value)
        if value != value.strip():
            raise ValueError("{0} must not have leading or trailing whitespace".format(param))
        if not value:
            raise ValueError("{0} must be non-empty".format(param))
        if "/" in value:
            raise ValueError("{0} must not contain '/'".format(param))

    def __init__(self, client, mount_path: str = "pki") -> None:
        """
        Initialize the PKI client.

        Args:
            client (VaultClient): An authenticated VaultClient instance.
            mount_path (str): PKI secrets engine mount path. Defaults to ``pki``.

        Raises:
            TypeError: If ``mount_path`` is not a string after applying the default for falsy values.
        """
        self._client = client
        coalesced = mount_path if mount_path else "pki"
        self._require_str("mount_path", coalesced)
        self._mount_path = coalesced.strip().strip("/")

    def generate_certificate(
        self, role: str, common_name: str, extra: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate a new private key and certificate via POST ``/issue/:role``.

        Args:
            role (str): PKI role name (URL path segment after ``issue/``).
            common_name (str): Common name for the issued certificate.
            extra (dict, optional): Additional JSON body fields (e.g. ``alt_names``, ``ip_sans``, ``ttl``, ``format``).

        Returns:
            dict: Full Vault JSON response (``data`` typically contains ``certificate``, ``private_key``, ``issuing_ca``, etc.).

        Raises:
            TypeError: If ``role`` or ``common_name`` is not a string, or ``extra`` is not a dict when provided.
            ValueError: If ``role`` is empty, has leading/trailing whitespace, or contains ``/``.
        """
        self._require_pki_role_name("role", role)
        self._require_str("common_name", common_name)
        self._require_optional_dict("extra", extra)

        body: Dict[str, Any] = {"common_name": common_name}
        if extra is not None:
            body.update(extra)

        path = f"v1/{self._mount_path}/issue/{role}"
        logger.debug("POST PKI issue %s at role %s", path, role)
        return self._client._make_request("POST", path, json=body)

    def sign_certificate(
        self, role: str, csr: str, common_name: str, extra: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Sign a certificate signing request via POST ``/sign/:role``.

        Args:
            role (str): PKI role name (URL path segment after ``sign/``).
            csr (str): PEM-encoded certificate signing request.
            common_name (str): Common name for the signed certificate (required by the Vault PKI API).
            extra (dict, optional): Additional JSON body fields (e.g. ``alt_names``, ``ip_sans``, ``ttl``, ``format``).
                If ``common_name`` is present in ``extra``, it overrides this argument.

        Returns:
            dict: Full Vault JSON response (``data`` typically contains ``certificate``, ``issuing_ca``, etc.).

        Raises:
            TypeError: If ``role``, ``csr``, or ``common_name`` is not a string, or ``extra`` is not a dict when provided.
            ValueError: If ``role`` is empty, has leading/trailing whitespace, or contains ``/``.
        """
        self._require_pki_role_name("role", role)
        self._require_str("csr", csr)
        self._require_str("common_name", common_name)
        self._require_optional_dict("extra", extra)

        body: Dict[str, Any] = {"csr": csr, "common_name": common_name}
        if extra is not None:
            body.update(extra)

        path = f"v1/{self._mount_path}/sign/{role}"
        logger.debug("POST PKI sign %s at role %s", path, role)
        return self._client._make_request("POST", path, json=body)

    def revoke_certificate(
        self,
        serial_number: Optional[str] = None,
        certificate: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Revoke a certificate via POST ``/revoke`` on the PKI mount (see Vault PKI HTTP API).

        The request body must include exactly one of ``serial_number`` or ``certificate``.

        Args:
            serial_number (str, optional): Certificate serial in Vault format (colon-separated hex). Omit when using ``certificate``.
            certificate (str, optional): PEM-encoded certificate to revoke. Omit when using ``serial_number``.

        Returns:
            dict: Full Vault JSON response.

        Raises:
            TypeError: If the provided argument is not a string.
            ValueError: If both or neither of ``serial_number`` and ``certificate`` are set.
        """
        if serial_number is not None:
            self._require_str("serial_number", serial_number)
        if certificate is not None:
            self._require_str("certificate", certificate)

        has_serial = serial_number is not None
        has_cert = certificate is not None
        if has_serial == has_cert:
            raise ValueError("Exactly one of serial_number and certificate must be provided")

        path = f"v1/{self._mount_path}/revoke"
        if has_serial:
            body: Dict[str, Any] = {"serial_number": serial_number}
            logger.debug("POST PKI revoke by serial %s", serial_number)
        else:
            body = {"certificate": certificate}
            logger.debug("POST PKI revoke by certificate PEM (%d chars)", len(certificate or ""))
        logger.debug("POST PKI revoke %s", path)
        return self._client._make_request("POST", path, json=body)

    def read_certificate(self, serial_number: str) -> Dict[str, Any]:
        """
        Read certificate metadata and PEM by serial via GET ``/cert/:serial``.

        Args:
            serial_number (str): Certificate serial (colon-separated hex or Vault ``certs`` list key).

        Returns:
            dict: Full Vault JSON response (``data`` typically contains ``certificate``).

        Raises:
            TypeError: If ``serial_number`` is not a string.
        """
        self._require_str("serial_number", serial_number)

        encoded_serial = quote(serial_number, safe="")
        path = f"v1/{self._mount_path}/cert/{encoded_serial}"
        logger.debug("GET PKI cert %s", serial_number)
        logger.debug("GET PKI cert %s", path)
        return self._client._make_request("GET", path)

    def list_certificates(self) -> List[str]:
        """
        List stored certificate serial numbers via LIST ``/certs`` (see Vault PKI HTTP API).

        Returns:
            list: Serial numbers (``keys`` from the LIST response ``data``).
        """
        path = f"v1/{self._mount_path}/certs"
        response_data = self._client._make_request("LIST", path)
        keys = response_data.get("data", {}).get("keys", [])
        return [k for k in keys if isinstance(k, str)]


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
        List all Vault ACL policy names via GET /sys/policy.

        Returns:
            list: ACL policy names sorted lexicographically.
        """
        response = self._client._make_request("GET", "v1/sys/policy")
        # HCP commonly returns top-level "policies"; keeping a small fallback for data.policies.
        names = response.get("policies") or response.get("data", {}).get("policies") or []
        names = [name for name in names if isinstance(name, str)]
        return sorted(names)

    def read_acl_policy(self, name: str) -> dict:
        """
        Read a Vault ACL policy by name via GET /sys/policy/:name.

        Args:
            name (str): The name of the ACL policy to read.

        Returns:
            dict: ACL policy data with "name" and "rules" keys.
        """
        path = f"v1/sys/policy/{name}"
        raw = self._client._make_request("GET", path)
        data = raw.get("data") or {}
        rules = raw.get("rules") or raw.get("policy") or data.get("rules") or data.get("policy") or ""
        return {"name": name, "rules": rules.strip()}

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


class Secrets:
    """A container class for different secrets engine clients.

    Attributes:
        kv1: Key-Value version 1 secrets engine
        kv2: Key-Value version 2 secrets engine
        pki: PKI (Public Key Infrastructure) secrets engine
    """

    def __init__(self, client):
        self.kv2 = VaultKv2Secrets(client)
        self.kv1 = VaultKv1Secrets(client)
        self.pki = VaultPki(client)
