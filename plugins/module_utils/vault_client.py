# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json  # noqa: F401
import logging
from typing import Dict, Optional, Union

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError as imp_exc:
    REQUESTS_IMPORT_ERROR = imp_exc
else:
    REQUESTS_IMPORT_ERROR = None

from ansible.module_utils.parsing.convert_bool import boolean

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_acl_policies import VaultAclPolicies
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultConfigurationError,
    VaultConnectionError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_kv1_secrets import VaultKv1Secrets
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_kv2_secrets import VaultKv2Secrets
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_namespaces import VaultNamespaces
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_pki import VaultPki
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_secrets import Secrets

logger = logging.getLogger(__name__)

__all__ = [
    'VaultClient',
    'VaultKv2Secrets',
    'VaultKv1Secrets',
    'VaultPki',
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

    def __init__(
        self,
        vault_address: str,
        vault_namespace: str,
        ca_certificate: Optional[str] = None,
        tls_skip_verify: bool = None,
        proxies: Optional[Union[str, Dict[str, str]]] = None,
        timeout: Optional[int] = None,
        retries: Optional[Union[int, str, Dict]] = None,
    ) -> None:
        """
        Initialize the Vault client.

        Creates an unauthenticated HTTP client with proper headers configured.
        You must use an Authenticator to authenticate before making API calls.

        Args:
            vault_address (str): The Vault server address (e.g., "https://vault.example.com:8200")
            vault_namespace (str): Vault Enterprise namespace (use "root" for OSS Vault)
            ca_certificate (str): Path to an optional custom CA certificate file.
            tls_skip_verify (bool): When set to true, skip tls verification.
            timeout (int): Request timeout in seconds.
            retries: Retry configuration (int, dict, or string).

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
        self.vault_token = None
        self.timeout = int(timeout) if timeout is not None else None

        # Set up HTTP session with namespace header
        self.session = requests.Session()
        self.session.headers.update({"X-Vault-Namespace": vault_namespace})

        if retries is not None:
            retry_config = self._build_retry(retries)
            adapter = HTTPAdapter(max_retries=retry_config)
            self.session.mount('https://', adapter)
            self.session.mount('http://', adapter)

        logger.info("Initialized VaultClient for %s", vault_address)
        self.secrets = Secrets(self)
        self.acl_policies = VaultAclPolicies(self)
        self.namespaces = VaultNamespaces(self)

        tls_skip_verify_b = boolean(tls_skip_verify) if tls_skip_verify is not None else False
        if ca_certificate or tls_skip_verify_b:
            self.session.verify = not tls_skip_verify_b if tls_skip_verify_b else ca_certificate
        # add proxy configuration
        if proxies:
            self.session.proxies.update(self.read_proxies(proxies))

    def set_token(self, token: str) -> None:
        """
        Set or update the Vault token for the client.
        Args:
            token (str): The Vault client token (e.g., "hvs.abc123...")
        """
        self.vault_token = token
        self.session.headers.update({"X-Vault-Token": token})
        logger.debug("Token set for VaultClient")

    @staticmethod
    def read_proxies(proxies: Union[str, dict]) -> Dict[str, str]:
        """
        Parses and validates proxy configurations from multiple input formats.

        This method normalizes the `proxies` input into a standard dictionary.
        It supports three input types:
        1. A dictionary: Returned as-is.
        2. A JSON string: Parsed and validated to ensure only 'http' and 'https' keys exist.
        3. A plain string: Treated as a single URL to be used for both 'http' and 'https'.

        Args:
            proxies (Union[str, dict]): The proxy configuration.
                Can be a dictionary, a JSON-encoded string, or a single URL string.

        Returns:
            Dict[str, str]: A dictionary containing 'http' and/or 'https' proxy URLs.

        Raises:
            VaultConfigurationError: If the input is a JSON string containing keys
                other than 'http' or 'https'.

        Example:
            >>> VaultClient.read_proxies('http://proxy.example.com:8888')
            {'http': 'http://proxy.example.com:8888', 'https': 'http://proxy.example.com:8888'}

            >>> VaultClient.read_proxies('{"http": "http://10.10.1.10:1080"}')
            {'http': 'http://10.10.1.10:1080'}
        """
        if isinstance(proxies, dict):
            return proxies
        else:
            try:
                proxies = json.loads(proxies)
                for key in proxies.keys():
                    if key not in ("http", "https"):
                        raise VaultConfigurationError(
                            f"Unexpected proxy key '{key}', should be one of ['http', 'https']"
                        )
            except json.decoder.JSONDecodeError:
                proxies = {
                    'http': proxies,
                    'https': proxies,
                }
            return proxies

    @staticmethod
    def _build_retry(retries):
        if isinstance(retries, str):
            try:
                retries = int(retries)
            except ValueError:
                try:
                    retries = json.loads(retries)
                except json.JSONDecodeError:
                    raise VaultConfigurationError(
                        f'retries must be an integer or a JSON dictionary string, got: {retries!r}'
                    )
        if isinstance(retries, int):
            return Retry(total=retries)
        elif isinstance(retries, dict):
            try:
                return Retry(**retries)
            except TypeError as e:
                raise VaultConfigurationError(f'Invalid retries configuration: {e}') from e
        else:
            raise VaultConfigurationError(f'retries must be an integer or a dictionary, got {type(retries).__name__}')

    @property
    def token(self) -> Optional[str]:
        """
        Retrieve the current token

        Returns:
            (str): A token currently used by the client or None if not set.
        """
        return self.vault_token

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
        if self.timeout is not None and 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout
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
