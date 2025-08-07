# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
HashiCorp Vault Authentication Methods.

Example Usage:
    ```python
    from vault_client import VaultClient
    from authentication import TokenAuthenticator, AppRoleAuthenticator

    # Create client
    client = VaultClient("https://vault.example.com:8200", "root")

    # Authenticate with token
    auth = TokenAuthenticator()
    auth.authenticate(client, token="hvs.abc123...")

    # Or authenticate with AppRole
    auth = AppRoleAuthenticator()
    auth.authenticate(
        client,
        vault_address="https://vault.example.com:8200",
        role_id="role-123",
        secret_id="secret-456"
    )
    ```
"""

from abc import ABC, abstractmethod


try:
    import requests
except ImportError as imp_exc:
    REQUESTS_IMPORT_ERROR = imp_exc
else:
    REQUESTS_IMPORT_ERROR = None


class VaultError(Exception):
    """Base exception for all Vault-related errors."""

    pass


class VaultConfigurationError(VaultError):
    """
    Raised when Vault configuration is invalid.

    Examples:
        - Missing required arguments
        - Invalid URLs or paths
        - Misconfigured authentication parameters
    """

    pass


class VaultCredentialsError(VaultError):
    """
    Raised when there are credential issues.

    Examples:
        - Missing credentials (role_id, secret_id, token)
        - Invalid credential format
        - Authentication method failures
    """

    pass


class VaultAppRoleLoginError(VaultError):
    """
    Raised when AppRole login fails.

    This includes both HTTP errors (401, 403, 500) and network errors.
    """

    def __init__(self, message: str, status_code: int = None):
        """
        Initialize AppRole login error.

        Args:
            message (str): Error description
            status_code (int, optional): HTTP status code if applicable
        """
        super().__init__(message)
        self.status_code = status_code


class Authenticator(ABC):
    """
    Abstract base class for all Vault authentication methods.
    """

    @abstractmethod
    def authenticate(self, client, **kwargs):
        """
        Authenticate the client using this authentication method.

        Args:
            client: VaultClient instance to authenticate
            **kwargs: Method-specific authentication parameters

        Raises:
            VaultCredentialsError: If authentication fails due to credential issues
            VaultConfigurationError: If authentication fails due to configuration issues
        """
        pass


class TokenAuthenticator(Authenticator):
    """
    Authenticator for direct token authentication.
    """

    def authenticate(self, client, *, token=None):
        """
        Authenticate the client with a token.

        Args:
            client: VaultClient instance to authenticate
            token (str): The Vault client token

        Raises:
            VaultCredentialsError: If token is missing or empty
        """
        if not token:
            raise VaultCredentialsError("Token is required for token authentication.")
        client.set_token(token)


class AppRoleAuthenticator(Authenticator):
    """
    Authenticator for AppRole authentication.
    """

    def authenticate(
        self,
        client,
        *,
        vault_address,
        role_id,
        secret_id,
        vault_namespace=None,
        approle_path="approle",
    ):
        """
        Authenticate the client using AppRole credentials.

        Args:
            client: VaultClient instance to authenticate
            vault_address (str): Vault server address (e.g., "https://vault.example.com:8200")
            role_id (str): AppRole role ID
            secret_id (str): AppRole secret ID
            vault_namespace (str, optional): Vault namespace for Enterprise
            approle_path (str, optional): Custom AppRole mount path (default: "approle")

        Raises:
            VaultCredentialsError: If role_id or secret_id are missing
            VaultAppRoleLoginError: If authentication fails
        """
        if REQUESTS_IMPORT_ERROR:
            raise ImportError(
                "The 'requests' library is required for AppRole authentication"
            ) from REQUESTS_IMPORT_ERROR

        if not role_id or not secret_id:
            raise VaultCredentialsError(
                "role_id and secret_id are required for AppRole authentication."
            )

        token = self._login_with_approle(
            vault_address, role_id, secret_id, vault_namespace, approle_path
        )
        client.set_token(token)

    def _login_with_approle(
        self, vault_address, role_id, secret_id, vault_namespace=None, approle_path="approle"
    ):
        """
        Login to Vault using AppRole credentials.

        Args:
            vault_address (str): Vault server address
            role_id (str): AppRole role ID
            secret_id (str): AppRole secret ID
            vault_namespace (str, optional): Vault namespace
            approle_path (str, optional): AppRole mount path

        Returns:
            str: Vault client token

        Raises:
            VaultAppRoleLoginError: If login fails
        """
        login_url = f"{vault_address}/v1/auth/{approle_path}/login"
        payload = {"role_id": role_id, "secret_id": secret_id}
        headers = {}

        if vault_namespace:
            headers["X-Vault-Namespace"] = vault_namespace

        try:
            response = requests.post(login_url, json=payload, headers=headers)

            if response.status_code != 200:
                raise VaultAppRoleLoginError(
                    f"AppRole login failed: HTTP {response.status_code} - {response.text}",
                    status_code=response.status_code,
                )

            auth_data = response.json()
            return auth_data["auth"]["client_token"]

        except requests.ConnectionError as e:
            raise VaultAppRoleLoginError(f"Network error during AppRole login: {e}")
        except (KeyError, ValueError) as e:
            raise VaultAppRoleLoginError(f"Invalid response format from Vault: {e}")
