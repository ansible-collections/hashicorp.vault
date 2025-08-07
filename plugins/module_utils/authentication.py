# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
HashiCorp Vault Authentication Methods.

This module provides a clean, extensible authentication system for Vault.
It uses a pluggable architecture where authentication methods are implemented
as separate classes and selected via the Authenticator factory.

The design allows for easy addition of new authentication methods without
modifying existing code.

Example Usage:
    ```python
    from vault_client import VaultClient
    from authentication import Authenticator

    # Create client
    client = VaultClient("https://vault.example.com:8200", "root")

    # Authenticate with token
    auth = Authenticator(method="token")
    auth.authenticate(client, token="hvs.abc123...")

    # Or authenticate with AppRole
    auth = Authenticator(method="approle")
    auth.authenticate(
        client,
        vault_address="https://vault.example.com:8200",
        role_id="role-123",
        secret_id="secret-456"
    )
    ```
"""

import requests


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
        - Conflicting authentication methods
        - Invalid credential format
        - Unsupported authentication method
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


class TokenAuthenticator:
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


class AppRoleAuthenticator:
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
        **kwargs,
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
            **kwargs: Ignored (for compatibility)

        Raises:
            VaultCredentialsError: If role_id or secret_id are missing
            VaultAppRoleLoginError: If authentication fails
        """
        if not role_id or not secret_id:
            raise VaultCredentialsError(
                "role_id and secret_id are required for AppRole authentication."
            )

        token = self._login_with_approle(
            vault_address, role_id, secret_id, vault_namespace, approle_path
        )
        client.set_token(token)

    def _login_with_approle(
        self,
        vault_address: str,
        role_id: str,
        secret_id: str,
        vault_namespace: str = None,
        approle_path: str = "approle",
    ) -> str:
        """
        Perform the actual AppRole login API call.

        Args:
            vault_address (str): Vault server address
            role_id (str): AppRole role ID
            secret_id (str): AppRole secret ID
            vault_namespace (str, optional): Vault namespace
            approle_path (str): AppRole mount path

        Returns:
            str: Client token from successful authentication

        Raises:
            VaultAppRoleLoginError: If login fails (HTTP error or network error)
        """
        api_url = f"{vault_address.rstrip('/')}/v1/auth/{approle_path}/login"

        headers = {}
        if vault_namespace:
            headers["X-Vault-Namespace"] = vault_namespace

        try:
            response = requests.post(
                api_url,
                json={"role_id": role_id, "secret_id": secret_id},
                headers=headers,
                timeout=10,
            )
            if response.status_code != 200:
                raise VaultAppRoleLoginError(
                    f"AppRole login failed: HTTP {response.status_code} - {response.text}",
                    status_code=response.status_code,
                )
            return response.json()["auth"]["client_token"]
        except requests.RequestException as e:
            raise VaultAppRoleLoginError(f"Network error during AppRole login: {str(e)}") from e


class Authenticator:
    """
    Factory class for selecting and using authentication methods.
    """

    def __init__(self, method: str):
        """
        Initialize authenticator for the specified method.

        Args:
            method (str): Authentication method ("token" or "approle")

        Raises:
            VaultCredentialsError: If method is not supported
        """
        authenticators = {
            "token": TokenAuthenticator,
            "approle": AppRoleAuthenticator,
        }

        if method not in authenticators:
            supported_methods = ", ".join(authenticators.keys())
            raise VaultCredentialsError(
                f"Unsupported authentication method: '{method}'. "
                f"Supported methods: {supported_methods}"
            )

        self._authenticator = authenticators[method]()

    def authenticate(self, client, **kwargs):
        """
        Authenticate the client using the configured method.

        Args:
            client: VaultClient instance to authenticate
            **kwargs: Method-specific authentication parameters

        The required kwargs depend on the authentication method:

        For "token":
            - token (str): The Vault client token

        For "approle":
            - vault_address (str): Vault server address
            - role_id (str): AppRole role ID
            - secret_id (str): AppRole secret ID
            - vault_namespace (str, optional): Vault namespace
            - approle_path (str, optional): Custom AppRole mount path

        Raises:
            VaultCredentialsError: If required parameters are missing
            VaultAppRoleLoginError: If AppRole authentication fails
        """
        return self._authenticator.authenticate(client, **kwargs)
