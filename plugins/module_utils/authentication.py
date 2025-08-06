# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import os


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
    """Raised when Vault configuration is invalid (missing env vars, etc.)."""

    pass


class VaultCredentialsError(VaultError):
    """Raised when there are credential issues (missing, conflicting, invalid)."""

    pass


class VaultAppRoleLoginError(VaultError):
    """Raised when AppRole login fails."""

    def __init__(self, message: str, status_code: int = None):
        super().__init__(message)
        self.status_code = status_code


class TokenAuthenticator:
    """Authenticator for direct token authentication."""

    def authenticate(self, client, *args, **kwargs):
        """Authenticate using a pre-existing token."""
        token = os.environ.get("VAULT_TOKEN")
        if not token:
            raise VaultCredentialsError(
                "VAULT_TOKEN environment variable is required for token authentication."
            )
        client.set_token(token)


class AppRoleAuthenticator:
    """Authenticator for AppRole authentication."""

    def authenticate(
        self, client, vault_address, vault_namespace=None, approle_path="approle", *args, **kwargs
    ):
        """Authenticate using AppRole credentials."""
        role_id = os.environ.get("VAULT_APPROLE_ROLE_ID")
        secret_id = os.environ.get("VAULT_APPROLE_SECRET_ID")

        if not role_id or not secret_id:
            raise VaultCredentialsError(
                "VAULT_APPROLE_ROLE_ID and VAULT_APPROLE_SECRET_ID environment variables are required for AppRole authentication."
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
        """Logs into Vault using AppRole and retrieves a client token."""
        api_url = f"{vault_address.rstrip('/')}/v1/auth/{approle_path}/login"

        # Build headers conditionally
        headers = {}
        if vault_namespace:
            headers["X-Vault-Namespace"] = vault_namespace

        try:
            response = requests.post(
                api_url, json={"role_id": role_id, "secret_id": secret_id}, headers=headers
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
    """Factory class for managing different Vault authentication methods."""

    def __init__(self, method):
        authenticators = {
            "approle": AppRoleAuthenticator,
            "token": TokenAuthenticator,
        }
        if method not in authenticators:
            raise VaultCredentialsError(f"Unsupported authentication method: {method}")
        self._authenticator = authenticators[method]()

    def authenticate(self, client, *args, **kwargs):
        return self._authenticator.authenticate(client, *args, **kwargs)
