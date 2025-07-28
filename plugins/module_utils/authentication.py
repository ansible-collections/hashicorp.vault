# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import os
import requests


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


def get_vault_token(
    vault_address: str, vault_namespace: str = None, approle_path: str = "approle"
) -> str:
    """
    Retrieves a Vault token using environment variables.
    - If VAULT_TOKEN is set, use it directly.
    - If VAULT_APPROLE_ROLE_ID and VAULT_APPROLE_SECRET_ID are set, perform AppRole login.

    Args:
        vault_address (str): The Vault server address (e.g., http://127.0.0.1:8200).
        vault_namespace (str, optional): The Vault namespace to use.
        approle_path (str, optional): The AppRole mount path. Defaults to "approle".

    Returns:
        str: A Vault client token.

    Raises:
        VaultCredentialsError: If credentials are missing or conflicting.
        VaultAppRoleLoginError: If AppRole login fails.
    """
    token = os.environ.get("VAULT_TOKEN")
    role_id = os.environ.get("VAULT_APPROLE_ROLE_ID")
    secret_id = os.environ.get("VAULT_APPROLE_SECRET_ID")

    if token and (role_id or secret_id):
        raise VaultCredentialsError("VAULT_TOKEN and VAULT_APPROLE_* are mutually exclusive.")

    if token:
        return token
    elif role_id and secret_id:
        return _login_with_approle(vault_address, role_id, secret_id, vault_namespace, approle_path)
    else:
        raise VaultCredentialsError(
            "No Vault token or AppRole credentials found in environment variables."
        )


def _login_with_approle(
    vault_address: str,
    role_id: str,
    secret_id: str,
    vault_namespace: str = None,
    approle_path: str = "approle",
) -> str:
    """
    Logs into Vault using AppRole and retrieves a client token.

    Args:
        vault_address (str): The Vault server address.
        role_id (str): The AppRole role_id.
        secret_id (str): The AppRole secret_id.
        vault_namespace (str, optional): The Vault namespace to use for login.
        approle_path (str, optional): The AppRole mount path. Defaults to "approle".

    Returns:
        str: The Vault client token retrieved from login.

    Raises:
        VaultAppRoleLoginError: If login fails.
    """
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
