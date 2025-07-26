# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import os
import requests


def get_vault_token(vault_address: str, vault_namespace) -> str:
    """
    Retrieves a Vault token using environment variables.
    - If VAULT_TOKEN is set, use it directly.
    - If VAULT_APPROLE_ROLE_ID and VAULT_APPROLE_SECRET_ID are set, perform AppRole login.

    Args:
        vault_address (str): The Vault server address (e.g., http://127.0.0.1:8200).
        vault_namespace (str, optional): The Vault namespace to use.

    Returns:
        str: A Vault client token.

    Raises:
        Exception: If neither VAULT_TOKEN nor AppRole credentials are found.
    """
    token = os.environ.get("VAULT_TOKEN")
    role_id = os.environ.get("VAULT_APPROLE_ROLE_ID")
    secret_id = os.environ.get("VAULT_APPROLE_SECRET_ID")

    if token and (role_id or secret_id):
        raise Exception("VAULT_TOKEN and VAULT_APPROLE_* are mutually exclusive.")

    if token:
        return token
    elif role_id and secret_id:
        return _login_with_approle(vault_address, role_id, secret_id, vault_namespace)
    else:
        raise Exception("No Vault token or AppRole credentials found in environment variables.")


def _login_with_approle(
    vault_address: str, role_id: str, secret_id: str, vault_namespace: str
) -> str:
    """
    Logs into Vault using AppRole and retrieves a client token.

    The token returned will respect the token_ttl, renewable flag, and token_max_ttl set in the AppRole configuration.

    Args:
        vault_address (str): The Vault server address.
        role_id (str): The AppRole role_id.
        secret_id (str): The AppRole secret_id.
        vault_namespace (str): The Vault namespace to use for login.

    Returns:
        str: The Vault client token retrieved from login.

    Raises:
        Exception: If login fails.
    """
    api_url = f"{vault_address.rstrip('/')}/v1/auth/approle/login"
    headers = {"X-Vault-Namespace": vault_namespace}

    response = requests.post(
        api_url, json={"role_id": role_id, "secret_id": secret_id}, headers=headers
    )
    if response.status_code != 200:
        raise Exception(f"AppRole login failed: HTTP {response.status_code} - {response.text}")
    return response.json()["auth"]["client_token"]
