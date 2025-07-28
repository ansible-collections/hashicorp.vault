# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import os
import requests

from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import (
    get_vault_token,
    VaultConfigurationError,
)


class VaultClient:
    """
    A client for interacting with the HashiCorp Vault HTTP API.

    Environment Variables:
        - VAULT_ADDR (required): The Vault server address (e.g., http://127.0.0.1:8200)
        - VAULT_NAMESPACE (required): Vault Enterprise namespace
        - VAULT_TOKEN: (optional) Vault token for direct authentication
        - VAULT_APPROLE_ROLE_ID and VAULT_APPROLE_SECRET_ID: (optional) AppRole credentials
        - VAULT_APPROLE_PATH: (optional) AppRole mount path, defaults to "approle"

    Raises:
        VaultConfigurationError: If required environment variables are missing.
        VaultCredentialsError: If authentication credentials are invalid.
        VaultAppRoleLoginError: If AppRole login fails.
    """

    def __init__(self) -> None:
        vault_address = os.environ.get("VAULT_ADDR")
        vault_namespace = os.environ.get("VAULT_NAMESPACE")
        approle_path = os.environ.get("VAULT_APPROLE_PATH", "approle")

        if not vault_address:
            raise VaultConfigurationError("VAULT_ADDR environment variable is required")
        if not vault_namespace:
            raise VaultConfigurationError("VAULT_NAMESPACE environment variable is required")

        self.session = requests.Session()
        self.session.headers.update(
            {
                "X-Vault-Token": get_vault_token(vault_address, vault_namespace, approle_path),
                "X-Vault-Namespace": vault_namespace,
            }
        )
        print("Logged in to Vault!")
