# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import logging
import os


try:
    import requests
except ImportError as imp_exc:
    REQUESTS_IMPORT_ERROR = imp_exc
else:
    REQUESTS_IMPORT_ERROR = None

from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import (
    Authenticator,
    VaultConfigurationError,
)


logger = logging.getLogger(__name__)


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

    def __init__(self, auth_method: str = None) -> None:
        """
        Initialize the Vault client.

        Args:
            auth_method (str, optional): The authentication method to use.
                                       If not provided, defaults to token authentication.
        """
        vault_address = os.environ.get("VAULT_ADDR")
        vault_namespace = os.environ.get("VAULT_NAMESPACE")
        approle_path = os.environ.get("VAULT_APPROLE_PATH", "approle")

        if not vault_address:
            raise VaultConfigurationError("VAULT_ADDR environment variable is required")
        if not vault_namespace:
            raise VaultConfigurationError("VAULT_NAMESPACE environment variable is required")

        self.vault_address = vault_address
        self.vault_namespace = vault_namespace

        self.session = requests.Session()
        self.session.headers.update({"X-Vault-Namespace": vault_namespace})

        # Default to token authentication if no method is provided
        if not auth_method:
            auth_method = "token"

        authenticator = Authenticator(method=auth_method)
        authenticator.authenticate(self, vault_address, vault_namespace, approle_path)

        logger.info(
            "Successfully authenticated with Vault at %s using %s method",
            vault_address,
            auth_method,
        )

    def set_token(self, token: str) -> None:
        """
        Set or update the Vault token for the client.

        Args:
            token (str): The Vault client token.
        """
        self.session.headers.update({"X-Vault-Token": token})
