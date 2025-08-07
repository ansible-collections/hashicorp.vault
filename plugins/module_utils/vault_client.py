# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import logging


try:
    import requests
except ImportError as imp_exc:
    REQUESTS_IMPORT_ERROR = imp_exc
else:
    REQUESTS_IMPORT_ERROR = None

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultConfigurationError,
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
            raise ImportError(
                "The 'requests' library is required for VaultClient"
            ) from REQUESTS_IMPORT_ERROR

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

    def set_token(self, token: str) -> None:
        """
        Set or update the Vault token for the client.
        Args:
            token (str): The Vault client token (e.g., "hvs.abc123...")
        """
        self.session.headers.update({"X-Vault-Token": token})
        logger.debug("Token set for VaultClient")
