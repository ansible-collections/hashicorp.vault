# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from abc import ABC, abstractmethod
from typing import Any, Dict, List

try:
    import requests
except ImportError as imp_exc:
    REQUESTS_IMPORT_ERROR = imp_exc
else:
    REQUESTS_IMPORT_ERROR = None


from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultAppRoleLoginError,
    VaultConnectionError,
    VaultCredentialsError,
    VaultPermissionError,
)


class Authenticator(ABC):
    """Abstract base class for all Vault authentication methods."""

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
    """Authenticator for direct token authentication."""

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
    """Authenticator for AppRole authentication."""

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
            raise VaultCredentialsError("role_id and secret_id are required for AppRole authentication.")

        token = self._login_with_approle(vault_address, role_id, secret_id, vault_namespace, approle_path)
        client.set_token(token)

    def _login_with_approle(self, vault_address, role_id, secret_id, vault_namespace=None, approle_path="approle"):
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
            VaultConnectionError: If network issues occur
        """
        login_url = f"{vault_address}/v1/auth/{approle_path}/login"
        payload = {"role_id": role_id, "secret_id": secret_id}
        headers = {}

        if vault_namespace:
            headers["X-Vault-Namespace"] = vault_namespace

        try:
            response = requests.post(login_url, json=payload, headers=headers, timeout=90)

            response.raise_for_status()

            auth_data = response.json()
            return auth_data["auth"]["client_token"]

        except requests.ConnectionError as e:
            raise VaultConnectionError(f"Network error during AppRole login: {e}")
        except requests.HTTPError as e:
            raise VaultAppRoleLoginError(
                f"AppRole login failed: HTTP {e.response.status_code} - {e.response.text}",
                status_code=e.response.status_code,
                response_text=e.response.text,
            )
        except (KeyError, ValueError) as e:
            raise VaultAppRoleLoginError(f"Invalid response format from Vault: {e}")


class VaultTokens:
    """
    Handles interactions with the Vault token auth method API (/auth/token/).

    """

    def __init__(self, client):
        """
        Initializes the Vault Tokens API client.

        Args:
            client (VaultClient): An authenticated instance of the main VaultClient.
        """
        self._client = client

    def lookup_token(self, token_id, fail_if_not_found=False) -> dict:
        """
        Return information about the token or the current token when token option is None.

        Args:
            token_id (str): A token to retrieve.
            fail_if_not_found (bool): Whether the function should raise an error when the token does not exist.

        Returns:
            dict: Information for the token.
        """
        path = "v1/auth/token/lookup"
        try:
            response = self._client._make_request("POST", path, json={"token": token_id})
            return response.get("data", {}) or {}
        except VaultPermissionError as e:
            # API return status_code=403 and response ['bad token'] when the token does not exist.
            if not fail_if_not_found and e.response_text == ["bad token"] and e.status_code == 403:
                return {}
            raise

    def renew_token(self, token_id, increment=None) -> dict:
        """
        Renews a lease associated with a token or the current token when token option is None.

        Args:
            token_id (str): The ID of the token to renew.
            increment (str): An optional requested increment duration.

        Returns:
            dict: Information for the token.
        """
        path = "v1/auth/token/renew"
        body: Dict[str, Any] = {"token": token_id}
        if increment is not None:
            body["increment"] = increment
        response = self._client._make_request("POST", path, json=body)
        return response.get("auth", {}) or {}

    def revoke_token(self, token_id) -> None:
        """
        Revokes a token and all child tokens.

        Args:
            token_id (str): The ID of the token to revoke.

        Returns:
            None
        """
        path = "v1/auth/token/revoke"
        self._client._make_request("POST", path, json={"token": token_id})

    def create_token(self, **kwargs: Any) -> Dict[str, Any]:
        """
        Creates a new token.

        Args:
            kwargs (dict): A dict of optional argument which can be provided to create the new token
                id        (str): The id of the client token.
                role_name (str): The name of the token role.
                policies (list): A list of policies for the token.
                meta     (dict): A dict of metadata values.
                no_parent (bool): When set to true, the token created will not have a parent.
                no_default_policy (bool): If true the default policy will not be contained in this token's policy set.
                renewable (bool): Set to false to disable the ability of the token to be renewed past its initial TTL.
                ttl       (str): The TTL period of the token.
                type      (str): The token type. Can be "batch" or "service".
                explicit_max_ttl (str): If set, the token will have an explicit max TTL set upon it.
                display_name (str): The display name of the token.
                num_uses  (int): The maximum uses for the given token.
                period    (str): If specified, the token will be periodic.
                entity_alias (str): The name of the entity alias to associate with during token creation.

        Returns:
            dict: A dict containing information of the created token.
        """
        path = "v1/auth/token/create"

        response = self._client._make_request("POST", path, json=kwargs)
        return response.get("auth", {}) or {}

    def list_accessors(self, token_id: str) -> List[str]:
        """
        List token accessors.

        Args:
            token_id (str): The ID of the token to list accessors.

        Returns:
            list: A list of token for the accessors.
        """
        path = "v1/auth/token/accessors"

        # save the original token value
        original_token = self._client.token
        self._client.set_token(token_id)  # Use the token provide as input to retrieve accessors
        try:
            response = self._client._make_request("LIST", path)
            # set back the token value
            return response.get("data", {}).get("keys", []) or []
        finally:
            self._client.set_token(original_token)
