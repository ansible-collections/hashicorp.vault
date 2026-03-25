# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from abc import ABC, abstractmethod
from typing import Optional

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
    VaultLoginError,
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


class VaultLogin:
    """
    Handles vault login for different auth method.

    """

    LOGIN_CONFIG = {
        "alicloud": ["role", "identity_request_url", "identity_request_headers"],
        "approle": ["role_id", "secret_id"],
        "aws": [],
        "azure": ["role", "jwt"],
        "cf": ["role", "cf_instance_cert", "signing_time", "signature"],
        "github": ["token"],
        "gcp": ["role", "jwt"],
        "jwt": ["jwt"],
        "kerberos": [],  # Specific
        "kubernetes": ["role", "jwt"],
        "ldap": ["username", "password"],
        "oci": ["role"],
        "okta": ["username", "password"],
        "radius": ["username", "password"],
        "saml": ["client_verifier", "token_poll_id"],
        "scep": [],
        "spiffe": [],
        "cert": [],
        "userpass": ["username", "password"],
    }

    def __init__(
        self,
        vault_address: str,
        auth_method: str,
        vault_namespace: Optional[str] = None,
        mount_path: Optional[str] = None,
    ) -> None:
        """
        Initializes the Vault Login API client.

        Args:
            vault_address (str): The Vault server address
            auth_method (str): The auth method (e.g., approle, alicloud, aws, azure, etc).
            vault_namespace (str, optional): Vault namespace for Enterprise
            custom_mount_path: Custom path for the auth method. If omitted, the auth method name is used as the mount point

        Returns:
          None
        """
        if REQUESTS_IMPORT_ERROR:
            raise ImportError("The 'requests' library is required to fetch a token.") from REQUESTS_IMPORT_ERROR

        self._vault_address = vault_address
        self._auth_method = auth_method.lower()
        self._namespace = vault_namespace
        self._mount_path = mount_path if mount_path is not None else auth_method

    def validate_login_params(self, **kwargs: dict) -> None:
        """
        Validate that login parameters are as expected

        Args:
            auth_method (str): The authentication method
            kwargs (dict, optional): The optional arguments specific to the auth method

        Raises
            VaultCredentialsError: If required parameters are missing
        """
        for param in self.LOGIN_CONFIG.get(self._auth_method, {}):
            if param not in kwargs:
                raise VaultLoginError(f"Missing required parameter {param!r} for {self._auth_method!r} login.")

    def login(self, **kwargs: dict) -> tuple[str, dict]:
        """
        Fetch a token.

        Args:
            kwargs (dict, optional): The optional arguments specific to the auth method.

        Returns
            (str, dict): The client token and the dict representing the result of the login request
        """
        login_url = f"{self._vault_address}/v1/auth/{self._mount_path}/login"
        if self._auth_method in ("ldap", "okta", "userpass"):
            username = kwargs.pop("username")
            login_url += "/" + username
        elif self._auth_method == "oci":
            role = kwargs.pop("role")
            login_url += "/" + role
        elif self._auth_method == "saml":
            login_url = f"{self._vault_address}/v1/auth/{self._mount_path}/token"
        payload = {key: kwargs.get(key) for key in kwargs}
        headers = {}

        if self._namespace:
            headers["X-Vault-Namespace"] = self._namespace

        try:
            response = requests.post(login_url, json=payload, headers=headers, timeout=90)
            response.raise_for_status()
            raw_response = response.json()

            auth_data = raw_response.get("auth")
            # The OCI login operation uses the 'token' key for the client token
            client_token = auth_data.get("token") or auth_data.get("client_token")
            return client_token, auth_data

        except requests.ConnectionError as e:
            raise VaultConnectionError(f"Network error during login: {e}")
        except requests.HTTPError as e:
            raise VaultLoginError(
                f"login failed: HTTP {e.response.status_code} - {e.response.text}",
                status_code=e.response.status_code,
                response_text=e.response.text,
            )
        except (KeyError, ValueError) as e:
            raise VaultLoginError(f"Invalid response format from Vault: {e}")
