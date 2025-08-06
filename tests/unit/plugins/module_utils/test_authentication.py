# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import os

from unittest.mock import Mock, patch

import pytest
import requests

from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import (
    AppRoleAuthenticator,
    Authenticator,
    TokenAuthenticator,
    VaultAppRoleLoginError,
    VaultCredentialsError,
)


class TestTokenAuthenticator:
    """Tests for TokenAuthenticator class."""

    @patch.dict(os.environ, {"VAULT_TOKEN": "test-token-123"}, clear=True)
    def test_authenticate_success(self):
        """Test successful token authentication."""
        mock_client = Mock()
        authenticator = TokenAuthenticator()

        authenticator.authenticate(mock_client)

        mock_client.set_token.assert_called_once_with("test-token-123")

    @patch.dict(os.environ, {}, clear=True)
    def test_authenticate_missing_token(self):
        """Test token authentication fails when VAULT_TOKEN is not set."""
        mock_client = Mock()
        authenticator = TokenAuthenticator()

        with pytest.raises(
            VaultCredentialsError,
            match="VAULT_TOKEN environment variable is required for token authentication",
        ):
            authenticator.authenticate(mock_client)


class TestAppRoleAuthenticator:
    """Tests for AppRoleAuthenticator class."""

    @patch.dict(
        os.environ,
        {"VAULT_APPROLE_ROLE_ID": "role-123", "VAULT_APPROLE_SECRET_ID": "secret-456"},
        clear=True,
    )
    @patch("requests.post")
    def test_authenticate_success(self, mock_post):
        """Test successful AppRole authentication."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"auth": {"client_token": "hvs.123abc"}}
        mock_post.return_value = mock_response

        mock_client = Mock()
        authenticator = AppRoleAuthenticator()

        authenticator.authenticate(mock_client, "http://127.0.0.1:8200", "test-namespace")

        mock_client.set_token.assert_called_once_with("hvs.123abc")
        mock_post.assert_called_once_with(
            "http://127.0.0.1:8200/v1/auth/approle/login",
            json={"role_id": "role-123", "secret_id": "secret-456"},
            headers={"X-Vault-Namespace": "test-namespace"},
        )

    @patch.dict(
        os.environ,
        {"VAULT_APPROLE_ROLE_ID": "role-123", "VAULT_APPROLE_SECRET_ID": "secret-456"},
        clear=True,
    )
    @patch("requests.post")
    def test_authenticate_custom_path(self, mock_post):
        """Test AppRole authentication with custom path."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"auth": {"client_token": "hvs.456def"}}
        mock_post.return_value = mock_response

        mock_client = Mock()
        authenticator = AppRoleAuthenticator()

        authenticator.authenticate(
            mock_client, "http://127.0.0.1:8200", "test-namespace", "custom-approle"
        )

        mock_client.set_token.assert_called_once_with("hvs.456def")
        mock_post.assert_called_once_with(
            "http://127.0.0.1:8200/v1/auth/custom-approle/login",
            json={"role_id": "role-123", "secret_id": "secret-456"},
            headers={"X-Vault-Namespace": "test-namespace"},
        )

    @patch.dict(
        os.environ,
        {"VAULT_APPROLE_ROLE_ID": "role-123", "VAULT_APPROLE_SECRET_ID": "secret-456"},
        clear=True,
    )
    @patch("requests.post")
    def test_authenticate_no_namespace(self, mock_post):
        """Test AppRole authentication without namespace."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"auth": {"client_token": "hvs.789ghi"}}
        mock_post.return_value = mock_response

        mock_client = Mock()
        authenticator = AppRoleAuthenticator()

        authenticator.authenticate(mock_client, "http://127.0.0.1:8200")

        mock_client.set_token.assert_called_once_with("hvs.789ghi")
        mock_post.assert_called_once_with(
            "http://127.0.0.1:8200/v1/auth/approle/login",
            json={"role_id": "role-123", "secret_id": "secret-456"},
            headers={},
        )

    @patch.dict(os.environ, {"VAULT_APPROLE_ROLE_ID": "role-123"}, clear=True)
    def test_authenticate_missing_secret_id(self):
        """Test AppRole authentication fails when secret_id is missing."""
        mock_client = Mock()
        authenticator = AppRoleAuthenticator()

        with pytest.raises(
            VaultCredentialsError,
            match="VAULT_APPROLE_ROLE_ID and VAULT_APPROLE_SECRET_ID environment variables are required",
        ):
            authenticator.authenticate(mock_client, "http://127.0.0.1:8200", "test-namespace")

    @patch.dict(os.environ, {"VAULT_APPROLE_SECRET_ID": "secret-456"}, clear=True)
    def test_authenticate_missing_role_id(self):
        """Test AppRole authentication fails when role_id is missing."""
        mock_client = Mock()
        authenticator = AppRoleAuthenticator()

        with pytest.raises(
            VaultCredentialsError,
            match="VAULT_APPROLE_ROLE_ID and VAULT_APPROLE_SECRET_ID environment variables are required",
        ):
            authenticator.authenticate(mock_client, "http://127.0.0.1:8200", "test-namespace")

    @patch.dict(
        os.environ,
        {"VAULT_APPROLE_ROLE_ID": "role-123", "VAULT_APPROLE_SECRET_ID": "secret-456"},
        clear=True,
    )
    @patch("requests.post")
    def test_authenticate_login_failure(self, mock_post):
        """Test AppRole authentication handles login failures."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "permission denied"
        mock_post.return_value = mock_response

        mock_client = Mock()
        authenticator = AppRoleAuthenticator()

        with pytest.raises(
            VaultAppRoleLoginError, match="AppRole login failed: HTTP 401 - permission denied"
        ):
            authenticator.authenticate(mock_client, "http://127.0.0.1:8200", "test-namespace")

    @patch.dict(
        os.environ,
        {"VAULT_APPROLE_ROLE_ID": "role-123", "VAULT_APPROLE_SECRET_ID": "secret-456"},
        clear=True,
    )
    @patch("requests.post")
    def test_authenticate_network_error(self, mock_post):
        """Test AppRole authentication handles network errors."""
        mock_post.side_effect = requests.ConnectionError("Connection timeout")

        mock_client = Mock()
        authenticator = AppRoleAuthenticator()

        with pytest.raises(
            VaultAppRoleLoginError, match="Network error during AppRole login: Connection timeout"
        ):
            authenticator.authenticate(mock_client, "http://127.0.0.1:8200", "test-namespace")


class TestAuthenticator:
    """Tests for the Authenticator factory class."""

    @patch.dict(os.environ, {"VAULT_TOKEN": "test-token-123"}, clear=True)
    def test_token_method(self):
        """Test Authenticator with token method."""
        mock_client = Mock()
        authenticator = Authenticator(method="token")

        authenticator.authenticate(mock_client)

        mock_client.set_token.assert_called_once_with("test-token-123")

    @patch.dict(
        os.environ,
        {"VAULT_APPROLE_ROLE_ID": "role-123", "VAULT_APPROLE_SECRET_ID": "secret-456"},
        clear=True,
    )
    @patch("requests.post")
    def test_approle_method(self, mock_post):
        """Test Authenticator with approle method."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"auth": {"client_token": "hvs.123abc"}}
        mock_post.return_value = mock_response

        mock_client = Mock()
        authenticator = Authenticator(method="approle")

        authenticator.authenticate(mock_client, "http://127.0.0.1:8200", "test-namespace")

        mock_client.set_token.assert_called_once_with("hvs.123abc")

    def test_invalid_method(self):
        """Test Authenticator raises error for unsupported method."""
        with pytest.raises(VaultCredentialsError, match="Unsupported authentication method: ldap"):
            Authenticator(method="ldap")
