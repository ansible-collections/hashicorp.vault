# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from unittest.mock import Mock, patch

import pytest
import requests

from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import (
    AppRoleAuthenticator,
    TokenAuthenticator,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultAppRoleLoginError,
    VaultConnectionError,
    VaultCredentialsError,
)


class TestTokenAuthenticator:
    """Tests for TokenAuthenticator class."""

    def test_authenticate_success(self):
        """Test successful token authentication."""
        mock_client = Mock()
        authenticator = TokenAuthenticator()

        authenticator.authenticate(mock_client, token="test-token-123")

        mock_client.set_token.assert_called_once_with("test-token-123")

    @pytest.mark.parametrize(
        "token_kwargs",
        [
            {},  # missing token - no token parameter provided
            {"token": ""},  # empty token
            {"token": None},  # None token
        ],
        ids=["missing", "empty", "none"],
    )
    def test_authenticate_invalid_token(self, token_kwargs):
        """Test token authentication fails with invalid token values."""
        mock_client = Mock()
        authenticator = TokenAuthenticator()

        with pytest.raises(
            VaultCredentialsError,
            match="Token is required for token authentication.",
        ):
            authenticator.authenticate(mock_client, **token_kwargs)


class TestAppRoleAuthenticator:
    """Tests for AppRoleAuthenticator class."""

    @pytest.fixture
    def mock_client(self):
        """Fixture providing a mock Vault client."""
        return Mock()

    @pytest.fixture
    def authenticator(self):
        """Fixture providing an AppRoleAuthenticator instance."""
        return AppRoleAuthenticator()

    @pytest.fixture
    def successful_mock_response(self):
        """Fixture providing a mock response for successful authentication."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        return mock_response

    @pytest.fixture
    def auth_params(self):
        """Fixture providing common authentication parameters."""
        return {
            "vault_address": "http://127.0.0.1:8200",
            "role_id": "role-123",
            "secret_id": "secret-456",
            "vault_namespace": "test-namespace",
        }

    @patch("requests.post")
    def test_authenticate_success(
        self, mock_post, mock_client, authenticator, successful_mock_response, auth_params
    ):
        """Test successful AppRole authentication."""
        successful_mock_response.json.return_value = {"auth": {"client_token": "hvs.123abc"}}
        mock_post.return_value = successful_mock_response

        authenticator.authenticate(mock_client, **auth_params)

        mock_client.set_token.assert_called_once_with("hvs.123abc")

    @patch("requests.post")
    def test_authenticate_custom_path(
        self, mock_post, mock_client, authenticator, successful_mock_response, auth_params
    ):
        """Test AppRole authentication with custom path."""
        successful_mock_response.json.return_value = {"auth": {"client_token": "hvs.custom"}}
        mock_post.return_value = successful_mock_response

        authenticator.authenticate(mock_client, **auth_params, approle_path="custom-approle")

        expected_url = "http://127.0.0.1:8200/v1/auth/custom-approle/login"
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == expected_url

        mock_client.set_token.assert_called_once_with("hvs.custom")

    @patch("requests.post")
    def test_authenticate_no_namespace(
        self, mock_post, mock_client, authenticator, successful_mock_response
    ):
        """Test AppRole authentication without namespace."""
        successful_mock_response.json.return_value = {"auth": {"client_token": "hvs.nonamespace"}}
        mock_post.return_value = successful_mock_response

        authenticator.authenticate(
            mock_client,
            vault_address="http://127.0.0.1:8200",
            role_id="role-123",
            secret_id="secret-456",
        )

        mock_client.set_token.assert_called_once_with("hvs.nonamespace")

    def test_authenticate_missing_role_id(self, mock_client, authenticator, auth_params):
        """Test AppRole authentication fails without role_id."""
        with pytest.raises(
            VaultCredentialsError,
            match="role_id and secret_id are required for AppRole authentication.",
        ):
            authenticator.authenticate(mock_client, **{**auth_params, "role_id": None})

    def test_authenticate_missing_secret_id(self, mock_client, authenticator, auth_params):
        """Test AppRole authentication fails without secret_id."""
        with pytest.raises(
            VaultCredentialsError,
            match="role_id and secret_id are required for AppRole authentication.",
        ):
            authenticator.authenticate(mock_client, **{**auth_params, "secret_id": None})

    def test_authenticate_missing_both_credentials(self, mock_client, authenticator, auth_params):
        """Test AppRole authentication fails without both role_id and secret_id."""
        with pytest.raises(
            VaultCredentialsError,
            match="role_id and secret_id are required for AppRole authentication.",
        ):
            authenticator.authenticate(
                mock_client, **{**auth_params, "role_id": None, "secret_id": None}
            )

    @patch("requests.post")
    def test_authenticate_login_failure(self, mock_post, mock_client, authenticator, auth_params):
        """Test AppRole authentication handles login failures."""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.text = "permission denied"

        # Mock raise_for_status to raise HTTPError for 401
        http_error = requests.HTTPError("401 Client Error")
        http_error.response = mock_response
        mock_response.raise_for_status.side_effect = http_error

        mock_post.return_value = mock_response

        with pytest.raises(
            VaultAppRoleLoginError, match="AppRole login failed: HTTP 401 - permission denied"
        ):
            authenticator.authenticate(mock_client, **auth_params)

    @patch("requests.post")
    def test_authenticate_network_error(self, mock_post, mock_client, authenticator, auth_params):
        """Test AppRole authentication handles network errors."""
        mock_post.side_effect = requests.ConnectionError("Connection timeout")

        with pytest.raises(
            VaultConnectionError, match="Network error during AppRole login: Connection timeout"
        ):
            authenticator.authenticate(mock_client, **auth_params)

    @patch("requests.post")
    def test_authenticate_invalid_response_format(
        self, mock_post, mock_client, authenticator, successful_mock_response, auth_params
    ):
        """Test AppRole authentication handles invalid response format."""
        successful_mock_response.json.return_value = {"invalid": "format"}
        mock_post.return_value = successful_mock_response

        with pytest.raises(VaultAppRoleLoginError, match="Invalid response format from Vault"):
            authenticator.authenticate(mock_client, **auth_params)
