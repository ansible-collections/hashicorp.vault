# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock, Mock, patch

import pytest
from requests.exceptions import HTTPError

from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import (
    AppRoleAuthenticator,
    TokenAuthenticator,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultClient
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultConfigurationError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)

MOCK_REQUESTS_SESSION = "ansible_collections.hashicorp.vault.plugins.module_utils.vault_client.requests.Session"


@pytest.fixture
def mock_session():
    """Fixture providing a mock session."""
    session = Mock()
    session.request = Mock()
    return session


@pytest.fixture
def mock_session_class(mock_session):
    """Fixture providing a mock session class that returns mock_session."""
    with patch(MOCK_REQUESTS_SESSION) as mock_class:
        mock_class.return_value = mock_session
        yield mock_class


class TestVaultClient:
    """Test VaultClient initialization and basic functionality."""

    def test_vault_client_init_success(self, mock_session_class, mock_session):
        """Test successful VaultClient initialization."""
        client = VaultClient(vault_address="https://vault.example.com:8200", vault_namespace="test-namespace")

        assert client.vault_address == "https://vault.example.com:8200"
        assert client.vault_namespace == "test-namespace"
        assert client.session == mock_session

        # Verify namespace header is set
        mock_session.headers.update.assert_called_once_with({"X-Vault-Namespace": "test-namespace"})

    @pytest.mark.parametrize(
        "vault_address",
        ["", None],
        ids=["empty", "none"],
    )
    def test_vault_client_missing_vault_address(self, vault_address):
        """Test VaultClient fails with invalid vault_address."""
        with pytest.raises(VaultConfigurationError, match="vault_address is required"):
            VaultClient(vault_address=vault_address, vault_namespace="test-namespace")

    @pytest.mark.parametrize(
        "vault_namespace",
        ["", None],
        ids=["empty", "none"],
    )
    def test_vault_client_missing_vault_namespace(self, vault_namespace):
        """Test VaultClient fails with invalid vault_namespace."""
        with pytest.raises(VaultConfigurationError, match="vault_namespace is required"):
            VaultClient(vault_address="https://vault.example.com:8200", vault_namespace=vault_namespace)

    def test_vault_client_set_token(self, mock_session_class, mock_session):
        """Test VaultClient set_token method."""
        client = VaultClient(vault_address="https://vault.example.com:8200", vault_namespace="test-namespace")

        mock_session.headers.update.reset_mock()

        client.set_token("hvs.test-token-123")

        mock_session.headers.update.assert_called_once_with({"X-Vault-Token": "hvs.test-token-123"})

    def test_vault_client_multiple_token_updates(self, mock_session_class, mock_session):
        """Test that set_token can be called multiple times."""
        client = VaultClient(vault_address="https://vault.example.com:8200", vault_namespace="test-namespace")

        mock_session.headers.update.reset_mock()

        client.set_token("hvs.first-token")
        client.set_token("hvs.second-token")
        client.set_token("hvs.third-token")

        assert mock_session.headers.update.call_count == 3

        mock_session.headers.update.assert_called_with({"X-Vault-Token": "hvs.third-token"})


class TestVaultClientIntegrationWithAuthenticators:
    """Test VaultClient working with concrete Authenticator instances."""

    def test_token_authentication_flow(self, mock_session_class, mock_session):
        """Test the complete token authentication flow."""
        client = VaultClient(vault_address="https://vault.example.com:8200", vault_namespace="root")

        authenticator = TokenAuthenticator()
        authenticator.authenticate(client, token="hvs.test-token")

        assert client.vault_address == "https://vault.example.com:8200"
        assert client.vault_namespace == "root"
        mock_session.headers.update.assert_any_call({"X-Vault-Token": "hvs.test-token"})

    @patch("requests.post")
    def test_approle_authentication_flow(self, mock_post, mock_session_class, mock_session):
        """Test the complete AppRole authentication flow."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"auth": {"client_token": "hvs.approle-token"}}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        client = VaultClient(vault_address="https://vault.example.com:8200", vault_namespace="root")

        authenticator = AppRoleAuthenticator()
        authenticator.authenticate(
            client,
            vault_address="https://vault.example.com:8200",
            role_id="test-role-id",
            secret_id="test-secret-id",
            vault_namespace="root",
        )

        assert client.vault_address == "https://vault.example.com:8200"
        assert client.vault_namespace == "root"
        mock_session.headers.update.assert_any_call({"X-Vault-Token": "hvs.approle-token"})

    def test_client_without_authentication(self, mock_session_class, mock_session):
        """Test that VaultClient can be created without immediate authentication."""
        client = VaultClient(vault_address="https://vault.example.com:8200", vault_namespace="test-namespace")

        assert client.vault_address == "https://vault.example.com:8200"
        assert client.vault_namespace == "test-namespace"

        mock_session.headers.update.assert_called_with({"X-Vault-Namespace": "test-namespace"})

    def test_multiple_authentication_methods(self, mock_session_class, mock_session):
        """Test that different authenticators can be used with the same client."""
        client = VaultClient(vault_address="https://vault.example.com:8200", vault_namespace="test-namespace")

        mock_session.headers.update.reset_mock()

        token_auth = TokenAuthenticator()
        token_auth.authenticate(client, token="hvs.token-123")

        token_auth2 = TokenAuthenticator()
        token_auth2.authenticate(client, token="hvs.token-456")

        assert mock_session.headers.update.call_count == 2
        mock_session.headers.update.assert_called_with({"X-Vault-Token": "hvs.token-456"})


class TestVaultClientMakeRequest:
    """Test method _make_request() from VaultClient."""

    def test_make_request_success(self, mock_session_class, mock_session):
        """Test _make_request() success."""
        client = VaultClient(vault_address="https://vault.example.com:8200", vault_namespace="test-namespace")
        response = MagicMock()
        mock_session.request = MagicMock()
        mock_session.request.return_value = response
        path = "some/path"
        client._make_request("GET", path)
        expected_url = "https://vault.example.com:8200/some/path"
        client.session.request.assert_called_once_with("GET", expected_url)

    @pytest.mark.parametrize(
        "status_code,expected_exception",
        [
            (403, VaultPermissionError),
            (404, VaultSecretNotFoundError),
            (500, VaultApiError),
            (400, VaultApiError),
        ],
    )
    def test_make_request_permission_denied_403(
        self, mock_session_class, mock_session, status_code, expected_exception
    ):
        """Test _make_request() request error."""
        client = VaultClient(vault_address="https://vault.example.com:8200", vault_namespace="test-namespace")
        response = MagicMock(status_code=status_code)
        response.json.return_value = {"errors": ["error while making request"]}
        response.raise_for_status.side_effect = HTTPError(response=response)
        mock_session.request = MagicMock()
        mock_session.request.return_value = response
        path = "some/path"
        with pytest.raises(expected_exception):
            client._make_request("GET", path)
        expected_url = "https://vault.example.com:8200/some/path"
        client.session.request.assert_called_once_with("GET", expected_url)
