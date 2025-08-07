# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from unittest.mock import Mock, patch

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import (
    Authenticator,
    VaultConfigurationError,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultClient


MOCK_REQUESTS_SESSION = (
    "ansible_collections.hashicorp.vault.plugins.module_utils.vault_client.requests.Session"
)


class TestVaultClient:
    """Test VaultClient initialization and basic functionality."""

    @patch(MOCK_REQUESTS_SESSION)
    def test_vault_client_init_success(self, mock_session_class):
        """Test successful VaultClient initialization."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        client = VaultClient(
            vault_address="https://vault.example.com:8200", vault_namespace="test-namespace"
        )

        assert client.vault_address == "https://vault.example.com:8200"
        assert client.vault_namespace == "test-namespace"
        assert client.session == mock_session

        # Verify namespace header is set
        mock_session.headers.update.assert_called_once_with({"X-Vault-Namespace": "test-namespace"})

    def test_vault_client_missing_vault_address(self):
        """Test VaultClient fails with empty vault_address."""
        with pytest.raises(VaultConfigurationError, match="vault_address is required"):
            VaultClient(vault_address="", vault_namespace="test-namespace")

        with pytest.raises(VaultConfigurationError, match="vault_address is required"):
            VaultClient(vault_address=None, vault_namespace="test-namespace")

    def test_vault_client_missing_vault_namespace(self):
        """Test VaultClient fails with empty vault_namespace."""
        with pytest.raises(VaultConfigurationError, match="vault_namespace is required"):
            VaultClient(vault_address="https://vault.example.com:8200", vault_namespace="")

        with pytest.raises(VaultConfigurationError, match="vault_namespace is required"):
            VaultClient(vault_address="https://vault.example.com:8200", vault_namespace=None)

    @patch(MOCK_REQUESTS_SESSION)
    def test_vault_client_set_token(self, mock_session_class):
        """Test VaultClient set_token method."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        client = VaultClient(
            vault_address="https://vault.example.com:8200", vault_namespace="test-namespace"
        )

        # Reset the mock to check only the set_token call
        mock_session.headers.update.reset_mock()

        client.set_token("hvs.test-token-123")

        mock_session.headers.update.assert_called_once_with({"X-Vault-Token": "hvs.test-token-123"})

    @patch(MOCK_REQUESTS_SESSION)
    def test_vault_client_multiple_token_updates(self, mock_session_class):
        """Test that set_token can be called multiple times."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        client = VaultClient(
            vault_address="https://vault.example.com:8200", vault_namespace="test-namespace"
        )

        # Reset to track only our token calls
        mock_session.headers.update.reset_mock()

        # Set token multiple times
        client.set_token("hvs.first-token")
        client.set_token("hvs.second-token")
        client.set_token("hvs.third-token")

        # Should have been called 3 times
        assert mock_session.headers.update.call_count == 3

        # Check the final call
        mock_session.headers.update.assert_called_with({"X-Vault-Token": "hvs.third-token"})


class TestVaultClientIntegrationWithAuthenticator:
    """Test VaultClient working with Authenticator instances."""

    @patch(MOCK_REQUESTS_SESSION)
    def test_token_authentication_flow(self, mock_session_class):
        """Test the complete token authentication flow."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        # Step 1: Create client
        client = VaultClient(vault_address="https://vault.example.com:8200", vault_namespace="root")

        # Step 2: Authenticate using token
        authenticator = Authenticator(method="token")
        authenticator.authenticate(client, token="hvs.test-token")

        # Verify the workflow completed
        assert client.vault_address == "https://vault.example.com:8200"
        assert client.vault_namespace == "root"

    @patch(MOCK_REQUESTS_SESSION)
    @patch("requests.post")
    def test_approle_authentication_flow(self, mock_post, mock_session_class):
        """Test the complete AppRole authentication flow."""
        # Mock HTTP response for AppRole login
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"auth": {"client_token": "hvs.approle-token"}}
        mock_post.return_value = mock_response

        mock_session = Mock()
        mock_session_class.return_value = mock_session

        # Step 1: Create client
        client = VaultClient(vault_address="https://vault.example.com:8200", vault_namespace="root")

        # Step 2: Authenticate with AppRole
        authenticator = Authenticator(method="approle")
        authenticator.authenticate(
            client,
            vault_address="https://vault.example.com:8200",
            role_id="test-role-id",
            secret_id="test-secret-id",
            vault_namespace="root",
        )

        # Verify the workflow completed
        assert client.vault_address == "https://vault.example.com:8200"
        assert client.vault_namespace == "root"

    @patch(MOCK_REQUESTS_SESSION)
    def test_client_without_authentication(self, mock_session_class):
        """Test that VaultClient can be created without immediate authentication."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        # This should work fine - no authentication required at creation
        client = VaultClient(
            vault_address="https://vault.example.com:8200", vault_namespace="test-namespace"
        )

        # Client should be created but not authenticated yet
        assert client.vault_address == "https://vault.example.com:8200"
        assert client.vault_namespace == "test-namespace"

        # Namespace header should be set
        mock_session.headers.update.assert_called_with({"X-Vault-Namespace": "test-namespace"})
