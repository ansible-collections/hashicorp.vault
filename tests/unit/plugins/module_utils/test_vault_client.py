# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import os

from unittest.mock import Mock, patch

import pytest


MOCK_AUTHENTICATOR = (
    "ansible_collections.hashicorp.vault.plugins.module_utils.vault_client.Authenticator"
)
MOCK_REQUESTS_SESSION = (
    "ansible_collections.hashicorp.vault.plugins.module_utils.vault_client.requests.Session"
)

from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import (
    VaultConfigurationError,
    VaultCredentialsError,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultClient


@patch.dict(
    os.environ,
    {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_NAMESPACE": "test-namespace",
        "VAULT_TOKEN": "test-token",
    },
    clear=True,
)
@patch(MOCK_AUTHENTICATOR)
@patch(MOCK_REQUESTS_SESSION)
def test_vault_client_init_explicit_method(mock_session_class, mock_authenticator_class):
    """Test VaultClient initialization with explicitly specified auth method."""
    mock_authenticator = Mock()
    mock_authenticator_class.return_value = mock_authenticator
    mock_session = Mock()
    mock_session_class.return_value = mock_session

    client = VaultClient(auth_method="token")

    mock_authenticator_class.assert_called_once_with(method="token")


@patch.dict(
    os.environ,
    {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_NAMESPACE": "test-namespace",
        "VAULT_APPROLE_PATH": "custom-approle",
        "VAULT_TOKEN": "test-token",
    },
    clear=True,
)
@patch(MOCK_AUTHENTICATOR)
@patch(MOCK_REQUESTS_SESSION)
def test_vault_client_init_custom_approle_path(mock_session_class, mock_authenticator_class):
    """Test VaultClient initialization with custom AppRole path."""
    mock_authenticator = Mock()
    mock_authenticator_class.return_value = mock_authenticator
    mock_session = Mock()
    mock_session_class.return_value = mock_session

    client = VaultClient()

    assert client.session == mock_session
    assert client.vault_address == "http://127.0.0.1:8200"
    assert client.vault_namespace == "test-namespace"

    # Since no auth_method is specified, it defaults to "token"
    mock_authenticator_class.assert_called_once_with(method="token")
    mock_authenticator.authenticate.assert_called_once_with(
        client, "http://127.0.0.1:8200", "test-namespace", "custom-approle"
    )


@patch.dict(os.environ, {}, clear=True)
def test_vault_client_missing_vault_addr():
    """Test VaultClient fails without VAULT_ADDR set."""
    with pytest.raises(
        VaultConfigurationError, match="VAULT_ADDR environment variable is required"
    ):
        VaultClient()


@patch.dict(os.environ, {"VAULT_ADDR": "http://127.0.0.1:8200"}, clear=True)
def test_vault_client_missing_vault_namespace():
    """Test VaultClient fails without VAULT_NAMESPACE set."""
    with pytest.raises(
        VaultConfigurationError, match="VAULT_NAMESPACE environment variable is required"
    ):
        VaultClient()


@patch.dict(
    os.environ,
    {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_NAMESPACE": "test-ns",
        "VAULT_TOKEN": "test-token",
    },
    clear=True,
)
@patch(MOCK_AUTHENTICATOR)
def test_vault_client_authentication_error_propagates(mock_authenticator_class):
    """Test VaultClient raises when authentication fails."""
    mock_authenticator = Mock()
    mock_authenticator.authenticate.side_effect = VaultCredentialsError("Authentication failed")
    mock_authenticator_class.return_value = mock_authenticator

    with pytest.raises(VaultCredentialsError, match="Authentication failed"):
        VaultClient()


@patch.dict(
    os.environ,
    {
        "VAULT_ADDR": "http://127.0.0.1:8200",
        "VAULT_NAMESPACE": "test-namespace",
        "VAULT_TOKEN": "test-token",
    },
    clear=True,
)
@patch(MOCK_REQUESTS_SESSION)
def test_vault_client_set_token(mock_session_class):
    """Test VaultClient set_token method."""
    mock_session = Mock()
    mock_session_class.return_value = mock_session

    with patch(MOCK_AUTHENTICATOR) as mock_authenticator_class:
        mock_authenticator = Mock()
        mock_authenticator_class.return_value = mock_authenticator

        client = VaultClient()

        # Reset the mock to check only the set_token call
        mock_session.headers.update.reset_mock()

        client.set_token("new-token")

        mock_session.headers.update.assert_called_once_with({"X-Vault-Token": "new-token"})
