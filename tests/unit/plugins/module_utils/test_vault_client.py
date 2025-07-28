# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import os
import pytest

from unittest.mock import patch, Mock

MOCK_GET_VAULT_TOKEN = (
    "ansible_collections.hashicorp.vault.plugins.module_utils.vault_client.get_vault_token"
)
MOCK_REQUESTS_SESSION = (
    "ansible_collections.hashicorp.vault.plugins.module_utils.vault_client.requests.Session"
)

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultClient
from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import (
    VaultConfigurationError,
    VaultCredentialsError
)


@patch.dict(
    os.environ,
    {"VAULT_ADDR": "http://127.0.0.1:8200", "VAULT_NAMESPACE": "test-namespace"},
    clear=True,
)
@patch(MOCK_GET_VAULT_TOKEN)
@patch(MOCK_REQUESTS_SESSION)
def test_vault_client_init_success(mock_session_class, mock_get_token):
    """Test successful VaultClient initialization."""
    mock_get_token.return_value = "test-token"
    mock_session = Mock()
    mock_session_class.return_value = mock_session

    client = VaultClient()

    assert client.session == mock_session
    mock_get_token.assert_called_once_with("http://127.0.0.1:8200", "test-namespace")
    mock_session.headers.update.assert_any_call({"X-Vault-Token": "test-token"})
    mock_session.headers.update.assert_any_call({"X-Vault-Namespace": "test-namespace"})


@patch.dict(os.environ, {}, clear=True)
def test_vault_client_missing_vault_addr():
    """Test VaultClient fails without VAULT_ADDR set."""
    with pytest.raises(VaultConfigurationError, match="VAULT_ADDR environment variable is required"):
        VaultClient()


@patch.dict(os.environ, {"VAULT_ADDR": "http://127.0.0.1:8200"}, clear=True)
def test_vault_client_missing_vault_namespace():
    """Test VaultClient fails without VAULT_NAMESPACE set."""
    with pytest.raises(VaultConfigurationError, match="VAULT_NAMESPACE environment variable is required"):
        VaultClient()


@patch.dict(
    os.environ, {"VAULT_ADDR": "http://127.0.0.1:8200", "VAULT_NAMESPACE": "test-ns"}, clear=True
)
@patch(MOCK_GET_VAULT_TOKEN)
def test_vault_client_token_error_propagates(mock_get_token):
    """Test VaultClient raises when get_vault_token fails."""
    mock_get_token.side_effect = VaultCredentialsError("Token error")

    with pytest.raises(VaultCredentialsError, match="Token error"):
        VaultClient()
