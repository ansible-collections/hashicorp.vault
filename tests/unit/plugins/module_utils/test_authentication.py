# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import os
import pytest
import requests

from unittest.mock import patch, Mock

from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import (
    get_vault_token,
    _login_with_approle,
    VaultCredentialsError,
    VaultAppRoleLoginError,
)


@patch.dict(os.environ, {"VAULT_TOKEN": "test-token-123"}, clear=True)
def test_get_vault_token_with_token():
    """Test get_vault_token returns token from environment."""
    result = get_vault_token("http://127.0.0.1:8200", "test-ns")
    assert result == "test-token-123"


@patch.dict(
    os.environ,
    {"VAULT_APPROLE_ROLE_ID": "role-123", "VAULT_APPROLE_SECRET_ID": "secret-456"},
    clear=True,
)
@patch(
    "ansible_collections.hashicorp.vault.plugins.module_utils.authentication._login_with_approle"
)
def test_get_vault_token_with_approle(mock_login):
    """Test get_vault_token uses AppRole when no token."""
    mock_login.return_value = "approle-token"

    result = get_vault_token("http://127.0.0.1:8200", "test-ns")

    mock_login.assert_called_once_with(
        "http://127.0.0.1:8200", "role-123", "secret-456", "test-ns", "approle"
    )
    assert result == "approle-token"


@patch.dict(
    os.environ,
    {"VAULT_APPROLE_ROLE_ID": "role-123", "VAULT_APPROLE_SECRET_ID": "secret-456"},
    clear=True,
)
@patch(
    "ansible_collections.hashicorp.vault.plugins.module_utils.authentication._login_with_approle"
)
def test_get_vault_token_with_custom_approle_path(mock_login):
    """Test get_vault_token uses custom AppRole path."""
    mock_login.return_value = "approle-token"

    result = get_vault_token("http://127.0.0.1:8200", "test-ns", "custom-approle")

    mock_login.assert_called_once_with(
        "http://127.0.0.1:8200", "role-123", "secret-456", "test-ns", "custom-approle"
    )
    assert result == "approle-token"


@patch.dict(
    os.environ,
    {
        "VAULT_TOKEN": "test-token",
        "VAULT_APPROLE_ROLE_ID": "role-123",
        "VAULT_APPROLE_SECRET_ID": "secret-456",
    },
    clear=True,
)
def test_get_vault_token_mutually_exclusive():
    """Test get_vault_token raises exception when both token and AppRole credentials are provided."""
    with pytest.raises(
        VaultCredentialsError, match="VAULT_TOKEN and VAULT_APPROLE_\\* are mutually exclusive"
    ):
        get_vault_token("http://127.0.0.1:8200", "test-ns")


@patch.dict(
    os.environ,
    {"VAULT_TOKEN": "test-token", "VAULT_APPROLE_ROLE_ID": "role-123"},
    clear=True,
)
def test_get_vault_token_mutually_exclusive_token_and_role_id():
    """Test get_vault_token raises exception when token and role_id are provided."""
    with pytest.raises(
        VaultCredentialsError, match="VAULT_TOKEN and VAULT_APPROLE_\\* are mutually exclusive"
    ):
        get_vault_token("http://127.0.0.1:8200", "test-ns")


@patch.dict(
    os.environ,
    {"VAULT_TOKEN": "test-token", "VAULT_APPROLE_SECRET_ID": "secret-456"},
    clear=True,
)
def test_get_vault_token_mutually_exclusive_token_and_secret_id():
    """Test get_vault_token raises exception when token and secret_id are provided."""
    with pytest.raises(
        VaultCredentialsError, match="VAULT_TOKEN and VAULT_APPROLE_\\* are mutually exclusive"
    ):
        get_vault_token("http://127.0.0.1:8200", "test-ns")


@patch.dict(os.environ, {}, clear=True)
def test_get_vault_token_no_credentials():
    """Test get_vault_token raises exception with no credentials."""
    with pytest.raises(
        VaultCredentialsError,
        match="No Vault token or AppRole credentials found in environment variables",
    ):
        get_vault_token("http://127.0.0.1:8200", "test-ns")


@patch.dict(os.environ, {"VAULT_APPROLE_ROLE_ID": "role-123"}, clear=True)
def test_get_vault_token_missing_secret_id():
    """Test get_vault_token raises exception when only role_id is provided."""
    with pytest.raises(
        VaultCredentialsError,
        match="No Vault token or AppRole credentials found in environment variables",
    ):
        get_vault_token("http://127.0.0.1:8200", "test-ns")


@patch.dict(os.environ, {"VAULT_APPROLE_SECRET_ID": "secret-456"}, clear=True)
def test_get_vault_token_missing_role_id():
    """Test get_vault_token raises exception when only secret_id is provided."""
    with pytest.raises(
        VaultCredentialsError,
        match="No Vault token or AppRole credentials found in environment variables",
    ):
        get_vault_token("http://127.0.0.1:8200", "test-ns")


@patch("ansible_collections.hashicorp.vault.plugins.module_utils.authentication.requests.post")
def test_login_with_approle_success(mock_post):
    """Test successful AppRole login."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"auth": {"client_token": "hvs.123abc"}}
    mock_post.return_value = mock_response

    result = _login_with_approle("http://127.0.0.1:8200", "role-id", "secret-id", "namespace")

    assert result == "hvs.123abc"
    mock_post.assert_called_once_with(
        "http://127.0.0.1:8200/v1/auth/approle/login",
        json={"role_id": "role-id", "secret_id": "secret-id"},
        headers={"X-Vault-Namespace": "namespace"},
    )


@patch("ansible_collections.hashicorp.vault.plugins.module_utils.authentication.requests.post")
def test_login_with_approle_custom_path(mock_post):
    """Test AppRole login with custom path."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"auth": {"client_token": "hvs.456def"}}
    mock_post.return_value = mock_response

    result = _login_with_approle(
        "http://127.0.0.1:8200", "role-id", "secret-id", "namespace", "team1-approle"
    )

    assert result == "hvs.456def"
    mock_post.assert_called_once_with(
        "http://127.0.0.1:8200/v1/auth/team1-approle/login",
        json={"role_id": "role-id", "secret_id": "secret-id"},
        headers={"X-Vault-Namespace": "namespace"},
    )


@patch("ansible_collections.hashicorp.vault.plugins.module_utils.authentication.requests.post")
def test_login_with_approle_no_namespace(mock_post):
    """Test AppRole login without namespace."""
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"auth": {"client_token": "hvs.789ghi"}}
    mock_post.return_value = mock_response

    result = _login_with_approle("http://127.0.0.1:8200", "role-id", "secret-id")

    assert result == "hvs.789ghi"
    mock_post.assert_called_once_with(
        "http://127.0.0.1:8200/v1/auth/approle/login",
        json={"role_id": "role-id", "secret_id": "secret-id"},
        headers={},
    )


@patch("ansible_collections.hashicorp.vault.plugins.module_utils.authentication.requests.post")
def test_login_with_approle_401_failure(mock_post):
    """Test AppRole login failure with 401 unauthorized."""
    mock_response = Mock()
    mock_response.status_code = 401
    mock_response.text = "permission denied"
    mock_post.return_value = mock_response

    with pytest.raises(
        VaultAppRoleLoginError, match="AppRole login failed: HTTP 401 - permission denied"
    ):
        _login_with_approle("http://127.0.0.1:8200", "bad-role", "bad-secret", "namespace")


@patch("ansible_collections.hashicorp.vault.plugins.module_utils.authentication.requests.post")
def test_login_with_approle_403_failure(mock_post):
    """Test AppRole login failure with 403 forbidden."""
    mock_response = Mock()
    mock_response.status_code = 403
    mock_response.text = "forbidden"
    mock_post.return_value = mock_response

    with pytest.raises(
        VaultAppRoleLoginError, match="AppRole login failed: HTTP 403 - forbidden"
    ):
        _login_with_approle("http://127.0.0.1:8200", "bad-role", "bad-secret", "namespace")


@patch("ansible_collections.hashicorp.vault.plugins.module_utils.authentication.requests.post")
def test_login_with_approle_404_failure(mock_post):
    """Test AppRole login failure with 404 not found (invalid mount path)."""
    mock_response = Mock()
    mock_response.status_code = 404
    mock_response.text = "unsupported path"
    mock_post.return_value = mock_response

    with pytest.raises(
        VaultAppRoleLoginError, match="AppRole login failed: HTTP 404 - unsupported path"
    ):
        _login_with_approle("http://127.0.0.1:8200", "role-id", "secret-id", "namespace", "invalid-path")


@patch("ansible_collections.hashicorp.vault.plugins.module_utils.authentication.requests.post")
def test_login_with_approle_500_failure(mock_post):
    """Test AppRole login failure with 500 internal server error."""
    mock_response = Mock()
    mock_response.status_code = 500
    mock_response.text = "internal server error"
    mock_post.return_value = mock_response

    with pytest.raises(
        VaultAppRoleLoginError, match="AppRole login failed: HTTP 500 - internal server error"
    ):
        _login_with_approle("http://127.0.0.1:8200", "role-id", "secret-id", "namespace")


@patch("ansible_collections.hashicorp.vault.plugins.module_utils.authentication.requests.post")
def test_login_with_approle_network_error(mock_post):
    """Test AppRole login propagates network errors."""
    mock_post.side_effect = requests.ConnectionError("Connection timeout")

    with pytest.raises(
        VaultAppRoleLoginError, match="Network error during AppRole login: Connection timeout"
    ):
        _login_with_approle("http://127.0.0.1:8200", "role-id", "secret-id", "namespace")
