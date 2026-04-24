# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
    VaultClient,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_database import (
    VaultDatabaseDynamicRoles,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)

TEST_ROLE_NAME = "test-role"


@pytest.fixture
def vault_config():
    """Vault configuration for testing."""
    return {
        "addr": "http://mock-vault:8200",
        "token": "mock-token",
        "namespace": "root",
        "custom_mount_path": "my-db",
    }


@pytest.fixture
def authenticated_client(vault_config):
    """Authenticated Vault client for testing."""
    client = VaultClient(vault_address=vault_config["addr"], vault_namespace=vault_config["namespace"])
    client.set_token(vault_config["token"])
    client._make_request = MagicMock()
    return client


@pytest.fixture
def mock_list_dynamic_roles_response():
    return {"data": {"keys": ["readonly", "readwrite"]}}


@pytest.fixture
def mock_empty_response():
    return {"data": {}}


@pytest.fixture
def mock_read_dynamic_role_response():
    return {
        "data": {
            "db_name": "my-postgres-db",
            "creation_statements": [
                "CREATE ROLE '{{name}}' WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
                "GRANT SELECT ON ALL TABLES IN SCHEMA public TO '{{name}}';",
            ],
            "default_ttl": 3600,
            "max_ttl": 86400,
        }
    }


@pytest.fixture
def mock_create_response():
    """Mock response from Vault for create/update operations.

    Configuration write operations (POST/PUT) typically return 204 No Content
    with an empty response body per Vault API conventions.
    """
    return {}


@pytest.fixture
def sample_dynamic_role_config():
    """Sample dynamic role configuration for testing."""
    return {
        "db_name": "my-postgres-db",
        "creation_statements": [
            "CREATE ROLE '{{name}}' WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
            "GRANT SELECT ON ALL TABLES IN SCHEMA public TO '{{name}}';",
        ],
        "default_ttl": 3600,
        "max_ttl": 86400,
    }


@pytest.fixture
def mock_generate_credentials_response():
    """Mock response from Vault for credential generation."""
    return {
        "request_id": "5ad6de83-134c-4f51-a003-6c2e8b6f0633",
        "lease_id": "database/creds/readonly/abc123",
        "renewable": True,
        "lease_duration": 3600,
        "data": {
            "username": "v-token-readonly-abc123",
            "password": "A1a-randompassword123",
        },
    }


class TestDatabaseListDynamicRoles:
    def test_list_dynamic_roles_success(self, authenticated_client, mock_list_dynamic_roles_response):
        authenticated_client._make_request.return_value = mock_list_dynamic_roles_response

        dynamic_roles = VaultDatabaseDynamicRoles(client=authenticated_client)
        role_names = dynamic_roles.list_dynamic_roles()

        expected_path = "v1/database/roles"
        authenticated_client._make_request.assert_called_once_with("LIST", expected_path)
        assert role_names == mock_list_dynamic_roles_response["data"]["keys"]

    def test_list_dynamic_roles_empty_return_success(self, authenticated_client, mock_empty_response):
        authenticated_client._make_request.return_value = mock_empty_response

        dynamic_roles = VaultDatabaseDynamicRoles(client=authenticated_client)
        role_names = dynamic_roles.list_dynamic_roles()

        expected_path = "v1/database/roles"
        authenticated_client._make_request.assert_called_once_with("LIST", expected_path)
        assert role_names == []

    def test_list_dynamic_roles_custom_mount_path_success(
        self, authenticated_client, vault_config, mock_list_dynamic_roles_response
    ):
        authenticated_client._make_request.return_value = mock_list_dynamic_roles_response

        dynamic_roles = VaultDatabaseDynamicRoles(
            client=authenticated_client, mount_path=vault_config["custom_mount_path"]
        )
        role_names = dynamic_roles.list_dynamic_roles()

        expected_path = f"v1/{vault_config['custom_mount_path']}/roles"
        authenticated_client._make_request.assert_called_once_with("LIST", expected_path)
        assert role_names == mock_list_dynamic_roles_response["data"]["keys"]

    def test_list_dynamic_roles_not_found(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultSecretNotFoundError("not found")
        dynamic_roles = VaultDatabaseDynamicRoles(client=authenticated_client)
        result = dynamic_roles.list_dynamic_roles()
        assert result == []

    def test_list_dynamic_roles_error(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultPermissionError("permission denied")
        dynamic_roles = VaultDatabaseDynamicRoles(client=authenticated_client)
        with pytest.raises(VaultPermissionError):
            dynamic_roles.list_dynamic_roles()


class TestDatabaseReadDynamicRole:
    def test_read_dynamic_role_success(self, authenticated_client, mock_read_dynamic_role_response):
        authenticated_client._make_request.return_value = mock_read_dynamic_role_response

        dynamic_roles = VaultDatabaseDynamicRoles(client=authenticated_client)
        role_config = dynamic_roles.read_dynamic_role(name=TEST_ROLE_NAME)

        expected_path = f"v1/database/roles/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with("GET", expected_path)
        assert role_config == mock_read_dynamic_role_response["data"]

    def test_read_dynamic_role_custom_mount_path_success(
        self, authenticated_client, vault_config, mock_read_dynamic_role_response
    ):
        authenticated_client._make_request.return_value = mock_read_dynamic_role_response

        dynamic_roles = VaultDatabaseDynamicRoles(
            client=authenticated_client, mount_path=vault_config["custom_mount_path"]
        )
        role_config = dynamic_roles.read_dynamic_role(name=TEST_ROLE_NAME)

        expected_path = f"v1/{vault_config['custom_mount_path']}/roles/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with("GET", expected_path)
        assert role_config == mock_read_dynamic_role_response["data"]

    def test_read_dynamic_role_error(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultSecretNotFoundError("role not found")
        dynamic_roles = VaultDatabaseDynamicRoles(client=authenticated_client)
        with pytest.raises(VaultSecretNotFoundError):
            dynamic_roles.read_dynamic_role(TEST_ROLE_NAME)


class TestCreateOrUpdateDynamicRole:
    def test_create_or_update_dynamic_role_success(
        self, authenticated_client, sample_dynamic_role_config, mock_create_response
    ):
        authenticated_client._make_request.return_value = mock_create_response

        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client)
        result = dynamic_roles.create_or_update_dynamic_role(TEST_ROLE_NAME, sample_dynamic_role_config)
        expected_path = f"v1/database/roles/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with(
            "POST", expected_path, json=sample_dynamic_role_config
        )

        assert result == mock_create_response

    def test_create_or_update_dynamic_role_custom_mount_path(
        self, authenticated_client, vault_config, sample_dynamic_role_config, mock_create_response
    ):
        authenticated_client._make_request.return_value = mock_create_response

        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client, mount_path=vault_config["custom_mount_path"])
        result = dynamic_roles.create_or_update_dynamic_role(TEST_ROLE_NAME, sample_dynamic_role_config)

        expected_path = f"v1/{vault_config['custom_mount_path']}/roles/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with(
            "POST", expected_path, json=sample_dynamic_role_config
        )
        assert result == mock_create_response

    def test_create_or_update_dynamic_role_error(self, authenticated_client, sample_dynamic_role_config):
        authenticated_client._make_request.side_effect = VaultApiError("Test error")

        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client)
        with pytest.raises(VaultApiError):
            dynamic_roles.create_or_update_dynamic_role(TEST_ROLE_NAME, sample_dynamic_role_config)

    def test_create_or_update_dynamic_role_invalid_config_not_dict(self, authenticated_client):
        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client)

        with pytest.raises(TypeError, match="config must be a dict"):
            dynamic_roles.create_or_update_dynamic_role(TEST_ROLE_NAME, "invalid_config")
        authenticated_client._make_request.assert_not_called()

    def test_create_or_update_dynamic_role_invalid_name_type(self, authenticated_client):
        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client)
        with pytest.raises(TypeError, match="name must be a str"):
            dynamic_roles.create_or_update_dynamic_role(123, sample_dynamic_role_config)
        authenticated_client._make_request.assert_not_called()

    def test_create_or_update_dynamic_role_missing_name(self, authenticated_client):
        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client)
        with pytest.raises(ValueError, match="name must be a non-empty string"):
            dynamic_roles.create_or_update_dynamic_role("", sample_dynamic_role_config)
        authenticated_client._make_request.assert_not_called()

    def test_create_or_update_dynamic_role_missing_db_name(self, authenticated_client):
        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client)
        config = {
            "creation_statements": ["CREATE ROLE ..."],
        }

        with pytest.raises(ValueError, match='config must contain "db_name"'):
            dynamic_roles.create_or_update_dynamic_role(TEST_ROLE_NAME, config)
        authenticated_client._make_request.assert_not_called()

    def test_create_or_update_dynamic_role_invalid_db_name_type(self, authenticated_client):
        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client)
        config = {
            "db_name": 123,  # Should be string
            "creation_statements": ["CREATE ROLE ..."],
        }

        with pytest.raises(TypeError, match='config\\["db_name"\\] must be a str'):
            dynamic_roles.create_or_update_dynamic_role(TEST_ROLE_NAME, config)
        authenticated_client._make_request.assert_not_called()

    def test_create_or_update_dynamic_role_missing_creation_statements(self, authenticated_client):
        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client)
        config = {
            "db_name": "my-db",
        }

        with pytest.raises(ValueError, match='config must contain "creation_statements"'):
            dynamic_roles.create_or_update_dynamic_role(TEST_ROLE_NAME, config)
        authenticated_client._make_request.assert_not_called()

    def test_create_or_update_dynamic_role_invalid_creation_statements_type(self, authenticated_client):
        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client)
        config = {
            "db_name": "my-db",
            "creation_statements": "CREATE ROLE ...",  # Should be list
        }

        with pytest.raises(ValueError, match='config\\["creation_statements"\\] must be a non-empty list'):
            dynamic_roles.create_or_update_dynamic_role(TEST_ROLE_NAME, config)
        authenticated_client._make_request.assert_not_called()

    def test_create_or_update_dynamic_role_empty_creation_statements(self, authenticated_client):
        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client)
        config = {
            "db_name": "my-db",
            "creation_statements": [],  # Empty list
        }

        with pytest.raises(ValueError, match='config\\["creation_statements"\\] must be a non-empty list'):
            dynamic_roles.create_or_update_dynamic_role(TEST_ROLE_NAME, config)
        authenticated_client._make_request.assert_not_called()


class TestDeleteDynamicRole:
    def test_delete_dynamic_role_success(self, authenticated_client, mock_create_response):
        authenticated_client._make_request.return_value = mock_create_response

        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client)
        result = dynamic_roles.delete_dynamic_role(TEST_ROLE_NAME)

        expected_path = f"v1/database/roles/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with("DELETE", expected_path)

        assert result is None

    def test_delete_dynamic_role_custom_mount_path(self, authenticated_client, vault_config, mock_create_response):
        authenticated_client._make_request.return_value = mock_create_response

        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client, mount_path=vault_config["custom_mount_path"])
        result = dynamic_roles.delete_dynamic_role(TEST_ROLE_NAME)

        expected_path = f"v1/{vault_config['custom_mount_path']}/roles/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with("DELETE", expected_path)

        assert result is None

    def test_delete_dynamic_role_error(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultApiError("Test error")

        dynamic_roles = VaultDatabaseDynamicRoles(authenticated_client)
        with pytest.raises(VaultApiError):
            dynamic_roles.delete_dynamic_role(TEST_ROLE_NAME)


class TestGenerateDynamicRoleCredentials:
    def test_generate_credentials_success(self, authenticated_client, mock_generate_credentials_response):
        authenticated_client._make_request.return_value = mock_generate_credentials_response

        dynamic_roles = VaultDatabaseDynamicRoles(client=authenticated_client)
        credentials = dynamic_roles.generate_dynamic_role_credentials(name=TEST_ROLE_NAME)

        expected_path = f"v1/database/creds/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with("GET", expected_path)
        assert credentials == {
            **mock_generate_credentials_response["data"],
            "lease_id": mock_generate_credentials_response["lease_id"],
            "lease_duration": mock_generate_credentials_response["lease_duration"],
            "renewable": mock_generate_credentials_response["renewable"],
        }
        assert credentials["username"] == "v-token-readonly-abc123"
        assert credentials["password"] == "A1a-randompassword123"
        assert credentials["lease_id"] == "database/creds/readonly/abc123"
        assert credentials["lease_duration"] == 3600
        assert credentials["renewable"] is True

    def test_generate_credentials_custom_mount_path_success(
        self, authenticated_client, vault_config, mock_generate_credentials_response
    ):
        authenticated_client._make_request.return_value = mock_generate_credentials_response

        dynamic_roles = VaultDatabaseDynamicRoles(
            client=authenticated_client, mount_path=vault_config["custom_mount_path"]
        )
        credentials = dynamic_roles.generate_dynamic_role_credentials(name=TEST_ROLE_NAME)

        expected_path = f"v1/{vault_config['custom_mount_path']}/creds/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with("GET", expected_path)
        assert credentials == {
            **mock_generate_credentials_response["data"],
            "lease_id": mock_generate_credentials_response["lease_id"],
            "lease_duration": mock_generate_credentials_response["lease_duration"],
            "renewable": mock_generate_credentials_response["renewable"],
        }

    def test_generate_credentials_role_not_found(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultSecretNotFoundError("role not found")
        dynamic_roles = VaultDatabaseDynamicRoles(client=authenticated_client)
        with pytest.raises(VaultSecretNotFoundError):
            dynamic_roles.generate_dynamic_role_credentials(TEST_ROLE_NAME)

    def test_generate_credentials_permission_denied(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultPermissionError("permission denied")
        dynamic_roles = VaultDatabaseDynamicRoles(client=authenticated_client)
        with pytest.raises(VaultPermissionError):
            dynamic_roles.generate_dynamic_role_credentials(TEST_ROLE_NAME)

    def test_generate_credentials_api_error(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultApiError("API error")
        dynamic_roles = VaultDatabaseDynamicRoles(client=authenticated_client)
        with pytest.raises(VaultApiError):
            dynamic_roles.generate_dynamic_role_credentials(TEST_ROLE_NAME)
