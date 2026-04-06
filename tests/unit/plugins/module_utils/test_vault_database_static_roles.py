# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
    VaultClient,
    VaultDatabaseStaticRoles,
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
def mock_list_static_roles_response():
    return {"data": {"keys": ["role-one", "role-two"]}}


@pytest.fixture
def mock_empty_response():
    return {"data": {}}


@pytest.fixture
def mock_read_static_role_response():
    return {
        "data": {
            "db_name": "my-postgres-db",
            "username": "vault-user",
            "rotation_period": "86400s",
            "rotation_statements": ["ALTER USER \"{{username}}\" WITH PASSWORD '{{password}}';"],
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
def mock_static_credentials_response():
    return {
        "data": {
            "username": "vault-user",
            "password": "secret-password-123",
            "last_vault_rotation": "2026-04-01T00:00:00Z",
            "rotation_period": 86400,
            "ttl": 86400,
        }
    }


@pytest.fixture
def sample_static_role_config():
    """Sample static role configuration for testing."""
    return {
        "db_name": "my-postgres-db",
        "username": "vault-user",
        "rotation_period": "86400s",
    }


class TestDatabaseListStaticRoles:
    def test_list_static_roles_success(self, authenticated_client, mock_list_static_roles_response):
        authenticated_client._make_request.return_value = mock_list_static_roles_response

        static_roles = VaultDatabaseStaticRoles(client=authenticated_client)
        role_names = static_roles.list_static_roles()

        expected_path = "v1/database/static-roles"
        authenticated_client._make_request.assert_called_once_with("LIST", expected_path, params={})
        assert role_names == mock_list_static_roles_response["data"]["keys"]

    def test_list_static_roles_with_snapshot_id(self, authenticated_client, mock_list_static_roles_response):
        authenticated_client._make_request.return_value = mock_list_static_roles_response

        static_roles = VaultDatabaseStaticRoles(client=authenticated_client)
        role_names = static_roles.list_static_roles(read_snapshot_id="snapshot-123")

        expected_path = "v1/database/static-roles"
        authenticated_client._make_request.assert_called_once_with(
            "LIST", expected_path, params={"read_snapshot_id": "snapshot-123"}
        )
        assert role_names == mock_list_static_roles_response["data"]["keys"]

    def test_list_static_roles_empty_return_success(self, authenticated_client, mock_empty_response):
        authenticated_client._make_request.return_value = mock_empty_response

        static_roles = VaultDatabaseStaticRoles(client=authenticated_client)
        role_names = static_roles.list_static_roles()

        expected_path = "v1/database/static-roles"
        authenticated_client._make_request.assert_called_once_with("LIST", expected_path, params={})
        assert role_names == []

    def test_list_static_roles_custom_mount_path_success(
        self, authenticated_client, vault_config, mock_list_static_roles_response
    ):
        authenticated_client._make_request.return_value = mock_list_static_roles_response

        static_roles = VaultDatabaseStaticRoles(
            client=authenticated_client, mount_path=vault_config["custom_mount_path"]
        )
        role_names = static_roles.list_static_roles()

        expected_path = f"v1/{vault_config['custom_mount_path']}/static-roles"
        authenticated_client._make_request.assert_called_once_with("LIST", expected_path, params={})
        assert role_names == mock_list_static_roles_response["data"]["keys"]

    def test_list_static_roles_not_found(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultSecretNotFoundError("not found")
        static_roles = VaultDatabaseStaticRoles(client=authenticated_client)
        result = static_roles.list_static_roles()
        assert result == []

    def test_list_static_roles_error(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultPermissionError("permission denied")
        static_roles = VaultDatabaseStaticRoles(client=authenticated_client)
        with pytest.raises(VaultPermissionError):
            static_roles.list_static_roles()


class TestDatabaseReadStaticRole:
    def test_read_static_role_success(self, authenticated_client, mock_read_static_role_response):
        authenticated_client._make_request.return_value = mock_read_static_role_response

        static_roles = VaultDatabaseStaticRoles(client=authenticated_client)
        role_config = static_roles.read_static_role(name=TEST_ROLE_NAME)

        expected_path = f"v1/database/static-roles/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with("GET", expected_path, params={})
        assert role_config == mock_read_static_role_response["data"]

    def test_read_static_role_with_snapshot_id(self, authenticated_client, mock_read_static_role_response):
        authenticated_client._make_request.return_value = mock_read_static_role_response

        static_roles = VaultDatabaseStaticRoles(client=authenticated_client)
        role_config = static_roles.read_static_role(name=TEST_ROLE_NAME, read_snapshot_id="snapshot-123")

        expected_path = f"v1/database/static-roles/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with(
            "GET", expected_path, params={"read_snapshot_id": "snapshot-123"}
        )
        assert role_config == mock_read_static_role_response["data"]

    def test_read_static_role_custom_mount_path_success(
        self, authenticated_client, vault_config, mock_read_static_role_response
    ):
        authenticated_client._make_request.return_value = mock_read_static_role_response

        static_roles = VaultDatabaseStaticRoles(
            client=authenticated_client, mount_path=vault_config["custom_mount_path"]
        )
        role_config = static_roles.read_static_role(name=TEST_ROLE_NAME)

        expected_path = f"v1/{vault_config['custom_mount_path']}/static-roles/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with("GET", expected_path, params={})
        assert role_config == mock_read_static_role_response["data"]

    def test_read_static_role_error(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultSecretNotFoundError("role not found")
        static_roles = VaultDatabaseStaticRoles(client=authenticated_client)
        with pytest.raises(VaultSecretNotFoundError):
            static_roles.read_static_role(TEST_ROLE_NAME)


class TestCreateOrUpdateStaticRole:
    def test_create_or_update_static_role_success(
        self, authenticated_client, sample_static_role_config, mock_create_response
    ):
        authenticated_client._make_request.return_value = mock_create_response

        static_roles = VaultDatabaseStaticRoles(authenticated_client)
        result = static_roles.create_or_update_static_role(TEST_ROLE_NAME, sample_static_role_config)
        expected_path = f"v1/database/static-roles/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with(
            "POST", expected_path, json=sample_static_role_config
        )

        assert result == mock_create_response

    def test_create_or_update_static_role_custom_mount_path(
        self, authenticated_client, vault_config, sample_static_role_config, mock_create_response
    ):
        authenticated_client._make_request.return_value = mock_create_response

        static_roles = VaultDatabaseStaticRoles(authenticated_client, mount_path=vault_config["custom_mount_path"])
        result = static_roles.create_or_update_static_role(TEST_ROLE_NAME, sample_static_role_config)

        expected_path = f"v1/{vault_config['custom_mount_path']}/static-roles/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with(
            "POST", expected_path, json=sample_static_role_config
        )
        assert result == mock_create_response

    def test_create_or_update_static_role_error(self, authenticated_client, sample_static_role_config):
        authenticated_client._make_request.side_effect = VaultApiError("Test error")

        static_roles = VaultDatabaseStaticRoles(authenticated_client)
        with pytest.raises(VaultApiError):
            static_roles.create_or_update_static_role(TEST_ROLE_NAME, sample_static_role_config)

    def test_create_or_update_static_role_invalid_config(self, authenticated_client):
        static_roles = VaultDatabaseStaticRoles(authenticated_client)

        with pytest.raises(TypeError, match="config must be a dict"):
            static_roles.create_or_update_static_role(TEST_ROLE_NAME, "invalid_config")
        authenticated_client._make_request.assert_not_called()


class TestDeleteStaticRole:
    def test_delete_static_role_success(self, authenticated_client, mock_create_response):
        authenticated_client._make_request.return_value = mock_create_response

        static_roles = VaultDatabaseStaticRoles(authenticated_client)
        result = static_roles.delete_static_role(TEST_ROLE_NAME)

        expected_path = f"v1/database/static-roles/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with("DELETE", expected_path)

        assert result is None

    def test_delete_static_role_custom_mount_path(self, authenticated_client, vault_config, mock_create_response):
        authenticated_client._make_request.return_value = mock_create_response

        static_roles = VaultDatabaseStaticRoles(authenticated_client, mount_path=vault_config["custom_mount_path"])
        result = static_roles.delete_static_role(TEST_ROLE_NAME)

        expected_path = f"v1/{vault_config['custom_mount_path']}/static-roles/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with("DELETE", expected_path)

        assert result is None

    def test_delete_static_role_error(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultApiError("Test error")

        static_roles = VaultDatabaseStaticRoles(authenticated_client)
        with pytest.raises(VaultApiError):
            static_roles.delete_static_role(TEST_ROLE_NAME)


class TestGetStaticRoleCredentials:
    def test_get_static_role_credentials_success(self, authenticated_client, mock_static_credentials_response):
        authenticated_client._make_request.return_value = mock_static_credentials_response

        static_roles = VaultDatabaseStaticRoles(client=authenticated_client)
        credentials = static_roles.get_static_role_credentials(name=TEST_ROLE_NAME)

        expected_path = f"v1/database/static-creds/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with("GET", expected_path, params={})
        assert credentials == mock_static_credentials_response["data"]

    def test_get_static_role_credentials_with_snapshot_id(self, authenticated_client, mock_static_credentials_response):
        authenticated_client._make_request.return_value = mock_static_credentials_response

        static_roles = VaultDatabaseStaticRoles(client=authenticated_client)
        credentials = static_roles.get_static_role_credentials(name=TEST_ROLE_NAME, read_snapshot_id="snapshot-123")

        expected_path = f"v1/database/static-creds/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with(
            "GET", expected_path, params={"read_snapshot_id": "snapshot-123"}
        )
        assert credentials == mock_static_credentials_response["data"]

    def test_get_static_role_credentials_custom_mount_path(
        self, authenticated_client, vault_config, mock_static_credentials_response
    ):
        authenticated_client._make_request.return_value = mock_static_credentials_response

        static_roles = VaultDatabaseStaticRoles(
            client=authenticated_client, mount_path=vault_config["custom_mount_path"]
        )
        credentials = static_roles.get_static_role_credentials(name=TEST_ROLE_NAME)

        expected_path = f"v1/{vault_config['custom_mount_path']}/static-creds/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with("GET", expected_path, params={})
        assert credentials == mock_static_credentials_response["data"]

    def test_get_static_role_credentials_error(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultSecretNotFoundError("role not found")
        static_roles = VaultDatabaseStaticRoles(client=authenticated_client)
        with pytest.raises(VaultSecretNotFoundError):
            static_roles.get_static_role_credentials(TEST_ROLE_NAME)
