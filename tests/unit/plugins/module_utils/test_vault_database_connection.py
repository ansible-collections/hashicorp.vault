# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
    VaultClient,
    VaultDatabaseConnection,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)


@pytest.fixture
def vault_config():
    """Vault configuration for testing."""
    return {
        "addr": "http://mock-vault:8200",
        "token": "mock-token",
        "namespace": "root",
        "custom_mount_path": "my-db",
        "database_name": "test-database",
    }


@pytest.fixture
def mock_list_connections_response():
    return {"data": {"keys": ["db-one", "db-two"]}}


@pytest.fixture
def mock_empty_response():
    return {"data": {}}


@pytest.fixture
def mock_read_connection_response():
    return {
        "data": {
            "allowed_roles": ["readonly"],
            "connection_details": {
                "connection_url": "{{username}}:{{password}}@tcp(127.0.0.1:3306)/",
                "username": "vaultuser",
            },
            "password_policy": "",
            "plugin_name": "mysql-database-plugin",
            "plugin_version": "",
            "root_credentials_rotate_statements": [],
            "skip_static_role_import_rotation": False,
        }
    }


@pytest.fixture
def authenticated_client(mocker, vault_config):
    """Authenticated Vault client for testing."""
    client = VaultClient(vault_address=vault_config["addr"], vault_namespace=vault_config["namespace"])
    client.set_token(vault_config["token"])
    client._make_request = MagicMock()
    return client


@pytest.fixture
def mock_configure_response():
    """Mock response from Vault for configure/update operations."""
    return {
        "request_id": "1234567890",
        "lease_id": "",
        "lease_duration": 0,
        "renewable": False,
        "data": None,
        "warnings": None,
    }


@pytest.fixture
def sample_db_config():
    """Sample database configuration for testing."""
    return {
        "plugin_name": "mysql-database-plugin",
        "allowed_roles": "readonly",
        "connection_url": "{{username}}:{{password}}@tcp(127.0.0.1:3306)/",
        "username": "vaultuser",
        "password": "secretpassword",
    }


class TestDatabaseListConnections:
    def test_list_connections_success(self, authenticated_client, mock_list_connections_response):
        authenticated_client._make_request.return_value = mock_list_connections_response

        db_conn = VaultDatabaseConnection(client=authenticated_client)
        db_names = db_conn.list_connections()

        expected_path = "v1/database/config"
        authenticated_client._make_request.assert_called_once_with("LIST", expected_path)
        assert db_names == mock_list_connections_response["data"]["keys"]

    def test_list_connections_empty_return_success(self, authenticated_client, mock_empty_response):
        authenticated_client._make_request.return_value = mock_empty_response

        db_conn = VaultDatabaseConnection(client=authenticated_client)
        db_names = db_conn.list_connections()

        expected_path = "v1/database/config"
        authenticated_client._make_request.assert_called_once_with("LIST", expected_path)
        assert db_names == []

    def test_list_connections_custom_mount_path_success(
        self, authenticated_client, vault_config, mock_list_connections_response
    ):
        authenticated_client._make_request.return_value = mock_list_connections_response

        db_conn = VaultDatabaseConnection(client=authenticated_client, mount_path=vault_config["custom_mount_path"])
        db_names = db_conn.list_connections()

        expected_path = f"v1/{vault_config['custom_mount_path']}/config"
        authenticated_client._make_request.assert_called_once_with("LIST", expected_path)
        assert db_names == mock_list_connections_response["data"]["keys"]

    def test_list_connections_not_found(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultSecretNotFoundError("not found")
        db_conn = VaultDatabaseConnection(client=authenticated_client)
        result = db_conn.list_connections()
        assert result == []

    def test_list_connections_error(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultPermissionError("permission denied")
        db_conn = VaultDatabaseConnection(client=authenticated_client)
        with pytest.raises(VaultPermissionError):
            db_conn.list_connections()


class TestDatabaseReadConnection:
    def test_read_connection_success(self, authenticated_client, vault_config, mock_read_connection_response):
        authenticated_client._make_request.return_value = mock_read_connection_response

        db_conn = VaultDatabaseConnection(client=authenticated_client)
        db_config = db_conn.read_connection(name=vault_config["database_name"])

        expected_path = f"v1/database/config/{vault_config['database_name']}"
        authenticated_client._make_request.assert_called_once_with("GET", expected_path)
        assert db_config == mock_read_connection_response["data"]

    def test_read_connection_custom_mount_path_success(
        self, authenticated_client, vault_config, mock_read_connection_response
    ):
        authenticated_client._make_request.return_value = mock_read_connection_response

        db_conn = VaultDatabaseConnection(client=authenticated_client, mount_path=vault_config["custom_mount_path"])
        db_config = db_conn.read_connection(name=vault_config["database_name"])

        expected_path = f"v1/{vault_config['custom_mount_path']}/config/{vault_config['database_name']}"
        authenticated_client._make_request.assert_called_once_with("GET", expected_path)
        assert db_config == mock_read_connection_response["data"]

    def test_read_connection_error(self, authenticated_client, vault_config):
        authenticated_client._make_request.side_effect = VaultSecretNotFoundError("connection not found")
        db_conn = VaultDatabaseConnection(client=authenticated_client)
        with pytest.raises(VaultSecretNotFoundError):
            db_conn.read_connection(vault_config["database_name"])


class TestCreateOrUpdateConnection:
    """Test suite for create_or_update_connection."""

    def test_create_or_update_connection_success(
        self, authenticated_client, vault_config, sample_db_config, mock_configure_response
    ):
        """Test that create_or_update_connection creates a new connection if it doesn't exist."""
        authenticated_client._make_request.return_value = mock_configure_response

        db_conn = VaultDatabaseConnection(authenticated_client)
        result = db_conn.create_or_update_connection(vault_config["database_name"], sample_db_config)
        expected_path = f"v1/database/config/{vault_config['database_name']}"
        authenticated_client._make_request.assert_called_once_with("POST", expected_path, json=sample_db_config)

        assert result == mock_configure_response

    def test_create_or_update_connection_error(self, authenticated_client, vault_config, sample_db_config):
        """Test that create_or_update_connection raises VaultApiError if the API request fails."""
        authenticated_client._make_request.side_effect = VaultApiError("Test error")

        db_conn = VaultDatabaseConnection(authenticated_client)
        with pytest.raises(VaultApiError):
            db_conn.create_or_update_connection(vault_config["database_name"], sample_db_config)

    def test_create_or_update_connection_invalid_config(self, authenticated_client, vault_config):
        """Test that create_or_update_connection raises TypeError if config is not a dict."""
        db_conn = VaultDatabaseConnection(authenticated_client)

        with pytest.raises(TypeError, match="config must be a dict"):
            db_conn.create_or_update_connection(vault_config["database_name"], "invalid_config")
        authenticated_client._make_request.assert_not_called()

    def test_create_or_update_connection_missing_plugin_name(self, authenticated_client, vault_config):
        """Test that create_or_update_connection raises TypeError if config lacks plugin_name."""
        db_conn = VaultDatabaseConnection(authenticated_client)
        config_without_plugin = {
            "connection_url": "postgresql://localhost:5432/mydb",
            "username": "vault",
        }

        with pytest.raises(TypeError, match='config must contain "plugin_name"'):
            db_conn.create_or_update_connection(vault_config["database_name"], config_without_plugin)
        authenticated_client._make_request.assert_not_called()

    def test_create_or_update_connection_plugin_name_not_string(self, authenticated_client, vault_config):
        """Test that create_or_update_connection raises TypeError if plugin_name is not a str."""
        db_conn = VaultDatabaseConnection(authenticated_client)
        config_plugin_name_not_str = {
            "plugin_name": 123,
            "connection_url": "postgresql://localhost:5432/mydb",
        }

        with pytest.raises(TypeError, match='config\\["plugin_name"\\] must be a str'):
            db_conn.create_or_update_connection(vault_config["database_name"], config_plugin_name_not_str)
        authenticated_client._make_request.assert_not_called()

    def test_create_or_update_connection_with_minimal_config(
        self, authenticated_client, vault_config, mock_configure_response
    ):
        """Test configuration with minimal required parameters."""
        authenticated_client._make_request.return_value = mock_configure_response

        minimal_config = {
            "plugin_name": "mysql-database-plugin",
            "connection_url": "{{username}}:{{password}}@tcp(127.0.0.1:3306)/",
        }

        db_conn = VaultDatabaseConnection(authenticated_client)
        result = db_conn.create_or_update_connection(vault_config["database_name"], minimal_config)

        expected_path = f"v1/database/config/{vault_config['database_name']}"
        authenticated_client._make_request.assert_called_once_with("POST", expected_path, json=minimal_config)
        assert result == mock_configure_response


class TestDeleteConnection:
    """Test suite for delete_connection."""

    def test_delete_connection_success(self, authenticated_client, vault_config, mock_configure_response):
        """Test that delete_connection deletes a connection if it exists."""
        authenticated_client._make_request.return_value = mock_configure_response

        db_conn = VaultDatabaseConnection(authenticated_client)
        result = db_conn.delete_connection(vault_config["database_name"])

        expected_path = f"v1/database/config/{vault_config['database_name']}"
        authenticated_client._make_request.assert_called_once_with("DELETE", expected_path)

        assert result is None

    def test_delete_connection_error(self, authenticated_client, vault_config):
        """Test that delete_connection raises VaultApiError if the API request fails."""
        authenticated_client._make_request.side_effect = VaultApiError("Test error")

        db_conn = VaultDatabaseConnection(authenticated_client)
        with pytest.raises(VaultApiError):
            db_conn.delete_connection(vault_config["database_name"])


class TestResetConnection:
    """Test suite for reset_connection."""

    def test_reset_connection_success(self, authenticated_client, vault_config, mock_configure_response):
        """Test that reset_connection resets a connection if it exists."""
        authenticated_client._make_request.return_value = mock_configure_response

        db_conn = VaultDatabaseConnection(authenticated_client)
        result = db_conn.reset_connection(vault_config["database_name"])

        expected_path = f"v1/database/reset/{vault_config['database_name']}"
        authenticated_client._make_request.assert_called_once_with("POST", expected_path, json={})

        assert result is None

    def test_reset_connection_error(self, authenticated_client, vault_config):
        """Test that reset_connection raises VaultApiError if the API request fails."""
        authenticated_client._make_request.side_effect = VaultApiError("Test error")

        db_conn = VaultDatabaseConnection(authenticated_client)
        with pytest.raises(VaultApiError):
            db_conn.reset_connection(vault_config["database_name"])
