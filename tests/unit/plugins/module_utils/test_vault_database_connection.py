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
    VaultPermissionError,
    VaultSecretNotFoundError,
)


@pytest.fixture
def vault_config():
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
    client = VaultClient(vault_address=vault_config["addr"], vault_namespace=vault_config["namespace"])
    client.set_token(vault_config["token"])
    client._make_request = MagicMock()
    return client


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


def test_create_or_update_connection_success(authenticated_client, vault_config):
    pass


def test_create_or_update_connection_error(authenticated_client, vault_config):
    pass


def test_delete_connection_success(authenticated_client, vault_config):
    pass


def test_delete_connection_error(authenticated_client, vault_config):
    pass


def test_reset_connection_success(authenticated_client, vault_config):
    pass


def test_reset_connection_error(authenticated_client, vault_config):
    pass
