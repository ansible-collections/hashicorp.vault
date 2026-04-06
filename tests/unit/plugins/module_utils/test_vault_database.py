# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
    Database,
    VaultClient,
    VaultDatabaseConnection,
    VaultDatabaseStaticRoles,
)


@pytest.fixture
def vault_config():
    """Vault configuration for testing."""
    return {
        "addr": "http://mock-vault:8200",
        "token": "mock-token",
        "namespace": "root",
    }


@pytest.fixture
def authenticated_client(vault_config):
    """Authenticated Vault client for testing."""
    client = VaultClient(vault_address=vault_config["addr"], vault_namespace=vault_config["namespace"])
    client.set_token(vault_config["token"])
    client._make_request = MagicMock()
    return client


class TestDatabaseContainer:
    def test_database_container_initialization_default_mount(self, authenticated_client):
        db = Database(authenticated_client)

        assert isinstance(db.connections, VaultDatabaseConnection)
        assert isinstance(db.static_roles, VaultDatabaseStaticRoles)
        assert db.connections._mount_path == "database"
        assert db.static_roles._mount_path == "database"

    def test_database_container_initialization_custom_mount(self, authenticated_client):
        db = Database(authenticated_client, mount_path="postgres-prod")

        assert isinstance(db.connections, VaultDatabaseConnection)
        assert isinstance(db.static_roles, VaultDatabaseStaticRoles)
        assert db.connections._mount_path == "postgres-prod"
        assert db.static_roles._mount_path == "postgres-prod"

    def test_database_container_multiple_instances(self, authenticated_client):
        prod_db = Database(authenticated_client, mount_path="postgres-prod")
        dev_db = Database(authenticated_client, mount_path="postgres-dev")
        default_db = Database(authenticated_client)

        assert prod_db.connections._mount_path == "postgres-prod"
        assert prod_db.static_roles._mount_path == "postgres-prod"

        assert dev_db.connections._mount_path == "postgres-dev"
        assert dev_db.static_roles._mount_path == "postgres-dev"

        assert default_db.connections._mount_path == "database"
        assert default_db.static_roles._mount_path == "database"

    def test_database_container_shares_client(self, authenticated_client):
        db = Database(authenticated_client)

        assert db.connections._client is authenticated_client
        assert db.static_roles._client is authenticated_client
