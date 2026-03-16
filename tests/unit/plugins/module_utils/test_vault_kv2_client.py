# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
    VaultClient,
    VaultKv2Secrets,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultPermissionError,
)


@pytest.fixture
def vault_config():
    return {
        "addr": "http://mock-vault:8200",
        "token": "mock-token",
        "namespace": "admin",
        "mount_path": "secret",
        "secret_path": "test/my-secret",
    }


@pytest.fixture
def mock_success_response():
    return {
        "data": {
            "data": {"username": "test-user", "password": "test-password"},
            "metadata": {"created_time": "2025-08-06T12:00:00Z", "version": 3, "destroyed": False},
        }
    }


@pytest.fixture
def authenticated_client(mocker, vault_config):
    client = VaultClient(vault_address=vault_config["addr"], vault_namespace=vault_config["namespace"])
    client.set_token(vault_config["token"])
    client._make_request = MagicMock()
    return client


def test_read_secret_latest_version_success(authenticated_client, vault_config, mock_success_response):

    authenticated_client._make_request.return_value = mock_success_response
    kv2_secret = VaultKv2Secrets(authenticated_client)
    secret = kv2_secret.read_secret(vault_config["mount_path"], vault_config["secret_path"])

    expected_path = f"v1/{vault_config['mount_path']}/data/{vault_config['secret_path']}"
    authenticated_client._make_request.assert_called_once_with("GET", expected_path, params={})
    assert secret == mock_success_response["data"]


def test_read_secret_specific_version_success(authenticated_client, vault_config, mock_success_response):
    authenticated_client._make_request.return_value = mock_success_response
    secret_version = 2
    kv2_secret = VaultKv2Secrets(authenticated_client)
    secret = kv2_secret.read_secret(vault_config["mount_path"], vault_config["secret_path"], version=secret_version)

    expected_url = f"v1/{vault_config['mount_path']}/data/{vault_config['secret_path']}"
    authenticated_client._make_request.assert_called_once_with("GET", expected_url, params={"version": secret_version})
    assert secret == mock_success_response["data"]


def test_read_secret_error(authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = VaultPermissionError("error while reading secret")
    kv2_secret = VaultKv2Secrets(authenticated_client)
    with pytest.raises(VaultPermissionError):
        kv2_secret.read_secret(vault_config["mount_path"], vault_config["secret_path"])


def test_create_or_update_secret_success(authenticated_client, vault_config):
    json_data = {"data": {"created_time": "2025-01-20T12:00:00Z", "version": 1}}
    authenticated_client._make_request.return_value = json_data

    secret_data = {"username": "admin", "password": "secret123"}
    kv2_secret = VaultKv2Secrets(authenticated_client)
    result = kv2_secret.create_or_update_secret(vault_config["mount_path"], vault_config["secret_path"], secret_data)

    expected_path = f"v1/{vault_config['mount_path']}/data/{vault_config['secret_path']}"
    expected_data = {"data": secret_data}
    authenticated_client._make_request.assert_called_once_with("POST", expected_path, json=expected_data)
    assert result == json_data


def test_create_or_update_secret_with_cas(authenticated_client, vault_config):
    json_data = {"data": {"created_time": "2025-01-20T12:00:00Z", "version": 2}}
    authenticated_client._make_request.return_value = json_data

    secret_data = {"username": "admin", "password": "newsecret"}
    cas_value = 1
    kv2_secret = VaultKv2Secrets(authenticated_client)
    kv2_secret.create_or_update_secret(
        vault_config["mount_path"], vault_config["secret_path"], secret_data, cas=cas_value
    )

    expected_path = f"v1/{vault_config['mount_path']}/data/{vault_config['secret_path']}"
    expected_data = {"data": secret_data, "options": {"cas": cas_value}}
    authenticated_client._make_request.assert_called_once_with("POST", expected_path, json=expected_data)


def test_create_or_update_secret_error(authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = VaultPermissionError("error while deleting secret")
    secret_data = {"username": "admin", "password": "newsecret"}
    kv2_secret = VaultKv2Secrets(authenticated_client)
    with pytest.raises(VaultPermissionError):
        kv2_secret.create_or_update_secret(vault_config["mount_path"], vault_config["secret_path"], secret_data)


def test_delete_secret(authenticated_client, vault_config):
    kv2_secret = VaultKv2Secrets(authenticated_client)
    kv2_secret.delete_secret(vault_config["mount_path"], vault_config["secret_path"])

    expected_path = f"v1/{vault_config['mount_path']}/data/{vault_config['secret_path']}"
    authenticated_client._make_request.assert_called_once_with("DELETE", expected_path)


def test_delete_secret_with_versions(authenticated_client, vault_config):
    kv2_secret = VaultKv2Secrets(authenticated_client)
    versions = [1, 2, 3]
    kv2_secret.delete_secret(vault_config["mount_path"], vault_config["secret_path"], versions)

    expected_path = f"v1/{vault_config['mount_path']}/delete/{vault_config['secret_path']}"
    authenticated_client._make_request.assert_called_once_with("POST", expected_path, json={"versions": versions})


def test_delete_secret_error(authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = VaultPermissionError("error while deleting secret")
    kv2_secret = VaultKv2Secrets(authenticated_client)
    with pytest.raises(VaultPermissionError):
        kv2_secret.delete_secret(vault_config["mount_path"], vault_config["secret_path"])
