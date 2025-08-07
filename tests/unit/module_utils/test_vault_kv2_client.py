from unittest.mock import MagicMock

import pytest
import requests

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultConnectionError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_kv2_client import VaultKv2Client


@pytest.fixture
def vault_config():
    return {
        "addr": "http://mock-vault:8200",
        "token": "mock-token",
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
def vault_client(vault_config):
    return VaultKv2Client(vault_addr=vault_config["addr"], vault_token=vault_config["token"])


def test_client_initialization_success(vault_config):
    client = VaultKv2Client(vault_addr=vault_config["addr"], vault_token=vault_config["token"])
    assert client.vault_addr == vault_config["addr"]
    assert "X-Vault-Token" in client.session.headers
    assert client.session.headers["X-Vault-Token"] == vault_config["token"]


def test_initialization_fails_with_no_address(vault_config):
    with pytest.raises(ValueError, match="Vault address cannot be empty"):
        VaultKv2Client("", vault_config["token"])


def test_initialization_fails_with_no_token(vault_config):
    with pytest.raises(ValueError, match="Vault token cannot be empty"):
        VaultKv2Client(vault_config["addr"], "")


def test_read_secret_latest_version_success(
    mocker, vault_client, vault_config, mock_success_response
):
    mock_request = mocker.patch("requests.Session.request", return_value=MagicMock())
    mock_request.return_value.json.return_value = mock_success_response

    secret = vault_client.read_secret(vault_config["mount_path"], vault_config["secret_path"])

    expected_url = (
        f"{vault_config['addr']}/v1/{vault_config['mount_path']}/data/{vault_config['secret_path']}"
    )
    mock_request.assert_called_once_with("GET", expected_url, params={})
    assert secret == mock_success_response["data"]


def test_read_secret_specific_version_success(
    mocker, vault_client, vault_config, mock_success_response
):
    mock_request = mocker.patch("requests.Session.request", return_value=MagicMock())
    mock_request.return_value.json.return_value = mock_success_response
    secret_version = 2

    secret = vault_client.read_secret(
        vault_config["mount_path"], vault_config["secret_path"], version=secret_version
    )

    expected_url = (
        f"{vault_config['addr']}/v1/{vault_config['mount_path']}/data/{vault_config['secret_path']}"
    )
    mock_request.assert_called_once_with("GET", expected_url, params={"version": secret_version})
    assert secret == mock_success_response["data"]


def test_read_secret_permission_denied_403(mocker, vault_client, vault_config):
    mock_response = MagicMock(status_code=403)
    mock_response.json.return_value = {"errors": ["permission denied"]}
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=mock_response
    )
    mocker.patch("requests.Session.request", return_value=mock_response)

    with pytest.raises(VaultPermissionError):
        vault_client.read_secret(vault_config["mount_path"], vault_config["secret_path"])


def test_read_secret_not_found_404(mocker, vault_client, vault_config):
    mock_response = MagicMock(status_code=404)
    mock_response.json.return_value = {"errors": []}
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=mock_response
    )
    mocker.patch("requests.Session.request", return_value=mock_response)

    with pytest.raises(VaultSecretNotFoundError):
        vault_client.read_secret(vault_config["mount_path"], "non/existent/path")


def test_read_secret_generic_api_error_500(mocker, vault_client, vault_config):
    mock_response = MagicMock(status_code=500)
    mock_response.json.return_value = {"errors": ["internal server error"]}
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=mock_response
    )
    mocker.patch("requests.Session.request", return_value=mock_response)

    with pytest.raises(VaultApiError):
        vault_client.read_secret(vault_config["mount_path"], vault_config["secret_path"])


def test_connection_error(mocker, vault_client, vault_config):
    mocker.patch(
        "requests.Session.request",
        side_effect=requests.exceptions.ConnectionError("Failed to connect"),
    )

    with pytest.raises(VaultConnectionError):
        vault_client.read_secret(vault_config["mount_path"], vault_config["secret_path"])
