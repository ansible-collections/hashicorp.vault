import json

from unittest.mock import MagicMock

import pytest
import requests

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (  # noqa: F401 # pylint: disable=unused-import
    VaultClient,
    VaultKv2Secrets,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultConnectionError,
    VaultPermissionError,
    VaultSecretNotFoundError,
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
    client = VaultClient(
        vault_address=vault_config["addr"], vault_namespace=vault_config["namespace"]
    )
    client.set_token(vault_config["token"])
    return client


def test_read_secret_latest_version_success(
    mocker, authenticated_client, vault_config, mock_success_response
):
    mock_request = mocker.patch("requests.Session.request", return_value=MagicMock())
    mock_request.return_value.json.return_value = mock_success_response

    secret = authenticated_client.secrets.kv2.read_secret(
        vault_config["mount_path"], vault_config["secret_path"]
    )

    expected_url = (
        f"{vault_config['addr']}/v1/{vault_config['mount_path']}/data/{vault_config['secret_path']}"
    )
    mock_request.assert_called_once_with("GET", expected_url, params={})
    assert secret == mock_success_response["data"]


def test_read_secret_specific_version_success(
    mocker, authenticated_client, vault_config, mock_success_response
):
    mock_request = mocker.patch("requests.Session.request", return_value=MagicMock())
    mock_request.return_value.json.return_value = mock_success_response
    secret_version = 2

    secret = authenticated_client.secrets.kv2.read_secret(
        vault_config["mount_path"], vault_config["secret_path"], version=secret_version
    )

    expected_url = (
        f"{vault_config['addr']}/v1/{vault_config['mount_path']}/data/{vault_config['secret_path']}"
    )
    mock_request.assert_called_once_with("GET", expected_url, params={"version": secret_version})
    assert secret == mock_success_response["data"]


def test_read_secret_permission_denied_403(mocker, authenticated_client, vault_config):
    mock_response = MagicMock(status_code=403)
    mock_response.json.return_value = {"errors": ["permission denied"]}
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=mock_response
    )
    mocker.patch("requests.Session.request", return_value=mock_response)

    with pytest.raises(VaultPermissionError):
        authenticated_client.secrets.kv2.read_secret(
            vault_config["mount_path"], vault_config["secret_path"]
        )


def test_read_secret_not_found_404(mocker, authenticated_client, vault_config):
    mock_response = MagicMock(status_code=404)
    mock_response.json.return_value = {"errors": []}
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=mock_response
    )
    mocker.patch("requests.Session.request", return_value=mock_response)

    with pytest.raises(VaultSecretNotFoundError):
        authenticated_client.secrets.kv2.read_secret(
            vault_config["mount_path"], "non/existent/path"
        )


def test_read_secret_generic_api_error_500(mocker, authenticated_client, vault_config):
    mock_response = MagicMock(status_code=500)
    mock_response.json.return_value = {"errors": ["internal server error"]}
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=mock_response
    )
    mocker.patch("requests.Session.request", return_value=mock_response)

    with pytest.raises(VaultApiError):
        authenticated_client.secrets.kv2.read_secret(
            vault_config["mount_path"], vault_config["secret_path"]
        )


def test_connection_error(mocker, authenticated_client, vault_config):
    mocker.patch(
        "requests.Session.request",
        side_effect=requests.exceptions.ConnectionError("Failed to connect"),
    )

    with pytest.raises(VaultConnectionError):
        authenticated_client.secrets.kv2.read_secret(
            vault_config["mount_path"], vault_config["secret_path"]
        )


def test_create_or_update_secret_success(mocker, authenticated_client, vault_config):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {"created_time": "2025-01-20T12:00:00Z", "version": 1}
    }
    mock_request = mocker.patch("requests.Session.request", return_value=mock_response)

    secret_data = {"username": "admin", "password": "secret123"}
    result = authenticated_client.secrets.kv2.create_or_update_secret(
        vault_config["mount_path"], vault_config["secret_path"], secret_data
    )

    expected_url = (
        f"{vault_config['addr']}/v1/{vault_config['mount_path']}/data/{vault_config['secret_path']}"
    )
    expected_data = {"data": secret_data}
    mock_request.assert_called_once_with("POST", expected_url, json=expected_data)
    assert result == mock_response.json.return_value


def test_create_or_update_secret_with_cas(mocker, authenticated_client, vault_config):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {"created_time": "2025-01-20T12:00:00Z", "version": 2}
    }
    mock_request = mocker.patch("requests.Session.request", return_value=mock_response)

    secret_data = {"username": "admin", "password": "newsecret"}
    cas_value = 1

    authenticated_client.secrets.kv2.create_or_update_secret(
        vault_config["mount_path"], vault_config["secret_path"], secret_data, cas=cas_value
    )

    expected_url = (
        f"{vault_config['addr']}/v1/{vault_config['mount_path']}/data/{vault_config['secret_path']}"
    )
    expected_data = {"data": secret_data, "options": {"cas": cas_value}}
    mock_request.assert_called_once_with("POST", expected_url, json=expected_data)


def test_create_or_update_secret_permission_denied_403(mocker, authenticated_client, vault_config):
    mock_response = MagicMock(status_code=403)
    mock_response.json.return_value = {"errors": ["permission denied"]}
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=mock_response
    )
    mocker.patch("requests.Session.request", return_value=mock_response)

    with pytest.raises(VaultPermissionError):
        authenticated_client.secrets.kv2.create_or_update_secret(
            vault_config["mount_path"], vault_config["secret_path"], {"key": "value"}
        )


def test_create_or_update_secret_cas_conflict_400(mocker, authenticated_client, vault_config):
    mock_response = MagicMock(status_code=400)
    mock_response.json.return_value = {
        "errors": ["check-and-set parameter did not match the current version"]
    }
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=mock_response
    )
    mocker.patch("requests.Session.request", return_value=mock_response)

    with pytest.raises(VaultApiError):
        authenticated_client.secrets.kv2.create_or_update_secret(
            vault_config["mount_path"], vault_config["secret_path"], {"key": "value"}, cas=5
        )


def test_create_or_update_secret_connection_error(mocker, authenticated_client, vault_config):
    mocker.patch(
        "requests.Session.request",
        side_effect=requests.exceptions.ConnectionError("Failed to connect"),
    )

    with pytest.raises(VaultConnectionError):
        authenticated_client.secrets.kv2.create_or_update_secret(
            vault_config["mount_path"], vault_config["secret_path"], {"key": "value"}
        )


@pytest.mark.parametrize(
    "version,expected_method,expected_path,expected_data",
    [
        # Delete latest version (i.e., version unspecified)
        (None, "DELETE", "secret/data/test/my-secret", None),
        # Delete specific version
        (123, "POST", "secret/delete/test/my-secret", {"versions": [123]}),
    ],
)
def test_delete_secret_success(
    mocker,
    authenticated_client,
    vault_config,
    version,
    expected_method,
    expected_path,
    expected_data,
):
    mock_request = mocker.patch("requests.Session.request", return_value=MagicMock())
    mock_request.return_value.raise_for_status.return_value = None

    authenticated_client.secrets.kv2.delete_secret(
        vault_config["mount_path"], vault_config["secret_path"], version=version
    )

    expected_url = f"{vault_config['addr']}/v1/{expected_path}"
    if expected_data is None:
        mock_request.assert_called_once_with(expected_method, expected_url)
    else:
        mock_request.assert_called_once_with(expected_method, expected_url, json=expected_data)


@pytest.mark.parametrize(
    "version,status_code,error_response,expected_exception",
    [
        # Permission denied errors
        (None, 403, {"errors": ["permission denied"]}, VaultPermissionError),
        (1, 403, {"errors": ["insufficient privileges"]}, VaultPermissionError),
        # Not found errors
        (None, 404, {"errors": ["secret not found"]}, VaultSecretNotFoundError),
        (2, 404, {"errors": ["version not found"]}, VaultSecretNotFoundError),
        # Generic API errors
        (None, 500, {"errors": ["internal server error"]}, VaultApiError),
        (3, 400, {"errors": ["bad request"]}, VaultApiError),
    ],
)
def test_delete_secret_http_errors(
    mocker,
    authenticated_client,
    vault_config,
    version,
    status_code,
    error_response,
    expected_exception,
):
    mock_response = MagicMock(status_code=status_code)
    mock_response.json.return_value = error_response
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=mock_response
    )
    mocker.patch("requests.Session.request", return_value=mock_response)

    with pytest.raises(expected_exception):
        authenticated_client.secrets.kv2.delete_secret(
            vault_config["mount_path"], vault_config["secret_path"], version=version
        )


def test_delete_secret_connection_error(mocker, authenticated_client, vault_config):
    mocker.patch(
        "requests.Session.request",
        side_effect=requests.exceptions.ConnectionError("Failed to connect"),
    )

    with pytest.raises(VaultConnectionError):
        authenticated_client.secrets.kv2.delete_secret(
            vault_config["mount_path"], vault_config["secret_path"]
        )


def test_delete_secret_malformed_json_response(mocker, authenticated_client, vault_config):
    mock_response = MagicMock(status_code=400)
    mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
    mock_response.text = "Bad Request: Invalid JSON response"
    mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        response=mock_response
    )
    mocker.patch("requests.Session.request", return_value=mock_response)

    with pytest.raises(VaultApiError) as exc_info:
        authenticated_client.secrets.kv2.delete_secret(
            vault_config["mount_path"], vault_config["secret_path"], version=1
        )

    # Verify the error message contains the response text as fallback
    assert "Bad Request: Invalid JSON response" in str(exc_info.value)


@pytest.mark.parametrize("version", [0, -1, -5])
def test_delete_secret_invalid_version_numbers(mocker, authenticated_client, vault_config, version):
    mock_request = mocker.patch("requests.Session.request", return_value=MagicMock())
    mock_request.return_value.raise_for_status.return_value = None

    authenticated_client.secrets.kv2.delete_secret(
        vault_config["mount_path"], vault_config["secret_path"], version=version
    )

    expected_url = f"{vault_config['addr']}/v1/secret/delete/test/my-secret"
    mock_request.assert_called_once_with("POST", expected_url, json={"versions": [version]})


def test_delete_secret_with_special_characters_in_path(mocker, authenticated_client, vault_config):
    special_path = "test/my-secret with spaces/and-symbols!@#"
    mock_request = mocker.patch("requests.Session.request", return_value=MagicMock())
    mock_request.return_value.raise_for_status.return_value = None

    authenticated_client.secrets.kv2.delete_secret(
        vault_config["mount_path"], special_path, version=1
    )

    expected_url = f"{vault_config['addr']}/v1/secret/delete/{special_path}"
    mock_request.assert_called_once_with("POST", expected_url, json={"versions": [1]})
