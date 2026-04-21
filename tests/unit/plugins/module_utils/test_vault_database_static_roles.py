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
    VaultDatabaseStaticRoles,
    compare_vault_configs,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)
from ansible_collections.hashicorp.vault.plugins.modules.database_static_role import (
    _normalize_duration_to_seconds,
    _validate_duration_format,
)

TEST_ROLE_NAME = "test-role"


class TestConfigsMatch:
    """Test the compare_vault_configs utility function."""

    def test_empty_existing_config_returns_false(self):
        """Test that an empty existing config indicates a change (new creation)."""
        existing = {}
        user_config = {"db_name": "mydb", "username": "user", "rotation_period": 86400}

        assert compare_vault_configs(existing, user_config) is False

    def test_matching_configs_returns_true(self):
        """Test that matching configs indicate no change."""
        existing = {"db_name": "mydb", "username": "user", "rotation_period": 86400}
        user_config = {"db_name": "mydb", "username": "user", "rotation_period": 86400}

        assert compare_vault_configs(existing, user_config) is True

    def test_vault_defaults_ignored(self):
        """Test that Vault-added defaults don't affect comparison."""
        # User only provided these keys (normalized)
        user_config = {"db_name": "mydb", "username": "user", "rotation_period": 86400}

        # Existing has user keys + Vault defaults
        existing = {
            "db_name": "mydb",
            "username": "user",
            "rotation_period": 86400,
            "rotation_statements": [],  # Vault default
            "credential_type": "password",  # Vault default
        }

        # Should match because user-provided keys are the same
        assert compare_vault_configs(existing, user_config) is True

    def test_user_key_changed_returns_false(self):
        """Test that a change in a user-provided key is detected."""
        existing = {"db_name": "mydb", "username": "user", "rotation_period": 86400}
        user_config = {"db_name": "mydb", "username": "user", "rotation_period": 3600}  # Changed!

        assert compare_vault_configs(existing, user_config) is False

    def test_partial_user_config_match(self):
        """Test that only user-provided keys are checked."""
        # User only provided db_name and username (normalized)
        user_config = {"db_name": "mydb", "username": "user"}

        existing = {
            "db_name": "mydb",
            "username": "user",
            "rotation_period": 86400,  # Not in user_config, so not checked
        }

        # Should match because user keys (db_name, username) are the same
        assert compare_vault_configs(existing, user_config) is True

    def test_nested_dict_vault_defaults_ignored(self):
        """Test that Vault-added defaults in nested dicts don't affect comparison."""
        # User provided credential_config with only key_bits
        user_config = {"db_name": "mydb", "credential_type": "rsa_private_key", "credential_config": {"key_bits": 2048}}

        # Vault added algorithm default to credential_config
        existing = {
            "db_name": "mydb",
            "credential_type": "rsa_private_key",
            "credential_config": {"key_bits": 2048, "algorithm": "rsa"},  # Vault default
        }

        # Should match because user-provided keys in nested dict are the same
        assert compare_vault_configs(existing, user_config) is True

    def test_nested_dict_change_detected(self):
        """Test that changes in nested dict values are detected."""
        user_config = {"credential_config": {"key_bits": 2048}}

        existing = {"credential_config": {"key_bits": 4096}}  # Different!

        assert compare_vault_configs(existing, user_config) is False


class TestNormalizeDurationToSeconds:
    """Test the _normalize_duration_to_seconds helper function."""

    def test_integer_passthrough(self):
        """Test that integers are returned as-is."""
        assert _normalize_duration_to_seconds(86400) == 86400
        assert _normalize_duration_to_seconds(1) == 1
        assert _normalize_duration_to_seconds(3600) == 3600

    def test_hours_conversion(self):
        """Test hour-based duration strings."""
        assert _normalize_duration_to_seconds("24h") == 86400
        assert _normalize_duration_to_seconds("1h") == 3600
        assert _normalize_duration_to_seconds("72h") == 259200

    def test_minutes_conversion(self):
        """Test minute-based duration strings."""
        assert _normalize_duration_to_seconds("60m") == 3600
        assert _normalize_duration_to_seconds("1m") == 60
        assert _normalize_duration_to_seconds("90m") == 5400

    def test_seconds_conversion(self):
        """Test second-based duration strings."""
        assert _normalize_duration_to_seconds("86400s") == 86400
        assert _normalize_duration_to_seconds("1s") == 1
        assert _normalize_duration_to_seconds("3600s") == 3600

    def test_milliseconds_conversion(self):
        """Test millisecond-based duration strings."""
        assert _normalize_duration_to_seconds("1000ms") == 1
        assert _normalize_duration_to_seconds("500ms") == 0  # Rounds to 0 (banker's rounding: 0.5 → 0)
        assert _normalize_duration_to_seconds("1500ms") == 2  # Rounds to 2 (banker's rounding: 1.5 → 2)

    def test_microseconds_conversion(self):
        """Test microsecond-based duration strings."""
        assert _normalize_duration_to_seconds("1000000us") == 1
        assert _normalize_duration_to_seconds("1000000µs") == 1

    def test_nanoseconds_conversion(self):
        """Test nanosecond-based duration strings."""
        assert _normalize_duration_to_seconds("1000000000ns") == 1

    def test_decimal_duration(self):
        """Test duration strings with decimal values."""
        assert _normalize_duration_to_seconds("1.5h") == 5400  # 1.5 hours = 5400 seconds
        assert _normalize_duration_to_seconds("2.5m") == 150  # 2.5 minutes = 150 seconds

    def test_equivalent_formats(self):
        """Test that equivalent durations in different formats normalize to same value."""
        # All represent 24 hours
        assert _normalize_duration_to_seconds("24h") == 86400
        assert _normalize_duration_to_seconds("1440m") == 86400
        assert _normalize_duration_to_seconds("86400s") == 86400
        assert _normalize_duration_to_seconds(86400) == 86400

    def test_invalid_type_raises_error(self):
        """Test that invalid types raise TypeError."""
        with pytest.raises(TypeError, match="Duration must be int or str"):
            _normalize_duration_to_seconds(None)
        with pytest.raises(TypeError, match="Duration must be int or str"):
            _normalize_duration_to_seconds([1, 2, 3])
        with pytest.raises(TypeError, match="Duration must be int or str"):
            _normalize_duration_to_seconds({"duration": "24h"})

    def test_invalid_duration_string_raises_error(self):
        """Test that invalid duration strings raise TypeError."""
        # These should have been caught by validation, but test normalization fails fast
        with pytest.raises(TypeError, match="Invalid duration format"):
            _normalize_duration_to_seconds("invalid_time")
        with pytest.raises(TypeError, match="Invalid duration format"):
            _normalize_duration_to_seconds("24")  # Missing unit
        with pytest.raises(TypeError, match="Invalid duration format"):
            _normalize_duration_to_seconds("h24")  # Unit before number


class TestValidateDurationFormat:
    """Test the _validate_duration_format helper function."""

    def test_valid_integer_duration(self):
        """Test that positive integers are valid."""
        _validate_duration_format(86400, "rotation_period")
        _validate_duration_format(1, "rotation_period")
        _validate_duration_format(3600, "rotation_window")

    def test_invalid_integer_zero(self):
        """Test that zero is invalid."""
        with pytest.raises(ValueError, match="must be a positive integer"):
            _validate_duration_format(0, "rotation_period")

    def test_invalid_negative_integer(self):
        """Test that negative integers are invalid."""
        with pytest.raises(ValueError, match="must be a positive integer"):
            _validate_duration_format(-100, "rotation_period")

    def test_valid_duration_strings(self):
        """Test various valid duration string formats."""
        valid_durations = [
            "24h",
            "72h",
            "5m",
            "30s",
            "1h",
            "86400s",
            "1000ms",
            "500us",
            "500µs",
            "1000000ns",
            "1.5h",
            "2.5m",
        ]
        for duration in valid_durations:
            _validate_duration_format(duration, "rotation_period")

    def test_invalid_duration_strings(self):
        """Test invalid duration string formats."""
        invalid_durations = [
            "invalid_time",
            "24",  # Missing unit
            "h24",  # Unit before number
            "24hours",  # Invalid unit
            "24 h",  # Space between number and unit
            "",  # Empty string
            "abc",  # No number
        ]
        for duration in invalid_durations:
            with pytest.raises(ValueError, match="must be a valid duration string"):
                _validate_duration_format(duration, "rotation_period")

    def test_invalid_types(self):
        """Test that invalid types are rejected."""
        invalid_values = [
            ["list", "of", "times"],
            {"key": "value"},
            None,
            True,
            3.14,
        ]
        for value in invalid_values:
            with pytest.raises(ValueError, match="must be an integer"):
                _validate_duration_format(value, "rotation_period")


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
            static_roles.create_or_update_static_role(TEST_ROLE_NAME, "invalid_config")  # type: ignore[arg-type]
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
