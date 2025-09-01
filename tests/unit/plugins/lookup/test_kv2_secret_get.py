from unittest.mock import Mock, patch

import pytest

from ansible_collections.hashicorp.vault.plugins.lookup.kv2_secret_get import LookupModule


@pytest.fixture
def lookup_plugin():
    """Fixture providing a properly initialized LookupModule instance."""
    plugin = LookupModule()
    # Mock required Ansible plugin attributes
    plugin._load_name = "kv2_secret_get"
    plugin._original_path = "test_path"
    plugin.set_options = Mock()
    return plugin


@pytest.fixture
def mock_vault_client():
    """Fixture providing a mock VaultClient."""
    return Mock()


@pytest.fixture
def mock_vault_secrets():
    """Fixture providing a mock VaultSecret manager."""
    mock_secrets = Mock()
    mock_kv2 = Mock()
    mock_secrets.kv2 = mock_kv2
    return mock_secrets, mock_kv2


@pytest.fixture
def sample_secret_data():
    """Fixture providing sample secret data."""
    return {
        "data": {"username": "admin", "password": "secret123"},
        "metadata": {
            "created_time": "2024-01-15T10:30:00.0000000Z",
            "custom_metadata": None,
            "deletion_time": "",
            "destroyed": False,
            "version": 2,
        },
    }


class TestKv2SecretGetLookup:
    """Test the kv2_secret_get lookup plugin."""

    def mock_get_option(self, opt):
        options = {
            "version": None,
            "engine_mount_point": "secret",
            "secret": "test",
            "namespace": "admin",
            "url": "https://vault.example.com:8200",
        }
        return options.get(opt)

    @pytest.mark.parametrize(
        "test_case",
        [
            {
                "description": "default options",
                "options": {
                    "version": None,
                    "engine_mount_point": "secret",
                    "secret": "myapp/config",
                    "namespace": "admin",
                    "url": "https://vault.example.com:8200",
                },
                "expected_call": {
                    "mount_path": "secret",
                    "secret_path": "myapp/config",
                    "version": None,
                },
            },
            {
                "description": "with version",
                "options": {
                    "version": 5,
                    "engine_mount_point": "secret",
                    "secret": "myapp/config",
                    "namespace": "admin",
                    "url": "https://vault.example.com:8200",
                },
                "expected_call": {
                    "mount_path": "secret",
                    "secret_path": "myapp/config",
                    "version": 5,
                },
            },
            {
                "description": "custom mount point",
                "options": {
                    "version": None,
                    "engine_mount_point": "custom-kv2",
                    "secret": "myapp/config",
                    "namespace": "admin",
                    "url": "https://vault.example.com:8200",
                },
                "expected_call": {
                    "mount_path": "custom-kv2",
                    "secret_path": "myapp/config",
                    "version": None,
                },
            },
        ],
    )
    def test_run_success_combinations(
        self, lookup_plugin, mock_vault_client, mock_vault_secrets, sample_secret_data, test_case
    ):
        """Test successful secret retrieval with various option combinations."""
        mock_secrets, mock_kv2 = mock_vault_secrets
        mock_kv2.read_secret.return_value = sample_secret_data

        with patch.object(lookup_plugin, "get_option") as mock_get_option, patch(
            "ansible_collections.hashicorp.vault.plugins.lookup.kv2_secret_get.VaultSecret",
            return_value=mock_secrets,
        ), patch(
            "ansible_collections.hashicorp.vault.plugins.plugin_utils.base.VaultClient",
            return_value=mock_vault_client,
        ), patch.object(
            lookup_plugin, "_authenticate"
        ):

            mock_get_option.side_effect = test_case["options"].get

            result = lookup_plugin.run([], {})

            assert result == [sample_secret_data]
            mock_kv2.read_secret.assert_called_once_with(**test_case["expected_call"])

    def test_run_with_base_class_initialization(self, lookup_plugin, mock_vault_client):
        """Test that the run method properly calls parent class initialization."""
        with patch.object(lookup_plugin, "get_option") as mock_get_option, patch(
            "ansible_collections.hashicorp.vault.plugins.lookup.kv2_secret_get.VaultSecret"
        ) as mock_vault_secret, patch(
            "ansible_collections.hashicorp.vault.plugins.plugin_utils.base.VaultClient"
        ) as mock_vault_client_class, patch.object(
            lookup_plugin, "_authenticate"
        ) as mock_auth:

            mock_vault_client_class.return_value = mock_vault_client

            mock_get_option.side_effect = self.mock_get_option

            mock_vault_secret.return_value.kv2.read_secret.return_value = {}

            test_terms = ["test_term"]
            test_variables = {"test_var": "value"}
            test_kwargs = {"test_kwarg": "value"}

            lookup_plugin.run(test_terms, test_variables, **test_kwargs)

            # Verify that VaultClient was created with correct parameters
            mock_vault_client_class.assert_called_once_with(
                vault_address="https://vault.example.com:8200", vault_namespace="admin"
            )

            # Verify authentication was called
            mock_auth.assert_called_once()

            # Verify VaultSecret was initialized with the client
            mock_vault_secret.assert_called_once_with(mock_vault_client)

    @pytest.mark.parametrize(
        "test_case",
        [
            {
                "description": "minimal parameters",
                "options": {
                    "version": None,
                    "engine_mount_point": "secret",
                    "secret": "app/config",
                    "namespace": "admin",
                    "url": "https://vault.example.com:8200",
                },
                "expected_call": {
                    "mount_path": "secret",
                    "secret_path": "app/config",
                    "version": None,
                },
            },
            {
                "description": "with version and custom mount",
                "options": {
                    "version": 3,
                    "engine_mount_point": "team-secrets",
                    "secret": "api/keys",
                    "namespace": "admin",
                    "url": "https://vault.example.com:8200",
                },
                "expected_call": {
                    "mount_path": "team-secrets",
                    "secret_path": "api/keys",
                    "version": 3,
                },
            },
            {
                "description": "nested secret path",
                "options": {
                    "version": 1,
                    "engine_mount_point": "prod",
                    "secret": "database/postgres/credentials",
                    "namespace": "admin",
                    "url": "https://vault.example.com:8200",
                },
                "expected_call": {
                    "mount_path": "prod",
                    "secret_path": "database/postgres/credentials",
                    "version": 1,
                },
            },
        ],
    )
    def test_parameter_combinations(
        self, lookup_plugin, mock_vault_client, mock_vault_secrets, sample_secret_data, test_case
    ):
        """Test various parameter combinations."""
        mock_secrets, mock_kv2 = mock_vault_secrets
        mock_kv2.read_secret.return_value = sample_secret_data

        with patch.object(lookup_plugin, "get_option") as mock_get_option, patch(
            "ansible_collections.hashicorp.vault.plugins.lookup.kv2_secret_get.VaultSecret",
            return_value=mock_secrets,
        ), patch(
            "ansible_collections.hashicorp.vault.plugins.plugin_utils.base.VaultClient",
            return_value=mock_vault_client,
        ), patch.object(
            lookup_plugin, "_authenticate"
        ):

            mock_get_option.side_effect = test_case["options"].get

            result = lookup_plugin.run([], {})

            assert result == [sample_secret_data], f"Failed for case: {test_case['description']}"
            mock_kv2.read_secret.assert_called_with(**test_case["expected_call"])

    def test_vault_secret_manager_initialization(
        self, lookup_plugin, mock_vault_client, mock_vault_secrets
    ):
        """Test that VaultSecret is properly initialized with the client."""
        mock_secrets, mock_kv2 = mock_vault_secrets
        mock_kv2.read_secret.return_value = {}

        with patch.object(lookup_plugin, "get_option") as mock_get_option, patch(
            "ansible_collections.hashicorp.vault.plugins.lookup.kv2_secret_get.VaultSecret"
        ) as mock_vault_secret_class, patch(
            "ansible_collections.hashicorp.vault.plugins.plugin_utils.base.VaultClient",
            return_value=mock_vault_client,
        ), patch.object(
            lookup_plugin, "_authenticate"
        ):

            mock_vault_secret_class.return_value = mock_secrets
            mock_get_option.side_effect = self.mock_get_option

            lookup_plugin.run([], {})

            # Verify VaultSecret was initialized with the client
            mock_vault_secret_class.assert_called_once_with(mock_vault_client)

    @pytest.mark.parametrize("missing_option", ["secret", "engine_mount_point"])
    def test_missing_required_options(
        self, lookup_plugin, mock_vault_client, mock_vault_secrets, missing_option
    ):
        """Test behavior when required options are missing."""
        mock_secrets, mock_kv2 = mock_vault_secrets

        with patch.object(lookup_plugin, "get_option") as mock_get_option, patch(
            "ansible_collections.hashicorp.vault.plugins.lookup.kv2_secret_get.VaultSecret",
            return_value=mock_secrets,
        ), patch(
            "ansible_collections.hashicorp.vault.plugins.plugin_utils.base.VaultClient",
            return_value=mock_vault_client,
        ), patch.object(
            lookup_plugin, "_authenticate"
        ):

            # Return None for the missing option
            mock_get_option.side_effect = lambda opt: (
                None
                if opt == missing_option
                else {
                    "version": None,
                    "engine_mount_point": "secret",
                    "secret": "test",
                    "namespace": "admin",
                    "url": "https://vault.example.com:8200",
                }.get(opt, None)
            )

            # This should proceed to the vault call which may raise an exception
            # The actual validation happens in the vault client layer
            lookup_plugin.run([], {})

    def test_return_format(
        self, lookup_plugin, mock_vault_client, mock_vault_secrets, sample_secret_data
    ):
        """Test that the return format is correctly structured."""
        mock_secrets, mock_kv2 = mock_vault_secrets
        mock_kv2.read_secret.return_value = sample_secret_data

        with patch.object(lookup_plugin, "get_option") as mock_get_option, patch(
            "ansible_collections.hashicorp.vault.plugins.lookup.kv2_secret_get.VaultSecret",
            return_value=mock_secrets,
        ), patch(
            "ansible_collections.hashicorp.vault.plugins.plugin_utils.base.VaultClient",
            return_value=mock_vault_client,
        ), patch.object(
            lookup_plugin, "_authenticate"
        ):

            mock_get_option.side_effect = self.mock_get_option

            result = lookup_plugin.run([], {})

            # Should return a list with one item (the secret data)
            assert isinstance(result, list)
            assert len(result) == 1
            assert result[0] == sample_secret_data
            assert "data" in result[0]
            assert "metadata" in result[0]
            assert result[0]["data"]["username"] == "admin"
            assert result[0]["metadata"]["version"] == 2
