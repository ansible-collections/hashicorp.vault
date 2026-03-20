# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
    VaultClient,
    VaultNamespaces,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultPermissionError,
    VaultSecretNotFoundError,
)


@pytest.fixture
def vault_config():
    return {
        'addr': 'http://mock-vault:8200',
        'token': 'mock-token',
        'namespace': 'admin',
    }


@pytest.fixture
def mock_list_namespaces_response():
    return {
        'data': {
            'keys': ['ns1/', 'ns2/', 'ns3/'],
            'key_info': {
                'ns1/': {'id': 'id-ns1', 'path': 'ns1/', 'custom_metadata': {'team': 'platform'}},
                'ns2/': {'id': 'id-ns2', 'path': 'ns2/', 'custom_metadata': {'team': 'security'}},
                'ns3/': {'id': 'id-ns3', 'path': 'ns3/', 'custom_metadata': None},
            },
        }
    }


@pytest.fixture
def mock_read_namespace_response():
    return {
        'data': {
            'id': 'id-ns1',
            'path': 'ns1/',
            'custom_metadata': {'team': 'platform', 'environment': 'production'},
        }
    }


@pytest.fixture
def authenticated_client(vault_config):
    client = VaultClient(vault_address=vault_config['addr'], vault_namespace=vault_config['namespace'])
    client.set_token(vault_config['token'])
    client._make_request = MagicMock()
    return client


class TestVaultListNamespaces:
    """Test the list_namespaces method of the VaultNamespaces class."""

    def test_list_namespaces_success(self, authenticated_client, mock_list_namespaces_response):
        """Test the list_namespaces method with a successful response."""
        authenticated_client._make_request.return_value = mock_list_namespaces_response
        namespaces = VaultNamespaces(authenticated_client)
        result = namespaces.list_namespaces()

        expected_path = 'v1/sys/namespaces'
        authenticated_client._make_request.assert_called_once_with('LIST', expected_path)
        assert len(result) == 1
        assert result == [mock_list_namespaces_response['data']]
        assert result[0]['keys'] == ['ns1/', 'ns2/', 'ns3/']
        assert result[0]['key_info']['ns1/']['id'] == 'id-ns1'

    def test_list_namespaces_empty(self, authenticated_client):
        """Test the list_namespaces method with an empty response."""
        empty_response = {'data': {'keys': [], 'key_info': {}}}
        authenticated_client._make_request.return_value = empty_response
        namespaces = VaultNamespaces(authenticated_client)
        result = namespaces.list_namespaces()

        assert result == [{'keys': [], 'key_info': {}}]

    def test_list_namespaces_keys_without_key_info(self, authenticated_client):
        """Vault may omit key_info; the data object is wrapped as a single list element."""
        authenticated_client._make_request.return_value = {'data': {'keys': ['a/', 'b/']}}
        namespaces = VaultNamespaces(authenticated_client)
        result = namespaces.list_namespaces()

        assert result == [{'keys': ['a/', 'b/']}]

    def test_list_namespaces_no_data_key(self, authenticated_client):
        """Missing data yields one empty dict in the list."""
        authenticated_client._make_request.return_value = {}
        namespaces = VaultNamespaces(authenticated_client)
        result = namespaces.list_namespaces()

        assert result == [{}]

    def test_list_namespaces_error(self, authenticated_client):
        """Test the list_namespaces method with an error response."""
        authenticated_client._make_request.side_effect = VaultPermissionError('error while listing namespaces')
        namespaces = VaultNamespaces(authenticated_client)
        with pytest.raises(VaultPermissionError):
            namespaces.list_namespaces()


class TestVaultReadNamespace:
    """Test the read_namespace method of the VaultNamespaces class."""

    def test_read_namespace_success(self, authenticated_client, mock_read_namespace_response):
        """Test the read_namespace method with a successful response."""
        authenticated_client._make_request.return_value = mock_read_namespace_response
        namespaces = VaultNamespaces(authenticated_client)
        namespace_path = 'ns1/'
        result = namespaces.read_namespace(namespace_path)

        expected_path = f'v1/sys/namespaces/{namespace_path}'
        authenticated_client._make_request.assert_called_once_with('GET', expected_path)
        assert result == mock_read_namespace_response['data']
        assert result['id'] == 'id-ns1'
        assert result['path'] == 'ns1/'
        assert result['custom_metadata']['team'] == 'platform'

    def test_read_namespace_not_found(self, authenticated_client):
        """Test the read_namespace method with a not found response."""
        authenticated_client._make_request.side_effect = VaultSecretNotFoundError('namespace not found')
        namespaces = VaultNamespaces(authenticated_client)
        with pytest.raises(VaultSecretNotFoundError):
            namespaces.read_namespace('nonexistent/')

    def test_read_namespace_permission_error(self, authenticated_client):
        """Test the read_namespace method with a permission error response."""
        authenticated_client._make_request.side_effect = VaultPermissionError('error while reading namespace')
        namespaces = VaultNamespaces(authenticated_client)
        with pytest.raises(VaultPermissionError):
            namespaces.read_namespace('ns1/')

    def test_read_namespace_no_custom_metadata(self, authenticated_client):
        """Test the read_namespace method with a no custom metadata response."""
        response = {'data': {'id': 'id-ns-minimal', 'path': 'minimal/', 'custom_metadata': None}}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)
        result = namespaces.read_namespace('minimal/')

        assert result['custom_metadata'] is None
