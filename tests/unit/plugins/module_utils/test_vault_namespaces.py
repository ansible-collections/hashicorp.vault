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
        namespace_path = 'ns1'
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
            namespaces.read_namespace('nonexistent')

    def test_read_namespace_permission_error(self, authenticated_client):
        """Test the read_namespace method with a permission error response."""
        authenticated_client._make_request.side_effect = VaultPermissionError('error while reading namespace')
        namespaces = VaultNamespaces(authenticated_client)
        with pytest.raises(VaultPermissionError):
            namespaces.read_namespace('ns1')

    def test_read_namespace_no_custom_metadata(self, authenticated_client):
        """Test the read_namespace method with a no custom metadata response."""
        response = {'data': {'id': 'id-ns-minimal', 'path': 'minimal/', 'custom_metadata': None}}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)
        result = namespaces.read_namespace('minimal')

        assert result['custom_metadata'] is None


class TestVaultCreateNamespace:
    """Test the create_namespace method of the VaultNamespaces class."""

    def test_create_namespace_with_metadata(self, authenticated_client):
        """Test creating a namespace with custom metadata."""
        response = {'data': {'id': 'new-id', 'path': 'engineering/'}}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)
        custom_metadata = {'team': 'platform', 'environment': 'prod'}

        result = namespaces.create_namespace('engineering', custom_metadata=custom_metadata)

        expected_path = 'v1/sys/namespaces/engineering'
        authenticated_client._make_request.assert_called_once_with(
            'POST', expected_path, json={'custom_metadata': custom_metadata}
        )
        assert result == response

    def test_create_namespace_without_metadata(self, authenticated_client):
        """Test creating a namespace without custom metadata."""
        response = {'data': {'id': 'new-id', 'path': 'qa/'}}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)

        result = namespaces.create_namespace('qa')

        expected_path = 'v1/sys/namespaces/qa'
        authenticated_client._make_request.assert_called_once_with('POST', expected_path, json={})
        assert result == response

    def test_create_namespace_with_none_metadata(self, authenticated_client):
        """Test creating a namespace with None as metadata."""
        response = {'data': {'id': 'new-id', 'path': 'dev/'}}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)

        result = namespaces.create_namespace('dev', custom_metadata=None)

        expected_path = 'v1/sys/namespaces/dev'
        authenticated_client._make_request.assert_called_once_with('POST', expected_path, json={})
        assert result == response

    def test_create_namespace_invalid_metadata_type(self, authenticated_client):
        """Test creating a namespace with invalid metadata type."""
        namespaces = VaultNamespaces(authenticated_client)

        with pytest.raises(TypeError, match='custom_metadata must be a dict'):
            namespaces.create_namespace('test', custom_metadata='invalid')

    def test_create_namespace_error(self, authenticated_client):
        """Test creating a namespace with an error response."""
        authenticated_client._make_request.side_effect = VaultPermissionError('error creating namespace')
        namespaces = VaultNamespaces(authenticated_client)

        with pytest.raises(VaultPermissionError):
            namespaces.create_namespace('forbidden')


class TestVaultPatchNamespace:
    """Test the patch_namespace method of the VaultNamespaces class."""

    def test_patch_namespace_success(self, authenticated_client):
        """Test patching a namespace with custom metadata."""
        response = {}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)
        custom_metadata = {'owner': 'alice', 'cost_center': '1234'}

        result = namespaces.patch_namespace('engineering', custom_metadata)

        expected_path = 'v1/sys/namespaces/engineering'
        authenticated_client._make_request.assert_called_once_with(
            'PATCH',
            expected_path,
            json={'custom_metadata': custom_metadata},
            headers={'Content-Type': 'application/merge-patch+json'},
        )
        assert result == response

    def test_patch_namespace_without_metadata(self, authenticated_client):
        """Test patching a namespace without custom metadata."""
        response = {}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)

        result = namespaces.patch_namespace('engineering')

        expected_path = 'v1/sys/namespaces/engineering'
        authenticated_client._make_request.assert_called_once_with(
            'PATCH', expected_path, json={}, headers={'Content-Type': 'application/merge-patch+json'}
        )
        assert result == response

    def test_patch_namespace_with_none_metadata(self, authenticated_client):
        """Test patching a namespace with None as metadata."""
        response = {}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)

        result = namespaces.patch_namespace('engineering', custom_metadata=None)

        expected_path = 'v1/sys/namespaces/engineering'
        authenticated_client._make_request.assert_called_once_with(
            'PATCH', expected_path, json={}, headers={'Content-Type': 'application/merge-patch+json'}
        )
        assert result == response

    def test_patch_namespace_invalid_metadata_type(self, authenticated_client):
        """Test patching a namespace with invalid metadata type."""
        namespaces = VaultNamespaces(authenticated_client)

        with pytest.raises(TypeError, match='custom_metadata must be a dict'):
            namespaces.patch_namespace('test', custom_metadata='invalid')

    def test_patch_namespace_not_found(self, authenticated_client):
        """Test patching a non-existent namespace."""
        authenticated_client._make_request.side_effect = VaultSecretNotFoundError('namespace not found')
        namespaces = VaultNamespaces(authenticated_client)

        with pytest.raises(VaultSecretNotFoundError):
            namespaces.patch_namespace('nonexistent', {'key': 'value'})


class TestVaultDeleteNamespace:
    """Test the delete_namespace method of the VaultNamespaces class."""

    def test_delete_namespace_success(self, authenticated_client):
        """Test deleting a namespace."""
        authenticated_client._make_request.return_value = {}
        namespaces = VaultNamespaces(authenticated_client)

        result = namespaces.delete_namespace('old-namespace')

        expected_path = 'v1/sys/namespaces/old-namespace'
        authenticated_client._make_request.assert_called_once_with('DELETE', expected_path)
        assert result is None

    def test_delete_namespace_not_found(self, authenticated_client):
        """Test deleting a non-existent namespace."""
        authenticated_client._make_request.side_effect = VaultSecretNotFoundError('namespace not found')
        namespaces = VaultNamespaces(authenticated_client)

        with pytest.raises(VaultSecretNotFoundError):
            namespaces.delete_namespace('nonexistent')

    def test_delete_namespace_permission_error(self, authenticated_client):
        """Test deleting a namespace with insufficient permissions."""
        authenticated_client._make_request.side_effect = VaultPermissionError('permission denied')
        namespaces = VaultNamespaces(authenticated_client)

        with pytest.raises(VaultPermissionError):
            namespaces.delete_namespace('protected')


class TestVaultLockNamespace:
    """Test the lock_namespace method of the VaultNamespaces class."""

    def test_lock_namespace_current(self, authenticated_client):
        """Test locking the current namespace."""
        response = {'unlock_key': 'test-unlock-key-123'}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)

        result = namespaces.lock_namespace()

        expected_path = 'v1/sys/namespaces/api-lock/lock'
        authenticated_client._make_request.assert_called_once_with('POST', expected_path, json={})
        assert result == response
        assert result['unlock_key'] == 'test-unlock-key-123'

    def test_lock_namespace_with_subpath(self, authenticated_client):
        """Test locking a namespace subpath."""
        response = {'unlock_key': 'subpath-unlock-key'}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)

        result = namespaces.lock_namespace(subpath='child')

        expected_path = 'v1/sys/namespaces/api-lock/lock/child'
        authenticated_client._make_request.assert_called_once_with('POST', expected_path, json={})
        assert result == response

    def test_lock_namespace_error(self, authenticated_client):
        """Test locking a namespace with an error response."""
        authenticated_client._make_request.side_effect = VaultPermissionError('cannot lock namespace')
        namespaces = VaultNamespaces(authenticated_client)

        with pytest.raises(VaultPermissionError):
            namespaces.lock_namespace()


class TestVaultUnlockNamespace:
    """Test the unlock_namespace method of the VaultNamespaces class."""

    def test_unlock_namespace_with_key(self, authenticated_client):
        """Test unlocking the current namespace with an unlock key."""
        response = {}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)
        unlock_key = 'test-unlock-key-123'

        result = namespaces.unlock_namespace(unlock_key=unlock_key)

        expected_path = 'v1/sys/namespaces/api-lock/unlock'
        authenticated_client._make_request.assert_called_once_with(
            'POST', expected_path, json={'unlock_key': unlock_key}
        )
        assert result == response

    def test_unlock_namespace_without_key(self, authenticated_client):
        """Test unlocking as root (no key needed)."""
        response = {}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)

        result = namespaces.unlock_namespace()

        expected_path = 'v1/sys/namespaces/api-lock/unlock'
        authenticated_client._make_request.assert_called_once_with('POST', expected_path, json={})
        assert result == response

    def test_unlock_namespace_with_subpath(self, authenticated_client):
        """Test unlocking a namespace subpath."""
        response = {}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)
        unlock_key = 'subpath-unlock-key'

        result = namespaces.unlock_namespace(subpath='child', unlock_key=unlock_key)

        expected_path = 'v1/sys/namespaces/api-lock/unlock/child'
        authenticated_client._make_request.assert_called_once_with(
            'POST', expected_path, json={'unlock_key': unlock_key}
        )
        assert result == response

    def test_unlock_namespace_subpath_without_key(self, authenticated_client):
        """Test unlocking a subpath as root (no key needed)."""
        response = {}
        authenticated_client._make_request.return_value = response
        namespaces = VaultNamespaces(authenticated_client)

        result = namespaces.unlock_namespace(subpath='child')

        expected_path = 'v1/sys/namespaces/api-lock/unlock/child'
        authenticated_client._make_request.assert_called_once_with('POST', expected_path, json={})
        assert result == response

    def test_unlock_namespace_error(self, authenticated_client):
        """Test unlocking a namespace with an error response."""
        authenticated_client._make_request.side_effect = VaultPermissionError('cannot unlock namespace')
        namespaces = VaultNamespaces(authenticated_client)

        with pytest.raises(VaultPermissionError):
            namespaces.unlock_namespace(unlock_key='invalid-key')
