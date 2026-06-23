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
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_kubernetes import (
    VaultKubernetes,
)

TEST_ROLE_NAME = "superuser"


@pytest.fixture
def vault_config():
    """Vault configuration for testing."""
    return {
        "addr": "http://mock-vault:8200",
        "token": "mock-token",
        "namespace": "root",
        "custom_mount_path": "my-ocp-cluster",
    }


@pytest.fixture
def authenticated_client(vault_config):
    """Authenticated Vault client for testing."""
    client = VaultClient(
        vault_address=vault_config["addr"],
        vault_namespace=vault_config["namespace"],
    )
    client.set_token(vault_config["token"])
    client._make_request = MagicMock()
    return client


@pytest.fixture
def mock_generate_token_response():
    """Mock response from Vault for Kubernetes token generation."""
    return {
        "request_id": "5ad6de83-134c-4f51-a003-6c2e8b6f0633",
        "lease_id": "kubernetes/creds/superuser/abc123",
        "renewable": False,
        "lease_duration": 3600,
        "data": {
            "service_account_name": "vault-secrets-superuser",
            "service_account_namespace": "kube-system",
            "service_account_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9...",
        },
    }


class TestVaultKubernetes:
    def test_generate_token_success(self, authenticated_client, mock_generate_token_response):
        authenticated_client._make_request.return_value = mock_generate_token_response

        kubernetes = VaultKubernetes(client=authenticated_client)
        token = kubernetes.generate_token(
            TEST_ROLE_NAME,
            kubernetes_namespace="kube-system",
            ttl="1h",
            audience="openshift",
        )

        expected_path = f"v1/kubernetes/creds/{TEST_ROLE_NAME}"
        expected_payload = {
            "kubernetes_namespace": "kube-system",
            "ttl": "1h",
            "audience": "openshift",
        }
        authenticated_client._make_request.assert_called_once_with(
            "POST",
            expected_path,
            json=expected_payload,
        )
        assert token == {
            "service_account_name": "vault-secrets-superuser",
            "service_account_namespace": "kube-system",
            "service_account_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9...",
            "lease_id": "kubernetes/creds/superuser/abc123",
            "lease_duration": 3600,
            "renewable": False,
        }

    def test_generate_token_custom_mount_path_success(
        self, authenticated_client, vault_config, mock_generate_token_response
    ):
        authenticated_client._make_request.return_value = mock_generate_token_response

        kubernetes = VaultKubernetes(
            client=authenticated_client,
            mount_path=vault_config["custom_mount_path"],
        )
        token = kubernetes.generate_token(TEST_ROLE_NAME)

        expected_path = f"v1/{vault_config['custom_mount_path']}/creds/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with(
            "POST",
            expected_path,
            json={},
        )
        assert token["service_account_name"] == "vault-secrets-superuser"

    def test_generate_token_omits_none_values(self, authenticated_client, mock_generate_token_response):
        authenticated_client._make_request.return_value = mock_generate_token_response

        kubernetes = VaultKubernetes(client=authenticated_client)
        kubernetes.generate_token(TEST_ROLE_NAME, ttl="1h")

        expected_path = f"v1/kubernetes/creds/{TEST_ROLE_NAME}"
        authenticated_client._make_request.assert_called_once_with(
            "POST",
            expected_path,
            json={"ttl": "1h"},
        )

    def test_generate_token_error(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultApiError("Test error")

        kubernetes = VaultKubernetes(authenticated_client)
        with pytest.raises(VaultApiError):
            kubernetes.generate_token(TEST_ROLE_NAME)
