# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
    VaultAclPolicies,
    VaultClient,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultPermissionError,
    VaultSecretNotFoundError,
)


@pytest.fixture
def vault_config():
    """Fixture for VaultClient; acl_policy_name is a sample ACL policy name."""
    return {
        "addr": "http://mock-vault:8200",
        "token": "mock-token",
        "namespace": "admin",
        "acl_policy_name": "my-policy",
    }


@pytest.fixture
def authenticated_client(mocker, vault_config):
    client = VaultClient(vault_address=vault_config["addr"], vault_namespace=vault_config["namespace"])
    client.set_token(vault_config["token"])
    client._make_request = MagicMock()
    return client


def test_list_acl_policies_success(authenticated_client):
    response = {"policies": ["root", "deploy", "my-policy"]}
    authenticated_client._make_request.return_value = response

    policies_client = VaultAclPolicies(authenticated_client)
    result = policies_client.list_acl_policies()

    authenticated_client._make_request.assert_called_once_with("GET", "v1/sys/policy")
    assert result == ["root", "deploy", "my-policy"]


def test_list_acl_policies_empty_response(authenticated_client):
    authenticated_client._make_request.return_value = {}

    policies_client = VaultAclPolicies(authenticated_client)
    result = policies_client.list_acl_policies()

    assert result == []


def test_list_acl_policies_error(authenticated_client):
    authenticated_client._make_request.side_effect = VaultPermissionError("permission denied")
    policies_client = VaultAclPolicies(authenticated_client)

    with pytest.raises(VaultPermissionError):
        policies_client.list_acl_policies()


def test_read_acl_policy_success(authenticated_client, vault_config):
    response = {
        "name": vault_config["acl_policy_name"],
        "rules": 'path "secret/*" {\n  capabilities = ["read"]\n}',
    }
    authenticated_client._make_request.return_value = response

    policies_client = VaultAclPolicies(authenticated_client)
    result = policies_client.read_acl_policy(vault_config["acl_policy_name"])

    expected_path = f"v1/sys/policy/{vault_config['acl_policy_name']}"
    authenticated_client._make_request.assert_called_once_with("GET", expected_path)
    assert result == response
    assert result["name"] == vault_config["acl_policy_name"]
    assert "rules" in result


def test_read_acl_policy_not_found(authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = VaultSecretNotFoundError("ACL policy not found", 404, [])
    policies_client = VaultAclPolicies(authenticated_client)

    with pytest.raises(VaultSecretNotFoundError):
        policies_client.read_acl_policy(vault_config["acl_policy_name"])


def test_read_acl_policy_error(authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = VaultPermissionError("permission denied")
    policies_client = VaultAclPolicies(authenticated_client)

    with pytest.raises(VaultPermissionError):
        policies_client.read_acl_policy(vault_config["acl_policy_name"])


def test_create_or_update_acl_policy_success(authenticated_client, vault_config):
    acl_policy_rules = 'path "secret/*" {\n  capabilities = ["read"]\n}'
    authenticated_client._make_request.return_value = {}

    policies_client = VaultAclPolicies(authenticated_client)
    result = policies_client.create_or_update_acl_policy(vault_config["acl_policy_name"], acl_policy_rules)

    expected_path = f"v1/sys/policy/{vault_config['acl_policy_name']}"
    expected_body = {"policy": acl_policy_rules}
    authenticated_client._make_request.assert_called_once_with("POST", expected_path, json=expected_body)
    assert result == {}


def test_create_or_update_acl_policy_error(authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = VaultPermissionError("permission denied")
    policies_client = VaultAclPolicies(authenticated_client)

    with pytest.raises(VaultPermissionError):
        policies_client.create_or_update_acl_policy(vault_config["acl_policy_name"], 'path "secret/*" {}')


def test_create_or_update_acl_policy_type_error(authenticated_client, vault_config):
    policies_client = VaultAclPolicies(authenticated_client)

    with pytest.raises(TypeError, match="ACL policy rules must be a string"):
        policies_client.create_or_update_acl_policy(vault_config["acl_policy_name"], {"key": "value"})


def test_delete_acl_policy_success(authenticated_client, vault_config):
    policies_client = VaultAclPolicies(authenticated_client)
    policies_client.delete_acl_policy(vault_config["acl_policy_name"])

    expected_path = f"v1/sys/policy/{vault_config['acl_policy_name']}"
    authenticated_client._make_request.assert_called_once_with("DELETE", expected_path)


def test_delete_acl_policy_error(authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = VaultPermissionError("permission denied")
    policies_client = VaultAclPolicies(authenticated_client)

    with pytest.raises(VaultPermissionError):
        policies_client.delete_acl_policy(vault_config["acl_policy_name"])


def test_vault_client_has_acl_policies_attr(vault_config):
    client = VaultClient(vault_address=vault_config["addr"], vault_namespace=vault_config["namespace"])
    assert hasattr(client, "acl_policies")
    assert isinstance(client.acl_policies, VaultAclPolicies)
