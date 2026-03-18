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
    """Empty GET /sys/policy, LIST and GET ?list=true yield no names -> []."""
    authenticated_client._make_request.side_effect = [
        {},
        {"keys": []},
        {},
    ]

    policies_client = VaultAclPolicies(authenticated_client)
    result = policies_client.list_acl_policies()

    assert result == []
    assert authenticated_client._make_request.call_count == 3


def test_list_acl_policies_fallback_sys_policies_acl(authenticated_client):
    authenticated_client._make_request.side_effect = [
        {"policies": []},
        {"keys": ["default", "my-policy"]},
    ]

    policies_client = VaultAclPolicies(authenticated_client)
    result = policies_client.list_acl_policies()

    assert result == ["default", "my-policy"]
    authenticated_client._make_request.assert_any_call("GET", "v1/sys/policy")
    authenticated_client._make_request.assert_any_call("LIST", "v1/sys/policies/acl")


def test_list_acl_policies_list_acl_permission_denied_returns_empty(authenticated_client):
    authenticated_client._make_request.side_effect = [
        {"policies": []},
        VaultPermissionError("denied"),
        VaultPermissionError("denied"),
    ]

    policies_client = VaultAclPolicies(authenticated_client)
    result = policies_client.list_acl_policies()

    assert result == []


def test_list_acl_policies_sys_policies_acl_data_keys(authenticated_client):
    """HCP-style JSON wraps list results under data.keys."""
    authenticated_client._make_request.side_effect = [
        {"policies": []},
        {"data": {"keys": ["default", "ansible-test"]}},
    ]

    policies_client = VaultAclPolicies(authenticated_client)
    result = policies_client.list_acl_policies()

    assert result == ["default", "ansible-test"]
    authenticated_client._make_request.assert_any_call("LIST", "v1/sys/policies/acl")


def test_list_acl_policies_get_list_true_fallback(authenticated_client):
    """When LIST fails, GET ?list=true may still return policy names."""
    authenticated_client._make_request.side_effect = [
        {"policies": []},
        VaultPermissionError("LIST not allowed"),
        {"data": {"keys": ["p1"]}},
    ]

    policies_client = VaultAclPolicies(authenticated_client)
    result = policies_client.list_acl_policies()

    assert result == ["p1"]
    authenticated_client._make_request.assert_any_call(
        "GET",
        "v1/sys/policies/acl",
        params={"list": "true"},
    )


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
    assert result["name"] == vault_config["acl_policy_name"]
    assert result["rules"] == response["rules"]


def test_read_acl_policy_fallback_sys_policies_acl_when_rules_empty(authenticated_client, vault_config):
    """HCP and some servers return empty rules on /sys/policy; body is on /sys/policies/acl."""
    name = vault_config["acl_policy_name"]
    body = 'path "secret/*" { capabilities = ["read"] }'
    authenticated_client._make_request.side_effect = [
        {"name": name, "rules": ""},
        {"name": name, "policy": body},
    ]

    policies_client = VaultAclPolicies(authenticated_client)
    result = policies_client.read_acl_policy(name)

    assert result == {"name": name, "rules": body}
    assert authenticated_client._make_request.call_count == 2
    authenticated_client._make_request.assert_any_call("GET", f"v1/sys/policy/{name}")
    authenticated_client._make_request.assert_any_call("GET", f"v1/sys/policies/acl/{name}")


def test_read_acl_policy_data_wrapper_rules(authenticated_client, vault_config):
    name = vault_config["acl_policy_name"]
    body = "path \"x\" {}"
    authenticated_client._make_request.return_value = {
        "data": {"name": name, "rules": body},
    }
    policies_client = VaultAclPolicies(authenticated_client)
    result = policies_client.read_acl_policy(name)
    assert result["rules"] == body
    authenticated_client._make_request.assert_called_once()


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
