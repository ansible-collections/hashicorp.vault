# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import Mock

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultClient
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import VaultSecretNotFoundError
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_tpm import (
    VaultTpm,
    decide_config_action,
    decide_group_action,
    decide_identity_action,
    decide_role_action,
    group_result,
    identity_result,
    normalize_pem,
    record_matches,
)

PEM = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n"


def test_normalize_pem_ignores_surrounding_whitespace():
    assert normalize_pem("  " + PEM.strip() + "  \n") == PEM


def test_record_matches_compares_id_lists_as_sets_and_ignores_unset_fields():
    existing = {"tpm_ids": ["b", "a"], "token_ttl": 3600, "display_name": "kept"}
    assert record_matches(existing, {"tpm_ids": ["a", "b"], "token_ttl": "3600"})
    assert not record_matches(existing, {"tpm_ids": ["a"]})


def test_record_matches_treats_false_token_flag_as_unset():
    assert record_matches({}, {"token_no_default_policy": False})
    assert not record_matches({}, {"token_no_default_policy": True})


def test_record_matches_treats_zero_ttl_as_unset_when_vault_omits_it():
    assert record_matches({}, {"cert_ttl": 0, "token_ttl": 0})
    assert not record_matches({"cert_ttl": 30}, {"cert_ttl": 0})


def test_decide_config_action():
    assert decide_config_action(None, {}) == "missing"
    assert decide_config_action({"ca_lifetime": 10}, {}) == "unchanged"
    assert decide_config_action({"ca_lifetime": 10}, {"ca_lifetime": 10}) == "unchanged"
    assert decide_config_action({"ca_lifetime": 10}, {"ca_lifetime": 20}) == "write"
    assert decide_config_action(None, {"default_cert_ttl": 0}) == "write"


def test_decide_role_action():
    desired = {"tpm_ids": ["a"], "token_policies": ["p"]}
    assert decide_role_action(None, desired) == "create"
    assert decide_role_action({"tpm_ids": ["a"], "token_policies": ["p"], "token_ttl": 1}, desired) == "unchanged"
    assert decide_role_action({"tpm_ids": ["a"], "token_policies": ["other"]}, desired) == "update"


def test_decide_identity_action_replaces_only_when_the_key_material_changes():
    existing = {"id": "sha256-1", "name": "host", "tpm_ek_public_key": PEM, "disabled": False, "metadata": {}}
    assert decide_identity_action(existing, {"tpm_ek_public_key": "  " + PEM.strip()}) == "unchanged"
    assert decide_identity_action(None, {"tpm_ek_public_key": PEM}) == "create"
    assert decide_identity_action(existing, {"tpm_ek_public_key": PEM, "disabled": True}) == "update"
    replaced = "-----BEGIN PUBLIC KEY-----\nOTHER\n-----END PUBLIC KEY-----\n"
    assert decide_identity_action(existing, {"tpm_ek_public_key": replaced}) == "replace"


def test_decide_group_action_ignores_member_order():
    existing = {"id": "g1", "name": "prod", "member_tpm_ids": ["b", "a"], "metadata": {"env": "prod"}}
    assert decide_group_action(existing, {"member_tpm_ids": ["a", "b"], "metadata": {"env": "prod"}}) == "unchanged"
    assert decide_group_action(existing, {"member_tpm_ids": ["a"]}) == "update"
    assert decide_group_action(None, {"name": "prod"}) == "create"


def test_result_helpers_rename_vault_ids():
    assert identity_result({"id": "sha256-1", "name": "host", "disabled": False})["tpm_id"] == "sha256-1"
    assert group_result({"id": "g1", "member_tpm_ids": None})["tpm_group_id"] == "g1"


def test_identity_paths_and_not_found():
    client = Mock()
    client._make_request.side_effect = [
        {"data": {"id": "sha256-1", "name": "host", "tpm_ek_public_key": PEM}},
        VaultSecretNotFoundError("missing", 404, []),
        {},
    ]
    tpm = VaultTpm(client)

    created = tpm.create_identity({"name": "host", "tpm_ek_public_key": PEM})
    assert created["id"] == "sha256-1"
    assert tpm.read_identity(name="missing") is None
    tpm.delete_identity(tpm_id="sha256-1")

    assert client._make_request.call_args_list[0].args == ("POST", "v1/identity/tpm")
    assert client._make_request.call_args_list[1].args == ("GET", "v1/identity/tpm/name/missing")
    assert client._make_request.call_args_list[2].args == ("DELETE", "v1/identity/tpm/id/sha256-1")


def test_role_and_config_and_group_paths():
    client = Mock()
    client._make_request.return_value = {"data": {"id": "g1", "cert_ttl": 0}}
    tpm = VaultTpm(client)

    tpm.write_config("tpm", {"ca_lifetime": 10})
    tpm.read_role("tpm", "app")
    tpm.write_role("tpm", "app", {"tpm_ids": ["a"]})
    tpm.delete_role("tpm", "app")
    tpm.create_group({"name": "prod", "member_tpm_ids": ["a"]})
    tpm.update_group({"member_tpm_ids": ["a", "b"]}, tpm_group_id="g1")
    tpm.read_group(name="prod")

    paths = [call.args[1] for call in client._make_request.call_args_list]
    assert paths == [
        "v1/auth/tpm/config",
        "v1/auth/tpm/role/app",
        "v1/auth/tpm/role/app",
        "v1/auth/tpm/role/app",
        "v1/identity/tpmgroup",
        "v1/identity/tpmgroup/id/g1",
        "v1/identity/tpmgroup/name/prod",
    ]


def test_delete_role_ignores_404():
    client = Mock()
    client._make_request.side_effect = VaultSecretNotFoundError("gone", 404, [])
    VaultTpm(client).delete_role("tpm", "app")


def test_get_404_returns_none_and_post_404_raises():
    client = Mock()
    client._make_request.side_effect = VaultSecretNotFoundError("missing", 404, [])
    with pytest.raises(VaultSecretNotFoundError):
        VaultTpm(client).create_identity({"name": "host"})


def test_vault_client_exposes_tpm():
    client = VaultClient(vault_address="http://vault.example:8200", vault_namespace="admin")
    assert isinstance(client.tpm, VaultTpm)
