# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock, Mock

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_methods import (
    VaultAuthMethods,
    plan_auth_change,
    resolve_auth_path,
    vault_path,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultClient
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultConfigurationError,
)


def _mount(auth_type="tpm", description="", local=False, accessor="auth_123"):
    return {
        "path": "tpm",
        "type": auth_type,
        "description": description,
        "local": local,
        "accessor": accessor,
        "identity_token_key": None,
    }


def test_vault_path_quotes_segments():
    assert vault_path("sys/auth", "tpm") == "v1/sys/auth/tpm"
    assert vault_path("auth", "/tpm/", "role", "app server") == "v1/auth/tpm/role/app%20server"


def test_resolve_auth_path_defaults_to_type():
    assert resolve_auth_path(None, "userpass") == "userpass"
    assert resolve_auth_path("tpm/", "userpass") == "tpm"


def test_resolve_auth_path_requires_a_path():
    with pytest.raises(VaultConfigurationError):
        resolve_auth_path(None, None)


def test_plan_enables_a_missing_mount():
    plan = plan_auth_change(None, {"path": "tpm", "type": "tpm", "tune": {"default_lease_ttl": "1h"}})
    assert plan == {"action": "enable", "tune": {"default_lease_ttl": "1h"}}


def test_plan_leaves_an_existing_mount_of_the_same_type():
    plan = plan_auth_change(_mount(), {"path": "tpm", "type": "tpm", "description": None, "local": None, "tune": None})
    assert plan["action"] == "unchanged"
    assert plan["tune"] == {}


def test_plan_rejects_a_different_type():
    with pytest.raises(VaultConfigurationError, match="already enabled with type"):
        plan_auth_change(_mount(auth_type="userpass"), {"path": "tpm", "type": "tpm"})


def test_plan_rejects_changing_local():
    with pytest.raises(VaultConfigurationError, match="Changing local"):
        plan_auth_change(_mount(local=False), {"path": "tpm", "type": "tpm", "local": True})


def test_plan_tunes_description_and_duration():
    plan = plan_auth_change(
        _mount(description="old"),
        {
            "path": "tpm",
            "type": "tpm",
            "description": "new",
            "tune": {"default_lease_ttl": "1h", "max_lease_ttl": None},
        },
        current_tune={"default_lease_ttl": 60},
    )
    assert plan["action"] == "tune"
    assert plan["tune"]["description"] == "new"
    assert plan["tune"]["default_lease_ttl"] == "1h"


def test_plan_treats_matching_duration_as_unchanged():
    plan = plan_auth_change(
        _mount(),
        {"path": "tpm", "type": "tpm", "tune": {"default_lease_ttl": "1h"}},
        current_tune={"default_lease_ttl": 3600},
    )
    assert plan["action"] == "unchanged"


def test_plan_skips_identity_token_key_when_vault_does_not_return_it():
    existing = _mount()
    existing["identity_token_key"] = None
    plan = plan_auth_change(existing, {"path": "tpm", "type": "tpm", "identity_token_key": "signing-key"})
    assert plan["action"] == "unchanged"


def test_plan_tunes_identity_token_key_when_the_returned_value_differs():
    existing = _mount()
    existing["identity_token_key"] = "old"
    plan = plan_auth_change(existing, {"path": "tpm", "type": "tpm", "identity_token_key": "new"})
    assert plan["tune"]["identity_token_key"] == "new"


def test_read_auth_method_strips_the_catalog_slash():
    client = Mock()
    client._make_request.return_value = {
        "data": {
            "tpm/": {"type": "tpm", "description": "machines", "local": False, "accessor": "auth_tpm"},
            "request_id": "not-a-mount",
        }
    }
    auth = VaultAuthMethods(client)
    mount = auth.read_auth_method("tpm")
    assert mount["type"] == "tpm"
    assert mount["accessor"] == "auth_tpm"
    assert mount["path"] == "tpm"
    client._make_request.assert_called_once_with("GET", "v1/sys/auth")


def test_read_auth_method_missing():
    client = Mock()
    client._make_request.return_value = {"data": {}}
    assert VaultAuthMethods(client).read_auth_method("tpm") is None


def test_enable_and_tune_and_disable_paths():
    client = Mock()
    client._make_request.return_value = {}
    auth = VaultAuthMethods(client)

    auth.enable_auth_method("tpm", "tpm", description="machines", local=False, identity_token_key="key-1")
    auth.tune_auth_method("tpm", {"default_lease_ttl": "1h"})
    auth.disable_auth_method("tpm")

    assert client._make_request.call_args_list[0].args == ("POST", "v1/sys/auth/tpm")
    assert client._make_request.call_args_list[0].kwargs["json"] == {
        "type": "tpm",
        "description": "machines",
        "local": False,
        "config": {"identity_token_key": "key-1"},
    }
    assert client._make_request.call_args_list[1].args == ("POST", "v1/sys/mounts/auth/tpm/tune")
    assert client._make_request.call_args_list[2].args == ("DELETE", "v1/sys/auth/tpm")


def test_vault_client_exposes_auth_methods():
    client = VaultClient(vault_address="http://vault.example:8200", vault_namespace="admin")
    assert isinstance(client.auth_methods, VaultAuthMethods)


def test_list_auth_methods_uses_the_client():
    client = MagicMock()
    client._make_request.return_value = {"data": {"token/": {"type": "token"}}}
    mounts = VaultAuthMethods(client).list_auth_methods()
    assert list(mounts) == ["token"]
