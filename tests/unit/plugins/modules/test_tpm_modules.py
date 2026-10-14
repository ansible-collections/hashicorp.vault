# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import Mock

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import VaultConfigurationError
from ansible_collections.hashicorp.vault.plugins.modules.auth_method import (
    ensure_auth_absent,
    ensure_auth_present,
)
from ansible_collections.hashicorp.vault.plugins.modules.identity_tpm import ensure_identity_present
from ansible_collections.hashicorp.vault.plugins.modules.tpm_auth_config import ensure_config_absent
from ansible_collections.hashicorp.vault.plugins.modules.tpm_role import ensure_role_present

PEM = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n"


class ExitJson(Exception):
    def __init__(self, kwargs):
        super().__init__(kwargs)
        self.kwargs = kwargs


def _module(params, check_mode=False):
    module = Mock()
    module.params = params
    module.check_mode = check_mode
    module.exit_json.side_effect = lambda **kwargs: (_ for _ in ()).throw(ExitJson(kwargs))
    return module


def test_existing_auth_mount_is_not_enabled_again():
    module = _module(
        {
            "path": "tpm/",
            "type": "tpm",
            "description": None,
            "local": None,
            "identity_token_key": None,
            "tune": None,
        }
    )
    auth = Mock()
    auth.read_auth_method.return_value = {
        "path": "tpm",
        "type": "tpm",
        "description": "",
        "local": False,
        "accessor": "auth_tpm",
        "identity_token_key": None,
    }

    with pytest.raises(ExitJson) as exc:
        ensure_auth_present(module, auth)

    auth.enable_auth_method.assert_not_called()
    auth.tune_auth_method.assert_not_called()
    assert exc.value.kwargs["changed"] is False
    assert exc.value.kwargs["data"]["accessor"] == "auth_tpm"


def test_auth_type_conflict_fails_without_enabling():
    module = _module(
        {
            "path": "tpm",
            "type": "approle",
            "description": None,
            "local": None,
            "identity_token_key": None,
            "tune": None,
        }
    )
    auth = Mock()
    auth.read_auth_method.return_value = {
        "path": "tpm",
        "type": "tpm",
        "description": "",
        "local": False,
        "accessor": "auth_tpm",
        "identity_token_key": None,
    }

    with pytest.raises(VaultConfigurationError, match="already enabled"):
        ensure_auth_present(module, auth)

    auth.enable_auth_method.assert_not_called()


def test_auth_absent_disables_only_when_the_mount_exists():
    module = _module({"path": "tpm", "type": None})
    auth = Mock()
    auth.read_auth_method.return_value = None
    with pytest.raises(ExitJson) as exc:
        ensure_auth_absent(module, auth)
    assert exc.value.kwargs["changed"] is False
    auth.disable_auth_method.assert_not_called()


def test_config_absent_does_not_call_vault():
    module = _module({"mount": "tpm", "state": "absent"})
    tpm = Mock()
    with pytest.raises(ExitJson) as exc:
        ensure_config_absent(module, tpm)
    assert exc.value.kwargs["changed"] is False
    tpm.write_config.assert_not_called()
    tpm.read_config.assert_not_called()
    module.warn.assert_called_once()


def test_role_check_mode_does_not_write():
    module = _module(
        {
            "mount": "tpm",
            "name": "app",
            "display_name": None,
            "cert_ttl": None,
            "tpm_ids": ["a"],
            "tpmgroup_ids": None,
            "token_ttl": None,
            "token_max_ttl": None,
            "token_period": None,
            "token_explicit_max_ttl": None,
            "token_policies": ["p"],
            "token_bound_cidrs": None,
            "token_no_default_policy": None,
            "token_num_uses": None,
            "token_type": None,
            "alias_metadata": None,
        },
        check_mode=True,
    )
    tpm = Mock()
    tpm.read_role.return_value = None
    with pytest.raises(ExitJson) as exc:
        ensure_role_present(module, tpm)
    assert exc.value.kwargs["changed"] is True
    tpm.write_role.assert_not_called()


def test_role_requires_a_binding():
    module = _module({"mount": "tpm", "name": "app", "tpm_ids": None, "tpmgroup_ids": None})
    with pytest.raises(VaultConfigurationError, match="tpm_ids or tpmgroup_ids"):
        ensure_role_present(module, Mock())

    module.params["tpm_ids"] = []
    with pytest.raises(VaultConfigurationError, match="at least one id"):
        ensure_role_present(module, Mock())


def test_identity_second_run_with_whitespace_does_not_write():
    module = _module(
        {
            "name": "host",
            "tpm_ek_public_key": "  " + PEM.strip() + "\n\n",
            "device_path": None,
            "disabled": None,
            "metadata": None,
            "tpm_id": None,
        }
    )
    tpm = Mock()
    tpm.read_identity.return_value = {
        "id": "sha256-1",
        "name": "host",
        "tpm_ek_public_key": PEM,
        "disabled": False,
        "metadata": {},
    }
    with pytest.raises(ExitJson) as exc:
        ensure_identity_present(module, tpm)
    assert exc.value.kwargs["changed"] is False
    assert exc.value.kwargs["tpm_id"] == "sha256-1"
    tpm.create_identity.assert_not_called()
    tpm.update_identity.assert_not_called()
    tpm.delete_identity.assert_not_called()


def test_identity_key_change_replaces_the_record():
    module = _module(
        {
            "name": "host",
            "tpm_ek_public_key": "-----BEGIN PUBLIC KEY-----\nOTHER\n-----END PUBLIC KEY-----\n",
            "device_path": None,
            "disabled": False,
            "metadata": {"env": "prod"},
            "tpm_id": None,
        }
    )
    tpm = Mock()
    tpm.read_identity.side_effect = [
        {"id": "sha256-old", "name": "host", "tpm_ek_public_key": PEM, "disabled": False, "metadata": {}},
        {
            "id": "sha256-new",
            "name": "host",
            "tpm_ek_public_key": module.params["tpm_ek_public_key"],
            "disabled": False,
        },
    ]
    tpm.create_identity.return_value = {"id": "sha256-new", "name": "host"}
    with pytest.raises(ExitJson) as exc:
        ensure_identity_present(module, tpm)
    tpm.delete_identity.assert_called_once()
    tpm.create_identity.assert_called_once()
    assert exc.value.kwargs["changed"] is True
    assert exc.value.kwargs["tpm_id"] == "sha256-new"


def test_identity_check_mode_replace_does_not_delete():
    module = _module(
        {
            "name": "host",
            "tpm_ek_public_key": "-----BEGIN PUBLIC KEY-----\nOTHER\n-----END PUBLIC KEY-----\n",
            "device_path": None,
            "disabled": None,
            "metadata": None,
            "tpm_id": None,
        },
        check_mode=True,
    )
    tpm = Mock()
    tpm.read_identity.return_value = {"id": "sha256-old", "name": "host", "tpm_ek_public_key": PEM}
    with pytest.raises(ExitJson) as exc:
        ensure_identity_present(module, tpm)
    assert "replaced" in exc.value.kwargs["msg"]
    tpm.delete_identity.assert_not_called()
    tpm.create_identity.assert_not_called()
