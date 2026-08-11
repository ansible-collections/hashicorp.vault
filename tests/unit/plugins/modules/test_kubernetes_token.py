# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE = "ansible_collections.hashicorp.vault.plugins.modules.kubernetes_token"

FAKE_TOKEN_DATA = {
    "service_account_token": "supersecrettoken",
    "service_account_name": "vault-secrets-superuser",
    "service_account_namespace": "kube-system",
    "lease_id": "kubernetes/creds/superuser/abc123",
    "lease_duration": 3600,
    "renewable": False,
}


def _make_module(check_mode=False):
    """Return a minimal AnsibleModule mock with no_log_values initialised."""
    module = MagicMock()
    module.check_mode = check_mode
    module.no_log_values = set()
    module.params = {
        "kubernetes_mount_path": "kubernetes",
        "name": "superuser",
        "kubernetes_namespace": "kube-system",
        "ttl": "1h",
        "audience": None,
    }
    return module


# ---------------------------------------------------------------------------
# no_log_values scrubbing
# ---------------------------------------------------------------------------


@patch(f"{MODULE}.VaultKubernetes")
@patch(f"{MODULE}.get_authenticated_client")
@patch(f"{MODULE}.AnsibleModule")
def test_service_account_token_available_in_registered_result(mock_ansible_module, mock_auth, mock_k8s_cls):
    """The bearer token must be present in the exit_json result so callers can use it.

    Protection against accidental exposure is the responsibility of the task author
    via no_log: true at the task level — the module does not scrub no_log_values
    because doing so would make the token unavailable to subsequent tasks.
    """
    module = _make_module()
    mock_ansible_module.return_value = module

    mock_k8s = MagicMock()
    mock_k8s.generate_token.return_value = FAKE_TOKEN_DATA
    mock_k8s_cls.return_value = mock_k8s

    from ansible_collections.hashicorp.vault.plugins.modules.kubernetes_token import main

    main()

    _, kwargs = module.exit_json.call_args
    assert kwargs["kubernetes_token"]["service_account_token"] == "supersecrettoken"


@patch(f"{MODULE}.VaultKubernetes")
@patch(f"{MODULE}.get_authenticated_client")
@patch(f"{MODULE}.AnsibleModule")
def test_missing_service_account_token_does_not_raise(mock_ansible_module, mock_auth, mock_k8s_cls):
    """If service_account_token is absent from the Vault response no exception should be raised."""
    module = _make_module()
    mock_ansible_module.return_value = module

    data_without_token = {k: v for k, v in FAKE_TOKEN_DATA.items() if k != "service_account_token"}
    mock_k8s = MagicMock()
    mock_k8s.generate_token.return_value = data_without_token
    mock_k8s_cls.return_value = mock_k8s

    from ansible_collections.hashicorp.vault.plugins.modules.kubernetes_token import main

    main()

    assert len(module.no_log_values) == 0
    module.exit_json.assert_called_once()


# ---------------------------------------------------------------------------
# Normal execution
# ---------------------------------------------------------------------------


@patch(f"{MODULE}.VaultKubernetes")
@patch(f"{MODULE}.get_authenticated_client")
@patch(f"{MODULE}.AnsibleModule")
def test_exit_json_called_with_changed_and_full_token_dict(mock_ansible_module, mock_auth, mock_k8s_cls):
    """exit_json must be called with changed=True and the complete token dict returned by Vault."""
    module = _make_module()
    mock_ansible_module.return_value = module

    mock_k8s = MagicMock()
    mock_k8s.generate_token.return_value = FAKE_TOKEN_DATA
    mock_k8s_cls.return_value = mock_k8s

    from ansible_collections.hashicorp.vault.plugins.modules.kubernetes_token import main

    main()

    module.exit_json.assert_called_once_with(changed=True, kubernetes_token=FAKE_TOKEN_DATA)


# ---------------------------------------------------------------------------
# check_mode
# ---------------------------------------------------------------------------


@patch(f"{MODULE}.AnsibleModule")
def test_check_mode_exits_without_contacting_vault(mock_ansible_module):
    """In check mode the module must exit immediately with an empty token dict and never call Vault.

    exit_json is configured to raise SystemExit to replicate AnsibleModule's real behaviour —
    without this the mock doesn't halt execution and main() falls through to get_authenticated_client.
    """
    module = _make_module(check_mode=True)
    module.exit_json.side_effect = SystemExit(0)
    mock_ansible_module.return_value = module

    from ansible_collections.hashicorp.vault.plugins.modules.kubernetes_token import main

    with pytest.raises(SystemExit):
        main()

    module.exit_json.assert_called_once_with(changed=True, kubernetes_token={})


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


@patch(f"{MODULE}.VaultKubernetes")
@patch(f"{MODULE}.get_authenticated_client")
@patch(f"{MODULE}.AnsibleModule")
def test_vault_permission_error_surfaces_as_fail_json(mock_ansible_module, mock_auth, mock_k8s_cls):
    """A VaultPermissionError from generate_token must call fail_json with a 'Permission denied' message."""
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
        VaultPermissionError,
    )

    module = _make_module()
    mock_ansible_module.return_value = module

    mock_k8s = MagicMock()
    mock_k8s.generate_token.side_effect = VaultPermissionError("forbidden")
    mock_k8s_cls.return_value = mock_k8s

    from ansible_collections.hashicorp.vault.plugins.modules.kubernetes_token import main

    main()

    _, kwargs = module.fail_json.call_args
    assert "Permission denied" in kwargs.get("msg", "")


@patch(f"{MODULE}.VaultKubernetes")
@patch(f"{MODULE}.get_authenticated_client")
@patch(f"{MODULE}.AnsibleModule")
def test_vault_api_error_surfaces_as_fail_json(mock_ansible_module, mock_auth, mock_k8s_cls):
    """A VaultApiError from generate_token must call fail_json with a 'Vault API error' message."""
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
        VaultApiError,
    )

    module = _make_module()
    mock_ansible_module.return_value = module

    mock_k8s = MagicMock()
    mock_k8s.generate_token.side_effect = VaultApiError("bad request")
    mock_k8s_cls.return_value = mock_k8s

    from ansible_collections.hashicorp.vault.plugins.modules.kubernetes_token import main

    main()

    _, kwargs = module.fail_json.call_args
    assert "Vault API error" in kwargs.get("msg", "")
