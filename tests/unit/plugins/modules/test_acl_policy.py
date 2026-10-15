# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import Mock

import pytest

from ansible_collections.hashicorp.vault.plugins.modules.acl_policy import ensure_policy_present

BLOCK_RULES = 'path "secret/data/myapp/*" {\n  capabilities = ["read", "list"]\n}\n'


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


def _client(rules):
    client = Mock()
    client.acl_policies.read_acl_policy.return_value = {"name": "my-app-policy", "rules": rules}
    return client


def test_present_is_idempotent_when_rules_end_with_newline():
    module = _module({"name": "my-app-policy", "policy": BLOCK_RULES})
    client = _client(BLOCK_RULES)

    with pytest.raises(ExitJson) as exc:
        ensure_policy_present(module, client)

    assert exc.value.kwargs["changed"] is False
    client.acl_policies.create_or_update_acl_policy.assert_not_called()


def test_present_check_mode_is_idempotent_when_rules_end_with_newline():
    module = _module({"name": "my-app-policy", "policy": BLOCK_RULES}, check_mode=True)
    client = _client(BLOCK_RULES)

    with pytest.raises(ExitJson) as exc:
        ensure_policy_present(module, client)

    assert exc.value.kwargs["changed"] is False
    client.acl_policies.create_or_update_acl_policy.assert_not_called()


def test_present_writes_rules_including_trailing_newline():
    desired = 'path "secret/data/myapp/*" {\n  capabilities = ["read", "list", "update"]\n}\n'
    module = _module({"name": "my-app-policy", "policy": desired})
    client = _client(BLOCK_RULES)

    with pytest.raises(ExitJson) as exc:
        ensure_policy_present(module, client)

    assert exc.value.kwargs["changed"] is True
    client.acl_policies.create_or_update_acl_policy.assert_called_once_with("my-app-policy", desired)
