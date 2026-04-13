# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy
from unittest.mock import Mock, patch

import pytest

from ansible_collections.hashicorp.vault.plugins.modules.pki_certificate import (
    _build_issue_sign_extra,
    _csv_option,
)


@pytest.mark.parametrize(
    "value,result",
    [
        (None, None),
        (True, True),
        ("ansible-test", "ansible-test"),
        (["ansible-test-0", "ansible-test-1", "ansible-test-2"], "ansible-test-0,ansible-test-1,ansible-test-2"),
        (["ansible", True, 0], "ansible,True,0"),
    ],
)
def test__csv_options(value, result):
    """Test the _csv_option() function."""
    assert _csv_option(value) == result


@pytest.mark.parametrize(
    "module_params",
    [
        ({"alt_names": "ansible", "format": "PEM", "private_key_format": "RSA"}),
        ({"uri_sans": "uri", "exclude_cn_from_sans": True}),
    ],
)
@patch("ansible_collections.hashicorp.vault.plugins.modules.pki_certificate._csv_option")
def test__build_issue_sign_extra(mock_csv_option, module_params):
    """Test the _build_issue_sign_extra() function."""
    mock_csv_option.side_effect = lambda x: x

    module = Mock()
    module.params = module_params

    result_without_private_key = copy.deepcopy(module_params)
    result_without_private_key.pop("private_key_format", None)
    result_with_private_key = copy.deepcopy(module_params)

    assert _build_issue_sign_extra(module, include_private_key_format=False) == result_without_private_key
    assert _build_issue_sign_extra(module, include_private_key_format=True) == result_with_private_key
