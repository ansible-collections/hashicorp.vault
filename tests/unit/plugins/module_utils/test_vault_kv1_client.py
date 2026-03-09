# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

import random
import string

from unittest.mock import MagicMock

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultKv1Secrets


@pytest.fixture
def vault_kv1_secret():
    client = MagicMock()
    client._make_request = MagicMock()
    return VaultKv1Secrets(client=client)


@pytest.fixture
def mock_success_response():
    return {"data": MagicMock()}


def random_string(length=12):
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=length))


def test_read_secret(vault_kv1_secret, mock_success_response):
    vault_kv1_secret._client._make_request.return_value = mock_success_response

    engine_mount_point = random_string(length=16)
    secret_path = random_string()
    secret = vault_kv1_secret.read_secret(engine_mount_point, secret_path)

    expected_path = f"v1/{engine_mount_point}/{secret_path}"
    vault_kv1_secret._client._make_request.assert_called_once_with("GET", expected_path, params={})
    assert secret == mock_success_response["data"]


def test_delete_secret(vault_kv1_secret):
    vault_kv1_secret._client._make_request.return_value = mock_success_response

    engine_mount_point = random_string(length=16)
    secret_path = random_string()
    result = vault_kv1_secret.delete_secret(engine_mount_point, secret_path)

    expected_path = f"v1/{engine_mount_point}/{secret_path}"
    vault_kv1_secret._client._make_request.assert_called_once_with("DELETE", expected_path)

    assert result is None


def test_create_or_update_secret(vault_kv1_secret):
    vault_kv1_secret._client._make_request.return_value = mock_success_response

    engine_mount_point = random_string(length=16)
    secret_path = random_string()
    secret_data = {"secret": MagicMock()}
    result = vault_kv1_secret.create_or_update_secret(engine_mount_point, secret_path, secret_data)

    expected_path = f"v1/{engine_mount_point}/{secret_path}"
    vault_kv1_secret._client._make_request.assert_called_once_with(
        "POST", expected_path, json=secret_data
    )

    assert result == mock_success_response


def test_create_or_update_secret_secret_data_error(vault_kv1_secret):
    vault_kv1_secret._client._make_request.return_value = mock_success_response

    engine_mount_point = random_string(length=16)
    secret_path = random_string()
    secret_data = MagicMock()
    with pytest.raises(TypeError):
        vault_kv1_secret.create_or_update_secret(engine_mount_point, secret_path, secret_data)

    vault_kv1_secret._client._make_request.assert_not_called()
