# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultClient, VaultTpm
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_tpm import compute_tpm_id

# Fixture keys and their expected IDs. The IDs were computed with openssl, not with compute_tpm_id:
#   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa.key
#   openssl pkey -in rsa.key -pubout -out rsa_pub.pem
#   openssl pkey -pubin -in rsa_pub.pem -outform DER | openssl dgst -sha256
#   openssl ecparam -name prime256v1 -genkey -noout -param_enc named_curve -out ec.key
#   openssl ec -in ec.key -pubout -out ec_pub.pem
#   openssl pkey -pubin -in ec_pub.pem -outform DER | openssl dgst -sha256
# The TPM ID is "sha256-" followed by the hex digest printed by the last command.
RSA_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuwhOJC7qSavaeXH31o5L
LNbZ+q8QPjGHGOw5au2hKXNAAFlxD4s6cxZ93icA14CmJAAMrfdsh5b2ljnKnaH2
kNCQ8vnlhHGKco3N96bMPPoOmZN0juoRY87/3XHCW47e7Bxa1qjyzQeiP8AZX/8y
MKzp6Z/hpVKdSpASXikGwap9q8mnZNlxM8ZlJxHfm/2258h58I7aEjiV7JE30rD2
o7VnwsAM3m0Eo8VGXybZBlm6rijgHq6IV9uhomK9wtrKz+ENY8faJz+bcY0unhut
valGWqA89jWsWbvb7ZB2Mw6RRGulTK0fNOWQaPwsPbQcaCITtrFj9AT/sMkZIUqn
EwIDAQAB
-----END PUBLIC KEY-----
"""
RSA_ID = "sha256-dbf62239ad357dab053d7f9e368eae133f33fdc1e0e774953961d03f0632d32a"

EC_PEM = """-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAET9AIOUy0NAOw3XA4qJ0xqeIdzFDr
f4g+ekFBtbDH8k/HqriB4eNwZhlJ+4ivsUGFeZOBXswi1NYxjolZEb487A==
-----END PUBLIC KEY-----
"""
EC_ID = "sha256-1a8a1b1e101f82bcad6281872ba7cac58aa33cce53bdcd0583c075072ea449b7"


@pytest.fixture
def vault_config():
    """Fixture for VaultClient; tpm_name and group_name are sample names."""
    return {
        "addr": "http://mock-vault:8200",
        "token": "mock-token",
        "namespace": "admin",
        "tpm_name": "host-1",
        "group_name": "web-hosts",
    }


@pytest.fixture
def authenticated_client(mocker, vault_config):
    client = VaultClient(vault_address=vault_config["addr"], vault_namespace=vault_config["namespace"])
    client.set_token(vault_config["token"])
    client._make_request = MagicMock()
    return client


@pytest.fixture
def tpm_client(authenticated_client):
    return VaultTpm(authenticated_client)


def _tpm_data(name="host-1", tpm_id=RSA_ID, disabled=False, metadata=None):
    return {
        "data": {
            "id": tpm_id,
            "name": name,
            "metadata": metadata or {},
            "tpm_ek_public_key": RSA_PEM,
            "disabled": disabled,
        }
    }


# compute_tpm_id


@pytest.mark.parametrize("pem, expected", [(RSA_PEM, RSA_ID), (EC_PEM, EC_ID)])
def test_compute_tpm_id_known_vectors(pem, expected):
    assert compute_tpm_id(pem) == expected


@pytest.mark.parametrize(
    "variant",
    [
        RSA_PEM.rstrip("\n"),
        RSA_PEM + "\n\n",
        RSA_PEM.replace("\n", "\r\n"),
        "  \n" + RSA_PEM,
        "\t" + RSA_PEM + "  ",
    ],
    ids=["no-trailing-newline", "extra-trailing-newlines", "crlf", "leading-whitespace", "tab-and-trailing-space"],
)
def test_compute_tpm_id_whitespace_variants_accepted(variant):
    assert compute_tpm_id(variant) == RSA_ID


@pytest.mark.parametrize(
    "pem, message",
    [
        ("", "not a PEM"),
        ("not a pem", "not a PEM"),
        ("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", "not a PEM"),
        (RSA_PEM.replace("PUBLIC KEY", "CERTIFICATE"), "PUBLIC KEY PEM block, got CERTIFICATE"),
        (RSA_PEM.replace("PUBLIC KEY", "RSA PUBLIC KEY"), "PUBLIC KEY PEM block, got RSA PUBLIC KEY"),
        ("-----BEGIN PUBLIC KEY-----\n!!!notbase64!!!\n-----END PUBLIC KEY-----", "invalid base64"),
        ("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----", "invalid base64"),
        ("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----", "no key data"),
        (RSA_PEM.replace("END PUBLIC KEY", "END CERTIFICATE"), "not a PEM"),
    ],
)
def test_compute_tpm_id_invalid_pem(pem, message):
    with pytest.raises(ValueError, match=message):
        compute_tpm_id(pem)


def test_compute_tpm_id_not_a_string():
    with pytest.raises(TypeError, match="ek_pem must be a string"):
        compute_tpm_id(b"-----BEGIN PUBLIC KEY-----")


# check_vault_version


@pytest.mark.parametrize(
    "payload",
    [
        {"enterprise": True, "version": "2.2.0"},
        {"enterprise": True, "version": "2.2.0+ent"},
        {"enterprise": True, "version": "2.10.1+ent"},
        {"enterprise": True, "version": "3.0.0+ent"},
        {"enterprise": True, "version": "2.2.0+ent.hsm", "sealed": True},
        {"enterprise": True, "version": "2.2.0+ent", "standby": True, "initialized": True, "sealed": False},
    ],
)
def test_check_vault_version_supported(tpm_client, authenticated_client, payload):
    authenticated_client._make_request.return_value = payload

    assert tpm_client.check_vault_version() is None


@pytest.mark.parametrize(
    "payload, found",
    [
        ({"enterprise": False, "version": "2.2.0"}, "2.2.0"),
        ({"enterprise": False, "version": "2.5.0"}, "2.5.0"),
        ({"enterprise": True, "version": "2.1.9+ent"}, "2.1.9+ent"),
        ({"enterprise": True, "version": "1.21.0+ent"}, "1.21.0+ent"),
        ({"version": "2.2.0+ent"}, "2.2.0+ent"),
        ({"enterprise": True}, "unknown"),
        ({"enterprise": True, "version": "garbage"}, "garbage"),
        ({}, "unknown"),
    ],
)
def test_check_vault_version_unsupported(tpm_client, authenticated_client, payload, found):
    authenticated_client._make_request.return_value = payload

    with pytest.raises(VaultApiError) as exc_info:
        tpm_client.check_vault_version()

    assert str(exc_info.value) == f"This module requires Vault Enterprise >= 2.2.0. Found: {found}."


def test_check_vault_version_pre_release_of_minimum_passes(tpm_client, authenticated_client):
    """A pre-release suffix is ignored, only major.minor.patch is compared."""
    authenticated_client._make_request.return_value = {"enterprise": True, "version": "2.2.0-rc1+ent"}

    assert tpm_client.check_vault_version() is None


def test_check_vault_version_request(tpm_client, authenticated_client):
    authenticated_client._make_request.return_value = {"enterprise": True, "version": "2.2.0+ent"}

    tpm_client.check_vault_version()

    authenticated_client._make_request.assert_called_once_with(
        "GET", "v1/sys/health", params={"sealedcode": 299, "standbycode": 299}
    )


def test_check_vault_version_custom_minimum(tpm_client, authenticated_client):
    authenticated_client._make_request.return_value = {"enterprise": True, "version": "2.3.0+ent"}

    with pytest.raises(VaultApiError, match=r"Enterprise >= 2\.4\.0\. Found: 2\.3\.0\+ent\."):
        tpm_client.check_vault_version(min_version="2.4.0")


def test_check_vault_version_without_token(vault_config):
    """sys/health needs no token, so the check must work on a client that was never authenticated."""
    client = VaultClient(vault_address=vault_config["addr"], vault_namespace=vault_config["namespace"])
    assert client.token is None
    client._make_request = MagicMock(return_value={"enterprise": True, "version": "2.2.0+ent"})

    client.tpm.check_vault_version()

    assert "X-Vault-Token" not in client.session.headers
    client._make_request.assert_called_once()


def test_check_vault_version_connection_error_propagates(tpm_client, authenticated_client):
    authenticated_client._make_request.side_effect = VaultPermissionError("permission denied")

    with pytest.raises(VaultPermissionError):
        tpm_client.check_vault_version()


# register_tpm


def test_register_tpm_success(tpm_client, authenticated_client, vault_config):
    response = _tpm_data(vault_config["tpm_name"])
    authenticated_client._make_request.return_value = response

    result = tpm_client.register_tpm(vault_config["tpm_name"], RSA_PEM, {"env": "prod"})

    authenticated_client._make_request.assert_called_once_with(
        "POST",
        "v1/identity/tpm",
        json={"name": "host-1", "tpm_ek_public_key": RSA_PEM, "metadata": {"env": "prod"}},
    )
    assert result == response


def test_register_tpm_without_metadata(tpm_client, authenticated_client, vault_config):
    tpm_client.register_tpm(vault_config["tpm_name"], RSA_PEM)

    authenticated_client._make_request.assert_called_once_with(
        "POST", "v1/identity/tpm", json={"name": "host-1", "tpm_ek_public_key": RSA_PEM}
    )


def test_register_tpm_sends_pem_unchanged(tpm_client, authenticated_client, vault_config):
    pem = RSA_PEM.rstrip("\n")

    tpm_client.register_tpm(vault_config["tpm_name"], pem)

    assert authenticated_client._make_request.call_args.kwargs["json"]["tpm_ek_public_key"] == pem


def test_register_tpm_metadata_type_error(tpm_client, authenticated_client, vault_config):
    with pytest.raises(TypeError, match="metadata must be a dict"):
        tpm_client.register_tpm(vault_config["tpm_name"], RSA_PEM, "env=prod")

    authenticated_client._make_request.assert_not_called()


def test_register_tpm_error_propagates(tpm_client, authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = VaultApiError(
        "API request failed", 400, ["tpm record already exists for given tpm_ek_public_key"]
    )

    with pytest.raises(VaultApiError):
        tpm_client.register_tpm(vault_config["tpm_name"], RSA_PEM)


def test_register_tpm_not_found_propagates(tpm_client, authenticated_client, vault_config):
    """A 404 on the POST (no TPM API, not Enterprise) is for the module layer to translate."""
    authenticated_client._make_request.side_effect = VaultSecretNotFoundError("not found", 404, [])

    with pytest.raises(VaultSecretNotFoundError):
        tpm_client.register_tpm(vault_config["tpm_name"], RSA_PEM)


# read_tpm / read_tpm_by_id


def test_read_tpm_success(tpm_client, authenticated_client, vault_config):
    authenticated_client._make_request.return_value = _tpm_data(vault_config["tpm_name"], metadata={"a": "b"})

    result = tpm_client.read_tpm(vault_config["tpm_name"])

    authenticated_client._make_request.assert_called_once_with("GET", "v1/identity/tpm/name/host-1")
    assert result == {
        "id": RSA_ID,
        "name": "host-1",
        "metadata": {"a": "b"},
        "tpm_ek_public_key": RSA_PEM,
        "disabled": False,
    }


def test_read_tpm_not_found_returns_none(tpm_client, authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = VaultSecretNotFoundError("not found", 404, [])

    assert tpm_client.read_tpm(vault_config["tpm_name"]) is None


def test_read_tpm_empty_response_returns_empty_dict(tpm_client, authenticated_client, vault_config):
    authenticated_client._make_request.return_value = {}

    assert tpm_client.read_tpm(vault_config["tpm_name"]) == {}


def test_read_tpm_permission_error_propagates(tpm_client, authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = VaultPermissionError("permission denied", 403, [])

    with pytest.raises(VaultPermissionError):
        tpm_client.read_tpm(vault_config["tpm_name"])


def test_read_tpm_by_id_success(tpm_client, authenticated_client):
    authenticated_client._make_request.return_value = _tpm_data()

    result = tpm_client.read_tpm_by_id(RSA_ID)

    authenticated_client._make_request.assert_called_once_with("GET", f"v1/identity/tpm/id/{RSA_ID}")
    assert result["id"] == RSA_ID


def test_read_tpm_by_id_not_found_returns_none(tpm_client, authenticated_client):
    authenticated_client._make_request.side_effect = VaultSecretNotFoundError("not found", 404, [])

    assert tpm_client.read_tpm_by_id(RSA_ID) is None


def test_read_tpm_by_id_api_error_propagates(tpm_client, authenticated_client):
    authenticated_client._make_request.side_effect = VaultApiError("server error", 500, [])

    with pytest.raises(VaultApiError):
        tpm_client.read_tpm_by_id(RSA_ID)


# update_tpm


@pytest.mark.parametrize(
    "kwargs, body",
    [
        ({"disabled": True}, {"disabled": True}),
        ({"disabled": False}, {"disabled": False}),
        ({"metadata": {"env": "dev"}}, {"metadata": {"env": "dev"}}),
        ({"metadata": {}}, {"metadata": {}}),
        ({"disabled": True, "metadata": {"env": "dev"}}, {"disabled": True, "metadata": {"env": "dev"}}),
        ({}, {}),
    ],
)
def test_update_tpm_sends_only_given_fields(tpm_client, authenticated_client, vault_config, kwargs, body):
    authenticated_client._make_request.return_value = {}

    tpm_client.update_tpm(vault_config["tpm_name"], **kwargs)

    authenticated_client._make_request.assert_called_once_with("POST", "v1/identity/tpm/name/host-1", json=body)
    assert "tpm_ek_public_key" not in authenticated_client._make_request.call_args.kwargs["json"]


def test_update_tpm_metadata_type_error(tpm_client, authenticated_client, vault_config):
    with pytest.raises(TypeError, match="metadata must be a dict"):
        tpm_client.update_tpm(vault_config["tpm_name"], metadata=["a"])

    authenticated_client._make_request.assert_not_called()


def test_update_tpm_error_propagates(tpm_client, authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = VaultPermissionError("permission denied")

    with pytest.raises(VaultPermissionError):
        tpm_client.update_tpm(vault_config["tpm_name"], disabled=True)


# delete_tpm


def test_delete_tpm_success(tpm_client, authenticated_client, vault_config):
    authenticated_client._make_request.return_value = {}

    assert tpm_client.delete_tpm(vault_config["tpm_name"]) is None

    authenticated_client._make_request.assert_called_once_with("DELETE", "v1/identity/tpm/name/host-1")


def test_delete_tpm_error_propagates(tpm_client, authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = VaultPermissionError("permission denied")

    with pytest.raises(VaultPermissionError):
        tpm_client.delete_tpm(vault_config["tpm_name"])


# add_tpm_to_group


def _group_data(members):
    return {"data": {"id": "grp-1", "name": "web-hosts", "metadata": {}, "member_tpm_ids": members}}


def test_add_tpm_to_group_appends_and_keeps_existing_members(tpm_client, authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = [_group_data(["sha256-aaa", "sha256-bbb"]), {}]

    result = tpm_client.add_tpm_to_group(vault_config["group_name"], RSA_ID)

    assert result is True
    path = "v1/identity/tpmgroup/name/web-hosts"
    assert authenticated_client._make_request.call_args_list[0] == (("GET", path),)
    assert authenticated_client._make_request.call_args_list[1] == (
        ("POST", path),
        {"json": {"member_tpm_ids": ["sha256-aaa", "sha256-bbb", RSA_ID]}},
    )


def test_add_tpm_to_group_already_member_makes_no_write(tpm_client, authenticated_client, vault_config):
    authenticated_client._make_request.return_value = _group_data(["sha256-aaa", RSA_ID])

    result = tpm_client.add_tpm_to_group(vault_config["group_name"], RSA_ID)

    assert result is False
    authenticated_client._make_request.assert_called_once_with("GET", "v1/identity/tpmgroup/name/web-hosts")


def test_add_tpm_to_group_empty_group(tpm_client, authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = [{"data": {"member_tpm_ids": None}}, {}]

    assert tpm_client.add_tpm_to_group(vault_config["group_name"], RSA_ID) is True

    assert authenticated_client._make_request.call_args_list[1].kwargs["json"] == {"member_tpm_ids": [RSA_ID]}


def test_add_tpm_to_group_missing_group_propagates(tpm_client, authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = VaultSecretNotFoundError("not found", 404, [])

    with pytest.raises(VaultSecretNotFoundError):
        tpm_client.add_tpm_to_group(vault_config["group_name"], RSA_ID)

    authenticated_client._make_request.assert_called_once()


def test_add_tpm_to_group_post_error_propagates(tpm_client, authenticated_client, vault_config):
    authenticated_client._make_request.side_effect = [
        _group_data([]),
        VaultApiError("TPM ID not found", 400, ["TPM ID sha256-x not found"]),
    ]

    with pytest.raises(VaultApiError):
        tpm_client.add_tpm_to_group(vault_config["group_name"], RSA_ID)


def test_add_tpm_to_group_does_not_mutate_response(tpm_client, authenticated_client, vault_config):
    response = _group_data(["sha256-aaa"])
    authenticated_client._make_request.side_effect = [response, {}]

    tpm_client.add_tpm_to_group(vault_config["group_name"], RSA_ID)

    assert response["data"]["member_tpm_ids"] == ["sha256-aaa"]


# VaultClient registration


def test_vault_client_has_tpm_attr(vault_config):
    client = VaultClient(vault_address=vault_config["addr"], vault_namespace=vault_config["namespace"])
    assert hasattr(client, "tpm")
    assert isinstance(client.tpm, VaultTpm)
