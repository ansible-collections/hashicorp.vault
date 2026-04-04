# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
    VaultClient,
    VaultPki,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultSecretNotFoundError,
)


@pytest.fixture
def vault_config():
    return {
        "addr": "http://mock-vault:8200",
        "token": "mock-token",
        "namespace": "root",
    }


@pytest.fixture
def authenticated_client(vault_config):
    client = VaultClient(vault_address=vault_config["addr"], vault_namespace=vault_config["namespace"])
    client.set_token(vault_config["token"])
    client._make_request = MagicMock()
    return client


@pytest.fixture
def issue_response():
    return {
        "lease_id": "",
        "renewable": False,
        "lease_duration": 0,
        "data": {
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
            "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
            "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n",
            "private_key_type": "rsa",
            "serial_number": "7e:5e:bf:...",
        },
    }


@pytest.fixture
def sign_response():
    return {
        "lease_duration": 0,
        "data": {
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
            "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
        },
    }


class TestVaultPkiInit:
    def test_mount_path_type_error(self, authenticated_client):
        with pytest.raises(TypeError, match="mount_path must be a str"):
            VaultPki(authenticated_client, mount_path=123)  # type: ignore[arg-type]


class TestVaultPkiGenerateCertificate:
    def test_generate_certificate_success(self, authenticated_client, issue_response):
        authenticated_client._make_request.return_value = issue_response
        pki = VaultPki(authenticated_client)

        result = pki.generate_certificate(role="server", common_name="svc.example.com")

        authenticated_client._make_request.assert_called_once_with(
            "POST",
            "v1/pki/issue/server",
            json={"common_name": "svc.example.com"},
        )
        assert result == issue_response

    def test_generate_certificate_with_extra(self, authenticated_client, issue_response):
        authenticated_client._make_request.return_value = issue_response
        pki = VaultPki(authenticated_client)
        extra = {"ttl": "720h", "ip_sans": "127.0.0.1"}

        pki.generate_certificate("server", "svc.example.com", extra=extra)

        authenticated_client._make_request.assert_called_once_with(
            "POST",
            "v1/pki/issue/server",
            json={"common_name": "svc.example.com", "ttl": "720h", "ip_sans": "127.0.0.1"},
        )

    def test_generate_certificate_extra_empty_dict(self, authenticated_client, issue_response):
        authenticated_client._make_request.return_value = issue_response
        pki = VaultPki(authenticated_client)

        pki.generate_certificate("server", "svc.example.com", extra={})

        authenticated_client._make_request.assert_called_once_with(
            "POST",
            "v1/pki/issue/server",
            json={"common_name": "svc.example.com"},
        )

    def test_generate_certificate_common_name_type_error(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(TypeError, match="common_name must be a str"):
            pki.generate_certificate("server", 123)  # type: ignore[arg-type]

    def test_generate_certificate_role_type_error(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(TypeError, match="role must be a str"):
            pki.generate_certificate(123, "cn")  # type: ignore[arg-type]

    def test_generate_certificate_role_empty(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(ValueError, match="role must be non-empty"):
            pki.generate_certificate("", "cn")

    def test_generate_certificate_role_slashes(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(ValueError, match="role must not contain"):
            pki.generate_certificate("evil/role", "cn")

    def test_generate_certificate_role_leading_whitespace(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(ValueError, match="role must not have leading or trailing whitespace"):
            pki.generate_certificate(" server", "cn")

    def test_generate_certificate_extra_type_error(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(TypeError, match="extra must be a dict"):
            pki.generate_certificate("server", "cn", extra="bad")  # type: ignore[arg-type]

    def test_generate_certificate_custom_mount(self, authenticated_client, issue_response):
        authenticated_client._make_request.return_value = issue_response
        pki = VaultPki(authenticated_client, mount_path="pki-int/")

        pki.generate_certificate("web", "www.example.com")

        authenticated_client._make_request.assert_called_once_with(
            "POST",
            "v1/pki-int/issue/web",
            json={"common_name": "www.example.com"},
        )


class TestVaultPkiSignCertificate:
    def test_sign_certificate_success(self, authenticated_client, sign_response):
        authenticated_client._make_request.return_value = sign_response
        pki = VaultPki(authenticated_client)
        csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----\n"

        result = pki.sign_certificate(role="server", csr=csr, common_name="svc.example.com")

        authenticated_client._make_request.assert_called_once_with(
            "POST",
            "v1/pki/sign/server",
            json={"csr": csr, "common_name": "svc.example.com"},
        )
        assert result == sign_response

    def test_sign_certificate_with_extra(self, authenticated_client, sign_response):
        authenticated_client._make_request.return_value = sign_response
        pki = VaultPki(authenticated_client)
        csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----\n"

        pki.sign_certificate(
            "server", csr, "signed.example.com", extra={"ttl": "24h", "common_name": "override.example.com"}
        )

        authenticated_client._make_request.assert_called_once_with(
            "POST",
            "v1/pki/sign/server",
            json={
                "csr": csr,
                "ttl": "24h",
                "common_name": "override.example.com",
            },
        )

    def test_sign_certificate_extra_empty_dict(self, authenticated_client, sign_response):
        authenticated_client._make_request.return_value = sign_response
        pki = VaultPki(authenticated_client)
        csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...\n-----END CERTIFICATE REQUEST-----\n"

        pki.sign_certificate("server", csr, "svc.example.com", extra={})

        authenticated_client._make_request.assert_called_once_with(
            "POST",
            "v1/pki/sign/server",
            json={"csr": csr, "common_name": "svc.example.com"},
        )

    def test_sign_certificate_role_type_error(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(TypeError, match="role must be a str"):
            pki.sign_certificate(123, "pem", "cn")  # type: ignore[arg-type]

    def test_sign_certificate_role_slashes(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(ValueError, match="role must not contain"):
            pki.sign_certificate("a/b", "pem", "cn")

    def test_sign_certificate_role_empty(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(ValueError, match="role must be non-empty"):
            pki.sign_certificate("", "pem", "cn")

    def test_sign_certificate_role_leading_whitespace(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(ValueError, match="role must not have leading or trailing whitespace"):
            pki.sign_certificate("server ", "pem", "cn")

    def test_sign_certificate_csr_type_error(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(TypeError, match="csr must be a str"):
            pki.sign_certificate("server", b"not-a-str", "cn")  # type: ignore[arg-type]

    def test_sign_certificate_common_name_type_error(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(TypeError, match="common_name must be a str"):
            pki.sign_certificate("server", "pem", 123)  # type: ignore[arg-type]

    def test_sign_certificate_extra_type_error(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(TypeError, match="extra must be a dict"):
            pki.sign_certificate("server", "pem", "cn", extra=[])  # type: ignore[arg-type]


class TestVaultPkiRevokeCertificate:
    def test_revoke_certificate_success(self, authenticated_client):
        authenticated_client._make_request.return_value = {"data": {"revocation_time": 1234567890}}
        pki = VaultPki(authenticated_client)
        serial = "7e:5e:bf:12:34:56:78:90:ab:cd:ef:00:11:22:33:44:55:66:77:88"

        result = pki.revoke_certificate(serial)

        authenticated_client._make_request.assert_called_once_with(
            "POST",
            "v1/pki/revoke",
            json={"serial_number": serial},
        )
        assert "data" in result

    def test_revoke_certificate_serial_type_error(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(TypeError, match="serial_number must be a str"):
            pki.revoke_certificate(999)  # type: ignore[arg-type]

    def test_revoke_certificate_by_pem(self, authenticated_client):
        authenticated_client._make_request.return_value = {"data": {"revocation_time": 1}}
        pki = VaultPki(authenticated_client)
        pem = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"

        pki.revoke_certificate(certificate=pem)

        authenticated_client._make_request.assert_called_once_with(
            "POST",
            "v1/pki/revoke",
            json={"certificate": pem},
        )

    def test_revoke_certificate_certificate_type_error(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(TypeError, match="certificate must be a str"):
            pki.revoke_certificate(certificate=999)  # type: ignore[arg-type]

    def test_revoke_certificate_neither_serial_nor_certificate(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(ValueError, match="Exactly one of serial_number and certificate"):
            pki.revoke_certificate()

    def test_revoke_certificate_both_serial_and_certificate(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(ValueError, match="Exactly one of serial_number and certificate"):
            pki.revoke_certificate(
                serial_number="7e:5e:bf:12",
                certificate="-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            )


class TestVaultPkiReadCertificate:
    def test_read_certificate_encodes_serial(self, authenticated_client):
        authenticated_client._make_request.return_value = {"data": {"certificate": "-----BEGIN..."}}
        pki = VaultPki(authenticated_client)
        serial = "7e:5e:bf:12:34"

        pki.read_certificate(serial)

        authenticated_client._make_request.assert_called_once_with(
            "GET",
            "v1/pki/cert/7e%3A5e%3Abf%3A12%3A34",
        )

    def test_read_certificate_serial_type_error(self, authenticated_client):
        pki = VaultPki(authenticated_client)
        with pytest.raises(TypeError, match="serial_number must be a str"):
            pki.read_certificate(None)  # type: ignore[arg-type]


class TestVaultPkiListCertificates:
    def test_list_certificates_success(self, authenticated_client):
        authenticated_client._make_request.return_value = {
            "data": {"keys": ["aa:bb:cc", "11:22:33"]},
        }
        pki = VaultPki(authenticated_client)

        keys = pki.list_certificates()

        authenticated_client._make_request.assert_called_once_with("LIST", "v1/pki/certs")
        assert keys == ["aa:bb:cc", "11:22:33"]

    def test_list_certificates_empty(self, authenticated_client):
        authenticated_client._make_request.return_value = {"data": {}}
        pki = VaultPki(authenticated_client)

        assert pki.list_certificates() == []

    def test_list_certificates_filters_non_strings(self, authenticated_client):
        authenticated_client._make_request.return_value = {"data": {"keys": ["aa:bb", 42, None, "cc:dd"]}}
        pki = VaultPki(authenticated_client)

        assert pki.list_certificates() == ["aa:bb", "cc:dd"]


class TestSecretsPkiAttribute:
    def test_secrets_exposes_pki(self, authenticated_client):
        assert authenticated_client.secrets.pki is not None
        assert authenticated_client.secrets.pki._mount_path == "pki"


class TestVaultPkiNotFound:
    def test_read_certificate_not_found(self, authenticated_client):
        authenticated_client._make_request.side_effect = VaultSecretNotFoundError("not found", 404, [])
        pki = VaultPki(authenticated_client)
        with pytest.raises(VaultSecretNotFoundError):
            pki.read_certificate("missing:serial")
