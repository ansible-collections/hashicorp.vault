# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import random
import string
import uuid
from unittest.mock import Mock, patch

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import VaultLogin
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import VaultLoginError


class TestVaultLogin:
    """Tests for VaultLogin class."""

    @staticmethod
    def generate_vault_addr():
        """Generates a random, valid-looking Vault address."""
        # Create a random 8-character prefix
        prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        cluster_id = str(uuid.uuid4())[:8]
        return f"https://{prefix}.vault.{cluster_id}.z0.hashicorp.cloud:8200"

    @pytest.mark.parametrize(
        "auth_method,params,missing_keys",
        [
            (
                "alicloud",
                {"role": "ansible-test-units", "identity_request_url": "identity"},
                ["identity_request_headers"],
            ),
            ("aws", {"iam_request_url": "ansible-test-url"}, []),
            ("azure", {"role": "ansible-test-units"}, ["jwt"]),
            ("cf", {"role": "ansible-test-units", "cf_instance_cert": "instance"}, ["signing_time", "signature"]),
            ("github", {"token": "ansible-test-token"}, []),
            ("github", {}, ["token"]),
            ("gcp", {"role": "ansible-test-units"}, ["jwt"]),
            ("gcp", {"role": "ansible-test-units", "jwt": "jwt-token"}, []),
            ("ldap", {"username": "user", "password": "pass123"}, []),
            ("ldap", {"username": "user"}, ["password"]),
            ("ldap", {"password": "pass123"}, ["username"]),
            ("oci", {"username": "user"}, ["role"]),
            ("okta", {"role": "ansible-test-units", "jwt": "jwt-token"}, ["username", "password"]),
            ("okta", {"username": "user"}, ["password"]),
            ("radius", {"username": "user"}, ["password"]),
            ("radius", {"password": "pass123"}, ["username"]),
            ("saml", {"username": "user"}, ["client_verifier", "token_poll_id"]),
            ("saml", {"client_verifier": "verifier"}, ["token_poll_id"]),
            ("userpass", {"username": "user"}, ["password"]),
            ("userpass", {"username": "user", "password": "123"}, []),
        ],
    )
    def test_validate_login_params(self, auth_method, params, missing_keys):
        """Test validate login params"""
        login = VaultLogin(vault_address=Mock(), auth_method=auth_method)
        if missing_keys:
            with pytest.raises(VaultLoginError) as excinfo:
                login.validate_login_params(**params)

            assert excinfo.type is VaultLoginError
            assert str(excinfo.value) in [
                f"Missing required parameter {key!r} for {auth_method!r} login." for key in missing_keys
            ]
        else:
            login.validate_login_params(**params)

    @pytest.mark.parametrize(
        "auth_method,mount_path,params,result",
        [
            (
                "alicloud",
                None,
                {"role": "ansible-test-units", "identity_request_url": "identity"},
                "v1/auth/alicloud/login",
            ),
            (
                "alicloud",
                "ansible-test-units",
                {"role": "ansible-test-units", "identity_request_url": "identity"},
                "v1/auth/ansible-test-units/login",
            ),
            ("ldap", None, {"username": "ansible-test-user"}, "v1/auth/ldap/login/ansible-test-user"),
            (
                "ldap",
                "ansible-test-units-ldap",
                {"username": "ansible-test-user"},
                "v1/auth/ansible-test-units-ldap/login/ansible-test-user",
            ),
            ("okta", None, {"username": "ansible-test-user-aa"}, "v1/auth/okta/login/ansible-test-user-aa"),
            (
                "okta",
                "ansible-test-units-abc",
                {"username": "ansible-test-user-abc"},
                "v1/auth/ansible-test-units-abc/login/ansible-test-user-abc",
            ),
            (
                "userpass",
                None,
                {"username": "ansible-test-user-upass"},
                "v1/auth/userpass/login/ansible-test-user-upass",
            ),
            ("oci", None, {"role": "ansible-test-units"}, "v1/auth/oci/login/ansible-test-units"),
            (
                "oci",
                "custom-oci-path",
                {"role": "ansible-test-units"},
                "v1/auth/custom-oci-path/login/ansible-test-units",
            ),
            ("saml", None, {}, "v1/auth/saml/token"),
            ("saml", "custom-saml-auth_path", {}, "v1/auth/custom-saml-auth_path/token"),
        ],
    )
    def test__build_login_url(self, auth_method, mount_path, params, result):
        """Test _build_login_url() method"""
        vault_addr = TestVaultLogin.generate_vault_addr()
        login = VaultLogin(
            vault_address=vault_addr, auth_method=auth_method, vault_namespace="admin", mount_path=mount_path
        )
        assert login._build_login_url(**params) == f"{vault_addr}/{result}"

    @pytest.mark.parametrize("namespace", [None, Mock()])
    @pytest.mark.parametrize(
        "response,result",
        [
            (
                {"auth": {"client_token": "client-token-abc", "raw": "ansible-test-units"}},
                ("client-token-abc", {"client_token": "client-token-abc", "raw": "ansible-test-units"}),
            ),
            (
                {"auth": {"token": "ansible-token-0000", "collection": "hashicorp.vault"}},
                ("ansible-token-0000", {"token": "ansible-token-0000", "collection": "hashicorp.vault"}),
            ),
        ],
    )
    def test_login(self, namespace, response, result):
        """Test the login() method"""

        request_response = Mock()
        request_response.json.return_value = response

        login_url = Mock()
        vault_addr = Mock()
        auth_method = Mock()

        login = VaultLogin(vault_address=vault_addr, auth_method=auth_method, vault_namespace=namespace)
        login._build_login_url = Mock()
        login._build_login_url.return_value = login_url

        login_params = {"username": Mock(), "password": Mock()}
        with patch.object(login._session, "post", return_value=request_response) as session_post:
            assert login.login(**login_params) == result

        headers = {} if namespace is None else {"X-Vault-Namespace": namespace}
        session_post.assert_called_once_with(login_url, json=login_params, headers=headers, timeout=90)

        login._build_login_url.assert_called_once_with(**login_params)
        request_response.raise_for_status.assert_called_once()

    @pytest.mark.parametrize(
        "login_kwargs,expected_verify",
        [
            ({"ca_certificate": "/etc/pki/tls/certs/custom-ca.pem"}, "/etc/pki/tls/certs/custom-ca.pem"),
            ({"tls_skip_verify": True}, False),
        ],
        ids=["ca_cert", "tls_skip_verify"],
    )
    def test_login_uses_session_so_tls_settings_apply(self, login_kwargs, expected_verify):
        """The login request must be issued on a TLS-configured session.

        A module level ``requests.post()`` builds its own session, which defaults to the
        certifi bundle and so ignores ``ca_cert`` and ``tls_skip_verify`` entirely.
        See https://github.com/ansible-collections/hashicorp.vault/issues/126.
        """
        vault_addr = TestVaultLogin.generate_vault_addr()
        login = VaultLogin(vault_address=vault_addr, auth_method="approle", **login_kwargs)
        assert login._session.verify == expected_verify

        response = Mock(status_code=200)
        response.raise_for_status.return_value = None
        response.json.return_value = {"auth": {"client_token": "hvs.tls"}}

        with patch.object(login._session, "post", return_value=response) as session_post:
            with patch("requests.post") as module_post:
                client_token, auth_data = login.login(role_id="role-123", secret_id="secret-456")

        session_post.assert_called_once()
        module_post.assert_not_called()
        assert client_token == "hvs.tls"

    def test_login_default_verify_unset(self):
        """Without ca_certificate/tls_skip_verify, the session keeps the default certifi verification."""
        vault_addr = TestVaultLogin.generate_vault_addr()
        login = VaultLogin(vault_address=vault_addr, auth_method="approle")
        assert login._session.verify is True
