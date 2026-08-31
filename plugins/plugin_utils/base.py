# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


import os
from typing import NoReturn

from ansible.errors import AnsibleLookupError
from ansible.module_utils.common.text.converters import to_text
from ansible.plugins.lookup import LookupBase

from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import (
    AppRoleAuthenticator,
    TokenAuthenticator,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultClient
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import VaultError


class VaultLookupBase(LookupBase):

    def fail(self, message: str) -> NoReturn:
        raise AnsibleLookupError(message)

    def _get_option_with_env(self, option_name: str, env_var: str, default=None):
        """Get option value with environment variable fallback."""
        value = self.get_option(option_name)
        if value is None:
            value = os.getenv(env_var, default)
        return value

    def _authenticate(self) -> None:
        auth_method = self._get_option_with_env("auth_method", "VAULT_AUTH_METHOD", "token")
        timeout = self._get_timeout()

        try:
            if auth_method == "token":
                self._authenticate_token()
            else:
                self._authenticate_approle(timeout)
        except VaultError as e:
            raise AnsibleLookupError(f"Vault lookup exception: {to_text(e)}")

    def _get_timeout(self):
        """Get timeout value with special handling for int conversion from env."""
        timeout = self.get_option("timeout")
        if timeout is None:
            timeout_env = os.getenv("VAULT_TIMEOUT")
            timeout = int(timeout_env) if timeout_env else None
        return timeout

    def _authenticate_token(self) -> None:
        """Authenticate using token method."""
        token = self._get_option_with_env("token", "VAULT_TOKEN")
        TokenAuthenticator().authenticate(self.client, token=token)

    def _authenticate_approle(self, timeout) -> None:
        """Authenticate using AppRole method."""
        params = {
            "vault_address": self._get_option_with_env("url", "VAULT_ADDR"),
            "role_id": self._get_option_with_env("role_id", "VAULT_APPROLE_ROLE_ID"),
            "secret_id": self._get_option_with_env("secret_id", "VAULT_APPROLE_SECRET_ID"),
            "vault_namespace": self._get_option_with_env("namespace", "VAULT_NAMESPACE", "root"),
        }

        vault_approle_path = self._get_option_with_env("vault_approle_path", "VAULT_APPROLE_PATH", "approle")
        if vault_approle_path:
            params["approle_path"] = vault_approle_path
        if timeout is not None:
            params["timeout"] = timeout

        AppRoleAuthenticator().authenticate(self.client, **params)

    def _get_tls_skip_verify(self):
        """Get tls_skip_verify with special boolean handling from env."""
        value = self.get_option("tls_skip_verify")
        if value is not None:
            return value

        env_value = os.getenv("VAULT_SKIP_VERIFY")
        if env_value is not None:
            return env_value.lower() in ("true", "1", "yes")

        return None

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        vault_address = self._get_option_with_env("url", "VAULT_ADDR")
        if not vault_address:
            raise AnsibleLookupError("The 'url' parameter or VAULT_ADDR environment variable must be set")

        self.client = VaultClient(
            vault_address=vault_address,
            vault_namespace=self._get_option_with_env("namespace", "VAULT_NAMESPACE", "root"),
            ca_certificate=self._get_option_with_env("ca_cert", "VAULT_CACERT"),
            tls_skip_verify=self._get_tls_skip_verify(),
            proxies=self._get_option_with_env("proxies", "VAULT_PROXIES"),
            timeout=self._get_timeout(),
            retries=self._get_option_with_env("retries", "VAULT_RETRIES"),
        )
        self._authenticate()
