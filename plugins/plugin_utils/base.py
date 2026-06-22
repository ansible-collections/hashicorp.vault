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

    def _authenticate(self) -> None:
        # Get authentication options with environment variable fallback
        auth_method = self.get_option("auth_method")
        if auth_method is None:
            auth_method = os.getenv("VAULT_AUTH_METHOD", "token")

        timeout_opt = self.get_option("timeout")
        timeout = (
            timeout_opt
            if timeout_opt is not None
            else (int(os.getenv("VAULT_TIMEOUT")) if os.getenv("VAULT_TIMEOUT") else None)
        )

        try:
            if auth_method == "token":
                token = self.get_option("token")
                if token is None:
                    token = os.getenv("VAULT_TOKEN")
                TokenAuthenticator().authenticate(self.client, token=token)
            else:
                vault_address = self.get_option("url")
                if vault_address is None:
                    vault_address = os.getenv("VAULT_ADDR")

                role_id = self.get_option("role_id")
                if role_id is None:
                    role_id = os.getenv("VAULT_APPROLE_ROLE_ID")

                secret_id = self.get_option("secret_id")
                if secret_id is None:
                    secret_id = os.getenv("VAULT_APPROLE_SECRET_ID")

                vault_namespace = self.get_option("namespace")
                if vault_namespace is None:
                    vault_namespace = os.getenv("VAULT_NAMESPACE", "admin")

                params = {
                    "vault_address": vault_address,
                    "role_id": role_id,
                    "secret_id": secret_id,
                    "vault_namespace": vault_namespace,
                }

                vault_approle_path = self.get_option("vault_approle_path")
                if vault_approle_path is None:
                    vault_approle_path = os.getenv("VAULT_APPROLE_PATH", "approle")
                if vault_approle_path:
                    params.update({"approle_path": vault_approle_path})
                if timeout is not None:
                    params.update({"timeout": timeout})

                AppRoleAuthenticator().authenticate(self.client, **params)
        except VaultError as e:
            raise AnsibleLookupError(f"Vault lookup exception: {to_text(e)}")

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        # Get options with environment variable fallback
        vault_namespace = self.get_option("namespace")
        if vault_namespace is None:
            vault_namespace = os.getenv("VAULT_NAMESPACE", "admin")

        vault_address = self.get_option("url")
        if vault_address is None:
            vault_address = os.getenv("VAULT_ADDR")

        ca_cert = self.get_option("ca_cert")
        if ca_cert is None:
            ca_cert = os.getenv("VAULT_CACERT")

        tls_skip_verify_opt = self.get_option("tls_skip_verify")
        tls_skip_verify_env = os.getenv("VAULT_SKIP_VERIFY")
        if tls_skip_verify_opt is not None:
            tls_skip_verify = tls_skip_verify_opt
        elif tls_skip_verify_env is not None:
            tls_skip_verify = tls_skip_verify_env.lower() in ("true", "1", "yes")
        else:
            tls_skip_verify = None

        proxies = self.get_option("proxies")
        if proxies is None:
            proxies = os.getenv("VAULT_PROXIES")

        timeout_opt = self.get_option("timeout")
        timeout = (
            timeout_opt
            if timeout_opt is not None
            else (int(os.getenv("VAULT_TIMEOUT")) if os.getenv("VAULT_TIMEOUT") else None)
        )

        retries = self.get_option("retries")
        if retries is None:
            retries = os.getenv("VAULT_RETRIES")
        self.client = VaultClient(
            vault_address=vault_address,
            vault_namespace=vault_namespace,
            ca_certificate=ca_cert,
            tls_skip_verify=tls_skip_verify,
            proxies=proxies,
            timeout=timeout,
            retries=retries,
        )
        self._authenticate()
