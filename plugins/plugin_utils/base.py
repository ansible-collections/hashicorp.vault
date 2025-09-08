# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from typing import NoReturn

from ansible.errors import AnsibleLookupError
from ansible.module_utils._text import to_native
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

        auth_method = self.get_option("auth_method")

        try:
            if auth_method == "token":
                TokenAuthenticator().authenticate(self.client, token=self.get_option("token"))
            else:
                params = {
                    "vault_address": self.get_option("url"),
                    "role_id": self.get_option("vault_approle_role_id"),
                    "secret_id": self.get_option("vault_approle_secret_id"),
                    "vault_namespace": self.get_option("namespace"),
                }

                vault_approle_path = self.get_option("vault_approle_path")
                if vault_approle_path is not None:
                    params.update({"approle_path": vault_approle_path})

                AppRoleAuthenticator().authenticate(self.client, **params)
        except VaultError as e:
            raise AnsibleLookupError(f"Vault lookup exception: {to_native(e)}")

    def run(self, terms, variables=None, **kwargs):

        self.set_options(var_options=variables, direct=kwargs)

        vault_namespace = self.get_option("namespace")
        vault_address = self.get_option("url")
        self.client = VaultClient(vault_address=vault_address, vault_namespace=vault_namespace)
        self._authenticate()
