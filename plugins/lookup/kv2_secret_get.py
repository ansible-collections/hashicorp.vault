# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = """
name: kv2_secret_get
short_description: Look up KV2 secrets stored in Hasicorp vault.
author:
    - Aubin Bikouo (@abikouo)
description:
    - Look up KV2 secrets stored in Hasicorp vault.
    - The plugin supports reading latest version as well as specific version of the KV2 secret.
options:
  auth_method:
    description:
      - Authentication method to use.
    default: token
    type: str
    choices: ['token', 'approle']
  token:
    description:
      - The token to use to authenticate when O(auth_method=token).
    type: str
    env:
      - name: VAULT_TOKEN
  vault_approle_role_id:
    description:
      - The role id to use to authenticate when O(auth_method=approle).
    type: str
    env:
      - name: VAULT_APPROLE_ROLE_ID
  vault_approle_secret_id:
    description:
      - The secret id to use to authenticate when O(auth_method=approle).
    type: str
    env:
      - name: VAULT_APPROLE_SECRET_ID
  vault_approle_path:
    description:
      - The custom AppRole mount path to use to authenticate when O(auth_method=approle).
    type: str
    default: approle
    env:
      - name: VAULT_APPROLE_PATH
  engine_mount_point:
    description:
      - The mount path of the KV2 secrets engine.
      - Secret paths are relative to this mount point.
    type: str
    default: secret
    aliases: ['mount_point', 'secret_mount_path']
  namespace:
    description:
      - Vault namespace where secrets reside.
    type: str
    default: admin
    aliases: ['vault_namespace']
  secret:
    description:
      - Vault path to the secret being requested.
      - Path is relative to the engine_mount_point.
    type: str
    required: true
    aliases: ['secret_path']
  url:
    description:
      - URL of the Vault service.
    type: str
    required: true
    aliases: ['vault_address']
    env:
      - name: VAULT_ADDR
  version:
    description:
      - Specifies the version to return. If not set the latest is returned.
    type: int
    required: false
"""


EXAMPLES = """
- name: Return latest KV2 secret from path
  ansible.builtin.debug:
    msg: "{{ lookup('hashicorp.vault.kv2_secret_get',
                    secret='hello',
                    url='https://myvault_url:8200') }}"

- name: Return a specific version of the KV2 secret from path
  ansible.builtin.debug:
    msg: "{{ lookup('hashicorp.vault.kv2_secret_get',
                    secret='bar',
                    version=3,
                    url='https://myvault_url:8200') }}"

- name: Return a secret using AppRole authentication
  ansible.builtin.debug:
    msg: "{{ lookup('hashicorp.vault.kv2_secret_get',
                    secret='foo',
                    auth_method='approle',
                    vault_approle_role_id='role-123',
                    vault_approle_secret_id='secret-456',
                    url='https://myvault_url:8200') }}"
"""

RETURN = """
_raw:
  description: Retrieves the KV2 secret data and metadata stored in HashiCorp Vault.
"""

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
    Secrets as VaultSecret,
)
from ansible_collections.hashicorp.vault.plugins.plugin_utils.base import VaultLookupBase


class LookupModule(VaultLookupBase):

    def run(self, terms, variables=None, **kwargs):
        """
        :arg terms: A list of terms passed to the function
        :variables: Ansible variables active at the time of the lookup
        :returns: A list containing the secret data
        """

        super().run(terms, variables, **kwargs)

        version = self.get_option("version")
        mount_path = self.get_option("engine_mount_point")
        secret = self.get_option("secret")
        secret_mgr = VaultSecret(self.client)

        result = secret_mgr.kv2.read_secret(
            mount_path=mount_path, secret_path=secret, version=version
        )
        return [result]
