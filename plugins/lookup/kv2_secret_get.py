# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = """
name: kv2_secret_get
short_description: Look up KV2 secrets stored in HashiCorp Vault.
version_added: 1.0.0
author:
    - Aubin Bikouo (@abikouo)
description:
    - Look up KV2 secrets stored in HashiCorp Vault.
    - The plugin supports reading latest version as well as specific version of the KV2 secret.
options:
  engine_mount_point:
    description:
      - The mount path of the KV2 secrets engine.
      - Secret paths are relative to this mount point.
    type: str
    default: secret
    aliases: ['mount_point', 'secret_mount_path']
  secret:
    description:
      - Vault path to the secret being requested.
      - Path is relative to the engine_mount_point.
    type: str
    required: true
    aliases: ['secret_path']
  version:
    description:
      - Specifies the version to return. If not set the latest is returned.
    type: int
    required: false
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.plugins
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
  description:
      - A list of dictionary containing the KV2 secret data and metadata stored in HashiCorp Vault.
      - The 'data' key contains the actual secret key-value pairs.
      - The 'metadata' key contains version information, timestamps, and other metadata.
  type: list
  elements: dict
  sample:
    data:
      foo: "bar"
    metadata:
      created_time: "2025-09-08T18:09:19.403229608Z"
      custom_metadata: null
      deletion_time: ""
      destroyed: false
      version: 1
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
