# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = """
name: kv1_secret_get
short_description: Look up KV1 secrets stored in HashiCorp Vault.
version_added: 1.1.0
author:
    - Aubin Bikouo (@abikouo)
description:
    - Look up KV1 secrets stored in HashiCorp Vault.
    - Read secret in HashiCorp Vault KV version 1 secrets engine.
options:
  engine_mount_point:
    description:
      - The KV secrets engine mount point.
    default: secret
    type: str
    aliases: ['mount_point', 'secret_mount_path']
  secret:
    description:
      - The Vault path to the secret being requested.
    required: true
    type: str
    aliases: ['secret_path']
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.plugins
"""


EXAMPLES = """
- name: Retrieve a secret from the Vault
  ansible.builtin.debug:
    msg: "{{ lookup('hashicorp.vault.kv1_secret_get',
                    secret='hello',
                    url='https://myvault_url:8200') }}"
"""

RETURN = """
_raw:
  description:
      - A list of dictionaries containing the KV1 secret data stored in HashiCorp Vault.
      - The 'data' key contains the actual secret key-value pairs.
  type: list
  elements: dict
  sample:
    foo: "bar"
"""

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
    Secrets as VaultSecret,
)
from ansible_collections.hashicorp.vault.plugins.plugin_utils.base import VaultLookupBase


class LookupModule(VaultLookupBase):

    def run(self, terms, variables=None, **kwargs):
        """
        :arg terms: A list of terms passed to the function
        :arg variables: Ansible variables active at the time of the lookup
        :returns: A list containing the secret data
        """

        super().run(terms, variables, **kwargs)

        mount_path = self.get_option("engine_mount_point")
        secret = self.get_option("secret")
        secret_mgr = VaultSecret(self.client)

        result = secret_mgr.kv1.read_secret(mount_path=mount_path, secret_path=secret)
        return [result]
