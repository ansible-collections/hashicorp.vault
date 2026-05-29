# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_kv1_secrets import VaultKv1Secrets
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_kv2_secrets import VaultKv2Secrets
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_pki import VaultPki

__all__ = ['Secrets']


class Secrets:
    """A container class for different secrets engine clients.

    Attributes:
        kv1: Key-Value version 1 secrets engine
        kv2: Key-Value version 2 secrets engine
        pki: PKI (Public Key Infrastructure) secrets engine
    """

    def __init__(self, client):
        self.kv2 = VaultKv2Secrets(client)
        self.kv1 = VaultKv1Secrets(client)
        self.pki = VaultPki(client)
