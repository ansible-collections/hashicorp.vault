# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type


class ModuleDocFragment:
    """Documentation fragment for HashiCorp Vault authentication options."""

    # Common Vault authentication options
    MODULES = r"""
options:
  url:
    description: Vault server URL.
    required: true
    type: str
    aliases: [vault_address]
  namespace:
    description: Vault namespace.
    default: admin
    type: str
    aliases: [vault_namespace]
  auth_method:
    description: Authentication method to use.
    choices: ['token', 'approle']
    default: token
    type: str
  token:
    description:
      - Vault token for authentication.
      - Token can be provided as a parameter or as an environment variable E(VAULT_TOKEN).
    type: str
  role_id:
    description:
      - Role ID for AppRole authentication.
      - AppRole O(role_id) can be provided as parameters or as environment variables E(VAULT_APPROLE_ROLE_ID).
    type: str
    aliases: [approle_role_id]
  secret_id:
    description:
      - Secret ID for AppRole authentication.
      - AppRole O(secret_id) can be provided as parameters or as environment variables E(VAULT_APPROLE_SECRET_ID).
    type: str
    aliases: [approle_secret_id]
  vault_approle_path:
    description: AppRole auth method mount path.
    default: approle
    type: str
notes:
  - Authentication is required for all Vault operations.
  - Token authentication is the default method.
  - For AppRole authentication, both O(role_id) and O(secret_id) are required.
  - Environment variables take precedence over module parameters when both are provided.
"""

    # Common Vault authentication options
    # - modules don't support 'env'
    PLUGINS = r"""
options:
  url:
    description: Vault server URL.
    required: true
    type: str
    aliases: [vault_address]
    env:
      - name: VAULT_ADDR
  namespace:
    description: Vault namespace.
    default: admin
    type: str
    aliases: [vault_namespace]
  auth_method:
    description: Authentication method to use.
    choices: ['token', 'approle']
    default: token
    type: str
  token:
    description:
      - Vault token for authentication.
    type: str
    env:
      - name: VAULT_TOKEN
  role_id:
    description:
      - Role ID for AppRole authentication.
      - Required when O(auth_method=approle).
    type: str
    aliases: [approle_role_id]
    env:
      - name: VAULT_APPROLE_ROLE_ID
  secret_id:
    description:
      - Secret ID for AppRole authentication.
      - Required when O(auth_method=approle).
    type: str
    aliases: [approle_secret_id]
    env:
      - name: VAULT_APPROLE_SECRET_ID
  vault_approle_path:
    description: AppRole auth method mount path.
    default: approle
    type: str
    env:
      - name: VAULT_APPROLE_PATH
notes:
  - Authentication is required for all Vault operations.
"""
