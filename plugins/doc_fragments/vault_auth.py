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
  ca_cert:
    description:
      - The path to a PEM-encoded CA certificate file to use for TLS verification.
      - If this parameter is not provided, the value of the E(VAULT_CACERT) environment variable will be used.
    type: str
    aliases:
      - cacert
      - ssl_ca_cert
    version_added: 1.2.0
  tls_skip_verify:
    description:
      - Controls whether the module verifies the TLS certificate presented by the Vault server.
      - If this parameter is not provided, the value of the E(VAULT_SKIP_VERIFY) environment variable will be used.
      - Setting this to V(true) disables certificate validation.
    type: bool
    default: false
    version_added: 1.2.0
  proxies:
    description:
      - URL(s) to the proxies used to access the Vault service.
      - It can be a string or a dict.
      - If it's a dict, provide the scheme (eg. C(http) or C(https)) as the key, and the URL as the value.
      - If it's a string, provide a single URL that will be used as the proxy for both C(http) and C(https) schemes.
      - A string that can be interpreted as a dictionary will be converted to one (see examples).
      - You can specify a different proxy for HTTP and HTTPS resources.
      - If not specified, the value of the E(VAULT_PROXIES) environment variable will be used.
      - This variable accepts either a simple string or a JSON-formatted string.
    type: raw
    version_added: 1.3.0
  timeout:
    description:
      - Timeout for Vault API requests in seconds.
      - If not specified, the value of the E(VAULT_TIMEOUT) environment variable will be used.
      - When not set, requests will wait indefinitely for a response.
    type: int
    version_added: 1.3.0
  retries:
    description:
    - Configure automatic retries for Vault API requests made through C(VaultClient).
    - When set to an integer, equivalent to C(urllib3.util.retry.Retry(total=N)).
      This retries transient transport failures (connection errors, read timeouts, and similar).
      It does not retry HTTP error status codes by default.
    - When set to a dict, passed as keyword arguments to C(urllib3.util.retry.Retry).
      Use this to retry specific HTTP status codes (C(status_forcelist)), include POST
      (C(allowed_methods)), or tune backoff (C(backoff_factor)).
    - Retries apply to API calls made after authentication, not to AppRole login requests.
      - If not specified, the value of the E(VAULT_RETRIES) environment variable will be used.
      - This variable accepts either a simple integer or a JSON-formatted string.
    type: raw
    version_added: 1.3.0
notes:
  - Authentication is required for all Vault operations.
  - Token authentication is the default method.
  - For AppRole authentication, both O(role_id) and O(secret_id) are required.
  - Module parameters take precedence over environment variables when both are provided.
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
  ca_cert:
    description:
      - The path to a PEM-encoded CA certificate file to use for TLS verification.
    type: str
    env:
      - name: VAULT_CACERT
    version_added: 1.2.0
  tls_skip_verify:
    description:
      - Controls whether the module verifies the TLS certificate presented by the Vault server.
      - Setting this to V(true) disables certificate validation.
    type: bool
    default: false
    env:
      - name: VAULT_SKIP_VERIFY
    version_added: 1.2.0
  proxies:
    description:
      - URL(s) to the proxies used to access the Vault service.
      - It can be a string or a dict.
      - If it's a dict, provide the scheme (eg. C(http) or C(https)) as the key, and the URL as the value.
      - If it's a string, provide a single URL that will be used as the proxy for both C(http) and C(https) schemes.
      - A string that can be interpreted as a dictionary will be converted to one (see examples).
      - If not specified, the value of the E(VAULT_PROXIES) environment variable will be used.
    type: raw
    env:
      - name: VAULT_PROXIES
    version_added: 1.3.0
  timeout:
    description:
      - Timeout for Vault API requests in seconds.
      - When not set, requests will wait indefinitely for a response.
    type: int
    env:
      - name: VAULT_TIMEOUT
    version_added: 1.3.0
  retries:
    description:
      - Number of retries to perform on failed requests, or a dictionary of retry configuration.
      - When set to an integer, retries that many times on connection errors and retryable status codes.
      - When set to a dict, it is passed as keyword arguments to C(urllib3.util.retry.Retry).
    type: raw
    env:
      - name: VAULT_RETRIES
    version_added: 1.3.0
notes:
  - Authentication is required for all Vault operations.
"""
