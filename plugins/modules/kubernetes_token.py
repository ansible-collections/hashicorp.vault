# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

__metaclass__ = type  # pylint: disable=C0103

DOCUMENTATION = """
---
module: kubernetes_token
author: Joshua Beha (@Joshua-Beha)
version_added: "1.3.0"
short_description: Generate a Kubernetes bearer token from the Kubernetes secrets engine.
description:
    - Generates a short-lived Kubernetes bearer token for a Vault Kubernetes secrets engine role.
    - Each invocation generates a new token with a unique lease.
    - Supports Vault token and AppRole authentication through the standard collection authentication options.
options:
  kubernetes_mount_path:
    description: Kubernetes secrets engine mount path.
    type: str
    default: kubernetes
    aliases: [path]
  name:
    description: The name of the Kubernetes role to generate a token for.
    required: true
    type: str
    aliases: [role]
  kubernetes_namespace:
    description:
      - Kubernetes namespace to request credentials for.
      - When omitted, Vault uses the role or engine defaults.
    type: str
  ttl:
    description:
      - Requested TTL for the generated token.
      - The effective TTL is still subject to Vault role and mount limits.
    type: str
  audience:
    description:
      - Audience claim to request for the generated Kubernetes token.
    type: str
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
notes:
  - This module should be used with B(no_log=true) and C(register) to prevent sensitive token data from being logged to console or log files, as the generated Kubernetes bearer token provides authentication credentials.
  - This module is NOT idempotent - each call generates a new token with a new lease.
  - This module returns a Kubernetes bearer token from the Vault Kubernetes secrets engine, not a Vault auth token.
"""

EXAMPLES = """
- name: Generate a Kubernetes token using Vault token authentication
  hashicorp.vault.kubernetes_token:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    kubernetes_mount_path: myOcpCluster
    name: superuser
    audience: openshift
    ttl: 1h
    kubernetes_namespace: vault-test
    namespace: root
  no_log: true
  register: result

- name: Generate a Kubernetes token using AppRole authentication
  hashicorp.vault.kubernetes_token:
    url: https://vault.example.com:8200
    auth_method: approle
    role_id: "{{ vault_role_id }}"
    secret_id: "{{ vault_secret_id }}"
    kubernetes_mount_path: myOcpCluster
    name: superuser
    kubernetes_namespace: kube-system
    ttl: 1h
  no_log: true
  register: result

- name: Use the generated bearer token
  ansible.builtin.debug:
    msg: "{{ result.kubernetes_token.service_account_token }}"
  no_log: true
"""

RETURN = """
kubernetes_token:
  description: The generated Kubernetes token data and lease information.
  type: dict
  returned: always
  sample:
    {
        "service_account_name": "vault-secrets-superuser",
        "service_account_namespace": "kube-system",
        "service_account_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9...",
        "lease_id": "kubernetes/creds/superuser/abc123",
        "lease_duration": 3600,
        "renewable": false
    }
"""

import copy

from ansible.module_utils.basic import AnsibleModule  # type: ignore

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_kubernetes import (
    VaultKubernetes,
)


def main() -> None:
    """Entry point for module execution"""
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            kubernetes_mount_path=dict(type="str", default="kubernetes", aliases=["path"]),
            name=dict(type="str", required=True, aliases=["role"]),
            kubernetes_namespace=dict(type="str"),
            ttl=dict(type="str"),
            audience=dict(type="str"),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    if module.check_mode:
        module.exit_json(changed=True, kubernetes_token={})

    client = get_authenticated_client(module)

    mount_path = module.params.get("kubernetes_mount_path")
    name = module.params.get("name")

    try:
        kubernetes_client = VaultKubernetes(client, mount_path=mount_path)

        data = kubernetes_client.generate_token(
            name=name,
            kubernetes_namespace=module.params.get("kubernetes_namespace"),
            ttl=module.params.get("ttl"),
            audience=module.params.get("audience"),
        )

        module.exit_json(changed=True, kubernetes_token=data)

    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
