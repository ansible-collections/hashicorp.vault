# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: vault_namespace_info
short_description: List and read HashiCorp Vault Enterprise namespaces
version_added: 1.2.0
author: Chyna Sanders (@chynasan)
description:
  - Query Vault Enterprise namespaces via the C(/sys/namespaces) API (list or read one namespace).
  - Omit O(path) to list all namespace paths.
  - Set O(path) to read that namespace's C(id), C(path), and C(custom_metadata).
  - Open Source Vault does not expose these APIs; operations will fail with an error from Vault.
options:
  path:
    description:
      - Namespace path to read. When omitted, lists all namespace paths.
    type: str
    required: false
    aliases: [namespace_path]
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
"""

EXAMPLES = """
- name: List all namespace paths (register for later tasks)
  hashicorp.vault.vault_namespace_info:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
  register: vault_namespaces

- name: Show namespace paths from registered result
  ansible.builtin.debug:
    msg: "{{ vault_namespaces.namespaces | map(attribute='path') | list }}"

- name: Read a single namespace (id, path, and custom_metadata)
  hashicorp.vault.vault_namespace_info:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    path: engineering/
  register: vault_namespace_details

- name: Use namespace metadata in a template
  ansible.builtin.debug:
    msg: "{{ vault_namespace_details.namespaces[0].custom_metadata }}"
"""

RETURN = """
namespaces:
  description:
    - List of namespace objects returned by C(vault_namespace_info).
    - Without O(path), returns all namespaces with C(id), C(path), and C(custom_metadata) for each.
    - With O(path), returns a single entry with C(id), C(path), and C(custom_metadata).
  returned: always
  type: list
  elements: dict
  sample:
    - id: "gsudz"
      path: "engineering/"
      custom_metadata:
        team: "platform"
        environment: "prod"
namespaces_keys:
  description:
    - List of namespace paths returned by Vault when listing namespaces.
    - Only returned when O(path) is not specified (list operation).
  returned: when listing all namespaces
  type: list
  elements: str
  sample:
    - "engineering/"
    - "finance/"
    - "operations/"
namespaces_key_info:
  description:
    - Dictionary mapping namespace paths to their detailed information.
    - Each entry contains C(id), C(path), and C(custom_metadata) for the namespace.
    - Only returned when O(path) is not specified (list operation).
  returned: when listing all namespaces
  type: dict
  sample:
    "engineering/":
      id: "gsudz"
      path: "engineering/"
      custom_metadata:
        team: "platform"
        environment: "prod"
    "finance/":
      id: "htvek"
      path: "finance/"
      custom_metadata:
        team: "finance"
        environment: "prod"
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)


def _normalize_namespace_path(path):
    """Strip slashes for Vault API paths to match vault_namespace behavior."""
    if path is None:
        return None
    normalized = path.strip("/")
    return normalized or None


def main():

    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            path=dict(type="str", aliases=["namespace_path"]),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Get authenticated client
    client = get_authenticated_client(module)
    path = _normalize_namespace_path(module.params.get("path"))

    try:
        if path:
            # Read a single namespace
            data = client.namespaces.read_namespace(path)
            module.exit_json(
                changed=False,
                namespaces=[data],
            )
        else:
            # List all namespaces
            # list_namespaces() returns [{"keys": [...], "key_info": {...}}]
            list_data = client.namespaces.list_namespaces()
            data = list_data[0] if list_data else {}
            key_info = data.get("key_info", {})
            keys = data.get("keys", [])
            namespaces = [v for k, v in key_info.items()]
            module.exit_json(
                changed=False,
                namespaces=namespaces,
                namespaces_key_info=key_info,
                namespaces_keys=keys,
            )
    except VaultSecretNotFoundError:
        module.exit_json(changed=False, namespaces=[], namespaces_keys=[], namespaces_key_info={})
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
