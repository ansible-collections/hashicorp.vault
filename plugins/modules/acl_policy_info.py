# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: acl_policy_info
short_description: List and read HashiCorp Vault ACL policies
version_added: 1.2.0
author: Mandar Kulkarni (@mandar242)
description:
  - Query Vault ACL policies via the C(/sys/policy) API (list names or read one policy).
  - Omit I(name) to list all policy names.
  - Set I(name) to read that policy's C(name) and C(rules).
options:
  name:
    description:
      - ACL policy name to read. When omitted, lists all policy names.
    type: str
    required: false
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
"""

EXAMPLES = """
- name: List all ACL policy names (register for later tasks)
  hashicorp.vault.acl_policy_info:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
  register: vault_acl_policies

- name: Show policy names from registered result
  ansible.builtin.debug:
    msg: "{{ vault_acl_policies.policies | map(attribute='name') | list }}"

- name: Read a single ACL policy (name and HCL rules)
  hashicorp.vault.acl_policy_info:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    name: my-app-policy
  register: vault_policy_doc

- name: Use policy rules in a demo or template
  ansible.builtin.debug:
    msg: "{{ vault_policy_doc.policies[0].rules }}"
"""

RETURN = """
policies:
  description:
    - List of policy objects returned by C(acl_policy_info).
    - Without I(name), each entry includes C(name).
    - With I(name), the single entry includes C(name) and C(rules).
  returned: always
  type: list
  elements: dict
  sample:
    - name: "my-policy"
      rules: |
        path "secret/data/myapp/*" {
          capabilities = ["read", "list"]
        }
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


def main():

    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            name=dict(type="str"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Get authenticated client
    client = get_authenticated_client(module)
    name = module.params.get("name")

    try:
        if name:
            data = client.acl_policies.read_acl_policy(name)
            module.exit_json(
                changed=False,
                policies=[{"name": name, "rules": data.get("rules", "")}],
            )
        else:
            policy_names = client.acl_policies.list_acl_policies()
            policies = [{"name": policy_name} for policy_name in policy_names]
            module.exit_json(changed=False, policies=policies)

    except VaultSecretNotFoundError:
        module.exit_json(changed=False, policies=[])
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
