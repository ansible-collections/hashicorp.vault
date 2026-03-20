# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: acl_policy
short_description: Manage HashiCorp Vault ACL policies
version_added: 1.2.0
author: Mandar Kulkarni (@mandar242)
description:
  - Create, update, or delete ACL policies via C(/sys/policy).
  - For read-only operations, use M(hashicorp.vault.acl_policy_info).
  - Uses the collection's shared connection and authentication options; HTTP calls are handled by the ACL policy client on the Vault client.
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
options:
  name:
    description:
      - Name of the ACL policy (URL path segment for C(/sys/policy/:name)).
    type: str
    required: true
  policy:
    description:
      - Policy document as a string (HCL rules body sent as the C(policy) field in the Vault API).
      - Required when O(state=present).
    type: str
    aliases: [rules]
  state:
    description:
      - V(present) creates the policy or updates it when the rules differ from the desired document.
      - V(absent) removes the policy. Deleting a non-existent policy succeeds with C(changed=false).
    type: str
    choices: [present, absent]
    default: present
"""

EXAMPLES = """
- name: Create or update an ACL policy
  hashicorp.vault.acl_policy:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    name: my-app-policy
    policy: |
      path "secret/data/myapp/*" {
        capabilities = ["read", "list"]
      }

- name: Same policy using rules alias
  hashicorp.vault.acl_policy:
    url: https://vault.example.com:8200
    name: deploy-policy
    rules: |
      path "secret/data/deploy/*" {
        capabilities = ["read", "update", "create"]
      }

- name: Remove an ACL policy
  hashicorp.vault.acl_policy:
    url: https://vault.example.com:8200
    name: old-policy
    state: absent
"""

RETURN = """
msg:
  description: Human-readable result message.
  returned: always
  type: str
raw:
  description: Raw JSON response from Vault on create/update (often empty).
  returned: when I(state=present) and the policy was created or updated
  type: dict
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


def ensure_policy_present(module: AnsibleModule, client) -> None:
    name = module.params["name"]
    desired_rules = module.params["policy"]

    action = "created"
    try:
        existing = client.acl_policies.read_acl_policy(name)
        current_rules = existing.get("rules", "")
        if current_rules == desired_rules:
            module.exit_json(
                changed=False,
                msg="ACL policy already exists with the same rules",
            )
        action = "updated"
    except VaultSecretNotFoundError:
        pass

    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have {action} ACL policy {name!r} if not in check mode.",
        )

    raw = client.acl_policies.create_or_update_acl_policy(name, desired_rules)
    module.exit_json(
        changed=True,
        msg=f"ACL policy {name!r} {action} successfully",
        raw=raw or {},
    )


def ensure_policy_absent(module: AnsibleModule, client) -> None:
    name = module.params["name"]

    # Use read for idempotency: Vault may return success on DELETE even when the
    # policy is already gone (e.g. HCP), so we cannot rely on 404 from delete alone.
    try:
        client.acl_policies.read_acl_policy(name)
    except VaultSecretNotFoundError:
        module.exit_json(
            changed=False,
            msg=f"ACL policy {name!r} already absent",
        )

    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have deleted ACL policy {name!r} if not in check mode.",
        )

    client.acl_policies.delete_acl_policy(name)
    module.exit_json(
        changed=True,
        msg=f"ACL policy {name!r} deleted successfully",
    )


def main():
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            policy=dict(type="str", aliases=["rules"]),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[("state", "present", ["policy"])],
        supports_check_mode=True,
    )

    client = get_authenticated_client(module)
    state = module.params["state"]

    try:
        if state == "present":
            ensure_policy_present(module, client)
        else:
            ensure_policy_absent(module, client)
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except TypeError as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
