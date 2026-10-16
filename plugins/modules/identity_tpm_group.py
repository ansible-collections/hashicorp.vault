# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: identity_tpm_group
short_description: Manage HashiCorp Vault TPM identity groups
version_added: 2.0.0
author: Ansible (@ansible)
description:
  - Create, update, or delete a TPM group at C(identity/tpmgroup).
  - Requires Vault Enterprise 2.2.0 or later.
  - Create writes the collection path. Later reads, updates, and deletes use the group id when it is known, otherwise the name.
  - Member ids are compared as a set, so a second run with the same members in a different order reports no change.
  - O(name) is what a later run uses to find the group. Vault generates a name when it is omitted, and each run then creates a new group.
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
options:
  name:
    description:
      - Name of the TPM group.
      - Required for an idempotent group. Vault generates a name when this is omitted.
    type: str
  member_tpm_ids:
    description:
      - TPM record ids that belong to the group.
    type: list
    elements: str
  metadata:
    description:
      - Metadata associated with the group.
    type: dict
  tpm_group_id:
    description:
      - Id Vault assigned to the group.
      - Set this to update or delete an existing group by id. When it is set and the group does not exist, the task fails instead of creating a new one.
    type: str
  state:
    description:
      - V(present) creates the group or updates members and metadata when they differ.
      - V(absent) deletes the group. Deleting a missing group succeeds with C(changed=false).
    type: str
    choices: [present, absent]
    default: present
"""

EXAMPLES = """
- name: Group enrolled servers
  hashicorp.vault.identity_tpm_group:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    name: production-servers
    member_tpm_ids:
      - "{{ enroll_tpm.tpm_id }}"
    metadata:
      environment: production
  register: server_group

- name: Remove a TPM group
  hashicorp.vault.identity_tpm_group:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    name: production-servers
    state: absent
"""

RETURN = """
msg:
  description: Human-readable result message.
  returned: always
  type: str
tpm_group_id:
  description: Id Vault assigned to the TPM group.
  returned: when the group exists or was just written
  type: str
data:
  description: TPM group record.
  returned: when the group exists or was just written
  type: dict
  contains:
    name:
      description: Group name.
      type: str
    member_tpm_ids:
      description: Member TPM ids.
      type: list
      elements: str
    metadata:
      description: Metadata stored on the group.
      type: dict
    tpm_group_id:
      description: Id Vault assigned to the group.
      type: str
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultConfigurationError,
    VaultPermissionError,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_tpm import (
    decide_group_action,
    group_result,
    omit_none,
)


def _exit_present(module, changed, msg, record):
    data = group_result(record)
    module.exit_json(changed=changed, msg=msg, tpm_group_id=data.get("tpm_group_id"), data=data)


def ensure_group_present(module: AnsibleModule, tpm) -> None:
    name = module.params.get("name")
    tpm_group_id = module.params.get("tpm_group_id")
    desired = omit_none(
        {
            "name": name,
            "member_tpm_ids": module.params.get("member_tpm_ids"),
            "metadata": module.params.get("metadata"),
        }
    )
    existing = tpm.read_group(name=name, tpm_group_id=tpm_group_id)
    if tpm_group_id and existing is None:
        module.fail_json(msg=f"TPM group {tpm_group_id!r} was not found")

    action = decide_group_action(existing, desired)
    label = name or tpm_group_id or "unnamed"

    if action == "unchanged":
        _exit_present(module, False, f"TPM group {label!r} already matches", existing)

    if module.check_mode:
        verb = "created" if action == "create" else "updated"
        module.exit_json(
            changed=True,
            msg=f"Would have {verb} TPM group {label!r} if not in check mode.",
            data=group_result(existing),
        )

    if action == "update":
        current_id = existing.get("id") or tpm_group_id
        tpm.update_group(desired, name=existing.get("name") or name, tpm_group_id=current_id)
        created = {"id": current_id, "name": existing.get("name") or name}
        verb = "updated"
    else:
        created = tpm.create_group(desired)
        verb = "created"

    current_id = (created or {}).get("id") or tpm_group_id
    current_name = (created or {}).get("name") or name
    current = tpm.read_group(name=current_name, tpm_group_id=current_id) or created
    _exit_present(module, True, f"TPM group {label!r} {verb} successfully", current)


def ensure_group_absent(module: AnsibleModule, tpm) -> None:
    name = module.params.get("name")
    tpm_group_id = module.params.get("tpm_group_id")
    if not name and not tpm_group_id:
        raise VaultConfigurationError("name or tpm_group_id is required when state=absent")

    existing = tpm.read_group(name=name, tpm_group_id=tpm_group_id)
    label = name or tpm_group_id
    if existing is None:
        module.exit_json(changed=False, msg=f"TPM group {label!r} already absent")

    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have deleted TPM group {label!r} if not in check mode.",
        )

    tpm.delete_group(name=existing.get("name") or name, tpm_group_id=existing.get("id") or tpm_group_id)
    module.exit_json(changed=True, msg=f"TPM group {label!r} deleted successfully")


def main():
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            name=dict(type="str"),
            member_tpm_ids=dict(type="list", elements="str"),
            metadata=dict(type="dict"),
            tpm_group_id=dict(type="str"),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    client = get_authenticated_client(module)
    try:
        if module.params["state"] == "present":
            ensure_group_present(module, client.tpm)
        else:
            ensure_group_absent(module, client.tpm)
    except VaultPermissionError as exc:
        module.fail_json(msg=f"Permission denied: {exc}")
    except VaultConfigurationError as exc:
        module.fail_json(msg=str(exc))
    except VaultApiError as exc:
        module.fail_json(msg=f"Vault API error: {exc}")
    except Exception as exc:
        module.fail_json(msg=f"Operation failed: {exc}")


if __name__ == "__main__":
    main()
