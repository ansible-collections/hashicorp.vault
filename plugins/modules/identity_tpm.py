# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: identity_tpm
short_description: Manage HashiCorp Vault TPM identity records
version_added: 2.0.0
author: Ansible (@ansible)
description:
  - Register or remove a TPM identity at C(identity/tpm).
  - Requires Vault Enterprise 2.2.0 or later.
  - This is the same write as C(vault tpm enroll) and the C(vault_identity_tpm) resource. Pass O(tpm_ek_public_key) when the endorsement key is already known, or O(device_path) to read the RSA endorsement key from the local TPM.
  - O(device_path) runs on the managed node and needs tpm2-tools (C(tpm2_createek) and C(tpm2_readpublic)). A controller-side HTTP call cannot create the key.
  - A second run against the same name reports no change when the endorsement key, disabled flag, and metadata match. PEM comparison ignores surrounding whitespace and a missing trailing newline, matching Vault's stored form.
  - Changing the endorsement key deletes the record and creates it again. The new record receives a new TPM id. C(disabled) and C(metadata) update in place.
  - O(name) is what a later run uses to find the record. Vault generates a name when it is omitted, and each run then creates a new record because Ansible does not keep the generated name.
  - O(state=absent) deletes by O(name) or O(tpm_id). Deleting a missing record succeeds with C(changed=false).
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
options:
  name:
    description:
      - Name of the TPM record.
      - Required for an idempotent enroll. Vault generates a name when this is omitted.
    type: str
  tpm_ek_public_key:
    description:
      - PEM-encoded TPM endorsement key public key.
      - Required when O(state=present) unless O(device_path) is set.
      - Mutually exclusive with O(device_path).
    type: str
  device_path:
    description:
      - TPM device to read the RSA endorsement key from, typically V(/dev/tpmrm0).
      - Required when O(state=present) unless O(tpm_ek_public_key) is set.
      - Mutually exclusive with O(tpm_ek_public_key).
    type: str
  disabled:
    description:
      - Whether the TPM record is disabled.
    type: bool
  metadata:
    description:
      - Metadata associated with the TPM record.
    type: dict
  tpm_id:
    description:
      - TPM id Vault assigned (SHA256 of the endorsement key).
      - Set this to update or delete an existing record by id. When it is set and the record does not exist, the task fails instead of creating a new one.
    type: str
  state:
    description:
      - V(present) creates the record, updates disabled and metadata, or replaces it when the endorsement key changed.
      - V(absent) deletes the record.
    type: str
    choices: [present, absent]
    default: present
"""

EXAMPLES = """
- name: Enroll the local TPM
  hashicorp.vault.identity_tpm:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    name: app-server-01
    device_path: /dev/tpmrm0
    metadata:
      environment: production
  register: enroll_tpm

- name: Enroll from a known endorsement key
  hashicorp.vault.identity_tpm:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    name: app-server-02
    tpm_ek_public_key: "{{ lookup('file', 'ek.pem') }}"
    disabled: false

- name: Remove a TPM identity
  hashicorp.vault.identity_tpm:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    name: app-server-01
    state: absent
"""

RETURN = """
msg:
  description: Human-readable result message.
  returned: always
  type: str
tpm_id:
  description: Id Vault assigned to the TPM record.
  returned: when the record exists or was just written
  type: str
data:
  description: TPM identity record.
  returned: when the record exists or was just written
  type: dict
  contains:
    name:
      description: TPM record name.
      type: str
    tpm_ek_public_key:
      description: PEM endorsement key stored by Vault.
      type: str
    disabled:
      description: Whether the record is disabled.
      type: bool
    metadata:
      description: Metadata stored on the record.
      type: dict
    tpm_id:
      description: Id Vault assigned to the record.
      type: str
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.tpm_device import (
    TpmDeviceError,
    read_endorsement_key_pem,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultConfigurationError,
    VaultPermissionError,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_tpm import (
    decide_identity_action,
    identity_result,
    normalize_pem,
    omit_none,
)


def _identity_body(desired: dict) -> dict:
    body = omit_none(desired)
    if "tpm_ek_public_key" in body:
        body["tpm_ek_public_key"] = normalize_pem(body["tpm_ek_public_key"])
    return body


def _exit_present(module, changed, msg, record):
    data = identity_result(record)
    module.exit_json(changed=changed, msg=msg, tpm_id=data.get("tpm_id"), data=data)


def ensure_identity_present(module: AnsibleModule, tpm) -> None:
    name = module.params.get("name")
    tpm_id = module.params.get("tpm_id")
    if module.params.get("device_path"):
        pem = read_endorsement_key_pem(module.params["device_path"])
    elif module.params.get("tpm_ek_public_key"):
        pem = normalize_pem(module.params["tpm_ek_public_key"])
    else:
        raise VaultConfigurationError("tpm_ek_public_key or device_path is required when state=present")

    desired = omit_none(
        {
            "name": name,
            "tpm_ek_public_key": pem,
            "disabled": module.params.get("disabled"),
            "metadata": module.params.get("metadata"),
        }
    )
    existing = tpm.read_identity(name=name, tpm_id=tpm_id)
    if tpm_id and existing is None:
        module.fail_json(msg=f"TPM identity {tpm_id!r} was not found")

    action = decide_identity_action(existing, desired)
    label = name or tpm_id or "unnamed"

    if action == "unchanged":
        _exit_present(module, False, f"TPM identity {label!r} already matches", existing)

    if module.check_mode:
        verbs = {"create": "created", "update": "updated", "replace": "replaced"}
        module.exit_json(
            changed=True,
            msg=f"Would have {verbs[action]} TPM identity {label!r} if not in check mode.",
            data=identity_result(existing),
        )

    if action == "replace":
        tpm.delete_identity(name=existing.get("name"), tpm_id=existing.get("id"))
        created = tpm.create_identity(_identity_body(desired))
        verb = "replaced"
    elif action == "update":
        current_id = existing.get("id") or tpm_id
        tpm.update_identity(_identity_body(desired), name=existing.get("name") or name, tpm_id=current_id)
        created = {"id": current_id}
        verb = "updated"
    else:
        created = tpm.create_identity(_identity_body(desired))
        verb = "created"

    current_id = (created or {}).get("id") or tpm_id
    current_name = (created or {}).get("name") or name
    current = tpm.read_identity(name=current_name, tpm_id=current_id) or created
    _exit_present(module, True, f"TPM identity {label!r} {verb} successfully", current)


def ensure_identity_absent(module: AnsibleModule, tpm) -> None:
    name = module.params.get("name")
    tpm_id = module.params.get("tpm_id")
    if not name and not tpm_id:
        raise VaultConfigurationError("name or tpm_id is required when state=absent")

    existing = tpm.read_identity(name=name, tpm_id=tpm_id)
    label = name or tpm_id
    if existing is None:
        module.exit_json(changed=False, msg=f"TPM identity {label!r} already absent")

    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have deleted TPM identity {label!r} if not in check mode.",
        )

    tpm.delete_identity(name=existing.get("name") or name, tpm_id=existing.get("id") or tpm_id)
    module.exit_json(changed=True, msg=f"TPM identity {label!r} deleted successfully")


def main():
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            name=dict(type="str"),
            tpm_ek_public_key=dict(type="str"),
            device_path=dict(type="str"),
            disabled=dict(type="bool"),
            metadata=dict(type="dict"),
            tpm_id=dict(type="str"),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        mutually_exclusive=[("tpm_ek_public_key", "device_path")],
        supports_check_mode=True,
    )

    client = get_authenticated_client(module)
    try:
        if module.params["state"] == "present":
            ensure_identity_present(module, client.tpm)
        else:
            ensure_identity_absent(module, client.tpm)
    except TpmDeviceError as exc:
        module.fail_json(msg=str(exc))
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
