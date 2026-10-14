# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: tpm_role
short_description: Manage HashiCorp Vault TPM auth roles
version_added: 2.0.0
author: Ansible (@ansible)
description:
  - Create, update, or delete a role at C(auth/:mount/role/:name).
  - Requires Vault Enterprise 2.2.0 or later.
  - At least one of O(tpm_ids) or O(tpmgroup_ids) must be set when O(state=present), and a list that is set cannot be empty. This matches vault_tpm_auth_backend_role.
  - A second run with the same parameters reports no change. Membership and token policy lists are compared as sets.
  - O(cert_ttl) and the token TTL fields are integer seconds. V(0) for O(cert_ttl) inherits default_cert_ttl from the auth backend config.
  - O(mount) and O(name) identify the role. Pointing them at a different role does not delete the previous one.
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
options:
  mount:
    description:
      - TPM auth backend mount path.
    type: str
    required: true
  name:
    description:
      - Name of the TPM role.
    type: str
    required: true
  display_name:
    description:
      - Display name for the role. Vault defaults this to the role name.
    type: str
  cert_ttl:
    description:
      - Certificate TTL for the role, in seconds.
      - V(0) inherits the backend default_cert_ttl.
    type: int
  tpm_ids:
    description:
      - TPM record IDs allowed to authenticate with this role.
      - At least one of O(tpm_ids) or O(tpmgroup_ids) is required when O(state=present).
    type: list
    elements: str
  tpmgroup_ids:
    description:
      - TPM group IDs allowed to authenticate with this role.
      - At least one of O(tpm_ids) or O(tpmgroup_ids) is required when O(state=present).
    type: list
    elements: str
  token_ttl:
    description:
      - Incremental lifetime for generated tokens, in seconds.
    type: int
  token_max_ttl:
    description:
      - Maximum lifetime for generated tokens, in seconds.
    type: int
  token_period:
    description:
      - Period for periodic tokens, in seconds. The token does not expire if it is renewed within this period.
    type: int
  token_explicit_max_ttl:
    description:
      - Hard cap on token lifetime, in seconds, even when O(token_ttl) and O(token_max_ttl) would allow renewal.
    type: int
  token_policies:
    description:
      - Policies encoded onto generated tokens.
    type: list
    elements: str
  token_bound_cidrs:
    description:
      - CIDR blocks which can authenticate, and which the resulting token is bound to.
    type: list
    elements: str
  token_no_default_policy:
    description:
      - When V(true), the default policy is not added to generated tokens.
    type: bool
  token_num_uses:
    description:
      - Maximum number of times a generated token may be used. V(0) means unlimited.
    type: int
  token_type:
    description:
      - Type of token to generate.
    type: str
    choices: [service, batch, default, default-service, default-batch]
  alias_metadata:
    description:
      - Metadata tied to the generated entity alias.
    type: dict
  state:
    description:
      - V(present) creates the role or updates it when the supplied fields differ.
      - V(absent) deletes the role. Deleting a missing role succeeds with C(changed=false).
    type: str
    choices: [present, absent]
    default: present
notes:
  - Omitted options are not sent. Vault replaces the role with the fields in the write, so pass every field this task should keep.
"""

EXAMPLES = """
- name: Create a TPM auth role for one machine
  hashicorp.vault.tpm_role:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    mount: tpm
    name: app-servers
    tpm_ids:
      - "{{ enroll_tpm.tpm_id }}"
    token_policies:
      - tpm-policy
    token_ttl: 3600
    token_max_ttl: 7200
    token_no_default_policy: true

- name: Authorize a TPM group
  hashicorp.vault.tpm_role:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    mount: tpm
    name: app-servers
    tpmgroup_ids:
      - "{{ server_group.tpm_group_id }}"
    cert_ttl: 2592000
    token_type: batch
    token_bound_cidrs:
      - 10.0.0.0/8

- name: Delete a TPM auth role
  hashicorp.vault.tpm_role:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    mount: tpm
    name: app-servers
    state: absent
"""

RETURN = """
msg:
  description: Human-readable result message.
  returned: always
  type: str
data:
  description: Role document read back from Vault.
  returned: when O(state=present) and the role exists or was just written
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
    VaultConfigurationError,
    VaultPermissionError,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_tpm import (
    decide_role_action,
    omit_none,
    role_result,
)

_ROLE_FIELDS = (
    "display_name",
    "cert_ttl",
    "tpm_ids",
    "tpmgroup_ids",
    "token_ttl",
    "token_max_ttl",
    "token_period",
    "token_explicit_max_ttl",
    "token_policies",
    "token_bound_cidrs",
    "token_no_default_policy",
    "token_num_uses",
    "token_type",
    "alias_metadata",
)


def _binding_lists(params: dict) -> None:
    provided = []
    for field in ("tpm_ids", "tpmgroup_ids"):
        value = params.get(field)
        if value is None:
            continue
        if len(value) < 1:
            raise VaultConfigurationError(f"{field} must contain at least one id")
        provided.append(field)
    if not provided:
        raise VaultConfigurationError("tpm_ids or tpmgroup_ids is required when state=present")


def ensure_role_present(module: AnsibleModule, tpm) -> None:
    mount = module.params["mount"].strip("/")
    name = module.params["name"]
    _binding_lists(module.params)
    desired = omit_none({field: module.params.get(field) for field in _ROLE_FIELDS})
    existing = tpm.read_role(mount, name)
    action = decide_role_action(existing, desired)

    if action == "unchanged":
        module.exit_json(
            changed=False,
            msg=f"TPM role {name!r} at {mount!r} already matches",
            data=role_result(existing),
        )

    if module.check_mode:
        verb = "created" if action == "create" else "updated"
        module.exit_json(
            changed=True,
            msg=f"Would have {verb} TPM role {name!r} at {mount!r} if not in check mode.",
            data=role_result(existing),
        )

    tpm.write_role(mount, name, desired)
    current = tpm.read_role(mount, name) or desired
    verb = "created" if action == "create" else "updated"
    module.exit_json(
        changed=True,
        msg=f"TPM role {name!r} at {mount!r} {verb} successfully",
        data=role_result(current),
    )


def ensure_role_absent(module: AnsibleModule, tpm) -> None:
    mount = module.params["mount"].strip("/")
    name = module.params["name"]
    existing = tpm.read_role(mount, name)
    if existing is None:
        module.exit_json(changed=False, msg=f"TPM role {name!r} at {mount!r} already absent")

    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have deleted TPM role {name!r} at {mount!r} if not in check mode.",
        )

    tpm.delete_role(mount, name)
    module.exit_json(changed=True, msg=f"TPM role {name!r} at {mount!r} deleted successfully")


def main():
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            mount=dict(type="str", required=True),
            name=dict(type="str", required=True),
            display_name=dict(type="str"),
            cert_ttl=dict(type="int"),
            tpm_ids=dict(type="list", elements="str"),
            tpmgroup_ids=dict(type="list", elements="str"),
            token_ttl=dict(type="int", no_log=False),
            token_max_ttl=dict(type="int", no_log=False),
            token_period=dict(type="int"),
            token_explicit_max_ttl=dict(type="int", no_log=False),
            token_policies=dict(type="list", elements="str", no_log=False),
            token_bound_cidrs=dict(type="list", elements="str", no_log=False),
            token_no_default_policy=dict(type="bool"),
            token_num_uses=dict(type="int", no_log=False),
            token_type=dict(
                type="str",
                choices=["service", "batch", "default", "default-service", "default-batch"],
            ),
            alias_metadata=dict(type="dict"),
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
            ensure_role_present(module, client.tpm)
        else:
            ensure_role_absent(module, client.tpm)
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
