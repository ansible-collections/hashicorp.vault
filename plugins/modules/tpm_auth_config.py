# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: tpm_auth_config
short_description: Manage HashiCorp Vault TPM auth backend configuration
version_added: 2.0.0
author: Ansible (@ansible)
description:
  - Set CA lifetime, CA soft expiry, and the default client certificate TTL at C(auth/:mount/config).
  - Requires Vault Enterprise 2.2.0 or later and an enabled TPM auth mount. Enable the mount with M(hashicorp.vault.auth_method).
  - Durations are integer seconds. Vault always returns a value for each field. O(default_cert_ttl) of V(0) means certificates fall back to the CA soft expiry.
  - O(state=absent) does not clear the configuration and does not disable the mount. Vault has no delete for this endpoint. Disable the mount with M(hashicorp.vault.auth_method) to remove it.
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
options:
  mount:
    description:
      - Path of the enabled TPM auth mount.
    type: str
    required: true
  ca_lifetime:
    description:
      - How long each CA is valid once it becomes active, in seconds.
    type: int
  ca_soft_expiry:
    description:
      - How long before hard expiry the active CA stops signing new certificates, in seconds.
    type: int
  default_cert_ttl:
    description:
      - Default lifetime for client certificates when a role does not set cert_ttl, in seconds.
      - V(0) falls back to the CA soft expiry. Vault still caps a certificate by the remaining validity of the signing CA.
    type: int
  state:
    description:
      - V(present) writes the fields that are set and skips the write when they already match.
      - V(absent) leaves the configuration in Vault and reports C(changed=false).
    type: str
    choices: [present, absent]
    default: present
notes:
  - Fields that are omitted are not sent and are not compared, so Vault keeps its current value for those fields.
"""

EXAMPLES = """
- name: Configure the TPM auth backend CA
  hashicorp.vault.tpm_auth_config:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    mount: tpm
    ca_lifetime: 315360000
    ca_soft_expiry: 31536000
    default_cert_ttl: 2592000

- name: Note that absent does not clear the config
  hashicorp.vault.tpm_auth_config:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    mount: tpm
    state: absent
"""

RETURN = """
msg:
  description: Human-readable result message.
  returned: always
  type: str
data:
  description: CA configuration read back from Vault.
  returned: when O(state=present) and the configuration could be read
  type: dict
  contains:
    ca_lifetime:
      description: CA lifetime in seconds.
      type: int
    ca_soft_expiry:
      description: CA soft expiry in seconds.
      type: int
    default_cert_ttl:
      description: Default client certificate TTL in seconds.
      type: int
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
    decide_config_action,
    omit_none,
)

_CONFIG_FIELDS = ("ca_lifetime", "ca_soft_expiry", "default_cert_ttl")
_ABSENT_MSG = (
    "TPM auth backend configuration remains in Vault. "
    "state=absent does not clear auth/<mount>/config or disable the mount. "
    "Disable the mount with hashicorp.vault.auth_method."
)


def _config_data(config: dict) -> dict:
    if not config:
        return {}
    return {field: config.get(field) for field in _CONFIG_FIELDS}


def ensure_config_present(module: AnsibleModule, tpm) -> None:
    mount = module.params["mount"].strip("/")
    desired = omit_none({field: module.params.get(field) for field in _CONFIG_FIELDS})
    existing = tpm.read_config(mount)
    action = decide_config_action(existing, desired)

    if action == "missing":
        module.fail_json(msg=f"TPM auth config at {mount!r} was not found. Enable the mount before setting config.")

    if action == "unchanged":
        module.exit_json(
            changed=False,
            msg=f"TPM auth config at {mount!r} already matches",
            data=_config_data(existing),
        )

    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have written TPM auth config at {mount!r} if not in check mode.",
            data=_config_data(existing),
        )

    tpm.write_config(mount, desired)
    current = tpm.read_config(mount) or desired
    module.exit_json(
        changed=True,
        msg=f"TPM auth config at {mount!r} written successfully",
        data=_config_data(current),
    )


def ensure_config_absent(module: AnsibleModule, tpm) -> None:
    """Match vault_tpm_auth_backend_config, whose delete only drops the resource from state."""
    module.warn(_ABSENT_MSG)
    module.exit_json(changed=False, msg=_ABSENT_MSG)


def main():
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            mount=dict(type="str", required=True),
            ca_lifetime=dict(type="int"),
            ca_soft_expiry=dict(type="int"),
            default_cert_ttl=dict(type="int"),
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
            ensure_config_present(module, client.tpm)
        else:
            ensure_config_absent(module, client.tpm)
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
