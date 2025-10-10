# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: kv1_secret
short_description: Manage HashiCorp Vault KV version 1 secrets
version_added: 1.1.0
author: Aubin Bikouo (@abikouo)
description:
  - Create, update, or delete secrets in HashiCorp Vault KV version 1 secrets engine.
  - This module is designed for writing operations only.
  - Supports token and AppRole authentication methods.
  - It does not create the secret engine if it does not exist.
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
options:
  engine_mount_point:
    description: KV secrets engine mount point.
    default: secret
    type: str
    aliases: [secret_mount_path]
  path:
    description:
      - Specifies the path of the secret.
    required: true
    type: str
    aliases: [secret_path]
  data:
    description:
      - Secret data as key-value pairs.
      - Required when O(state=present).
    type: dict
  state:
    description:
      - The desired state of the secret.
      - V(present) the secret will be created if does not exist or updated if it exists.
      - V(absent) the secret will be deleted.
    choices: ['present', 'absent']
    default: present
    type: str
"""

EXAMPLES = """
- name: Create a secret
  hashicorp.vault.kv1_secret:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    engine_mount_point: secret
    path: sample
    data:
      username: admin
      password: secret123

- name: Delete a secret
  hashicorp.vault.kv1_secret:
    url: https://vault.example.com:8200
    engine_mount_point: production
    token: "{{ vault_token }}"
    state: absent
"""

RETURN = """
data:
  description:
    - The raw result of the delete against the given path.
    - This is usually empty, but may contain warnings or other information.
    - Successful delete on Vault KV2 API returns 204 No Content, so the module returns an empty dictionary on successful deletion.
  returned: changed and state=absent
  type: dict
  sample: {}
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultClient
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)


def ensure_absent(module: AnsibleModule, client: VaultClient) -> None:
    """Ensure the secret is deleted"""
    mount_path = module.params["engine_mount_point"]
    secret_path = module.params.get("path")
    changed = False
    try:
        client.secrets.kv1.read_secret(mount_path=mount_path, secret_path=secret_path)
    except VaultSecretNotFoundError:
        # Secret doesn't exist, already in desired state
        module.exit_json(changed=changed, msg="Secret already absent")

    changed = True
    if module.check_mode:
        module.exit_json(changed=changed, msg="Would have deleted the secret if not in check_mode.")
    # Delete the secret
    result = client.secrets.kv1.delete_secret(mount_path=mount_path, secret_path=secret_path)
    module.exit_json(changed=changed, msg="Secret successfully deleted.", data=result or {})


def ensure_present(module: AnsibleModule, client: VaultClient) -> None:
    """Ensure the secret exists with the specified data by creating or updating it."""

    data = module.params["data"]
    secret_path = module.params["path"]
    mount_path = module.params["engine_mount_point"]
    changed = False

    # Get existing secret
    existing = None
    try:
        existing = client.secrets.kv1.read_secret(mount_path=mount_path, secret_path=secret_path)
    except VaultSecretNotFoundError:
        pass

    action = "created"
    if existing:
        # update the secret if the data does not match
        if existing == data:
            module.exit_json(changed=changed, msg="The secret already exists with the same data.")
        action = "updated"

    changed = True
    if module.check_mode:
        module.exit_json(
            changed=changed, msg=f"Would have {action} the secret if not in check mode."
        )

    result = client.secrets.kv1.create_or_update_secret(
        mount_path=mount_path, secret_path=secret_path, secret_data=data
    )
    module.exit_json(changed=changed, msg=f"Secret successfully {action}.", raw=result)


def main():

    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        {
            "path": {"required": True, "aliases": ["secret_path"]},
            "data": {"type": "dict"},
            "state": {"choices": ["present", "absent"], "default": "present"},
            "engine_mount_point": {"default": "secret", "aliases": ["secret_mount_path"]},
        }
    )

    required_if = [
        ("state", "present", ["data"]),
    ]

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=required_if,
        supports_check_mode=True,
    )

    # Get authenticated client
    client = get_authenticated_client(module)

    state = module.params["state"]
    try:
        if state == "present":
            ensure_present(module, client)
        else:
            ensure_absent(module, client)

    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
