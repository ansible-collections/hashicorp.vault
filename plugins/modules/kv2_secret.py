# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: kv2_secret
short_description: Manage HashiCorp Vault KV version 2 secrets
version_added: 1.0.0
author: Mandar Vijay Kulkarni (@mandar242)
description:
  - Create, update, or delete (soft-delete) secrets in HashiCorp Vault KV version 2 secrets engine.
  - This module is designed for writing operations only. To read secrets, use the P(hashicorp.vault.kv2_secret_get#lookup) lookup plugin.
  - Supports token and AppRole authentication methods.
  - It does not create the secret engine if it does not exist and will fail if the secret engine path (engine_mount_point) is not enabled.
extends_documentation_fragment:
  - hashicorp.vault.vault_auth
options:
  engine_mount_point:
    description: KV secrets engine mount point.
    default: secret
    type: str
    aliases: [secret_mount_path]
  path:
    description: Path to the secret.
    required: true
    type: str
    aliases: [secret_path]
  data:
    description: Secret data as key-value pairs.
    type: dict
  versions:
    description: One or more versions of the secret to delete. Used with O(state=absent).
    type: list
    elements: int
  state:
    description: Desired state of the secret.
    choices: ['present', 'absent']
    default: present
    type: str
  cas:
    description: Check-and-Set value for conditional updates.
    type: int
"""

EXAMPLES = """
- name: Create a secret with token authentication
  hashicorp.vault.kv2_secret:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    path: myapp/config
    data:
      username: admin
      password: secret123

- name: Create a secret with token authentication (using env var for auth)
  hashicorp.vault.kv2_secret:
    url: https://vault.example.com:8200
    path: myapp/config
    data:
      username: admin
      password: secret123

- name: Create a secret with AppRole authentication
  hashicorp.vault.kv2_secret:
    url: https://vault.example.com:8200
    auth_method: approle
    role_id: "{{ vault_role_id }}"
    secret_id: "{{ vault_secret_id }}"
    path: myapp/config
    data:
      api_key: secret-api-key

- name: Delete a secret
  hashicorp.vault.kv2_secret:
    url: https://vault.example.com:8200
    path: myapp/config
    state: absent
"""

RETURN = """
raw:
  description: The raw Vault response.
  returned: changed and state=present
  type: dict
  sample:
    auth: null
    data:
      created_time: "2023-02-21T19:51:50.801757862Z"
      custom_metadata: null
      deletion_time: ""
      destroyed: false
      version: 1
    lease_duration: 0
    lease_id: ""
    renewable: false
    request_id: "52eb1aa7-5a38-9a02-9246-efc5bf9581ec"
    warnings: null
    wrap_info: null
data:
  description:
    - The raw result of the delete against the given path.
    - This is usually empty, but may contain warnings or other information.
    - Successful delete on Vault KV2 API returns 204 No Content, so the module returns an empty dictionary on successful deletion.
  returned: changed and state=absent
  type: dict
  sample: {}
"""


from ansible.module_utils.basic import AnsibleModule, env_fallback


try:
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
        get_authenticated_client,
    )
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
        Secrets as VaultSecret,
    )
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
        VaultApiError,
        VaultPermissionError,
        VaultSecretNotFoundError,
    )

except ImportError as e:
    VAULT_IMPORT_ERROR = str(e)


def ensure_secret_present(module: AnsibleModule, secret_mgr: VaultSecret) -> None:
    """Ensure the secret exists with the specified data by creating or updating it."""
    # Get secret data and options
    data = module.params["data"]
    cas = module.params["cas"]
    mount_path = module.params["engine_mount_point"]
    secret_path = module.params["path"]
    action = "created"
    changed = True

    # First, try to read the existing secret to check for changes
    try:
        existing_secret = secret_mgr.kv2.read_secret(mount_path=mount_path, secret_path=secret_path)
        # The read_secret returns {"data": {...actual_secret_data...}, "metadata": {...}}
        existing_data = existing_secret.get("data", {})
        existing_metadata = existing_secret.get("metadata", {})

        # Check if the secret was previously deleted (soft-deleted)
        deletion_time = existing_metadata.get("deletion_time", "")

        if deletion_time:
            # Secret was soft-deleted, treat as if it doesn't exist for idempotency
            action_msg = "Secret recreated successfully"
            changed = True
        elif existing_data == data:
            # Secret already exists with the same data - no changes needed
            changed = False
            module.exit_json(
                changed=False,
                msg="Secret already exists with the same data",
            )
        else:
            # Data is different, proceed with update
            action_msg = "Secret updated successfully"
            action = "updated"
            changed = True

    except VaultSecretNotFoundError:
        # Secret doesn't exist, proceed with creation
        action_msg = "Secret created successfully"
        action = "created"
        changed = True

    # If in check mode, exit here with what would happen
    if module.check_mode:
        module.exit_json(
            changed=changed, msg=f"Would have {action} the secret if not in check_mode."
        )

    # Create or update the secret
    result = secret_mgr.kv2.create_or_update_secret(
        mount_path=mount_path, secret_path=secret_path, secret_data=data, cas=cas
    )

    # added `raw` to match return value of community.hashi_vault.vault_kv2_write
    module.exit_json(changed=changed, msg=action_msg, raw=result)


def ensure_secret_absent(module: AnsibleModule, secret_mgr: VaultSecret) -> None:
    """Ensure the secret is deleted (soft-deleted) by removing specified versions or the latest version."""
    mount_path = module.params["engine_mount_point"]
    secret_path = module.params["path"]
    versions = module.params["versions"]
    changed = False

    # First, check if the secret exists and its current state
    try:
        existing_secret = secret_mgr.kv2.read_secret(mount_path=mount_path, secret_path=secret_path)
        existing_metadata = existing_secret.get("metadata", {})

        # Check if the secret is already deleted (soft-deleted)
        deletion_time = existing_metadata.get("deletion_time", "")

        if deletion_time:
            # Secret is already soft-deleted, no action needed
            module.exit_json(changed=changed, msg="Secret already absent")

    except VaultSecretNotFoundError:
        # Secret doesn't exist, already in desired state
        module.exit_json(changed=changed, msg="Secret already absent")

    # If we reach this point, the secret exists and needs to be deleted
    changed = True

    # If in check mode, exit here with what would happen
    if module.check_mode:
        module.exit_json(
            changed=changed, msg="Would have soft-deleted the secret if not in check_mode."
        )

    # Delete the secret
    result = secret_mgr.kv2.delete_secret(mount_path, secret_path, versions)
    module.exit_json(
        changed=changed, msg="Secret deleted (soft-deleted) successfully", data=result or {}
    )


def main():

    argument_spec = dict(
        # Authentication parameters
        url=dict(type="str", required=True, aliases=["vault_address"]),
        namespace=dict(type="str", default="admin", aliases=["vault_namespace"]),
        auth_method=dict(type="str", choices=["token", "approle"], default="token"),
        token=dict(type="str", no_log=True, fallback=(env_fallback, ["VAULT_TOKEN"])),
        role_id=dict(
            type="str",
            aliases=["approle_role_id"],
            fallback=(env_fallback, ["VAULT_APPROLE_ROLE_ID"]),
        ),
        secret_id=dict(
            type="str",
            no_log=True,
            aliases=["approle_secret_id"],
            fallback=(env_fallback, ["VAULT_APPROLE_SECRET_ID"]),
        ),
        vault_approle_path=dict(type="str", default="approle"),
        # Secret parameters
        engine_mount_point=dict(type="str", default="secret", aliases=["secret_mount_path"]),
        path=dict(type="str", required=True, aliases=["secret_path"]),
        data=dict(type="dict", no_log=True),
        cas=dict(type="int"),
        versions=dict(type="list", elements="int"),
        # Other parameters
        state=dict(type="str", choices=["present", "absent"], default="present"),
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
        secret_mgr = VaultSecret(client)
        if state == "present":
            ensure_secret_present(module, secret_mgr)
        elif state == "absent":
            ensure_secret_absent(module, secret_mgr)

    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
