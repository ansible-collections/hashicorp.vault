# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


DOCUMENTATION = """
---
module: database_static_role
short_description: Manage database static roles in HashiCorp Vault.
version_added: 1.2.0
author: Hannah DeFazio (@hdefazio)
description:
  - This module allows you to create, update, and delete database static roles in HashiCorp Vault.
  - Static roles provide a mechanism to use Vault as a credential broker for existing database accounts.
  - Use C(state=present) to create or update a static role.
  - Use C(state=absent) to delete a static role.
options:
  state:
    description:
      - Goal state for the database static role.
      - Use V(present) to create or update the static role.
      - Use V(absent) to delete the static role.
    choices: [present, absent]
    default: present
    type: str
  database_mount_path:
    description: Database secret engine mount path.
    type: str
    default: database
    aliases: [vault_database_mount_path]
  name:
    description: The name of the database static role.
    type: str
    required: true
  db_name:
    description:
      - The name of the database connection to use for this static role.
      - This references a connection created by the M(hashicorp.vault.database_connection) module.
      - Required when O(state=present).
    type: str
  username:
    description:
      - The database username that Vault will manage and rotate credentials for.
      - This must be an existing user in the database.
      - Required when O(state=present).
    type: str
  rotation_period:
    description:
      - Specifies the amount of time Vault should wait before rotating the password.
      - The minimum rotation period is 5 seconds.
      - Can be specified as an integer (seconds) or a duration string (e.g., "86400s", "24h").
      - Required when O(state=present) unless O(rotation_schedule) is provided.
    type: raw
  rotation_schedule:
    description:
      - A cron-style schedule for password rotation (e.g., "0 0 * * *" for daily at midnight).
      - Required when O(state=present) unless O(rotation_period) is provided.
    type: str
  rotation_statements:
    description:
      - Specifies the database statements to be executed to rotate the password.
      - If not specified, Vault uses the default rotation statements for the database plugin.
    type: list
    elements: str
  skip_import_rotation:
    description:
      - When set to V(true), skips the automatic password rotation that normally occurs when creating a static role.
      - This allows testing configuration without requiring an active database connection.
      - The password will still be rotated on the first scheduled rotation or manual rotation request.
    type: bool
    default: false
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
"""

EXAMPLES = """
- name: Create a database static role
  hashicorp.vault.database_static_role:
    name: my-static-role
    state: present
    db_name: my-postgres-db
    username: vault-user
    rotation_period: 86400

- name: Create a database static role with custom rotation statements
  hashicorp.vault.database_static_role:
    name: my-static-role
    state: present
    db_name: my-mysql-db
    username: app_user
    rotation_period: 3600
    rotation_statements:
      - "ALTER USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';"
    database_mount_path: database
"""

RETURN = """
msg:
  description: A message describing the result of the operation.
  returned: always
  type: str
  sample: "Static role 'my-static-role' created successfully"
raw:
  description: The configuration settings for the database static role created/updated.
  returned: when I(state=present)
  type: dict
  sample:
    {
        "db_name": "my-postgres-db",
        "username": "vault-user",
        "rotation_period": 86400,
        "rotation_statements": []
    }
"""


__metaclass__ = type  # pylint: disable=C0103

import copy

from ansible.module_utils.basic import AnsibleModule  # type: ignore

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
    VaultDatabaseStaticRoles,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)


def ensure_present(module: AnsibleModule, db_static_role_client: VaultDatabaseStaticRoles) -> None:
    """Create or update a database static role."""
    name = module.params.get("name")

    # Validate that at least one of rotation_period or rotation_schedule is provided
    if not module.params.get("rotation_period") and not module.params.get("rotation_schedule"):
        module.fail_json(msg="one of rotation_period or rotation_schedule is required when state=present")

    # Build configuration from module parameters, filtering out None values
    config_params = ("username", "db_name", "rotation_period", "rotation_schedule", "rotation_statements", "skip_import_rotation")
    config = {key: val for key in config_params if (val := module.params.get(key)) is not None}

    # Check if the static role already exists
    # VaultSecretNotFoundError is raised if the role doesn't exist
    try:
        existing = db_static_role_client.read_static_role(name)
    except VaultSecretNotFoundError:
        existing = {}

    operation = "updated" if existing else "created"

    # In check mode, report what would happen without making changes
    if module.check_mode:
        module.exit_json(
            changed=True, msg=f"Would have {operation} database static role '{name}' if not in check mode", raw=existing
        )

    # Create or update the static role
    db_static_role_client.create_or_update_static_role(name, config)

    # Read back the configuration to compare for idempotency
    result = db_static_role_client.read_static_role(name)

    # Check idempotency - compare the new result with what existed before
    changed = not (result == existing)
    if not changed:
        msg = "The database static role already exists with the same data."
    else:
        msg = f"Database static role {name!r} {operation} successfully"

    module.exit_json(changed=changed, msg=msg, raw=result)


def ensure_absent(module: AnsibleModule, db_static_role_client: VaultDatabaseStaticRoles) -> None:
    """Delete a database static role."""
    name = module.params.get("name")

    # Check if the static role exists before attempting deletion
    # VaultSecretNotFoundError is raised if the role doesn't exist
    try:
        db_static_role_client.read_static_role(name)
    except VaultSecretNotFoundError:
        module.exit_json(
            changed=False,
            msg=f"Database static role {name!r} is already absent",
        )

    # In check mode, report what would happen without making changes
    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have deleted database static role {name!r} if not in check mode.",
        )

    # Actually delete the static role
    db_static_role_client.delete_static_role(name)
    module.exit_json(
        changed=True,
        msg=f"Database static role {name!r} deleted successfully",
    )


def main() -> None:
    """Entry point for module execution"""
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            state=dict(default="present", choices=["present", "absent"]),
            database_mount_path=dict(default="database", aliases=["vault_database_mount_path"]),
            name=dict(required=True),
            db_name=dict(),
            username=dict(),
            rotation_period=dict(type="raw"),
            rotation_schedule=dict(type="str"),
            rotation_statements=dict(type="list", elements="str"),
            skip_import_rotation=dict(type="bool"),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=(("state", "present", ["db_name", "username"]),),
        supports_check_mode=True,
    )

    client = get_authenticated_client(module)

    mount_path = module.params["database_mount_path"]
    db_static_role_client = VaultDatabaseStaticRoles(client, mount_path=mount_path)

    state = module.params["state"]
    try:
        if state == "present":
            ensure_present(module, db_static_role_client)
        elif state == "absent":
            ensure_absent(module, db_static_role_client)

    except VaultSecretNotFoundError as e:
        module.exit_json(data={})
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
