# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

DOCUMENTATION = """
---
module: database_static_role_info
short_description: List available static roles or read the configuration for a specific static role
version_added: 1.2.0
author: Hannah DeFazio (@hdefazio)
description:
  - This module retrieves information about database static roles in HashiCorp Vault.
  - When a role name is provided, it returns the full configuration for that specific role.
  - When no name is provided, it returns a list of all available static role names.
options:
  name:
    description: The name of the database static role to read.
    required: false
    type: str
  database_mount_path:
    description: Database secret engine mount path.
    type: str
    default: database
    aliases: [vault_database_mount_path]
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
"""

EXAMPLES = """
- name: Read configuration for a specific database static role
  hashicorp.vault.database_static_role_info:
    name: my-static-role

- name: List all available database static roles
  hashicorp.vault.database_static_role_info:
"""

RETURN = """
static_roles:
  description:
    - The list of database static roles.
    - When no O(name) is specified, only role names are returned.
    - When O(name) is specified, full configuration details are returned.
  returned: always
  type: list
  elements: dict
  sample:
    # When listing all roles (no name specified), only names are returned:
    # [{"name": "role1"}, {"name": "role2"}]
    # When reading a specific role (name specified), full details are returned:
    [
        {
            "name": "my-static-role",
            "db_name": "my-postgres-db",
            "username": "vault-user",
            "rotation_period": 86400,
            "rotation_statements": []
        }
    ]
"""


__metaclass__ = type  # pylint: disable=C0103

import copy

from ansible.module_utils.basic import AnsibleModule  # type: ignore

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_database import (
    VaultDatabaseStaticRoles,
    get_static_role,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
)


def main() -> None:
    """Entry point for module execution"""
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            name=dict(required=False),
            database_mount_path=dict(default="database", aliases=["vault_database_mount_path"]),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    client = get_authenticated_client(module)

    mount_path = module.params.get("database_mount_path")
    name = module.params.get("name")

    try:
        db_static_role_client = VaultDatabaseStaticRoles(client, mount_path=mount_path)

        # Read specific role configuration
        if name:
            data = get_static_role(db_static_role_client, name)
            if data:
                data.update({"name": name})
                static_roles = [data]
            else:
                static_roles = []
        # List all roles
        else:
            static_roles = [{"name": role_name} for role_name in db_static_role_client.list_static_roles()]

        module.exit_json(static_roles=static_roles)

    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
