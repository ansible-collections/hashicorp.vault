# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: database_connection_info
short_description: List available connections or read configuration for a specific connection.
version_added: 1.2.0
author: Aubin Bikouo (@abikouo)
description:
  - This module retrieves configuration details for a specific Vault database connection.
  - When a connection name is provided, it returns its full settings; if the name is omitted,
    the module returns a comprehensive list of all available database connections within the specified mount path.
options:
  name:
    description: The name of the database connection to read.
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
- name: Read database connection mysql
  hashicorp.vault.database_connection_info:
    name: mysql

- name: List available database connections
  hashicorp.vault.database_connection_info:
"""

RETURN = """
connections:
  description: The list of database connections.
  returned: always
  type: list
  sample:
    [
        {
            "name": "my-sample-connection",
            "allowed_roles": ["readonly"],
            "connection_details": {
                "connection_url": "dbuser:dbpassword123@tcp(127.0.0.1:3306)/",
                "username": "vaultuser"
            },
            "password_policy": "",
            "plugin_name": "mysql-database-plugin",
            "plugin_version": "",
            "root_credentials_rotate_statements": [],
            "skip_static_role_import_rotation": false
        }
    ]
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
    VaultDatabaseConnection,
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
            name=dict(required=False),
            database_mount_path=dict(default="database", aliases=["vault_database_mount_path"]),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Get authenticated client
    client = get_authenticated_client(module)
    mount_path = module.params.get("database_mount_path")
    name = module.params.get("name")

    try:
        db_conn = VaultDatabaseConnection(client, mount_path=mount_path)
        if name:
            data = db_conn.read_connection(name=name)
            data.update({"name": name})
            connections = [data]
        else:
            connections = [{"name": name} for name in db_conn.list_connections() or []]
        module.exit_json(connections=connections)

    except VaultSecretNotFoundError as e:
        module.exit_json(connections=[])
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
