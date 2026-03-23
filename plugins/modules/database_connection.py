# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: database_connection
short_description: Manage database secrets engine connections in HashiCorp Vault.
version_added: 1.2.0
author: Aubin Bikouo (@abikouo)
description:
  - This module manages (create, update, delete, and reset) the lifecycle of database
    connection configurations within the HashiCorp Vault Database secrets engine.
options:
  state:
    description:
      - Goal state for the database connection.
      - Use V(present) to create or update the connection.
      - Use V(reset) to trigger a connection reset.
      - Use V(absent) to remove the connection configuration.
    choices: [present, absent, reset]
    default: present
    type: str
  database_mount_path:
    description: Database secret engine mount path.
    type: str
    default: database
    aliases: [vault_database_mount_path]
  name:
    description: The name of the database connection configuration.
    required: true
    type: str
    aliases: [connection_name]
  username:
    description:
      - The username to connect to the database.
    required: false
    type: str
    aliases: [connection_username]
  password:
    description:
      - The password to connect to the database.
    required: false
    type: str
    aliases: [connection_password]
  disable_escaping:
    description: Determines whether special characters in the username and password fields will be escaped.
    type: bool
    default: false
  connection_url:
    description: The connection string used to connect to the database.
    type: str
  plugin_name:
    description:
      - The name of the plugin to use for this connection.
      - Required when O(state=present).
    required: false
    type: str
  plugin_version:
    description:
      - The semantic version of the plugin to use for this connection.
    type: str
    required: false
  plugin_options:
    description:
      - Additional parameters specific to the plugin.
      - This should be a dictionary of options required by the specific database plugin.
    type: dict
  verify_connection:
    description: Specifies if the connection is verified during initial configuration.
    default: true
    type: bool
  allowed_roles:
    description: A list of roles authorized to use this connection.
    type: list
    elements: str
  root_rotation_statements:
    description:
      - Specifies the database statements to be executed to rotate the root user's credentials.
      - Refer to the specific Vault database plugin documentation for supported formatting.
    type: list
    elements: str
  password_policy:
    description:
      - The name of the password policy to use when generating passwords for this database.
      - If not specified, Vault uses a default policy (20 characters, mixed case, number, dash).
    type: str
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
"""

EXAMPLES = """
- name: Create database connection with PostgreSQL plugin
  hashicorp.vault.database_connection:
    name: postgres-sample-connection
    plugin_name: "postgresql-database-plugin"
    allowed_roles:
      - "readonly"
    connection_url: "host=localhost port=5432 user='{{ username }}' password='{{ password }}'"
    plugin_options:
      max_open_connections: 5
      max_connection_lifetime: "5s"
    username: "admin_user"
    password: "secure_password"

- name: Update a database connection with MySQL
  hashicorp.vault.database_connection:
    name: mysql-sample-connection
    state: present
    connection_url: "mysql://vaultuser:secretpassword@localhost:3306/mydb"
    verify_connection: true
    plugin_name: "mysql-database-plugin"
    database_mount_path: "database-conn-config-integration-tests"
    allowed_roles:
      - "readonly"
      - "readwrite"
    username: "vaultuser"
    password: "secretpassword"

- name: Reset a database connection
  hashicorp.vault.database_connection:
    name: mysql-sample-connection
    state: reset

- name: Delete a database connection
  hashicorp.vault.database_connection:
    name: mysql-sample-connection
    state: absent
"""

RETURN = """
msg:
  description: A message describing the result of the operation.
  returned: always
  type: str
raw:
  description: The configuration settings for the database connection created/updated.
  returned: When I(state=present) or I(state=reset)
  type: dict
  sample:
    {
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


def read_connection(db_conn: VaultDatabaseConnection, name: str) -> dict:
    """
    Read database connection.

    Args:
        db_conn (VaultDatabaseConnection): The database connection object.
        name (str): The name of the connection to read.

    Returns:
        dict: A dict containing the connection details, empty when the connection does not exist.
    """
    try:
        return db_conn.read_connection(name=name)
    except VaultSecretNotFoundError as e:
        return {}


def perform_action(module: AnsibleModule) -> tuple[bool, dict]:
    """
    Create/update/delete/reset database connection based on parameters.

    Args:
        module (str): The ansible module object.

    Returns:
        (bool, dict): A tuple containing a boolean flag—indicating whether
        the module performed any changes—and a dictionary representing the JSON-structured result.
    """

    # Get authenticated client
    client = get_authenticated_client(module)
    mount_path = module.params.get("database_mount_path")
    name = module.params.get("name")

    db_conn = VaultDatabaseConnection(client, mount_path=mount_path)
    state = module.params.get("state")

    changed = False
    result = {}

    # Read existing database configuration
    existing = read_connection(db_conn, name)
    if state == "present":
        config_params = (
            "plugin_name",
            "plugin_version",
            "allowed_roles",
            "verify_connection",
            "root_rotation_statements",
            "password_policy",
            "connection_url",
            "username",
            "password",
            "disable_escaping",
        )
        config = {key: module.params.get(key) for key in config_params}
        plugin_options = module.params.get("plugin_options")
        if plugin_options:
            config.update(plugin_options)
        if module.check_mode:
            changed = True
            operation = "updated" if existing else "created"
            result['msg'] = f"Would have {operation} database connection '{name}' if not in check mode"
            return changed, result

        # Create/update database connection
        result = db_conn.create_or_update_connection(name, config)

        # read connection
        result["raw"] = read_connection(db_conn, name)

        # check idempotency to ensure change
        changed = not (result['raw'] == existing)
        if not changed:
            result['msg'] = "The database connection with these settings is already configured."
        else:
            action = "updated" if existing else "created"
            result['msg'] = f"The database connection has been successfully {action}."

    elif state == "reset":
        # state == 'reset' reset the connection if it exists
        if existing:
            changed = True
            result["msg"] = f"Would have reset the database connection '{name}' if not in check mode."
            if not module.check_mode:
                db_conn.reset_connection(name)
                result["msg"] = f"Database connection '{name}' successfully reset."
            # read connection
            result["raw"] = read_connection(db_conn, name)
    elif state == "absent":
        # state == 'absent' delete the connection if it exists
        if existing:
            changed = True
            result["msg"] = f"Would have deleted the database connection '{name}' if not in check mode."
            if not module.check_mode:
                db_conn.delete_connection(name)
                result["msg"] = f"Database connection '{name}' successfully deleted."

    return changed, result


def main():

    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            state=dict(choices=["present", "absent", "reset"], default="present"),
            database_mount_path=dict(default="database", aliases=["vault_database_mount_path"]),
            name=dict(required=True, aliases=["connection_name"]),
            username=dict(aliases=["connection_username"]),
            password=dict(aliases=["connection_password"], no_log=True),
            disable_escaping=dict(type="bool", default=False),
            connection_url=dict(no_log=True),  # since it can contains password information
            plugin_name=dict(required=False),
            plugin_version=dict(),
            plugin_options=dict(type="dict"),
            verify_connection=dict(type="bool", default=True),
            allowed_roles=dict(
                type="list",
                elements="str",
            ),
            root_rotation_statements=dict(type="list", elements="str"),
            password_policy=dict(no_log=False),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=(("state", "present", ["plugin_name"]),),
        supports_check_mode=True,
    )

    try:
        changed, result = perform_action(module=module)
        module.exit_json(changed=changed, **result)

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
