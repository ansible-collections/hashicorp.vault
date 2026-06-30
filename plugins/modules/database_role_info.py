# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: database_role_info
short_description: List available dynamic roles or read configuration for a specific role
version_added: 1.2.0
author: Matthew Johnson (@mjohns91)
description:
  - This module retrieves configuration details for a specific Vault database dynamic role.
  - When a role name is provided, it returns its full configuration; if the name is omitted,
    the module returns a comprehensive list of all available dynamic roles within the specified mount path.
  - This module is read-only and does not modify role configuration.
options:
  mount_path:
    description: Database secrets engine mount point.
    default: database
    type: str
  role_name:
    description: Name of the dynamic role to read.
    required: false
    type: str
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
"""

EXAMPLES = """
- name: List all available dynamic roles
  hashicorp.vault.database_role_info:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
  register: all_roles

- name: Read a specific dynamic role configuration with token authentication
  hashicorp.vault.database_role_info:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    role_name: readonly
  register: role_config

- name: Read a dynamic role configuration with AppRole authentication
  hashicorp.vault.database_role_info:
    url: https://vault.example.com:8200
    auth_method: approle
    role_id: "{{ vault_role_id }}"
    secret_id: "{{ vault_secret_id }}"
    role_name: readwrite
  register: role_config

- name: Display role configuration
  ansible.builtin.debug:
    var: role_config.roles
"""

RETURN = """
roles:
  description: The list of database dynamic roles.
  returned: always
  type: list
  sample:
    [
        {
            "name": "readonly",
            "db_name": "my-postgres-db",
            "creation_statements": [
                "CREATE ROLE '{{name}}' WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
                "GRANT SELECT ON ALL TABLES IN SCHEMA public TO '{{name}}';"
            ],
            "default_ttl": 3600,
            "max_ttl": 86400,
            "revocation_statements": [
                "DROP ROLE IF EXISTS '{{name}}';"
            ]
        }
    ]
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC

try:
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
        get_authenticated_client,
    )
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_database import (
        VaultDatabaseDynamicRoles,
        get_existing_role_or_none,
    )
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
        VaultApiError,
        VaultPermissionError,
    )

except ImportError as e:
    VAULT_IMPORT_ERROR = str(e)


def main():

    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            # Role parameters
            mount_path=dict(type='str', default='database'),
            role_name=dict(type='str', required=False),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Get authenticated client
    client = get_authenticated_client(module)

    mount_path = module.params["mount_path"]
    role_name = module.params["role_name"]

    try:
        db_roles = VaultDatabaseDynamicRoles(client, mount_path)
        if role_name:
            data = get_existing_role_or_none(db_roles, role_name, 'read_dynamic_role')
            if data is None:
                module.exit_json(roles=[])
            data.update({'name': role_name})
            roles = [data]
        else:
            roles = [{'name': name} for name in db_roles.list_dynamic_roles()]
        module.exit_json(roles=roles)

    except VaultPermissionError as e:
        module.fail_json(msg=f'Permission denied: {e}')
    except VaultApiError as e:
        module.fail_json(msg=f'Vault API error: {e}')
    except Exception as e:
        module.fail_json(msg=f'Operation failed: {e}')


if __name__ == '__main__':
    main()
