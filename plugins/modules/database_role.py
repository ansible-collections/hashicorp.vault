# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: database_role
short_description: Manage HashiCorp Vault database dynamic roles
version_added: 1.2.0
author: Matthew Johnson (@mjohns91)
description:
  - Create, update, or delete dynamic roles in HashiCorp Vault Database Secrets Engine.
  - Dynamic roles generate database credentials on-demand with configurable TTLs.
  - This module is designed for role configuration management. To read role configuration, use the M(hashicorp.vault.database_role_info) module.
  - Supports token and AppRole authentication methods.
  - It does not create the database secrets engine if it does not exist and will fail if the mount path is not enabled.
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
options:
  mount_path:
    description: Database secrets engine mount point.
    default: database
    type: str
  role_name:
    description: Name of the dynamic role.
    required: true
    type: str
  db_name:
    description:
      - Name of the database connection to use.
      - Required when O(state=present).
    type: str
    aliases: [connection_name]
  creation_statements:
    description:
      - SQL statements to execute when creating database credentials.
      - Required when O(state=present).
      - Supports templating with V({{name}}), V({{password}}), and V({{expiration}}).
    type: list
    elements: str
  default_ttl:
    description: Default TTL for generated credentials in seconds.
    type: int
  max_ttl:
    description: Maximum TTL for generated credentials in seconds.
    type: int
  revocation_statements:
    description: SQL statements to execute when revoking database credentials.
    type: list
    elements: str
  rollback_statements:
    description: SQL statements to execute when rolling back a partially created credential.
    type: list
    elements: str
  renew_statements:
    description: SQL statements to execute when renewing database credentials.
    type: list
    elements: str
  credential_type:
    description: Type of credential to generate.
    type: str
    choices: ['password', 'rsa_private_key', 'client_certificate']
  credential_config:
    description: Additional configuration for credential generation.
    type: dict
  state:
    description: Desired state of the dynamic role.
    choices: ['present', 'absent']
    default: present
    type: str
"""

EXAMPLES = """
- name: Create a dynamic role for read-only access with token authentication
  hashicorp.vault.database_role:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    role_name: readonly
    db_name: my-postgres-db
    creation_statements:
      - "CREATE ROLE '{{name}}' WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"
      - "GRANT SELECT ON ALL TABLES IN SCHEMA public TO '{{name}}';"
    default_ttl: 3600
    max_ttl: 86400

- name: Create a dynamic role with AppRole authentication
  hashicorp.vault.database_role:
    url: https://vault.example.com:8200
    auth_method: approle
    role_id: "{{ vault_role_id }}"
    secret_id: "{{ vault_secret_id }}"
    role_name: readwrite
    db_name: my-postgres-db
    creation_statements:
      - "CREATE ROLE '{{name}}' WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"
      - "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO '{{name}}';"
    revocation_statements:
      - "DROP ROLE IF EXISTS '{{name}}';"
    default_ttl: 1800
    max_ttl: 3600

- name: Update an existing dynamic role
  hashicorp.vault.database_role:
    url: https://vault.example.com:8200
    role_name: readonly
    db_name: my-postgres-db
    creation_statements:
      - "CREATE ROLE '{{name}}' WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"
      - "GRANT SELECT ON ALL TABLES IN SCHEMA public TO '{{name}}';"
    default_ttl: 7200

- name: Delete a dynamic role
  hashicorp.vault.database_role:
    url: https://vault.example.com:8200
    role_name: readonly
    state: absent
"""

RETURN = """
raw:
  description: The raw Vault response when creating or updating a role.
  returned: changed and state=present
  type: dict
  sample: {}
data:
  description: The raw result of the delete operation.
  returned: changed and state=absent
  type: dict
  sample: {}
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
        build_config_params,
        compare_vault_configs,
        get_existing_role_or_none,
    )
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
        VaultApiError,
        VaultPermissionError,
    )

except ImportError as e:
    VAULT_IMPORT_ERROR = str(e)


def ensure_role_present(module: AnsibleModule, db_roles: VaultDatabaseDynamicRoles) -> None:
    """Ensure the dynamic role exists with the specified configuration by creating or updating it."""
    role_name = module.params['role_name']

    # Build configuration dict from module parameters
    # Note: db_name and creation_statements are required (enforced by required_if),
    # so they are guaranteed to be non-None and will always be included
    config_params = [
        'db_name',
        'creation_statements',
        'default_ttl',
        'max_ttl',
        'revocation_statements',
        'rollback_statements',
        'renew_statements',
        'credential_type',
        'credential_config',
    ]
    config = build_config_params(module.params, config_params)

    # Check if role already exists
    existing_role = get_existing_role_or_none(db_roles, role_name, 'read_dynamic_role')

    if existing_role:
        # Role exists - check if the configuration matches
        if compare_vault_configs(existing_role, config):
            # Role already exists with the same configuration - no changes needed
            module.exit_json(
                changed=False,
                msg='Role already exists with the same configuration',
            )
        # Configuration is different, proceed with update
        action = 'update'
        action_msg = 'Role updated successfully'
    else:
        # Role doesn't exist, proceed with creation
        action = 'create'
        action_msg = 'Role created successfully'

    # If in check mode, exit here with what would happen
    if module.check_mode:
        module.exit_json(changed=True, msg=f'Would have {action}d the role if not in check_mode.')

    # Create or update the role
    result = db_roles.create_or_update_dynamic_role(role_name, config)

    module.exit_json(changed=True, msg=action_msg, raw=result)


def ensure_role_absent(module: AnsibleModule, db_roles: VaultDatabaseDynamicRoles) -> None:
    """Ensure the dynamic role is deleted."""
    role_name = module.params['role_name']

    # Check if the role exists
    existing_role = get_existing_role_or_none(db_roles, role_name, 'read_dynamic_role')

    if not existing_role:
        # Role doesn't exist, already in desired state
        module.exit_json(changed=False, msg='Role already absent')

    # Role exists, needs to be deleted
    changed = True

    # If in check mode, exit here with what would happen
    if module.check_mode:
        module.exit_json(changed=changed, msg='Would have deleted the role if not in check_mode.')

    # Delete the role
    db_roles.delete_dynamic_role(role_name)
    module.exit_json(changed=changed, msg='Role deleted successfully', data={})


def main():

    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            # Role parameters
            mount_path=dict(type='str', default='database'),
            role_name=dict(type='str', required=True),
            db_name=dict(type='str', aliases=['connection_name']),
            creation_statements=dict(type='list', elements='str'),
            default_ttl=dict(type='int'),
            max_ttl=dict(type='int'),
            revocation_statements=dict(type='list', elements='str'),
            rollback_statements=dict(type='list', elements='str'),
            renew_statements=dict(type='list', elements='str'),
            credential_type=dict(type='str', choices=['password', 'rsa_private_key', 'client_certificate']),
            credential_config=dict(type='dict', no_log=True),
            # Other parameters
            state=dict(type='str', choices=['present', 'absent'], default='present'),
        )
    )

    required_if = [
        ('state', 'present', ['db_name', 'creation_statements']),
    ]

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=required_if,
        supports_check_mode=True,
    )

    # Get authenticated client
    client = get_authenticated_client(module)

    state = module.params['state']
    mount_path = module.params['mount_path']

    try:
        db_roles = VaultDatabaseDynamicRoles(client, mount_path)
        if state == 'present':
            ensure_role_present(module, db_roles)
        elif state == 'absent':
            ensure_role_absent(module, db_roles)

    except VaultPermissionError as e:
        module.fail_json(msg=f'Permission denied: {e}')
    except VaultApiError as e:
        module.fail_json(msg=f'Vault API error: {e}')
    except Exception as e:
        module.fail_json(msg=f'Operation failed: {e}')


if __name__ == '__main__':
    main()
