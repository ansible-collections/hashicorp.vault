# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

DOCUMENTATION = """
---
module: database_dynamic_role_credentials
author: Matt Johnson (@mjohns91)
version_added: "1.2.0"
short_description: Generate credentials for a database dynamic role.
description:
    - Generates new database credentials for a dynamic role from HashiCorp Vault.
    - Each invocation generates a new set of temporary credentials with a unique lease.
    - Credentials are automatically revoked when the lease expires.
options:
  database_mount_path:
    description: Database secret engine mount path.
    type: str
    default: database
    aliases: [vault_database_mount_path]
  name:
    description: The name of the database dynamic role to generate credentials for.
    required: true
    type: str
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
notes:
  - For security reasons, this module should be used with B(no_log=true) and (register) functionalities.
  - This module is NOT idempotent - each call generates new credentials with a new lease.
  - Generated credentials are temporary and will be automatically revoked when the lease expires.
"""

EXAMPLES = """
- name: Generate credentials for a database dynamic role
  hashicorp.vault.database_dynamic_role_credentials:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    name: readonly
  no_log: true
  register: result

- name: Use the generated credentials
  ansible.builtin.debug:
    msg: "Username: {{ result.dynamic_role_credentials.username }}"
  no_log: true
"""

RETURN = """
dynamic_role_credentials:
  description: The generated credentials and lease information for the database dynamic role.
  type: dict
  returned: always
  sample:
    {
        "username": "v-token-readonly-abc123",
        "password": "A1a-randompassword",
        "lease_id": "database/creds/readonly/abc123",
        "lease_duration": 3600,
        "renewable": true
    }
"""


__metaclass__ = type  # pylint: disable=C0103

import copy

from ansible.module_utils.basic import AnsibleModule  # type: ignore

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_database import (
    VaultDatabaseDynamicRoles,
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
            database_mount_path=dict(default="database", aliases=["vault_database_mount_path"]),
            name=dict(type="str", required=True),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
    )

    client = get_authenticated_client(module)

    mount_path = module.params.get("database_mount_path")
    name = module.params.get("name")

    try:
        db_dynamic_role_client = VaultDatabaseDynamicRoles(client, mount_path=mount_path)

        data = db_dynamic_role_client.generate_dynamic_role_credentials(name)

        # Dynamic credentials are always "changed" since we generate new creds each time
        module.exit_json(changed=True, dynamic_role_credentials=data)

    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
