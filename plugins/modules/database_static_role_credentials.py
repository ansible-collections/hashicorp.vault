# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, annotations, division, print_function

DOCUMENTATION = """
---
module: database_static_role_credentials
author: Hannah DeFazio (@hdefazio)
version_added: "1.2.0"
short_description: Read the credentials for a specific static role.
description:
    - Reads the current credentials for a database static role from HashiCorp Vault.
options:
  database_mount_path:
    description: Database secrets engine mount path.
    type: str
    default: database
    aliases: [vault_database_mount_path]
  name:
    description: The name of the database static role to get credentials for.
    required: true
    type: str
  read_snapshot_id:
    description: Query parameter specifying the ID of a snapshot previously loaded into Vault.
    required: false
    type: str
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
notes:
  - For security reasons, use C(no_log=true) and C(register) so raw credentials are not written to the task log.
"""

EXAMPLES = """
- name: Read credentials for a specific database static role
  hashicorp.vault.database_static_role_credentials:
    name: my-static-role
  no_log: true
  register: result
"""

RETURN = """
static_role_credentials:
  description: The credentials and metadata for the database static role.
  type: dict
  returned: always
  sample:
    {
        "username": "static-user",
        "password": "132ae3ef-5a64-7499-351e-bfe59f3a2a21",
        "last_vault_rotation": "2019-05-06T15:26:42.525302-05:00",
        "rotation_schedule": "0 0 * * SAT",
        "rotation_window": 3600,
        "ttl": 5000
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
    VaultDatabaseStaticRoles,
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
            read_snapshot_id=dict(type="str", required=False),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    client = get_authenticated_client(module)

    mount_path = module.params.get("database_mount_path")
    name = module.params.get("name")
    read_snapshot_id = module.params.get("read_snapshot_id")

    try:
        db_static_role_client = VaultDatabaseStaticRoles(client, mount_path=mount_path)

        data = db_static_role_client.get_static_role_credentials(name, read_snapshot_id)

        module.exit_json(changed=False, static_role_credentials=data)

    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
