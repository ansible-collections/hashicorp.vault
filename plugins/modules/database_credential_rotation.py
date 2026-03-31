# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: database_credential_rotation
short_description: Rotate Database Credentials in HashiCorp Vault.
version_added: 1.2.0
author: Aubin Bikouo (@abikouo)
description:
  - This module triggers an immediate rotation of the root credentials for
    a configured database connection or a static role within the HashiCorp Vault Database Secrets Engine.
  - Communicates with the Vault API to trigger the C(/rotate-root) or C(/rotate-role) endpoints.
  - This module does not support idempotency, as it triggers an active rotation each time it is invoked.
    Consequently, it will always report change upon a successful API call.
options:
  database_mount_path:
    description: Database secret engine mount path.
    type: str
    default: database
    aliases: [vault_database_mount_path]
  name:
    description:
      - The identifier for the database connection (for root user rotation) or the static role to trigger
        a password rotation for.
    required: true
    type: str
  credential_type:
    description:
      - Use V(root) to rotate the "root" user credentials stored for the database connection.
      - Use V(role) to rotate the Static Role credentials stored for a given role name.
    type: str
    choices: ['root', 'role']
    default: root
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
"""

EXAMPLES = """
- name: Rotate static role credentials
  hashicorp.vault.database_credential_rotation:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    name: my-state-role
    credential_type: role

- name: Rotate root user credentials on custom database mount path
  hashicorp.vault.database_credential_rotation:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    name: "mysql"
    database_mount_path: "database-config-integration-tests"
"""

RETURN = """
msg:
  description: A message describing the result of the operation.
  returned: always
  type: str
raw:
  description: The complete response returned by Vault for the rotation operation..
  returned: success
  type: dict
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_database import (
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
            database_mount_path=dict(default="database", aliases=["vault_database_mount_path"]),
            name=dict(required=True, type="str"),
            credential_type=dict(choices=["root", "role"], default="root"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
    )

    # Get authenticated client
    client = get_authenticated_client(module)
    name = module.params.get("name")
    credential_type = module.params.get("credential_type")
    database_mount_path = module.params.get("database_mount_path")

    db_conn = VaultDatabaseConnection(client, mount_path=database_mount_path)
    try:
        result = db_conn.rotate_credentials(name=name, credential_type=credential_type)
        module.exit_json(changed=True, raw=result)

    except VaultSecretNotFoundError as e:
        module.fail_json(msg=f"Resource error: {e}")
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
