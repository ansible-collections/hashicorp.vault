# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: kv1_secret_info
short_description: Read HashiCorp Vault KV version 1 secrets
version_added: 2.0.0
author: Aubin Bikouo (@abikouo)
description:
  - Read secrets in HashiCorp Vault KV version 1 secrets engine.
options:
  engine_mount_point:
    description: KV secrets engine mount point.
    default: secret
    type: str
    aliases: [secret_mount_path]
  path:
    description:
      - Specifies the path of the secret.
    required: true
    type: str
    aliases: [secret_path]
  recover_snapshot_id:
    description:
      - The ID of a snapshot previously loaded into Vault that contains
        secrets at the provided path.
    type: str
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
"""

EXAMPLES = """
- name: Read a sample secret
  hashicorp.vault.kv1_secret_info:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    path: sample

- name: Read a secret with a specified snapshot location id
  hashicorp.vault.kv2_secret_info:
    url: https://vault.example.com:8200
    path: myapp/config
    recover_snapshot_id: '2403d301-94f2-46a1-a39d-02be83e2831a'
"""

RETURN = """
secret:
  description: The secret data and metadata when reading existing secrets.
  returned: always
  type: dict
  sample:
    data:
      env: "test"
      password: "initial_pass"
      username: "testuser"
    metadata:
      created_time: "2025-09-01T22:04:48.74947241Z"
      custom_metadata: null
      deletion_time: ""
      destroyed: false
      version: 42
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
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
            path=dict(type="str", required=True, aliases=["secret_path"]),
            recover_snapshot_id=dict(type="str"),
            engine_mount_point=dict(default="secret", aliases=["secret_mount_path"]),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Get authenticated client
    client = get_authenticated_client(module)
    mount_path = module.params.get("engine_mount_point")
    path = module.params.get("path")
    recover_snapshot_id = module.params.get("recover_snapshot_id")

    try:
        result = client.secrets.kv1.read_secret(
            mount_path=mount_path, secret_path=path, recover_snapshot_id=recover_snapshot_id
        )
        module.exit_json(changed=False, secret=result)

    except VaultSecretNotFoundError as e:
        module.fail_json(msg=f"Secret not found: {e}")
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
