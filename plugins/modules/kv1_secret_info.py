# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: kv1_secret_info
short_description: Read HashiCorp Vault KV version 1 secrets
version_added: 1.1.0
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
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
"""

EXAMPLES = """
- name: Read a sample secret
  hashicorp.vault.kv1_secret_info:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    path: sample
"""

RETURN = """
secret:
  description: The secret data and metadata when reading existing secrets.
  returned: when the secret exists
  type: dict
  sample:
    data:
      env: "test"
      password: "initial_pass"
      username: "testuser"
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

    try:
        result = client.secrets.kv1.read_secret(mount_path=mount_path, secret_path=path)
        module.exit_json(secret={"data": result})

    except VaultSecretNotFoundError as e:
        module.exit_json(secret={})
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
