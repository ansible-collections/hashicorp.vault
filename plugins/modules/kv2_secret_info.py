# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: kv2_secret_info
short_description: Read HashiCorp Vault KV version 2 secrets
version_added: 1.0.0
author: Aubin Bikouo (@abikouo)
description:
  - Read secrets in HashiCorp Vault KV version 2 secrets engine.
options:
  engine_mount_point:
    description: KV secrets engine mount point.
    default: secret
    type: str
    aliases: [secret_mount_path]
  path:
    description: Path to the secret.
    required: true
    type: str
    aliases: [secret_path]
  version:
    description: The version to retrieve.
    type: int
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
"""

EXAMPLES = """
- name: Read a secret with token authentication
  hashicorp.vault.kv2_secret_info:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    path: myapp/config

- name: Read a secret with a specific version
  hashicorp.vault.kv2_secret_info:
    url: https://vault.example.com:8200
    path: myapp/config
    version: 1
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


from ansible.module_utils.basic import AnsibleModule, env_fallback


try:
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
        get_authenticated_client,
    )
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
        Secrets as VaultSecret,
    )
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
        VaultApiError,
        VaultPermissionError,
        VaultSecretNotFoundError,
    )

except ImportError as e:
    VAULT_IMPORT_ERROR = str(e)


def main():

    argument_spec = dict(
        # Authentication parameters
        url=dict(type="str", required=True, aliases=["vault_address"]),
        namespace=dict(type="str", default="admin", aliases=["vault_namespace"]),
        auth_method=dict(type="str", choices=["token", "approle"], default="token"),
        token=dict(type="str", no_log=True, fallback=(env_fallback, ["VAULT_TOKEN"])),
        role_id=dict(
            type="str",
            aliases=["approle_role_id"],
            fallback=(env_fallback, ["VAULT_APPROLE_ROLE_ID"]),
        ),
        secret_id=dict(
            type="str",
            no_log=True,
            aliases=["approle_secret_id"],
            fallback=(env_fallback, ["VAULT_APPROLE_SECRET_ID"]),
        ),
        vault_approle_path=dict(type="str", default="approle"),
        # Secret parameters
        engine_mount_point=dict(type="str", default="secret", aliases=["secret_mount_path"]),
        path=dict(type="str", required=True, aliases=["secret_path"]),
        version=dict(type="int"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    # Get authenticated client
    client = get_authenticated_client(module)

    try:
        secret_mgr = VaultSecret(client)
        mount_path = module.params.get("engine_mount_point")
        secret_path = module.params.get("path")
        version = module.params.get("version")
        result = secret_mgr.kv2.read_secret(
            mount_path=mount_path, secret_path=secret_path, version=version
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
