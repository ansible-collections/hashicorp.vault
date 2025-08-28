# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type

DOCUMENTATION = """
---
module: kv2_secret
short_description: Manage HashiCorp Vault KV version 2 secrets
version_added: 1.0.0
author: Mandar Vijay Kulkarni (@mandar242)
description:
  - Create, update, or delete secrets in HashiCorp Vault KV version 2 secrets engine
  - Supports token and AppRole authentication methods
  - Token can be provided as a parameter or as an environment variable VAULT_TOKEN
  - AppRole authentication role_id and secret_id can be provided as parameters or as environment variables VAULT_APPROLE_ROLE_ID and VAULT_APPROLE_SECRET_ID
  - It does not create the secret engine if it does not exist and will fail if the secret engine path (engine_mount_point) is not enabled.
options:
  url:
    description: Vault server URL
    required: true
    type: str
    aliases: [vault_address]
  namespace:
    description: Vault namespace
    default: admin
    type: str
    aliases: [vault_namespace]
  auth_method:
    description: Authentication method to use
    choices: ['token', 'approle']
    default: token
    type: str
  token:
    description: Vault token for authentication
    type: str
  role_id:
    description: Role ID for AppRole authentication
    type: str
    aliases: [approle_role_id]
  secret_id:
    description: Secret ID for AppRole authentication
    type: str
    aliases: [approle_secret_id]
  vault_approle_path:
    description: AppRole auth method mount path
    default: approle
    type: str
  engine_mount_point:
    description: KV secrets engine mount point
    default: secret
    type: str
    aliases: [secret_mount_path]
  path:
    description: Path to the secret
    required: true
    type: str
    aliases: [secret_path]
  data:
    description: Secret data as key-value pairs
    type: dict
  versions:
    description: One or more versions of the secret to delete (used with state=absent)
    type: list
    elements: int
  state:
    description: Desired state of the secret
    choices: ['present', 'absent']
    default: present
    type: str
  cas:
    description: Check-and-Set value for conditional updates
    type: int
"""

EXAMPLES = """
- name: Create a secret with token authentication
  hashicorp.vault.kv2_secret:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    path: myapp/config
    data:
      username: admin
      password: secret123

- name: Create a secret with token authentication (using env var for auth)
  hashicorp.vault.kv2_secret:
    url: https://vault.example.com:8200
    path: myapp/config
    data:
      username: admin
      password: secret123

- name: Create a secret with AppRole authentication
  hashicorp.vault.kv2_secret:
    url: https://vault.example.com:8200
    auth_method: approle
    role_id: "{{ vault_role_id }}"
    secret_id: "{{ vault_secret_id }}"
    path: myapp/config
    data:
      api_key: secret-api-key

- name: Delete a secret
  hashicorp.vault.kv2_secret:
    url: https://vault.example.com:8200
    path: myapp/config
    state: absent
"""

RETURN = """
"""

import os

from typing import List, Optional

from ansible.module_utils.basic import AnsibleModule


try:
    from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import (
        AppRoleAuthenticator,
        TokenAuthenticator,
    )
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
        Secrets as VaultSecret,
    )
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import (
        VaultClient,
    )
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
        VaultApiError,
        VaultConfigurationError,
        VaultConnectionError,
        VaultCredentialsError,
        VaultPermissionError,
        VaultSecretNotFoundError,
    )

except ImportError as e:
    VAULT_IMPORT_ERROR = str(e)


def get_option(
    module: AnsibleModule, option_name: str, env_var: Optional[str] = None
) -> Optional[str]:
    """Get option value with optional environment variable fallback."""
    value = module.params.get(option_name)
    if not value and env_var:
        value = os.environ.get(env_var)
    return value


def _authenticate(module: AnsibleModule, client: VaultClient) -> None:
    """Authenticate the client using token or AppRole authentication."""
    auth_method = get_option(module, "auth_method")

    if auth_method == "token":
        token = get_option(module, "token", "VAULT_TOKEN")
        if not token:
            module.fail_json(
                msg="Token authentication requires 'token' parameter or VAULT_TOKEN environment variable"
            )
        TokenAuthenticator().authenticate(client, token=token)
    else:
        params = {
            "vault_address": get_option(module, "url"),
            "role_id": get_option(module, "role_id", "VAULT_APPROLE_ROLE_ID"),
            "secret_id": get_option(module, "secret_id", "VAULT_APPROLE_SECRET_ID"),
        }

        if not params["role_id"] or not params["secret_id"]:
            module.fail_json(
                msg="AppRole authentication requires 'role_id' and 'secret_id' parameters or "
                "VAULT_APPROLE_ROLE_ID and VAULT_APPROLE_SECRET_ID environment variables"
            )

        vault_namespace = get_option(module, "namespace")
        if vault_namespace is not None:
            params.update({"vault_namespace": vault_namespace})
        vault_approle_path = get_option(module, "vault_approle_path")
        if vault_approle_path is not None:
            params.update({"approle_path": vault_approle_path})

        AppRoleAuthenticator().authenticate(client, **params)


def get_authenticated_client(module: AnsibleModule) -> VaultClient:
    """Create and authenticate a Vault client using module parameters and environment variables."""
    vault_namespace = get_option(module, "namespace")
    vault_address = get_option(module, "url")

    if not vault_address:
        module.fail_json(msg="url parameter is required")

    try:
        # Create client
        client = VaultClient(vault_address=vault_address, vault_namespace=vault_namespace)

        # Authenticate using VaultLookupBase pattern
        _authenticate(module, client)

        return client

    except VaultConfigurationError as e:
        module.fail_json(msg=f"Vault configuration error: {e}")
    except VaultCredentialsError as e:
        module.fail_json(msg=f"Vault authentication error: {e}")
    except VaultConnectionError as e:
        module.fail_json(msg=f"Vault connection error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Failed to create authenticated Vault client: {e}")


def ensure_secret_present(
    module: AnsibleModule, secret_mgr: VaultSecret, mount_path: str, secret_path: str
) -> None:
    """Ensure the secret exists with the specified data by creating or updating it."""
    # Get secret data and options
    data = module.params["data"]
    cas = module.params["cas"]

    try:
        # First, try to read the existing secret to check for changes
        try:
            existing_secret = secret_mgr.kv2.read_secret(
                mount_path=mount_path, secret_path=secret_path
            )
            # The read_secret returns {"data": {...actual_secret_data...}, "metadata": {...}}
            existing_data = existing_secret.get("data", {})
            existing_metadata = existing_secret.get("metadata", {})

            # Check if the secret was previously deleted (soft-deleted)
            deletion_time = existing_metadata.get("deletion_time", "")

            if deletion_time:
                # Secret was soft-deleted, treat as if it doesn't exist for idempotency
                action_msg = "Secret recreated successfully"
            elif existing_data == data:
                # Secret already exists with the same data - no changes needed
                module.exit_json(
                    changed=False,
                    msg="Secret already exists with the same data",
                    secret=existing_secret,
                )
            else:
                # Data is different, proceed with update
                action_msg = "Secret updated successfully"

        except VaultSecretNotFoundError:
            # Secret doesn't exist, proceed with creation
            action_msg = "Secret created successfully"

        # Create or update the secret
        result = secret_mgr.kv2.create_or_update_secret(
            mount_path=mount_path, secret_path=secret_path, secret_data=data, cas=cas
        )

        # Read back to get metadata
        secret_result = secret_mgr.kv2.read_secret(mount_path=mount_path, secret_path=secret_path)

        module.exit_json(changed=True, msg=action_msg, secret=secret_result)

    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Failed to create/update secret: {e}")


def ensure_secret_absent(
    module: AnsibleModule,
    secret_mgr: VaultSecret,
    mount_path: str,
    secret_path: str,
    versions: Optional[List[int]] = None,
) -> None:
    """Ensure the secret is deleted by removing specified versions or the latest version."""
    try:
        # First, check if the secret exists and its current state
        try:
            existing_secret = secret_mgr.kv2.read_secret(
                mount_path=mount_path, secret_path=secret_path
            )
            existing_data = existing_secret.get("data", {})
            existing_metadata = existing_secret.get("metadata", {})

            # Check if the secret is already deleted (soft-deleted)
            deletion_time = existing_metadata.get("deletion_time", "")

            if deletion_time:
                # Secret is already soft-deleted, no action needed
                module.exit_json(changed=False, msg="Secret already absent")

            # Secret exists and is not deleted, proceed with deletion

        except VaultSecretNotFoundError:
            # Secret doesn't exist, already in desired state
            module.exit_json(changed=False, msg="Secret already absent")

        # Delete the secret
        secret_mgr.kv2.delete_secret(mount_path, secret_path, versions)
        module.exit_json(changed=True, msg="Secret deleted successfully")

    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Failed to delete secret: {e}")


def main():

    argument_spec = dict(
        # Authentication parameters
        url=dict(type="str", required=True, aliases=["vault_address"]),
        namespace=dict(type="str", default="admin", aliases=["vault_namespace"]),
        auth_method=dict(type="str", choices=["token", "approle"], default="token"),
        token=dict(type="str", no_log=True),
        role_id=dict(type="str", aliases=["approle_role_id"]),
        secret_id=dict(type="str", no_log=True, aliases=["approle_secret_id"]),
        vault_approle_path=dict(type="str", default="approle"),
        # Secret parameters
        engine_mount_point=dict(type="str", default="secret", aliases=["secret_mount_path"]),
        path=dict(type="str", required=True, aliases=["secret_path"]),
        data=dict(type="dict"),
        cas=dict(type="int"),
        versions=dict(type="list", elements="int"),
        # Other parameters
        state=dict(type="str", choices=["present", "absent"], default="present"),
    )

    required_if = [
        ("state", "present", ["data"]),
    ]

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=required_if,
        supports_check_mode=False,
    )

    # Get authenticated client
    client = get_authenticated_client(module)

    mount_path = module.params["engine_mount_point"]
    secret_path = module.params["path"]
    state = module.params["state"]
    versions = module.params["versions"]

    try:
        secret_mgr = VaultSecret(client)
        if state == "present":
            ensure_secret_present(module, secret_mgr, mount_path, secret_path)
        elif state == "absent":
            ensure_secret_absent(module, secret_mgr, mount_path, secret_path, versions)

    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
