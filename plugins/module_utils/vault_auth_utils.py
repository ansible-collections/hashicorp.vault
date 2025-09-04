# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Common helper functions for Ansible Vault modules.
"""

from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import (
    AppRoleAuthenticator,
    TokenAuthenticator,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultConfigurationError,
    VaultConnectionError,
    VaultCredentialsError,
)


def authenticate_module(module, client):
    """
    Authenticate a Vault client using Ansible module parameters.

    This function handles both token and AppRole authentication methods
    based on the module's auth_method parameter.

    Args:
        module: AnsibleModule instance with authentication parameters
        client: VaultClient instance to authenticate

    Raises:
        VaultCredentialsError: If required authentication parameters are missing
    """
    auth_method = module.params["auth_method"]

    if auth_method == "token":
        token = module.params["token"]
        if not token:
            raise VaultCredentialsError(
                msg="Token authentication requires 'token' parameter or VAULT_TOKEN environment variable"
            )
        TokenAuthenticator().authenticate(client, token=token)
    else:
        params = {
            "vault_address": module.params["url"],
            "role_id": module.params["role_id"],
            "secret_id": module.params["secret_id"],
        }

        if not params["role_id"] or not params["secret_id"]:
            raise VaultCredentialsError(
                msg="AppRole authentication requires 'role_id' and 'secret_id' parameters or "
                "VAULT_APPROLE_ROLE_ID and VAULT_APPROLE_SECRET_ID environment variables"
            )

        vault_namespace = module.params["namespace"]
        if vault_namespace is not None:
            params.update({"vault_namespace": vault_namespace})
        vault_approle_path = module.params["vault_approle_path"]
        if vault_approle_path is not None:
            params.update({"approle_path": vault_approle_path})

        AppRoleAuthenticator().authenticate(client, **params)


def get_authenticated_client(module):
    """
    Create and authenticate a Vault client using Ansible module parameters.

    This is a convenience function that combines client creation and authentication
    for common Vault module patterns.

    Args:
        module: AnsibleModule instance with authentication and connection parameters

    Returns:
        VaultClient: Authenticated Vault client ready for API calls

    Raises:
        Various VaultError exceptions if client creation or authentication fails
    """
    # Import here to avoid circular imports
    from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultClient

    vault_namespace = module.params["namespace"]
    vault_address = module.params["url"]

    try:
        # Create client
        client = VaultClient(vault_address=vault_address, vault_namespace=vault_namespace)

        # Authenticate using module parameters
        authenticate_module(module, client)

        return client

    except VaultConfigurationError as e:
        module.fail_json(msg=f"Vault configuration error: {e}")
    except VaultCredentialsError as e:
        module.fail_json(msg=f"Vault authentication error: {e}")
    except VaultConnectionError as e:
        module.fail_json(msg=f"Vault connection error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Failed to create authenticated Vault client: {e}")
