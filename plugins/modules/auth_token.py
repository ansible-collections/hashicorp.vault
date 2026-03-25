# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r'''
---
module: auth_token
short_description: Manage HashiCorp Vault tokens
description:
  - Create, renew, or revoke tokens in HashiCorp Vault.
  - Supports detailed token configuration including TTLs, roles, and metadata.
version_added: "1.2.0"
author:
  - Aubin Bikouo (@abikouo)
options:
  state:
    description:
      - Use C(present) to create or renew a token.
      - Use C(absent) to revoke a token.
    type: str
    choices: [ present, absent ]
    default: present
  token_id:
    description:
      - The ID of the client token.
      - If creating a token, this sets a specific ID. If revoking/renewing, this identifies the target.
    type: str
  role_name:
    description:
      - The name of the token role to create the token against.
    type: str
  policies:
    description:
      - A list of policies for the token.
    type: list
    elements: str
  meta:
    description:
      - A dictionary of metadata values to be tied to the token.
    type: dict
  no_parent:
    description:
      - When set to C(true), the token created will not have a parent (orphan token).
    type: bool
    default: false
  no_default_policy:
    description:
      - If C(true), the 'default' policy will not be contained in this token's policy set.
    type: bool
    default: false
  renewable:
    description:
      - Set to C(false) to disable the ability of the token to be renewed past its initial TTL.
    type: bool
    default: true
  ttl:
    description:
      - Initial TTL for a new token (e.g., "1h") or renewal increment.
      - Ignored when C(state=absent)
    type: str
  type:
    description:
      - The token type.
    type: str
    choices: [ batch, service ]
  explicit_max_ttl:
    description:
      - If set, the token will have an explicit maximum TTL set upon it.
    type: str
  display_name:
    description:
      - The display name of the token, useful for auditing.
    type: str
  num_uses:
    description:
      - The maximum number of times this token can be used. After this limit, the token expires.
    type: int
  period:
    description:
      - If specified, the token will be periodic; it will be renewed for this period every time.
    type: str
  entity_alias:
    description:
      - The name of the entity alias to associate with during token creation.
    type: str
  renew:
    description:
      - If C(true) and the token already exists, the module will attempt to renew it.
    type: bool
    default: false
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
'''

EXAMPLES = r'''
- name: Create a service token with specific metadata and no parent
  auth_token:
    url: "https://vault.example.com:8200"
    auth_method: token
    token: "{{ login_token }}"
    display_name: "ci-runner-token"
    no_parent: true
    policies: ["deploy-policy"]
    meta:
      project: "phoenix"
      env: "prod"
    num_uses: 10
    ttl: "24h"
    state: present

- name: Create a batch token (non-renewable)
  auth_token:
    url: https://vault.example.com:8200
    auth_method: approle
    role_id: "{{ vault_role_id }}"
    secret_id: "{{ vault_secret_id }}"
    type: batch
    ttl: "5m"
    state: present

- name: Renew an existing token
  auth_token:
    url: https://vault.example.com:8200
    auth_method: approle
    role_id: "{{ vault_role_id }}"
    secret_id: "{{ vault_secret_id }}"
    token_id: "s.xxxxXXXXxxxx"
    renew: true
    ttl: "24h"
    state: present

- name: Revoke a token by ID
  auth_token:
    url: https://vault.example.com:8200
    auth_method: approle
    role_id: "{{ vault_role_id }}"
    secret_id: "{{ vault_secret_id }}"
    token_id: "hvs.CAESIL..."
    state: absent
'''

RETURN = """
msg:
  description: Human-readable result message.
  returned: always
  type: str
token_id:
  description: The ID of the token resulting from the create or renew operation.
  returned: when I(state=present)
  type: dict
raw:
  description: The raw response from the Vault server for the create or renew request.
  returned: when I(state=present)
  type: dict
  sample:
    {
      "accessor": "vU4iGKoHUD66Jizpw1ZZfySm.KFvXV",
      "client_token": "hvs.ABC...",
      "entity_id": "00001111-aaaa-bbbb-0000-111122223333",
      "lease_duration": 3600,
      "metadata": null,
      "mfa_requirement": null,
      "num_uses": 0,
      "orphan": false,
      "policies": [
          "acl-policy-crud",
          "database-conn-config-and-roles-crud",
          "default",
          "integration-tests-policy",
          "kv1-kv2-secrets-crud",
          "namespaces-crud",
          "pki-crud",
          "token-and-auth-crud"
      ],
      "renewable": true,
      "token_policies": [
          "acl-policy-crud",
          "database-conn-config-and-roles-crud",
          "default",
          "integration-tests-policy",
          "kv1-kv2-secrets-crud",
          "namespaces-crud",
          "pki-crud",
          "token-and-auth-crud"
      ],
      "token_type": "service"
    }
"""

import copy
from typing import NoReturn

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import VaultTokens
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
)


def ensure_present(module: AnsibleModule, vault_token: VaultTokens) -> NoReturn:
    """
    create/renew the token

    Args:
        module (str): The ansible module object.
        vault_token (VaultTokens): The vault token object.

    Returns:
        (bool, dict): A tuple containing a boolean flag—indicating whether
        the module performed any changes and a dictionary representing the JSON-structured result.
    """

    # Read existing token
    token_id = module.params.get("token_id")
    renew = module.params.get("renew")
    existing = None
    if token_id:
        existing = vault_token.lookup_token(token_id)
        if renew and not existing:
            module.fail_json(msg="Failed to renew token: The token does not exist or has already expired.")

    if existing:
        if not renew:
            module.exit_json(changed=False, msg="The token is already present; no action required.", token_id=token_id)
        # Renew token
        if module.check_mode:
            module.exit_json(changed=True, msg="Would have renewed the token if not in check mode.")
        result = vault_token.renew_token(token_id=token_id, increment=module.params.get("ttl"))
        module.exit_json(
            changed=True,
            msg="The token has been successfully renewed",
            token_id=result["client_token"],
            raw=result,
        )

    # Create token
    if module.check_mode:
        module.exit_json(changed=True, msg="Would have created token if not in check mode.")

    params = {}
    if token_id:
        params.update({"id": token_id})
    keys = (
        "role_name",
        "policies",
        "meta",
        "display_name",
        "entity_alias",
        "no_default_policy",
        "no_parent",
        "renewable",
        "type",
        "num_uses",
        "ttl",
        "explicit_max_ttl",
        "period",
    )
    params.update({k: module.params.get(k) for k in keys if module.params.get(k) is not None})
    response = vault_token.create_token(**params)
    module.exit_json(
        changed=True,
        msg="Token successfully created",
        token_id=response["client_token"],
        raw=response,
    )


def ensure_absent(module: AnsibleModule, vault_token: VaultTokens) -> NoReturn:
    """
    revoke the token

    Args:
        module (str): The ansible module object.
        vault_token (VaultTokens): The vault token object.

    Returns:
        (bool, dict): A tuple containing a boolean flag—indicating whether
        the module performed any changes—and a dictionary representing the JSON-structured result.
    """

    # Read existing token
    token_id = module.params.get("token_id")
    existing = vault_token.lookup_token(token_id)
    if not existing:
        module.exit_json(
            changed=False,
            msg="The token is already absent; no action required.",
        )

    if module.check_mode:
        module.exit_json(
            changed=True,
            msg="Would have revoked the token if not in check mode.",
        )

    vault_token.revoke_token(token_id)
    module.exit_json(
        changed=True,
        msg="The token has been successfully revoked.",
    )


def main():
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            state=dict(type='str', choices=['present', 'absent'], default='present'),
            token_id=dict(type='str', no_log=True),
            role_name=dict(type='str'),
            renew=dict(type="bool", default=False),
            # Token Configuration
            policies=dict(type='list', elements='str'),
            meta=dict(type='dict'),
            display_name=dict(type='str'),
            entity_alias=dict(type='str'),
            # Behavior Flags
            no_parent=dict(type='bool', default=False),
            no_default_policy=dict(type='bool', default=False),
            renewable=dict(type='bool', default=True),
            # Constraints and Types
            type=dict(type='str', choices=['batch', 'service']),
            num_uses=dict(type='int'),
            # Time-based Settings
            ttl=dict(type='str'),
            explicit_max_ttl=dict(type='str'),
            period=dict(type='str'),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec, required_if=[('state', 'absent', ['token_id'])], supports_check_mode=True
    )

    state = module.params.get("state")
    # Get authenticated client
    client = get_authenticated_client(module)
    vault_token = VaultTokens(client)

    try:
        if state == "absent":
            ensure_absent(module, vault_token)
        else:
            ensure_present(module, vault_token)

    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == '__main__':
    main()
