# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r'''
---
module: auth_token_info
short_description: Retrieve information about a specific HashiCorp Vault token
description:
  - Uses the Vault API to look up properties of a token (TTL, policies, metadata, etc.).
  - Targets the C(auth/token/lookup) endpoint.
version_added: "1.2.0"
author:
  - Aubin Bikouo (@abikouo)
options:
  token_id:
    description:
      - The unique identifier of the Vault token to be inspected.
    type: str
    required: true
  list_accessors:
    description:
      - When set to V(true), the module will list the token accessors.
    type: bool
    default: False
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
'''

EXAMPLES = r'''
- name: Look up details for a specific token
  auth_token_info:
    url: "https://vault.example.com:8200"
    auth_token: "{{ vault_admin_token }}"
    token_id: "hvs.CAESIL..."
  register: token_details

- name: Debug token TTL
  debug:
    msg: "The token expires in {{ token_details.data.ttl }} seconds"

- name: Retrieve token details with token accessors
  auth_token_info:
    url: "https://vault.example.com:8200"
    auth_token: "{{ vault_admin_token }}"
    token_id: "hvs.CAESIL..."
    list_accessors: true
'''

RETURN = r'''
accessors:
    description: The list of token accessors.
    type: list
    returned: when O(list_accessors=true)
data:
    description: The properties of the token if found.
    returned: success
    type: dict
    sample:
      {
        "accessor": "4YOtAiwQUqesWmmslorPbVbp.KFvXV",
        "creation_time": 1774613969,
        "creation_ttl": 1800,
        "display_name": "token-ansible-test",
        "entity_id": "71761a3d-9b92-09b3-87fb-62290cc789ee",
        "expire_time": "2026-03-27T12:49:29.869027581Z",
        "explicit_max_ttl": 0,
        "id": "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER",
        "issue_time": "2026-03-27T12:19:29.869034151Z",
        "meta": null,
        "namespace_path": "admin/integration-tests/",
        "num_uses": 0,
        "orphan": false,
        "path": "auth/token/create",
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
        "ttl": 1798,
        "type": "service"
      }
'''

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import VaultTokens
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
            token_id=dict(type='str', required=True, no_log=True),
            list_accessors=dict(type='bool', default=False),
        )
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    token_id = module.params.get("token_id")
    list_accessors = module.params.get("list_accessors")
    # Get authenticated client
    client = get_authenticated_client(module)
    vault_token = VaultTokens(client)

    try:
        data = vault_token.lookup_token(token_id)
        result = {"data": data}
        if list_accessors:
            result["accessors"] = vault_token.list_accessors(token_id)
        module.exit_json(**result)

    except VaultSecretNotFoundError:
        module.exit_json(data={})
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == '__main__':
    main()
