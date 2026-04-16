# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: vault_http_request
short_description: Send request to Vault server
author: Aubin Bikouo (@abikouo)
description:
  - Send request to the specified endpoint of the vault server.
  - This module is dedicated for integration tests for the C(hashicorp.vault) collection, no support
    for any use outside of this scope.
options:
  url:
    description:
      - The URL endpoint to target (e.g V(https://127.0.0.1:8200/v1/sys/mounts/database)).
    type: str
    required: true
  method:
    description:
      - The HTTP method to use.
    type: str
    default: GET
    choices: [GET, POST, PUT, DELETE, LIST]
  namespace:
    description: The vault namespace.
    type: str
    default: admin
  token:
    description: The vault token to be used.
    type: str
    no_log: true
  payload:
    description:
      - The json payload for the HTTP request.
    type: dict
"""

EXAMPLES = """
- name: Enable database secrets engine via API
  vault_http_request:
    url: "https://127.0.0.1:8200/v1/sys/mounts/database"
    method: POST
    token: "root"
    payload:
      type: "database"
      description: "My DB Engine"

- name: List auth methods
  vault_http_request:
    url: "https://127.0.0.1:8200/v1/sys/auth"
    method: GET
    token: "root"
  register: auth_list
"""

RETURN = """
status:
  description: The HTTP status code returned by the server.
  returned: always
  type: int
  sample: 200
data:
  description: The JSON response body from the Vault server.
  returned: success
  type: dict
  sample: {"data": {"keys": ["aws/", "token/"]}}
"""

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url


def run_module():
    module_args = dict(
        url=dict(type='str', required=True),
        method=dict(type='str', default='GET', choices=['GET', 'POST', 'PUT', 'DELETE', 'LIST']),
        namespace=dict(type='str', default='admin'),
        token=dict(type='str', no_log=True),
        payload=dict(type='dict'),
    )

    result = dict(changed=False, status=None, data={})

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    # Setup Headers
    headers = {'Content-Type': 'application/json', 'X-Vault-Namespace': module.params['namespace']}

    if module.params['token']:
        headers['X-Vault-Token'] = module.params['token']

    # Prepare Payload
    data = None
    if module.params['payload']:
        data = module.jsonify(module.params['payload'])

    if module.check_mode:
        module.exit_json(**result)

    # Execute Request
    response, info = fetch_url(module, module.params['url'], data=data, headers=headers, method=module.params['method'])

    result['status'] = info.get('status')

    # Read response body
    if response:
        body = response.read()
        try:
            if body:
                result['data'] = json.loads(body)
        except ValueError:
            result['data'] = body

    # Handle Errors
    if info.get('status') not in [200, 204]:
        module.fail_json(msg="Vault request failed: %s" % info.get('msg'), **result)

    # Since this is a generic HTTP module, we mark changed as True
    # for methods that typically modify state.
    if module.params['method'] in ['POST', 'PUT', 'DELETE']:
        result['changed'] = True

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
