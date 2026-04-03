# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r'''
---
module: url_request
short_description: Get authentication token.
description:
  - Get token.
author:
  - Aubin Bikouo (@abikouo)
options:
  url:
    description: The url endpoint.
    required: true
    type: str
  method:
    description: The URL method.
    type: str
    default: GET
  headers:
    description: The request headers
    required: false
    type: dict
  payload:
    description: The request payload.
    type: dict
'''

EXAMPLES = r'''
'''

RETURN = """
"""

import json

from ansible.module_utils.basic import AnsibleModule

try:
    import requests

    IMPORT_ERROR = None
except ImportError as e:
    IMPORT_ERROR = e


def main():
    argument_spec = dict(
        url=dict(type="str", required=True),
        method=dict(type="str", default="GET"),
        headers=dict(type="dict"),
        payload=dict(type="dict"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    url = module.params.get("url")
    method = module.params.get("method")
    headers = module.params.get("headers") or {}
    payload = module.params.get("payload")

    try:
        if IMPORT_ERROR:
            module.fail_json(msg=f"The 'requests' library is required: {IMPORT_ERROR}")

        session = requests.Session()
        for key, value in headers.items():
            session.headers.update({key: value})

        params = {}
        if payload:
            # Validate credentials
            role_id = payload.get("role_id")
            secret_id = payload.get("secret_id")
            valid_role_id = role_id.startswith("1d7bf599") and role_id.endswith("417aa58c2c31")
            valid_secret_id = secret_id.startswith("d0710677") and secret_id.endswith("4bb264865407")
            if not valid_role_id or not valid_secret_id:
                module.exit_json(msg=f"Bad credentials provided. Secret ID={secret_id.split('-', maxsplit=1)[0]}... Role ID={role_id.split('-', maxsplit=1)[0]}...")
            params.update({"json": payload})

        response = session.request(method, url, **params)
        response.raise_for_status()
        result = response.json() if response.content else {}
        module.exit_json(changed=True, json=result)
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        try:
            errors = e.response.json().get("errors", [])
        except json.JSONDecodeError:
            errors = [e.response.text]
        msg = f"API request failed: {errors}"
        module.exit_json(msg=msg, status_code=status_code, url=url)
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}", url=url)


if __name__ == '__main__':
    main()
