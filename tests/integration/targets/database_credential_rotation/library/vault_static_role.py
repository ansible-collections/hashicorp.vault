# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: vault_static_role
short_description: This module creates hashicorp database static role.
author: Aubin Bikouo (@abikouo)
description:
  - This module creates hashicorp database static role.
  - The module is restricted to be used for integration tests for the hashicorp.vault collection.
options:
  operation:
    description:
      - The action to perform
      - Use V(create) to create static role.
      - Use V(read) to read static role credentials.
    choices: ["read", "create"]
    default: create
  vault_address:
    description: The vault url.
    type: str
    required: true
  vault_token:
    description: The vault token.
    type: str
    required: true
  vault_namespace:
    description: The vault namespace.
    default: admin
  name:
    description: The name of the static role.
    type: str
    required: true
  db_name:
    description:
      - The name of the database connection to use for this role.
      - Required if O(operation=create).
    type: str
  username:
    description:
      - The database username that this Vault role corresponds to.
      - Required if O(operation=create).
  rotation_period:
    description: The amount of time Vault should wait before rotating the password.
    type: str
    default: "1h"
"""

EXAMPLES = """
"""

RETURN = """
msg:
  description: A message describing the result of the login operation.
  returned: success
  type: str
"""

import json

try:
    import requests

    REQUESTS_IMPORT_ERROR = None
    HAS_REQUESTS = True
except ImportError as e:
    HAS_REQUESTS = False
    REQUESTS_IMPORT_ERROR = e

from ansible.module_utils.basic import AnsibleModule, missing_required_lib


def main():

    argument_spec = dict(
        vault_address=dict(required=True),
        vault_token=dict(required=True),
        name=dict(required=True),
        db_name=dict(),
        username=dict(),
        rotation_period=dict(default="1h"),
        vault_namespace=dict(default="admin"),
        operation=dict(choices=["read", "create"], default="create"),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_if=(("operation", "create", ["username", "db_name"]),),
    )

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"), exception=REQUESTS_IMPORT_ERROR)

    operation = module.params.get("operation")

    try:
        session = requests.Session()
        session.headers.update({"X-Vault-Namespace": module.params.get("vault_namespace")})
        session.headers.update({"X-Vault-Token": module.params.get("vault_token")})

        if operation == "create":
            body = {
                "name": module.params.get("name"),
                "db_name": module.params.get("db_name"),
                "username": module.params.get("username"),
                "rotation_period": module.params.get("rotation_period"),
            }
            url = module.params.get("vault_address") + "/v1/database/static-roles/" + module.params.get("name")
            response = session.request("PUT", url, json=body)
            response.raise_for_status()
            result = response.json() if response.content else {}
            module.exit_json(changed=True, msg="Static role successfully created", result=result)
        elif operation == "read":
            body = {"name": module.params.get("name")}
            url = module.params.get("vault_address") + "/v1/database/static-creds/" + module.params.get("name")
            response = session.request("GET", url, json=body)
            response.raise_for_status()
            result = response.json().get("data", {}) if response.content else {}
            module.exit_json(changed=False, auth=result)
    except requests.exceptions.HTTPError as e:
        status_code = e.response.status_code
        try:
            errors = e.response.json().get("errors", [])
        except json.JSONDecodeError:
            errors = [e.response.text]
        module.fail_json(msg=f"API request failed: {errors}", status_code=status_code)
    except Exception as e:
        module.fail_json(msg=f"Module failed with: {e}")


if __name__ == "__main__":
    main()
