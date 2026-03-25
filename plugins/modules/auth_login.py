# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r'''
---
module: auth_login
short_description: Authenticate to HashiCorp Vault.
description:
  - Authenticates to Hashicorp vault and returns generated token.
version_added: "1.2.0"
author:
  - Aubin Bikouo (@abikouo)
options:
  url:
    description: Vault server URL.
    required: true
    type: str
    aliases: [vault_address]
  namespace:
    description: Vault namespace.
    type: str
    aliases: [vault_namespace]
  auth_method:
    description:
        - Authentication method to use.
        - V(cf) used for Cloud foundry authentication.
        - V(gcp) used for Google cloud authentication.
        - V(cert) used for TLS Certificate authentication.
    choices:
      - alicloud
      - approle
      - aws
      - azure
      - cf
      - github
      - gcp
      - jwt
      - kerberos
      - kubernetes
      - ldap
      - oci
      - okta
      - radius
      - saml
      - scep
      - spiffe
      - cert
      - userpass
    default: approle
    type: str
  mount_path:
    description: The custom path where the auth method is mounted. Defaults to the value of O(auth_method).
    required: false
    type: str
  auth_params:
    description: Optional login parameters specific to the authentication method.
    type: dict
'''

EXAMPLES = r'''
- name: Login to Vault via AWS
  auth_login:
    url: "https://vault.example.com:8200"
    auth_method: "aws"
    auth_params:
      role: "prod-web-role"

- name: Login to a custom mount path via userpass
  auth_login:
    url: "https://vault.example.com:8200"
    namespace: "admin/it-ops"
    auth_method: "aws"
    mount_path: "aws-staging"
    auth_params:
      iam_http_request_method: "POST"
      iam_request_body: "QWN0aW9uPUdldENhbG..."
      iam_request_headers: "eyJBdXRob3JpemF0aW9uIj..."
      iam_request_ur": "aHR0cHM6L..."
      role: "dev-role"
'''

RETURN = """
msg:
  description: Human-readable result message.
  returned: always
  type: str
token_id:
  description: The ID of the token resulting from the login operation.
  returned: success
  type: dict
authentication:
  description: The authentication details from the Vault server for the login request.
  returned: success
  type: dict
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import VaultLogin
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultLoginError,
    VaultPermissionError,
)


def main():
    auth_methods = [
        'alicloud',
        'approle',
        'aws',
        'azure',
        'cf',
        'github',
        'gcp',
        'jwt',
        'kerberos',
        'kubernetes',
        'ldap',
        'oci',
        'okta',
        'radius',
        'saml',
        'scep',
        'spiffe',
        'cert',
        'userpass',
    ]
    argument_spec = dict(
        url=dict(type="str", required=True, aliases=["vault_address"]),
        namespace=dict(type="str", aliases=["vault_namespace"]),
        auth_method=dict(type="str", default="approle", choices=auth_methods),
        mount_path=dict(),
        auth_params=dict(type="dict"),
    )

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    url = module.params.get("url")
    namespace = module.params.get("namespace")
    auth_method = module.params.get("auth_method")
    mount_path = module.params.get("mount_path")
    auth_params = module.params.get("auth_params")

    try:
        vault_login = VaultLogin(
            vault_address=url, auth_method=auth_method, vault_namespace=namespace, mount_path=mount_path
        )
        vault_login.validate_login_params(**auth_params)
        if module.check_mode:
            module.exit_json(changed=True, msg="Would have performed a login if not in check mode.")
        client_token, auth = vault_login.login(**auth_params)
        module.exit_json(
            changed=True,
            token_id=client_token,
            authentication=auth,
            msg="Authentication successful; Vault token retrieved.",
        )

    except VaultLoginError as e:
        module.fail_json(msg=f"Vault login error: {e}")
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == '__main__':
    main()
