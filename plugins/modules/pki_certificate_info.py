# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: pki_certificate_info
short_description: List and read HashiCorp Vault PKI certificates
version_added: 1.2.0
author: Mandar Kulkarni (@mandar242)
description:
  - Queries stored certificates on a PKI mount (C(LIST .../certs) or C(GET .../cert/:serial)).
  - Omit I(serial_number) to list serial numbers known to Vault for the mount.
  - Set I(serial_number) to read PEM and metadata for that certificate.
  - For issue, sign, and revoke, use M(hashicorp.vault.pki_certificate).
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
options:
  engine_mount_point:
    description: PKI secrets engine mount path.
    type: str
    default: pki
  serial_number:
    description:
      - Certificate serial (colon-separated hex or Vault C(certs) list key). When omitted, the module lists serials.
    type: str
    required: false
"""

EXAMPLES = """
- name: List certificate serial numbers on the default PKI mount
  hashicorp.vault.pki_certificate_info:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
  register: pki_certs

- name: Read a specific certificate by serial
  hashicorp.vault.pki_certificate_info:
    url: https://vault.example.com:8200
    engine_mount_point: pki
    serial_number: "39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58"
  register: pki_cert
"""

RETURN = """
serials:
  description: Serial numbers returned by Vault when I(serial_number) is omitted.
  returned: when I(serial_number) is omitted
  type: list
  elements: str
certificate_info:
  description:
    - Inner C(data) object from Vault for C(GET .../cert/:serial) (PEM, revocation time, etc.).
    - Empty mapping when the certificate is not found.
  returned: when I(serial_number) is set
  type: dict
raw:
  description: Full Vault JSON envelope when reading a single certificate; omitted for list-only calls.
  returned: when I(serial_number) is set and the certificate exists
  type: dict
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultPki
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)


def main():
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            engine_mount_point=dict(type="str", default="pki"),
            serial_number=dict(type="str", required=False),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    client = get_authenticated_client(module)
    pki = VaultPki(client, module.params["engine_mount_point"])
    serial_number = module.params.get("serial_number")

    try:
        if serial_number:
            raw = pki.read_certificate(serial_number)
            module.exit_json(
                changed=False,
                certificate_info=(raw or {}).get("data") or {},
                raw=raw or {},
            )
        serials = pki.list_certificates()
        module.exit_json(changed=False, serials=serials)

    except VaultSecretNotFoundError as e:
        if serial_number:
            module.exit_json(changed=False, certificate_info={}, raw={})
        module.fail_json(msg="Could not list PKI certificates (mount missing or permission denied): {0}".format(e))
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
