# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: pki_certificate
short_description: Issue, sign, or revoke HashiCorp Vault PKI certificates
version_added: 1.2.0
author: Mandar Kulkarni (@mandar242)
description:
  - Uses the Vault PKI secrets engine HTTP API via the collection C(VaultPki) client.
  - O(state=issued) generates a new private key and certificate (C(POST .../issue/:role)).
  - O(state=signed) signs a PEM CSR (C(POST .../sign/:role)).
  - O(state=revoked) revokes by C(serial_number) or PEM C(certificate) (C(POST .../revoke)).
  - For read and list operations, use M(hashicorp.vault.pki_certificate_info).
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
options:
  state:
    description:
      - V(issued) issues a new certificate and key for O(role_name).
      - V(signed) signs the PEM O(csr) with O(role_name).
      - V(revoked) revokes an existing certificate; provide exactly one of O(serial_number) or O(certificate).
    type: str
    choices: [issued, signed, revoked]
    default: issued
  engine_mount_point:
    description:
      - PKI secrets engine mount path.
    type: str
    default: pki
  role_name:
    description:
      - PKI role name (path segment after C(/issue/) or C(/sign/)). Required when O(state) is V(issued) or V(signed).
    type: str
    aliases: [role]
  common_name:
    description:
      - Requested common name. Required when O(state) is V(issued) or V(signed).
    type: str
  csr:
    description:
      - PEM-encoded certificate signing request. Required when O(state) is V(signed).
    type: str
  serial_number:
    description:
      - Certificate serial in Vault format (colon-separated hex). Use with O(state=revoked) unless using O(certificate) instead.
    type: str
  certificate:
    description:
      - PEM-encoded certificate to revoke. Use with O(state=revoked) unless using O(serial_number) instead.
    type: str
  alt_names:
    description:
      - Subject Alternative Names (joined as a comma-separated string for the Vault API).
    type: list
    elements: str
  ip_sans:
    description:
      - IP SANs (joined for the Vault API).
    type: list
    elements: str
  uri_sans:
    description:
      - URI SANs (joined for the Vault API).
    type: list
    elements: str
  other_sans:
    description:
      - Other SANs (joined for the Vault API).
    type: list
    elements: str
  ttl:
    description:
      - Requested lease TTL (string, for example V(720h)).
    type: str
  format:
    description:
      - Encoding for returned certificate material.
    type: str
    choices: [pem, der, pem_bundle]
  exclude_cn_from_sans:
    description:
      - If V(true), the O(common_name) is not duplicated into DNS/email SANs automatically.
    type: bool
  private_key_format:
    description:
      - Private key encoding for O(state=issued) only (C(der) or C(pkcs8)).
    type: str
    choices: [der, pkcs8]
"""

EXAMPLES = """
- name: Issue a new certificate and key (token auth via module_defaults)
  hashicorp.vault.pki_certificate:
    engine_mount_point: pki
    role_name: my-role
    common_name: svc.example.com
    state: issued
    ttl: 720h
    alt_names:
      - alt.example.com

- name: Sign a CSR
  hashicorp.vault.pki_certificate:
    engine_mount_point: pki
    role_name: my-role
    common_name: client.example.com
    csr: "{{ lookup('file', 'request.csr') }}"
    state: signed

- name: Revoke by serial
  hashicorp.vault.pki_certificate:
    engine_mount_point: pki
    state: revoked
    serial_number: "39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58"
"""

RETURN = """
msg:
  description: Human-readable result message.
  returned: always
  type: str
changed:
  description: V(true) when Vault was called and the operation succeeded (or predicted in check mode for issue/sign/revoke).
  returned: always
  type: bool
raw:
  description: Full JSON response from Vault.
  returned: when not in check mode (or empty dict for check mode where applicable)
  type: dict
data:
  description:
    - Inner C(data) object from Vault (certificate fields, serial, private key for issue, etc.).
  returned: when not in check mode for successful issue/sign/revoke
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
)


def _csv_option(value):
    if value is None:
        return None
    if isinstance(value, list):
        return ",".join(str(item) for item in value)
    return value


def _build_issue_sign_extra(module, include_private_key_format):
    extra = {}
    for key in ("alt_names", "ip_sans", "uri_sans", "other_sans"):
        enc = _csv_option(module.params.get(key))
        if enc is not None:
            extra[key] = enc
    if module.params.get("ttl") is not None:
        extra["ttl"] = module.params["ttl"]
    if module.params.get("format") is not None:
        extra["format"] = module.params["format"]
    if module.params.get("exclude_cn_from_sans") is not None:
        extra["exclude_cn_from_sans"] = module.params["exclude_cn_from_sans"]
    if include_private_key_format and module.params.get("private_key_format") is not None:
        extra["private_key_format"] = module.params["private_key_format"]
    return extra


def ensure_issued(module, pki):
    role = module.params["role_name"]
    common_name = module.params["common_name"]
    extra = _build_issue_sign_extra(module, include_private_key_format=True)
    if module.check_mode:
        module.exit_json(
            changed=True,
            msg="Would have issued a new certificate and key if not in check mode.",
            raw={},
            data={},
        )
    raw = pki.generate_certificate(role, common_name, extra if extra else None)
    module.exit_json(
        changed=True,
        msg="Certificate issued successfully",
        raw=raw or {},
        data=(raw or {}).get("data") or {},
    )


def ensure_signed(module, pki):
    role = module.params["role_name"]
    common_name = module.params["common_name"]
    csr = module.params["csr"]
    extra = _build_issue_sign_extra(module, include_private_key_format=False)
    if module.check_mode:
        module.exit_json(
            changed=True,
            msg="Would have signed the CSR if not in check mode.",
            raw={},
            data={},
        )
    raw = pki.sign_certificate(role, csr, common_name, extra if extra else None)
    module.exit_json(
        changed=True,
        msg="Certificate signing request signed successfully",
        raw=raw or {},
        data=(raw or {}).get("data") or {},
    )


def ensure_revoked(module, pki):
    serial_number = module.params.get("serial_number")
    certificate = module.params.get("certificate")
    if module.check_mode:
        module.exit_json(
            changed=True,
            msg="Would have revoked the certificate if not in check mode.",
            raw={},
            data={},
        )
    raw = pki.revoke_certificate(serial_number=serial_number, certificate=certificate)
    module.exit_json(
        changed=True,
        msg="Certificate revoked successfully",
        raw=raw or {},
        data=(raw or {}).get("data") or {},
    )


def main():
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            state=dict(type="str", choices=["issued", "signed", "revoked"], default="issued"),
            engine_mount_point=dict(type="str", default="pki"),
            role_name=dict(type="str", required=False, aliases=["role"]),
            common_name=dict(type="str", required=False),
            csr=dict(type="str", required=False),
            serial_number=dict(type="str", required=False),
            certificate=dict(type="str", required=False),
            alt_names=dict(type="list", elements="str", required=False),
            ip_sans=dict(type="list", elements="str", required=False),
            uri_sans=dict(type="list", elements="str", required=False),
            other_sans=dict(type="list", elements="str", required=False),
            ttl=dict(type="str", required=False),
            format=dict(type="str", choices=["pem", "der", "pem_bundle"], required=False),
            exclude_cn_from_sans=dict(type="bool", required=False),
            private_key_format=dict(type="str", choices=["der", "pkcs8"], required=False),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ("state", "issued", ["role_name", "common_name"]),
            ("state", "signed", ["role_name", "common_name", "csr"]),
        ],
        mutually_exclusive=[["serial_number", "certificate"]],
        supports_check_mode=True,
    )

    state = module.params["state"]
    if state == "revoked":
        if not module.params.get("serial_number") and not module.params.get("certificate"):
            module.fail_json(msg="state is revoked but all of the following are missing: serial_number, certificate")
        if module.params.get("serial_number") and module.params.get("certificate"):
            module.fail_json(msg="parameters are mutually exclusive: serial_number|certificate")

    client = get_authenticated_client(module)
    pki = VaultPki(client, module.params["engine_mount_point"])

    try:
        if state == "issued":
            ensure_issued(module, pki)
        elif state == "signed":
            ensure_signed(module, pki)
        else:
            ensure_revoked(module, pki)
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except (TypeError, ValueError) as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
