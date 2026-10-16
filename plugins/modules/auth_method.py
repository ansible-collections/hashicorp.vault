# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: auth_method
short_description: Manage HashiCorp Vault auth method mounts
version_added: 2.0.0
author: Ansible (@ansible)
description:
  - Enable, tune, or disable an auth method at C(sys/auth/:path).
  - A second run leaves an existing mount of the same type in place. Posting an enable request for a mount that is already enabled returns an error from Vault, so this module reads C(sys/auth) first.
  - O(type) and O(local) cannot be changed on an existing mount. Disable it with O(state=absent) and enable it again. This matches vault_auth_backend, where both fields force a new resource.
  - O(path) defaults to O(type). A trailing slash is ignored.
  - O(description) and O(tune) are updated through the mount tune endpoint.
  - O(identity_token_key) is sent when the mount is enabled. On an existing mount it is updated only when Vault returns a different value.
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
options:
  path:
    description:
      - Path where the auth method is mounted.
      - Defaults to O(type), matching vault_auth_backend.
    type: str
  type:
    description:
      - Auth method type, for example V(userpass) or V(tpm).
      - Required when O(state=present).
    type: str
  description:
    description:
      - Human-readable description of the mount.
    type: str
  local:
    description:
      - Whether the auth method is local to the cluster.
      - Cannot be changed after the mount is enabled.
    type: bool
  identity_token_key:
    description:
      - Key used to sign identity tokens for this mount.
      - Requires Vault Enterprise 1.17 or later.
    type: str
  tune:
    description:
      - Mount tune settings written to C(sys/mounts/auth/:path/tune).
      - Lease TTLs are integer seconds, or a duration of the form V(30s), V(5m), or V(1h).
    type: dict
    suboptions:
      default_lease_ttl:
        description:
          - Default time-to-live for leases on this mount.
        type: str
      max_lease_ttl:
        description:
          - Maximum time-to-live for leases on this mount.
        type: str
      audit_non_hmac_request_keys:
        description:
          - Request data keys that audit devices will not HMAC.
        type: list
        elements: str
      audit_non_hmac_response_keys:
        description:
          - Response data keys that audit devices will not HMAC.
        type: list
        elements: str
      listing_visibility:
        description:
          - Whether the mount appears in the unauthenticated UI listing.
        type: str
        choices: [unauth, hidden]
      passthrough_request_headers:
        description:
          - Headers passed through to the auth method.
        type: list
        elements: str
      allowed_response_headers:
        description:
          - Response headers a plugin is allowed to include.
        type: list
        elements: str
      token_type:
        description:
          - Type of token the mount should return.
        type: str
        choices: [default-service, default-batch, service, batch]
  state:
    description:
      - V(present) enables the mount or tunes it when description or tune settings differ.
      - V(absent) disables the mount. Disabling a missing mount succeeds with C(changed=false).
    type: str
    choices: [present, absent]
    default: present
"""

EXAMPLES = """
- name: Enable the TPM auth method
  hashicorp.vault.auth_method:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    type: tpm
    path: tpm

- name: Leave an existing TPM mount unchanged
  hashicorp.vault.auth_method:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    type: tpm
    path: tpm

- name: Tune the userpass mount
  hashicorp.vault.auth_method:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    type: userpass
    path: userpass
    description: Human login
    tune:
      default_lease_ttl: "1h"
      max_lease_ttl: "24h"
      token_type: batch

- name: Disable an auth method
  hashicorp.vault.auth_method:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    path: userpass
    state: absent
"""

RETURN = """
msg:
  description: Human-readable result message.
  returned: always
  type: str
data:
  description: Mount path, type, description, local flag, and accessor.
  returned: when the mount exists or was just enabled
  type: dict
  contains:
    path:
      description: Mount path without a trailing slash.
      type: str
    type:
      description: Auth method type.
      type: str
    description:
      description: Mount description.
      type: str
    local:
      description: Whether the mount is local.
      type: bool
    accessor:
      description: Accessor Vault assigned to the mount.
      type: str
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_methods import (
    plan_auth_change,
    resolve_auth_path,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultConfigurationError,
    VaultPermissionError,
)


def _mount_data(mount: dict) -> dict:
    if not mount:
        return {}
    return {
        "path": mount.get("path"),
        "type": mount.get("type"),
        "description": mount.get("description") or "",
        "local": bool(mount.get("local")),
        "accessor": mount.get("accessor"),
    }


def ensure_auth_present(module: AnsibleModule, auth) -> None:
    params = module.params
    path = resolve_auth_path(params.get("path"), params.get("type"))
    desired = {
        "path": path,
        "type": params["type"],
        "description": params.get("description"),
        "local": params.get("local"),
        "identity_token_key": params.get("identity_token_key"),
        "tune": params.get("tune"),
    }
    existing = auth.read_auth_method(path)
    current_tune = None
    tune_requested = bool(params.get("description") or params.get("identity_token_key") or params.get("tune"))
    if existing is not None and tune_requested:
        current_tune = auth.read_auth_tune(path)

    plan = plan_auth_change(existing, desired, current_tune)
    if plan["action"] == "unchanged":
        module.exit_json(
            changed=False,
            msg=f"Auth method {path!r} is already enabled with type {params['type']!r}",
            data=_mount_data(existing),
        )

    if module.check_mode:
        verb = "enabled" if plan["action"] == "enable" else "tuned"
        module.exit_json(
            changed=True,
            msg=f"Would have {verb} auth method {path!r} if not in check mode.",
            data=_mount_data(existing),
        )

    if plan["action"] == "enable":
        auth.enable_auth_method(
            path,
            params["type"],
            description=params.get("description"),
            local=params.get("local"),
            identity_token_key=params.get("identity_token_key"),
        )
        action = "enabled"
    else:
        action = "tuned"

    if plan["tune"]:
        auth.tune_auth_method(path, plan["tune"])

    current = auth.read_auth_method(path) or {"path": path, "type": params["type"]}
    module.exit_json(
        changed=True,
        msg=f"Auth method {path!r} {action} successfully",
        data=_mount_data(current),
    )


def ensure_auth_absent(module: AnsibleModule, auth) -> None:
    path = resolve_auth_path(module.params.get("path"), module.params.get("type"))
    existing = auth.read_auth_method(path)
    if existing is None:
        module.exit_json(changed=False, msg=f"Auth method {path!r} already absent")

    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have disabled auth method {path!r} if not in check mode.",
            data=_mount_data(existing),
        )

    auth.disable_auth_method(path)
    module.exit_json(changed=True, msg=f"Auth method {path!r} disabled successfully")


def main():
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            path=dict(type="str"),
            type=dict(type="str"),
            description=dict(type="str"),
            local=dict(type="bool"),
            identity_token_key=dict(type="str", no_log=False),
            tune=dict(
                type="dict",
                options=dict(
                    default_lease_ttl=dict(type="str"),
                    max_lease_ttl=dict(type="str"),
                    audit_non_hmac_request_keys=dict(type="list", elements="str", no_log=False),
                    audit_non_hmac_response_keys=dict(type="list", elements="str", no_log=False),
                    listing_visibility=dict(type="str", choices=["unauth", "hidden"]),
                    passthrough_request_headers=dict(type="list", elements="str", no_log=False),
                    allowed_response_headers=dict(type="list", elements="str"),
                    token_type=dict(type="str", choices=["default-service", "default-batch", "service", "batch"]),
                ),
            ),
            state=dict(type="str", choices=["present", "absent"], default="present"),
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[("state", "present", ["type"])],
        supports_check_mode=True,
    )

    client = get_authenticated_client(module)
    try:
        if module.params["state"] == "present":
            ensure_auth_present(module, client.auth_methods)
        else:
            ensure_auth_absent(module, client.auth_methods)
    except VaultPermissionError as exc:
        module.fail_json(msg=f"Permission denied: {exc}")
    except VaultConfigurationError as exc:
        module.fail_json(msg=str(exc))
    except VaultApiError as exc:
        module.fail_json(msg=f"Vault API error: {exc}")
    except Exception as exc:
        module.fail_json(msg=f"Operation failed: {exc}")


if __name__ == "__main__":
    main()
