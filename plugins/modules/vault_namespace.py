# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: vault_namespace
short_description: Manage HashiCorp Vault Enterprise namespaces
version_added: 1.2.0
author: Mandar Kulkarni (@mandar242)
description:
  - Create or delete Vault B(Enterprise) namespaces and related operations using C(/sys/namespaces).
  - Open Source Vault does not expose these APIs; operations will fail with an error from Vault.
  - For read-only operations, use the Vault API or a dedicated info module if one is added.
  - Uses the collection's shared connection and authentication options; HTTP calls are handled by the namespaces API on the Vault client.
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
options:
  path:
    description:
      - Namespace path segment for C(/sys/namespaces/:path), relative to the connection C(namespace) header (for example V(engineering) or V(engineering/)).
      - Leading and trailing slashes are stripped before calling Vault; trailing slashes must not be sent on write operations because Vault returns an error.
      - Required when O(state) is V(present), V(metadata), or V(absent).
    type: str
    aliases: [namespace_path]
  state:
    description:
      - Goal state for the namespace or namespace API lock.
      - Multiple C(state) values are available.
      - V(present) ensures the namespace exists (C(POST) if missing).
      - With V(present), O(custom_metadata) is optional; if you set it, Vault only receives it when the namespace is created.
      - If the namespace already exists, the module does not read or update custom metadata (use V(metadata) to change it).
      - V(metadata) is only for custom metadata on a namespace that already exists at O(path); the module fails if that namespace is missing.
      - With V(metadata), O(custom_metadata) is required and is the full desired key/value map (use C({}) for no metadata).
      - The module reads the current custom metadata from Vault and compares it to that map.
      - If they differ, it sends C(PATCH) with C(application/merge-patch+json) once so the stored metadata matches (idempotent).
      - V(locked) calls C(POST /sys/namespaces/api-lock/lock) for the connection namespace, or C(.../lock/:subpath) when O(lock_subpath) is set.
      - V(unlocked) calls C(POST .../unlock) with optional O(unlock_key) (root-equivalent tokens may omit the key per Vault behavior).
      - V(absent) deletes the namespace at O(path); idempotent when already gone.
    type: str
    choices: [present, metadata, locked, unlocked, absent]
    default: present
  custom_metadata:
    description:
      - Key/value pairs (all values must be strings) stored as Vault namespace custom metadata.
      - With O(state=present), optional; when set, used only on C(POST) when creating the namespace.
      - Omit or ignore this option when the namespace already exists and you do not want to change metadata (see V(metadata)).
      - With O(state=metadata), required; declare the complete desired metadata (not a partial update).
      - Use C({}) if you want no custom metadata keys.
      - The module reconciles that map with Vault using V(metadata) state semantics above.
    type: dict
    required: false
  lock_subpath:
    description:
      - Subpath for O(state=locked) or O(state=unlocked) within the connection C(namespace).
      - Leading and trailing slashes are stripped (same as O(path)).
      - Omit to lock or unlock the namespace set by the connection header.
    type: str
    required: false
  unlock_key:
    description:
      - Unlock key from a prior lock response (see RV(unlock_key)). Root-equivalent tokens may omit this per Vault Enterprise behavior.
      - Treated as a sensitive value and not logged by the module (no_log = True).
    type: str
    required: false
"""

EXAMPLES = """
- name: Create a child namespace with metadata
  hashicorp.vault.vault_namespace:
    url: https://vault.example.com:8200
    token: "{{ vault_token }}"
    namespace: parent/
    path: engineering/
    state: present
    custom_metadata:
      team: platform
      environment: prod

- name: Ensure namespace exists without changing metadata on an existing namespace
  hashicorp.vault.vault_namespace:
    url: https://vault.example.com:8200
    path: engineering/
    state: present

- name: Update custom metadata only
  hashicorp.vault.vault_namespace:
    url: https://vault.example.com:8200
    path: engineering/
    state: metadata
    custom_metadata:
      owner: alice

- name: Remove a namespace
  hashicorp.vault.vault_namespace:
    url: https://vault.example.com:8200
    path: engineering/
    state: absent

- name: Lock API for the current connection namespace
  hashicorp.vault.vault_namespace:
    url: https://vault.example.com:8200
    state: locked
  register: ns_lock

- name: Unlock using key from lock response
  hashicorp.vault.vault_namespace:
    url: https://vault.example.com:8200
    state: unlocked
    unlock_key: "{{ ns_lock.unlock_key }}"

- name: Lock a subpath within the current namespace
  hashicorp.vault.vault_namespace:
    url: https://vault.example.com:8200
    namespace: parent/
    state: locked
    lock_subpath: child/
"""

RETURN = """
msg:
  description: Human-readable result message.
  returned: always
  type: str
  sample: "Namespace 'engineering' created successfully"
raw:
  description:
    - Decoded JSON body from Vault (the usual secret-style envelope with C(data), C(auth),
      C(lease_duration), C(request_id), C(mount_type), and so on).
    - For V(present) (create) and V(metadata) (patch), C(data) typically includes C(id), C(path),
      and C(custom_metadata).
    - C(path) is Vault's fully qualified namespace path (parent prefix plus segment), often with a
      trailing slash, not necessarily the same string as the module O(path) argument.
    - For V(locked), C(data) often contains only C(unlock_key). For V(unlocked), C(data) may be V(null) while the envelope is still returned.
    - Not returned for check mode, idempotent V(present)/V(metadata), V(absent) (including successful delete), or read-only outcomes that only set I(msg).
  returned: changed and not check mode
  type: dict
  sample:
    auth: null
    data:
      custom_metadata:
        team: "platform"
        environment: "prod"
      id: "9rvMM"
      path: "parent/ansible-test-ns-example/"
    lease_duration: 0
    lease_id: ""
    mount_type: "ns_system"
    renewable: false
    request_id: "11d31871-1407-5e29-28b7-db9259524c2f"
    warnings: null
    wrap_info: null
unlock_key:
  description:
    - Unlock key returned by Vault when locking the namespace API (duplicated from C(raw.data.unlock_key) when present).
    - Sensitive. Root-equivalent tokens may receive no key; then this key is omitted from the module result.
  returned: changed and state=locked when Vault returns an unlock key
  type: str
  sample: "unlock-key-from-vault"
"""

import copy

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultClient
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)


def _normalize_namespace_path(path):
    """Strip slashes for Vault API paths; Vault rejects writes to paths ending in '/'."""
    if path is None:
        return None
    normalized = path.strip("/")
    return normalized or None


def _normalize_custom_metadata(meta):
    """Return a comparable dict for idempotency; None and {} both become {}."""
    if not meta:
        return {}
    return dict(sorted((str(k), str(v)) for k, v in meta.items()))


def _validate_custom_metadata(module, meta, label):
    if meta is None:
        return None
    if not isinstance(meta, dict):
        module.fail_json(msg=f"{label} must be a dictionary")
    for key, val in meta.items():
        if not isinstance(val, str):
            module.fail_json(msg=f"{label} values must be strings; key {key!r} has type {type(val).__name__}")
    return meta


def ensure_present(module: AnsibleModule, client: VaultClient) -> None:
    path = _normalize_namespace_path(module.params["path"])
    param_meta = module.params.get("custom_metadata")

    try:
        client.namespaces.read_namespace(path)
    except VaultSecretNotFoundError:
        if module.check_mode:
            module.exit_json(
                changed=True,
                msg=f"Would have created namespace {path!r} if not in check mode.",
            )
        if param_meta is None:
            raw = client.namespaces.create_namespace(path, custom_metadata=None)
        else:
            raw = client.namespaces.create_namespace(path, custom_metadata=param_meta)
        module.exit_json(
            changed=True,
            msg=f"Namespace {path!r} created successfully",
            raw=raw or {},
        )

    module.exit_json(
        changed=False,
        msg=f"Namespace {path!r} already exists",
    )


def ensure_metadata(module: AnsibleModule, client: VaultClient) -> None:
    path = _normalize_namespace_path(module.params["path"])
    desired = _normalize_custom_metadata(module.params.get("custom_metadata"))

    try:
        existing = client.namespaces.read_namespace(path)
    except VaultSecretNotFoundError:
        module.fail_json(msg=f"Cannot set metadata on namespace {path!r}: namespace does not exist")

    current = _normalize_custom_metadata(existing.get("custom_metadata"))

    if current == desired:
        module.exit_json(
            changed=False,
            msg=f"Namespace {path!r} custom_metadata already matches desired state",
        )

    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have updated namespace {path!r} custom_metadata if not in check mode.",
        )

    raw = client.namespaces.patch_namespace(path, custom_metadata=desired)
    module.exit_json(
        changed=True,
        msg=f"Namespace {path!r} custom_metadata updated successfully",
        raw=raw or {},
    )


def ensure_absent(module: AnsibleModule, client: VaultClient) -> None:
    path = _normalize_namespace_path(module.params["path"])

    try:
        client.namespaces.read_namespace(path)
    except VaultSecretNotFoundError:
        module.exit_json(
            changed=False,
            msg=f"Namespace {path!r} already absent",
        )

    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have deleted namespace {path!r} if not in check mode.",
        )

    client.namespaces.delete_namespace(path)
    module.exit_json(
        changed=True,
        msg=f"Namespace {path!r} deleted successfully",
    )


def _normalize_lock_subpath(subpath):
    if subpath is None or subpath == "":
        return None
    normalized = subpath.strip("/")
    return normalized or None


def ensure_locked(module: AnsibleModule, client: VaultClient) -> None:
    subpath = _normalize_lock_subpath(module.params.get("lock_subpath"))

    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have locked namespace API (subpath={subpath!r}) if not in check mode.",
        )

    raw = client.namespaces.lock_namespace(subpath=subpath)
    unlock_key = (raw or {}).get("unlock_key") or (raw or {}).get("data", {}).get("unlock_key")
    result = {
        "changed": True,
        "msg": "Namespace API locked successfully",
        "raw": raw or {},
    }
    if unlock_key:
        result["unlock_key"] = unlock_key
    module.exit_json(**result)


def ensure_unlocked(module: AnsibleModule, client: VaultClient) -> None:
    subpath = _normalize_lock_subpath(module.params.get("lock_subpath"))
    unlock_key = module.params.get("unlock_key")

    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have unlocked namespace API (subpath={subpath!r}) if not in check mode.",
        )

    raw = client.namespaces.unlock_namespace(subpath=subpath, unlock_key=unlock_key)
    module.exit_json(
        changed=True,
        msg="Namespace API unlocked successfully",
        raw=raw or {},
    )


def main():

    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            path=dict(type="str", required=False, aliases=["namespace_path"]),
            state=dict(
                type="str",
                choices=["present", "metadata", "locked", "unlocked", "absent"],
                default="present",
            ),
            custom_metadata=dict(type="dict", required=False),
            lock_subpath=dict(type="str", required=False),
            unlock_key=dict(type="str", required=False, no_log=True),
        )
    )

    required_if = [
        ("state", "metadata", ["custom_metadata"]),
        ("state", "present", ["path"]),
        ("state", "metadata", ["path"]),
        ("state", "absent", ["path"]),
    ]

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=required_if,
        supports_check_mode=True,
    )

    state = module.params["state"]
    if state in ("present", "metadata", "absent"):
        if not _normalize_namespace_path(module.params["path"]):
            module.fail_json(msg="path must contain at least one non-slash segment")

    # Get authenticated client
    client = get_authenticated_client(module)

    if module.params.get("custom_metadata") is not None:
        _validate_custom_metadata(module, module.params["custom_metadata"], "custom_metadata")

    try:
        if state == "absent":
            ensure_absent(module, client)
        elif state == "present":
            ensure_present(module, client)
        elif state == "metadata":
            ensure_metadata(module, client)
        elif state == "locked":
            ensure_locked(module, client)
        elif state == "unlocked":
            ensure_unlocked(module, client)
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except TypeError as e:
        module.fail_json(msg=str(e))
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
