# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

DOCUMENTATION = """
---
module: database_static_role
short_description: Manage database static roles in HashiCorp Vault
version_added: 1.2.0
author: Hannah DeFazio (@hdefazio)
description:
  - This module allows you to create, update, and delete database static roles in HashiCorp Vault.
  - Use O(state=present) to create or update a static role.
  - Use O(state=absent) to delete a static role.
options:
  state:
    description:
      - Goal state for the database static role.
      - Use V(present) to create or update the static role.
      - Use V(absent) to delete the static role.
    choices: [present, absent]
    default: present
    type: str
  database_mount_path:
    description: Database secret engine mount path.
    type: str
    default: database
    aliases: [vault_database_mount_path]
  name:
    description: The name of the database static role.
    type: str
    required: true
  db_name:
    description:
      - The name of the database connection to use for this static role.
      - This references a connection created by the M(hashicorp.vault.database_connection) module.
      - Required when O(state=present).
    type: str
  username:
    description:
      - The database username that Vault will manage and rotate credentials for.
      - This must be an existing user in the database.
      - Required when O(state=present).
    type: str
  password:
    description:
      - The password corresponding to the username in the database.
      - Required when using the Rootless Password Rotation workflow or Skip Automatic Import Rotation workflow for static roles.
      - Only available in Vault Enterprise.
    type: str
  rotation_period:
    description:
      - Specifies the amount of time Vault should wait before rotating the password.
      - The minimum rotation period is 5 seconds.
      - Can be specified as an integer (seconds) or a duration string (e.g., "86400s", "24h").
      - Duration strings are normalized to integer seconds before being sent to Vault.
      - See U(https://developer.hashicorp.com/vault/docs/concepts/duration-format) for duration format details.
      - Required when O(state=present) unless O(rotation_schedule) is provided.
      - Mutually exclusive with O(rotation_schedule).
    type: raw
  rotation_schedule:
    description:
      - A cron-style schedule for password rotation (e.g., "0 0 * * *" for daily at midnight).
      - Vault interprets the schedule in UTC.
      - Required when O(state=present) unless O(rotation_period) is provided.
      - Mutually exclusive with O(rotation_period).
    type: str
  rotation_window:
    description:
      - Specifies the amount of time in which the rotation is allowed to occur starting from a given O(rotation_schedule).
      - If the credential is not rotated during this window, it will not be rotated until the next scheduled rotation.
      - The minimum is 1 hour.
      - Can be specified as an integer (seconds) or a duration string (e.g., "3600s", "1h").
      - Duration strings are normalized to integer seconds before being sent to Vault.
      - See U(https://developer.hashicorp.com/vault/docs/concepts/duration-format) for duration format details.
      - Optional when O(rotation_schedule) is set and disallowed when O(rotation_period) is set.
    type: raw
  rotation_statements:
    description:
      - Specifies the database statements to be executed to rotate the password.
      - If not specified, Vault uses the default rotation statements for the database plugin.
      - Not every plugin type supports this functionality.
    type: list
    elements: str
  skip_import_rotation:
    description:
      - When set to V(true), skips the automatic password rotation that normally occurs when creating a static role.
      - This allows testing configuration without requiring an active database connection.
      - The password will still be rotated on the first scheduled rotation or manual rotation request.
      - Only available in Vault Enterprise.
    type: bool
    default: false
  credential_type:
    description:
      - Specifies the type of credential that will be generated for the role.
    type: str
    default: password
    choices: [password, rsa_private_key, client_certificate]
  credential_config:
    description:
      - Specifies the configuration for the given O(credential_type).
      - This should be a dictionary of options required by the specific credential type.
    type: dict
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
"""

EXAMPLES = """
- name: Create a database static role with rotation period
  hashicorp.vault.database_static_role:
    name: my-static-role
    state: present
    db_name: my-postgres-db
    username: vault-user
    rotation_period: "24h"

- name: Create a database static role with rotation schedule
  hashicorp.vault.database_static_role:
    name: my-static-role
    state: present
    db_name: my-postgres-db
    username: vault-user
    rotation_schedule: "0 0 * * *"
    rotation_window: "3h"

- name: Create a database static role with custom rotation statements
  hashicorp.vault.database_static_role:
    name: my-static-role
    state: present
    db_name: my-mysql-db
    username: app_user
    rotation_period: "1h"
    rotation_statements:
      - "ALTER USER '{{name}}'@'%' IDENTIFIED BY '{{password}}';"

- name: Create a static role with RSA private key credential type
  hashicorp.vault.database_static_role:
    name: my-rsa-role
    state: present
    db_name: my-postgres-db
    username: rsa-user
    rotation_period: "24h"
    credential_type: rsa_private_key
    credential_config:
      key_bits: 2048

- name: Delete a database static role
  hashicorp.vault.database_static_role:
    name: my-static-role
    state: absent
"""

RETURN = """
msg:
  description: A message describing the result of the operation.
  returned: always
  type: str
  sample: "Static role 'my-static-role' created successfully"
raw:
  description: The configuration settings for the database static role created/updated.
  returned: when O(state=present)
  type: dict
  sample:
    {
        "db_name": "my-postgres-db",
        "username": "vault-user",
        "rotation_period": 86400,
        "rotation_statements": []
    }
"""


__metaclass__ = type  # pylint: disable=C0103

import copy
import re

from ansible.module_utils.basic import AnsibleModule  # type: ignore

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_auth_utils import (
    get_authenticated_client,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_database import (
    VaultDatabaseStaticRoles,
    build_config_params,
    compare_vault_configs,
    get_static_role,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)


def _validate_duration_format(value, param_name):
    """
    Validate that a duration parameter is in a valid format.

    Vault accepts durations as either:
    - An integer (interpreted as seconds)
    - A string with a valid duration suffix (e.g., "72h", "24h", "5m", "30s")

    Valid duration units: ns, us/µs, ms, s, m, h

    See: https://developer.hashicorp.com/vault/docs/concepts/duration-format

    Args:
        value: The value to validate
        param_name: The name of the parameter (for error messages)

    Raises:
        ValueError: If the value is not a valid duration format

    Examples:
        _validate_duration_format(86400, "rotation_period")  # Valid: int
        _validate_duration_format("24h", "rotation_period")  # Valid: duration string
        _validate_duration_format("invalid", "rotation_period")  # Raises ValueError
        _validate_duration_format([1, 2], "rotation_period")  # Raises ValueError
    """
    # Reject booleans explicitly (bool is a subclass of int in Python)
    if isinstance(value, bool):
        raise ValueError(
            f"{param_name} must be an integer (seconds) or a duration string (e.g., '72h', '5m', '30s'). "
            f"Got type bool: {value!r}"
        )

    # Check if it's a positive integer
    if isinstance(value, int):
        if value <= 0:
            raise ValueError(
                f"{param_name} must be a positive integer or a valid duration string. " f"Got integer value: {value}"
            )
        return

    # Check if it's a string with valid duration format
    if isinstance(value, str):
        # Vault duration format: optional negative sign, number, and unit suffix
        # Valid units: ns, us (or µs), ms, s, m, h
        duration_pattern = r'^-?(\d+(\.\d+)?)(ns|us|µs|ms|s|m|h)$'
        if not re.match(duration_pattern, value):
            raise ValueError(
                f"{param_name} must be a valid duration string (e.g., '72h', '5m', '30s') or an integer (seconds). "
                f"Valid units are: ns, us/µs, ms, s, m, h. Got: {value!r}"
            )
        return

    # If it's neither int nor string, raise an error
    raise ValueError(
        f"{param_name} must be an integer (seconds) or a duration string (e.g., '72h', '5m', '30s'). "
        f"Got type {value.__class__.__name__}: {value!r}"
    )


def _normalize_duration_to_seconds(value):
    """
    Convert a duration value to integer seconds for comparison with Vault's normalized format.

    Vault stores durations as integers (seconds), but accepts string formats like "24h" or "86400s".
    This function normalizes user input to match Vault's storage format.

    Args:
        value: Duration as integer (seconds) or string with unit suffix

    Returns:
        int: Duration in seconds

    Raises:
        TypeError: If value is not an int or str

    Examples:
        _normalize_duration_to_seconds(86400) → 86400
        _normalize_duration_to_seconds("24h") → 86400
        _normalize_duration_to_seconds("86400s") → 86400
        _normalize_duration_to_seconds("1.5h") → 5400
    """
    if isinstance(value, int):
        return value

    if isinstance(value, str):
        # Parse duration string: number + unit
        duration_pattern = r'^-?(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)$'
        match = re.match(duration_pattern, value)
        if not match:
            # Should not happen if validation ran first, but fail fast if it does
            raise TypeError(f"Invalid duration format: {value!r} (validation should have caught this)")

        number_str, unit = match.groups()
        number = float(number_str)

        # Convert to seconds based on unit
        unit_to_seconds = {
            'ns': 1e-9,
            'us': 1e-6,
            'µs': 1e-6,
            'ms': 1e-3,
            's': 1,
            'm': 60,
            'h': 3600,
        }

        seconds = number * unit_to_seconds[unit]
        # Vault stores as integer seconds, round to avoid sub-second values becoming 0
        return int(round(seconds))

    # If not int or string, this is a programming error
    raise TypeError(f"Duration must be int or str, got {value.__class__.__name__}: {value!r}")


def _validate_rotation_params(module):
    """
    Validate rotation-related parameters for database static roles.

    Ensures:
    - At least one of rotation_period or rotation_schedule is provided
    - Duration formats are valid

    Note: Mutual exclusivity and required_by constraints are handled by
    AnsibleModule's built-in validation (mutually_exclusive, required_by).

    Args:
        module: AnsibleModule instance

    Raises:
        Calls module.fail_json() if validation fails
    """
    rotation_period = module.params.get("rotation_period")
    rotation_schedule = module.params.get("rotation_schedule")
    rotation_window = module.params.get("rotation_window")

    # At least one of rotation_period or rotation_schedule is required
    if not rotation_period and not rotation_schedule:
        module.fail_json(
            msg=(
                "One of rotation_period or rotation_schedule is required when state=present. "
                f"Got rotation_period={rotation_period}, rotation_schedule={rotation_schedule}"
            )
        )

    # Validate duration formats
    try:
        if rotation_period is not None:
            _validate_duration_format(rotation_period, "rotation_period")
        if rotation_window is not None:
            _validate_duration_format(rotation_window, "rotation_window")
    except ValueError as e:
        module.fail_json(msg=str(e))


def ensure_present(module: AnsibleModule, db_static_role_client: VaultDatabaseStaticRoles) -> None:
    """Create or update a database static role."""
    name = module.params.get("name")

    _validate_rotation_params(module)

    # Build configuration from module parameters, filtering out None values
    config_params = (
        "username",
        "db_name",
        "password",
        "rotation_period",
        "rotation_schedule",
        "rotation_window",
        "rotation_statements",
        "skip_import_rotation",
        "credential_type",
        "credential_config",
    )
    config = build_config_params(module.params, config_params)

    # Normalize duration fields in config to match Vault's format (integer seconds)
    # This allows accurate comparison and avoids false positives like "24h" != 86400
    if 'rotation_period' in config:
        config['rotation_period'] = _normalize_duration_to_seconds(config['rotation_period'])
    if 'rotation_window' in config:
        config['rotation_window'] = _normalize_duration_to_seconds(config['rotation_window'])

    # Read existing role configuration from Vault for comparison
    existing = get_static_role(db_static_role_client, name)

    # Determine if update is needed by comparing normalized config with existing state
    needs_update = not compare_vault_configs(existing, config)

    # If role exists with matching config, exit early
    if existing and not needs_update:
        module.exit_json(
            changed=False, msg=f"Database static role {name!r} already exists with the same data.", raw=existing
        )

    # Determine operation type for messaging
    operation = "updated" if existing else "created"

    # In check mode, report what would happen without making changes
    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have {operation} database static role '{name}' if not in check mode",
            raw=existing or {},
        )

    # Create or update the static role
    db_static_role_client.create_or_update_static_role(name, config)

    # Read back the result
    result = db_static_role_client.read_static_role(name)

    module.exit_json(changed=True, msg=f"Database static role {name!r} {operation} successfully", raw=result)


def ensure_absent(module: AnsibleModule, db_static_role_client: VaultDatabaseStaticRoles) -> None:
    """Delete a database static role."""
    name = module.params.get("name")

    # Check if the static role exists before attempting deletion
    existing = get_static_role(db_static_role_client, name)
    if not existing:
        module.exit_json(
            changed=False,
            msg=f"Database static role {name!r} is already absent",
        )

    # In check mode, report what would happen without making changes
    if module.check_mode:
        module.exit_json(
            changed=True,
            msg=f"Would have deleted database static role {name!r} if not in check mode.",
        )

    # Actually delete the static role (404 if removed between read and delete)
    try:
        db_static_role_client.delete_static_role(name)
    except VaultSecretNotFoundError:
        module.exit_json(
            changed=False,
            msg=(
                f"Database static role {name!r} was present when read but Vault returned "
                "'not found' on delete (likely removed concurrently); treating as absent."
            ),
        )
    module.exit_json(
        changed=True,
        msg=f"Database static role {name!r} deleted successfully",
    )


def main() -> None:
    """Entry point for module execution"""
    argument_spec = copy.deepcopy(AUTH_ARG_SPEC)
    argument_spec.update(
        dict(
            state=dict(default="present", choices=["present", "absent"]),
            database_mount_path=dict(default="database", aliases=["vault_database_mount_path"]),
            name=dict(required=True),
            db_name=dict(),
            username=dict(),
            password=dict(no_log=True),
            rotation_period=dict(type="raw"),
            rotation_schedule=dict(type="str"),
            rotation_window=dict(type="raw"),
            rotation_statements=dict(type="list", elements="str"),
            skip_import_rotation=dict(type="bool", default=False),
            credential_type=dict(
                type="str", default="password", choices=["password", "rsa_private_key", "client_certificate"]
            ),
            credential_config=dict(type="dict", no_log=True),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=(("state", "present", ["db_name", "username"]),),
        mutually_exclusive=[
            ["rotation_period", "rotation_schedule"],
            ["rotation_period", "rotation_window"],
        ],
        required_by={"rotation_window": "rotation_schedule"},
        supports_check_mode=True,
    )

    client = get_authenticated_client(module)

    mount_path = module.params.get("database_mount_path")
    state = module.params.get("state")

    try:
        db_static_role_client = VaultDatabaseStaticRoles(client, mount_path=mount_path)

        if state == "present":
            ensure_present(module, db_static_role_client)
        elif state == "absent":
            ensure_absent(module, db_static_role_client)
    except VaultPermissionError as e:
        module.fail_json(msg=f"Permission denied: {e}")
    except VaultApiError as e:
        module.fail_json(msg=f"Vault API error: {e}")
    except Exception as e:
        module.fail_json(msg=f"Operation failed: {e}")


if __name__ == "__main__":
    main()
