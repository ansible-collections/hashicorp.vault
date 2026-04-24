# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
Vault Database Secrets Engine Client Classes.

This module provides client classes for interacting with HashiCorp Vault's
Database Secrets Engine, including connection management and both static
and dynamic role management.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Any, Dict, List, Literal, Optional

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultConfigurationError,
    VaultSecretNotFoundError,
)


def build_config_params(params: Dict[str, Any], param_names: List[str]) -> Dict[str, Any]:
    """
    Build a configuration dictionary from specified parameters, excluding None values.

    This utility function extracts a set of parameters from a source dictionary,
    returning only those parameters that have non-None values. This is useful
    when building configuration payloads for Vault API calls where None values
    should be omitted rather than sent as null.

    Works for both required and optional parameters - any parameter with a non-None
    value will be included in the returned dictionary.

    Args:
        params: Source dictionary containing parameter values (e.g., module.params).
        param_names: List of parameter names to extract from params.

    Returns:
        Dictionary containing only the parameters from param_names that have
        non-None values in params.

    Example:
        >>> module_params = {'db_name': 'mydb', 'max_ttl': 3600, 'default_ttl': None}
        >>> config = build_config_params(module_params, ['db_name', 'max_ttl', 'default_ttl'])
        >>> config
        {'db_name': 'mydb', 'max_ttl': 3600}
    """
    return {k: v for k in param_names if (v := params.get(k)) is not None}


def get_existing_role_or_none(
    role_client, role_name: str, read_method: Literal['read_dynamic_role', 'read_static_role']
) -> Optional[Dict[str, Any]]:
    """
    Attempt to read a role configuration, returning None if it doesn't exist.

    This helper function provides a consistent pattern for checking role existence
    across database role modules (both dynamic and static roles). It abstracts the
    try/except VaultSecretNotFoundError pattern into a reusable utility.

    Args:
        role_client: The role client instance (e.g., VaultDatabaseDynamicRoles or VaultDatabaseStaticRoles).
        role_name: Name of the role to read.
        read_method: Name of the read method to call on the role_client.
                     Must be either 'read_dynamic_role' or 'read_static_role'.

    Returns:
        Role configuration dictionary if the role exists, None if it doesn't exist.

    Raises:
        ValueError: If read_method is not one of the allowed values.

    Example:
        >>> db_roles = VaultDatabaseDynamicRoles(client, mount_path='database')
        >>> existing = get_existing_role_or_none(db_roles, 'my-role', 'read_dynamic_role')
        >>> if existing:
        ...     print(f"Role exists with config: {existing}")
        ... else:
        ...     print("Role does not exist")
    """
    # Allowlist of valid read methods for security
    allowed_methods = {'read_dynamic_role', 'read_static_role'}
    if read_method not in allowed_methods:
        raise ValueError(f"Invalid read_method '{read_method}'. Must be one of: {', '.join(sorted(allowed_methods))}")

    try:
        return getattr(role_client, read_method)(role_name)
    except VaultSecretNotFoundError:
        return None


def normalize_value(value: Any) -> Any:
    """
    Normalize a value for comparison by converting string numbers to integers.

    This utility handles type mismatches between module parameters (always integers
    due to Ansible validation) and Vault API responses (which may return integers
    as strings). This ensures idempotent configuration comparisons.

    Args:
        value: The value to normalize (any type).

    Returns:
        Normalized value - integer if the input is a numeric string, otherwise
        the original value unchanged.

    Example:
        >>> normalize_value("3600")
        3600
        >>> normalize_value(3600)
        3600
        >>> normalize_value("1h")
        '1h'
        >>> normalize_value(None)
        None
    """
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return value


def compare_vault_configs(existing: Dict[str, Any], desired: Dict[str, Any]) -> bool:
    """
    Compare Vault configurations with support for type normalization and nested structures.

    This function performs a semantic comparison of configurations, accounting for:
    - Type differences (e.g., string "3600" vs int 3600 for TTL/rotation values)
    - None values in desired config (treated as "don't care")
    - Nested dict recursion (e.g., credential_config sub-dictionaries)
    - List ordering preservation (e.g., SQL statements where order matters)

    This unified function supports both dynamic and static database roles, as well as
    any other Vault configuration comparisons requiring robust type handling.

    Args:
        existing: The current configuration from Vault.
        desired: The desired configuration from module parameters.

    Returns:
        True if configurations match semantically, False otherwise.

    Example:
        >>> # Type normalization
        >>> existing = {"default_ttl": "3600", "db_name": "mydb"}
        >>> desired = {"default_ttl": 3600, "db_name": "mydb"}
        >>> compare_vault_configs(existing, desired)
        True

        >>> # Nested dict comparison
        >>> existing = {"credential_config": {"key_bits": 2048, "algorithm": "rsa"}}
        >>> desired = {"credential_config": {"key_bits": 2048}}
        >>> compare_vault_configs(existing, desired)
        True
    """
    # If no existing config, it's definitely changed
    if not existing:
        return False

    for key, desired_value in desired.items():
        existing_value = existing.get(key)

        # Skip None values - user doesn't care about this field
        if desired_value is None:
            continue

        # Recursively compare nested dicts (e.g., credential_config)
        if isinstance(desired_value, dict) and isinstance(existing_value, dict):
            if not compare_vault_configs(existing_value, desired_value):
                return False

        # Preserve order for lists (e.g., SQL statements where order matters)
        elif isinstance(desired_value, list) and isinstance(existing_value, list):
            if desired_value != existing_value:
                return False

        # For primitives, normalize types (handle string/int mismatches)
        else:
            if normalize_value(existing_value) != normalize_value(desired_value):
                return False

    return True


class VaultDatabaseParent:
    """
    Base class for Vault Database Secrets Engine client classes.

    Provides common initialization for database-related clients that interact
    with a specific mount path.
    """

    def __init__(self, client, mount_path="database"):
        """
        Initialize the database client.

        Args:
            client (VaultClient): An authenticated instance of the main VaultClient.
            mount_path (str): The mount path of the database secrets engine. Defaults to "database".
        """
        self._client = client
        self._mount_path = (mount_path or "database").strip().strip("/")


class VaultDatabaseConnection(VaultDatabaseParent):
    """
    Handles interactions with Vault Database Secrets Engine connections.
    """

    def _connection_path(self, name: Optional[str] = None) -> str:
        """
        Build the API path for connection operations.

        Args:
            name (str, optional): The connection name. If None, returns the base connections path.
        """
        base = f"v1/{self._mount_path}/config"
        return f"{base}/{name}" if name else base

    def list_connections(self) -> list:
        """
        List all available connections.

        Returns:
            List[str]: A list of connection names. Returns empty list if no connections exist.
        """
        path = self._connection_path()
        try:
            response_data = self._client._make_request("LIST", path)
            connections = response_data.get("data", {}).get("keys", [])
            return connections
        except VaultSecretNotFoundError:
            # Vault returns 404 when no connections exist
            return []

    def read_connection(self, name: str) -> dict:
        """
        Read the configuration settings of a database connection.

        Args:
            name (str): The name of the connection to read.

        Returns:
            dict: The connection configuration data.

        Raises:
            VaultSecretNotFoundError: If the connection doesn't exist.
        """
        path = self._connection_path(name)
        response_data = self._client._make_request("GET", path)
        return response_data.get("data", {})

    def create_or_update_connection(self, name: str, config: dict) -> dict:
        """
        Configure a database connection.

        Args:
            name (str): The name of the database connection
            config (dict): Connection configuration containing:
                - plugin_name (str, required): Database plugin type (e.g., 'postgresql-database-plugin')
                - plugin_version (str, optional): Semantic version of the plugin
                - allowed_roles (list, optional): Roles allowed to use this connection
                - verify_connection (bool, optional): Verify during setup (default: true)
                - root_rotation_statements (list, optional): Statements to execute during root rotation
                - password_policy (str, optional): Password policy to use for the connection
                - Other common fields (reference the individual plugin documentation to determine support)
                  - connection_url (str, optional): Database connection string
                  - username (str, optional): Database username
                  - password (str, optional): Database password
                  - disable_escaping (bool, optional): Disable escaping of special characters in the connection URL (default: false)

        Returns:
            dict: Response from Vault

        Raises:
            TypeError: If config is not a dict, or if config does not contain
                "plugin_name" with a string value.

        Example:
            db.create_or_update_connection(
              name="my-postgres-db",
              config={
                  "plugin_name": "postgresql-database-plugin",
                  "connection_url": "postgresql://{{username}}:{{password}}@localhost:5432/mydb",
                  "username": "vault",
                  "password": "secret",
                  "allowed_roles": ["readonly", "readwrite"]}
              )
        """
        if not isinstance(config, dict):
            raise TypeError("config must be a dict")
        if "plugin_name" not in config:
            raise TypeError('config must contain "plugin_name"')
        if not isinstance(config["plugin_name"], str):
            raise TypeError('config["plugin_name"] must be a str')

        path = self._connection_path(name)
        return self._client._make_request("POST", path, json=config)

    def delete_connection(self, name: str) -> None:
        """
        Delete a database connection.

        Args:
            name (str): The name of the connection to delete.

        Returns:
            None
        """
        path = self._connection_path(name)
        self._client._make_request("DELETE", path)

    def reset_connection(self, name: str) -> None:
        """
        Reset a database connection by closing the connection and its underlying plugin,
        then restarting it.

        Args:
            name (str): The name of the connection to reset.

        Returns:
            None
        """
        path = f"v1/{self._mount_path}/reset/{name}"
        self._client._make_request("POST", path, json={})

    def rotate_credentials(self, name: str, credential_type: str) -> None:
        """
        Trigger immediate credential rotation via the Vault Database Secrets Engine API.

        Sends POST to 'v1/{mount}/rotate-root/{name}' when 'credential_type' is 'root',
        or 'v1/{mount}/rotate-role/{name}' when it is 'role' (static role password rotation).

        Args:
            name (str): Database connection name (for 'root') or static role name (for 'role')
            credential_type (str): 'root' or 'role'

        Returns:
            None
        """
        credential_type_options = ('root', 'role')
        if credential_type not in credential_type_options:
            raise VaultConfigurationError(
                f"Unexpected type used to rotate credential {credential_type!r}, should be one of {credential_type_options}"
            )
        path = f"v1/{self._mount_path}/rotate-{credential_type}/{name}"
        self._client._make_request("POST", path, json={})


class VaultDatabaseStaticRoles(VaultDatabaseParent):
    """
    Handles interactions with Vault Database Secrets Engine static roles.
    """

    def _static_role_path(self, name: Optional[str] = None) -> str:
        """
        Build the API path for static role operations.

        Args:
            name (str, optional): The role name. If None, returns the base roles path.

        Returns:
            str: The full API path for the static role operation.
        """
        base = f"v1/{self._mount_path}/static-roles"
        return f"{base}/{name}" if name else base

    def list_static_roles(self, read_snapshot_id: Optional[str] = None) -> list:
        """
        List all available static roles.

        Args:
            read_snapshot_id (str, optional): ID of a snapshot previously loaded into Vault
                that contains the roles at the provided path

        Returns:
            List[str]: A list of static role names. Returns empty list if no static roles exist.
        """
        path = self._static_role_path()
        params = {}
        if read_snapshot_id is not None:
            params["read_snapshot_id"] = read_snapshot_id

        try:
            response_data = self._client._make_request("LIST", path, params=params)
            roles = response_data.get("data", {}).get("keys", [])
            return roles
        except VaultSecretNotFoundError:
            # Vault returns 404 when no static roles exist
            return []

    def read_static_role(self, name: str, read_snapshot_id: Optional[str] = None) -> dict:
        """
        Read the configuration of a database static role.

        Args:
            name (str): The name of the static role to read
            read_snapshot_id (str, optional): ID of a snapshot previously loaded into Vault
                that contains the role at the provided path

        Returns:
            dict: The static role configuration data

        Raises:
            VaultSecretNotFoundError: If the static role doesn't exist
        """
        path = self._static_role_path(name)
        params = {}
        if read_snapshot_id is not None:
            params["read_snapshot_id"] = read_snapshot_id

        response_data = self._client._make_request("GET", path, params=params)
        return response_data.get("data", {})

    def create_or_update_static_role(self, name: str, config: dict) -> dict:
        """
        Configure a database static role.

        Args:
            name (str): The name of the static role
            config (dict): Static role configuration containing:
                - username (str, required): Database username for this role
                - db_name (str, required): Name of the database connection to use
                - Additional optional fields (see Vault database secrets engine documentation)

        Returns:
            dict: Response from Vault

        Raises:
            TypeError: If config is not a dict

        Example:
            db.create_or_update_static_role(
                name="my-static-role",
                config={
                    "db_name": "my-postgres-db",
                    "username": "vault-user",
                    "rotation_period": "86400s"
                }
            )
        """
        if not isinstance(config, dict):
            raise TypeError("config must be a dict")

        path = self._static_role_path(name)
        return self._client._make_request("POST", path, json=config)

    def delete_static_role(self, name: str) -> None:
        """
        Delete a database static role.

        Args:
            name (str): The name of the static role to delete.

        Returns:
            None
        """
        path = self._static_role_path(name)
        self._client._make_request("DELETE", path)

    def get_static_role_credentials(self, name: str, read_snapshot_id: Optional[str] = None) -> dict:
        """
        Retrieve the current credentials for a database static role.

        Args:
            name (str): The name of the static role
            read_snapshot_id (str, optional): ID of a snapshot previously loaded into Vault
                that contains the credentials at the provided path

        Returns:
            dict: The credentials data containing username, password, and other metadata

        Raises:
            VaultSecretNotFoundError: If the static role doesn't exist
        """
        path = f"v1/{self._mount_path}/static-creds/{name}"
        params = {}
        if read_snapshot_id is not None:
            params["read_snapshot_id"] = read_snapshot_id

        response_data = self._client._make_request("GET", path, params=params)
        return response_data.get("data", {})


class VaultDatabaseDynamicRoles(VaultDatabaseParent):
    """
    Handles interactions with Vault Database Secrets Engine dynamic roles.

    Dynamic roles generate database credentials on-demand with configurable TTLs.
    """

    def _role_path(self, name: Optional[str] = None) -> str:
        """
        Build the API path for dynamic role operations.

        Args:
            name (str, optional): The role name. If None, returns the base roles path.

        Returns:
            str: The full API path for the role operation.
        """
        base = f"v1/{self._mount_path}/roles"
        return f"{base}/{name}" if name else base

    def list_dynamic_roles(self) -> List[str]:
        """
        List all dynamic role names.

        Returns:
            List[str]: A list of dynamic role names. Returns empty list if no roles exist.

        Example:
            roles = db.list_dynamic_roles()
            # Returns: ["readonly", "readwrite"]
        """
        path = self._role_path()
        try:
            response_data = self._client._make_request("LIST", path)
            roles = response_data.get("data", {}).get("keys", [])
            return roles
        except VaultSecretNotFoundError:
            # Vault returns 404 when no roles exist
            return []

    def read_dynamic_role(self, name: str) -> Dict[str, Any]:
        """
        Read the configuration of a dynamic role.

        Args:
            name (str): The name of the dynamic role to read.

        Returns:
            Dict[str, Any]: The dynamic role configuration data.

        Raises:
            VaultSecretNotFoundError: If the role doesn't exist.

        Example:
            role_config = db.read_dynamic_role("readonly")
            # Returns: {
            #     "db_name": "my-postgres-db",
            #     "creation_statements": ["CREATE ROLE ..."],
            #     "default_ttl": 3600,
            #     "max_ttl": 86400
            # }
        """
        path = self._role_path(name)
        response_data = self._client._make_request("GET", path)
        return response_data.get("data", {})

    def create_or_update_dynamic_role(self, name: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create or update a dynamic role configuration.

        Args:
            name (str): The name of the dynamic role.
            config (Dict[str, Any]): Role configuration containing:
                - db_name (str, required): Name of the database connection to use
                - creation_statements (list, required): SQL statements to create credentials
                - default_ttl (int, optional): Default TTL for credentials in seconds
                - max_ttl (int, optional): Maximum TTL for credentials in seconds
                - revocation_statements (list, optional): SQL statements to revoke credentials
                - rollback_statements (list, optional): SQL statements to rollback partial creation
                - renew_statements (list, optional): SQL statements executed during credential renewal
                - credential_type (str, optional): Type of credential (e.g., "password", "rsa_private_key")
                - credential_config (dict, optional): Additional credential configuration

        Returns:
            Dict[str, Any]: Response from Vault (typically empty dict on success).

        Raises:
            TypeError: If config is not a dict.
            ValueError: If a required field is missing/invalid.

        Example:
            db.create_or_update_dynamic_role(
                name="readonly",
                config={
                    "db_name": "my-postgres-db",
                    "creation_statements": [
                        "CREATE ROLE '{{name}}' WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
                        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO '{{name}}';"
                    ],
                    "default_ttl": 3600,
                    "max_ttl": 86400
                }
            )
        """
        if not isinstance(name, str):
            raise TypeError("name must be a str")
        if not name:
            raise ValueError("name must be a non-empty string")
        if not isinstance(config, dict):
            raise TypeError("config must be a dict")
        if "db_name" not in config:
            raise ValueError('config must contain "db_name"')
        if not isinstance(config["db_name"], str):
            raise TypeError('config["db_name"] must be a str')
        if "creation_statements" not in config:
            raise ValueError('config must contain "creation_statements"')

        statements = config["creation_statements"]
        if not isinstance(statements, list) or not statements:
            raise ValueError('config["creation_statements"] must be a non-empty list')

        path = self._role_path(name)
        return self._client._make_request("POST", path, json=config)

    def delete_dynamic_role(self, name: str) -> None:
        """
        Delete a dynamic role.

        Args:
            name (str): The name of the dynamic role to delete.

        Returns:
            None

        Example:
            db.delete_dynamic_role("readonly")
        """
        path = self._role_path(name)
        self._client._make_request("DELETE", path)

    def generate_dynamic_role_credentials(self, name: str) -> Dict[str, Any]:
        """
        Generate new credentials for a database dynamic role.

        Each call to this method generates a new set of database credentials
        with a new lease. The credentials are temporary and will be automatically
        revoked when the lease expires.

        Args:
            name (str): The name of the dynamic role to generate credentials for.

        Returns:
            Dict[str, Any]: The generated credentials and lease information containing:
                - username (str): The generated database username
                - password (str): The generated database password
                - lease_id (str): The lease ID for these credentials
                - lease_duration (int): TTL in seconds before credentials expire
                - renewable (bool): Whether the lease can be renewed

        Raises:
            VaultSecretNotFoundError: If the dynamic role doesn't exist.

        Example:
            creds = db.generate_dynamic_role_credentials("readonly")
            # Returns: {
            #     "username": "v-token-readonly-abc123",
            #     "password": "A1a-randompassword",
            #     "lease_id": "database/creds/readonly/abc123",
            #     "lease_duration": 3600,
            #     "renewable": True
            # }
        """
        path = f"v1/{self._mount_path}/creds/{name}"
        response_data = self._client._make_request("GET", path)
        out = dict(response_data.get("data", {}))
        # Vault returns credentials under 'data' but lease info at the top level.
        # Merge lease fields into the output for easier access to credential lifecycle info.
        for key in ("lease_id", "lease_duration", "renewable"):
            if key in response_data:
                out[key] = response_data[key]
        return out


class Database:
    """A container class for database secrets engine clients.

    This class groups related database secrets engine clients (connections, static_roles,
    and dynamic_roles) that share the same mount path. It provides a convenient way to
    manage connections and roles for a specific database secrets engine mount.

    Examples:
        # Default mount path ("database")
        db = Database(client)
        db.connections.list_connections()
        db.static_roles.list_static_roles()
        db.dynamic_roles.list_dynamic_roles()

        # Custom mount path
        prod_db = Database(client, mount_path="postgres-prod")
        dev_db = Database(client, mount_path="postgres-dev")
        dev_db.connections.list_connections()
        prod_db.static_roles.list_static_roles()
        dev_db.dynamic_roles.list_dynamic_roles()

        # Or use individual classes directly
        from ansible_collections.hashicorp.vault.plugins.module_utils.vault_database import (
            VaultDatabaseConnection,
            VaultDatabaseStaticRoles,
            VaultDatabaseDynamicRoles
        )
        connections = VaultDatabaseConnection(client, "postgres-prod")
        static_roles = VaultDatabaseStaticRoles(client, "postgres-prod")
        dynamic_roles = VaultDatabaseDynamicRoles(client, "postgres-prod")
    """

    def __init__(self, client, mount_path="database"):
        """
        Initializes the Database container.

        Args:
            client (VaultClient): An authenticated instance of the main VaultClient.
            mount_path (str): The mount path of the database secrets engine. Defaults to "database".
        """
        self.connections = VaultDatabaseConnection(client, mount_path)
        self.static_roles = VaultDatabaseStaticRoles(client, mount_path)
        self.dynamic_roles = VaultDatabaseDynamicRoles(client, mount_path)


def get_static_role(static_role_client: "VaultDatabaseStaticRoles", name: str) -> Dict[str, Any]:
    """
    Get a database static role configuration, returning an empty dict if not found.

    This is a utility function to avoid repetitive try/except blocks when
    reading static roles where a "not found" condition is acceptable.

    Args:
        static_role_client: VaultDatabaseStaticRoles instance
        name: The name of the static role to read

    Returns:
        dict: The static role configuration, or {} if not found
    """
    try:
        return static_role_client.read_static_role(name)
    except VaultSecretNotFoundError:
        return {}


__all__ = [
    'VaultDatabaseParent',
    'Database',
    'VaultDatabaseConnection',
    'VaultDatabaseStaticRoles',
    'VaultDatabaseDynamicRoles',
    'build_config_params',
    'get_existing_role_or_none',
    'get_static_role',
    'normalize_value',
    'compare_vault_configs',
]
