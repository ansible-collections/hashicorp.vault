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

from typing import Any, Dict, List, Optional

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultConfigurationError,
    VaultSecretNotFoundError,
)


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
        Reset a database connection by closing the connection and its underlying plugin,
        then restarting it.

        Args:
            name (str): The identifier for the database connection (for root user rotation) or the static role to trigger
                        a password rotation for.
            type (str): Whether to rotate root or static-role credentials. choices are 'root' or 'role'

        Returns:
            None
        """
        credential_type_options = ('root', 'role')
        if credential_type not in credential_type_options:
            raise VaultConfigurationError(
                f"Unexpected used to rotate credential {credential_type!r}, should be one of {credential_type_options}"
            )
        path = f"v1/{self._mount_path}/rotate-{type}/{name}"
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


__all__ = [
    'VaultDatabaseParent',
    'Database',
    'VaultDatabaseConnection',
    'VaultDatabaseStaticRoles',
    'VaultDatabaseDynamicRoles',
]
