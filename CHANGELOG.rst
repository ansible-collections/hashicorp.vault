=============================
Hashicorp.Vault Release Notes
=============================

.. contents:: Topics

v1.2.0
======

Release Summary
---------------

This release significantly expands the hashicorp.vault collection with new modules.

New capabilities include:
- **Database Secrets Engine**: Manage database connections, dynamic roles, static roles, and credential generation/rotation (9 modules)
- **PKI**: Issue, sign, revoke, and read PKI certificates (2 modules)
- **Authentication & ACL**: Manage Vault tokens, authentication, and ACL policies (5 modules)
- **Namespaces**: Manage and query Vault Enterprise namespaces (2 modules)

Minor Changes
-------------

- module_utils/vault_client.py - add ACL policy management on the Vault client (list, read, create/update, delete) (https://github.com/ansible-collections/hashicorp.vault/pull/45).
- module_utils/vault_client.py - add ``Database`` container class to organize database-related clients (connections and static_roles) for a specific mount path (https://github.com/ansible-collections/hashicorp.vault/pull/81).
- module_utils/vault_client.py - add ``VaultDatabaseStaticRoles`` class for managing database static roles with ``list_static_roles()``, ``read_static_role()``, ``create_or_update_static_role()``, ``delete_static_role()``, and ``get_static_role_credentials()`` (https://github.com/ansible-collections/hashicorp.vault/pull/81).
- module_utils/vault_client.py - add ``VaultPki`` with ``generate_certificate()``, ``sign_certificate()``, ``revoke_certificate()``, ``read_certificate()``, and ``list_certificates()`` for managing PKI certificate lifecycle (https://github.com/ansible-collections/hashicorp.vault/pull/78).
- module_utils/vault_client.py - add ``mount_path`` parameter to support database engines mounted at custom paths (https://github.com/hashicorp/hashicorp.vault/pull/34).
- module_utils/vault_client.py - add custom CA certificate verification via the ``ca_cert`` parameter or the ``VAULT_CACERT`` environment variable (https://github.com/ansible-collections/hashicorp.vault/pull/109).
- module_utils/vault_client.py - add optional TLS verification bypass via the ``tls_skip_verify`` parameter or the ``VAULT_SKIP_VERIFY`` environment variable (https://github.com/ansible-collections/hashicorp.vault/pull/109).
- module_utils/vault_client.py - extend ``VaultNamespaces`` with ``create_namespace()``, ``patch_namespace()``, ``delete_namespace()``, ``lock_namespace()``, and ``unlock_namespace()`` for managing namespace lifecycle and API locks (https://github.com/ansible-collections/hashicorp.vault/pull/55).
- module_utils/vault_client.py - implement ``VaultNamespaces`` with ``list_namespaces()`` and ``read_namespace()`` for listing and reading namespace configuration (https://github.com/ansible-collections/hashicorp.vault/pull/51).
- module_utils/vault_client.py - implement ``create_or_update_connection()`` in ``VaultDatabaseConnection`` (https://github.com/ansible-automation-platform/hashicorp.vault/pull/36).
- module_utils/vault_client.py - implement ``delete_connection()`` in ``VaultDatabaseConnection`` (https://github.com/ansible-automation-platform/hashicorp.vault/pull/36).
- module_utils/vault_client.py - implement ``list_connections()`` to list all configured database connections in the Database Secrets Engine (https://github.com/hashicorp/hashicorp.vault/pull/34).
- module_utils/vault_client.py - implement ``read_connection()`` to read configuration details for a specific database connection (https://github.com/hashicorp/hashicorp.vault/pull/34).
- module_utils/vault_client.py - implement ``reset_connection()`` in ``VaultDatabaseConnection`` (https://github.com/ansible-automation-platform/hashicorp.vault/pull/36).
- module_utils/vault_database.py - add ``VaultDatabaseDynamicRoles`` class for managing database dynamic roles with ``list_dynamic_roles()``, ``read_dynamic_role()``, ``create_or_update_dynamic_role()``, and ``delete_dynamic_role()`` (https://github.com/ansible-collections/hashicorp.vault/pull/91).
- module_utils/vault_database.py - add ``VaultDatabaseParent`` base class to eliminate code duplication across database client classes (https://github.com/ansible-collections/hashicorp.vault/pull/91).
- module_utils/vault_database.py - add ``generate_dynamic_role_credentials()`` to ``VaultDatabaseDynamicRoles`` (https://github.com/ansible-collections/hashicorp.vault/pull/116).
- module_utils/vault_database.py - refactor database secrets engine classes into a dedicated module. Move ``VaultDatabaseConnection``, ``VaultDatabaseStaticRoles``, ``VaultDatabaseDynamicRoles``, and ``Database`` classes from ``vault_client.py`` to ``vault_database.py`` for better code organization (https://github.com/ansible-collections/hashicorp.vault/pull/91).
- module_utils/vault_database.py - update ``Database`` container class to include ``dynamic_roles`` client for managing dynamic database roles (https://github.com/ansible-collections/hashicorp.vault/pull/91).

Bugfixes
--------

- module_utils/vault_client.py - ``VaultDatabaseConnection.list_connections()`` now returns an empty list instead of raising ``VaultSecretNotFoundError`` when no database connections are configured (https://github.com/ansible-collections/hashicorp.vault/pull/66).

New Modules
-----------

- hashicorp.vault.acl_policy - Manage HashiCorp Vault ACL policies
- hashicorp.vault.acl_policy_info - List and read HashiCorp Vault ACL policies
- hashicorp.vault.auth_login - Authenticate to HashiCorp Vault
- hashicorp.vault.auth_token - Manage HashiCorp Vault tokens
- hashicorp.vault.auth_token_info - Retrieve information about a specific HashiCorp Vault token
- hashicorp.vault.database_connection - Manage database secrets engine connections in HashiCorp Vault.
- hashicorp.vault.database_connection_info - List available connections or read configuration for a specific connection.
- hashicorp.vault.database_credential_rotation - Rotate Database Credentials in HashiCorp Vault.
- hashicorp.vault.database_dynamic_role_credentials - Generate credentials for a database dynamic role.
- hashicorp.vault.database_role - Manage HashiCorp Vault database dynamic roles
- hashicorp.vault.database_role_info - List available dynamic roles or read configuration for a specific role
- hashicorp.vault.database_static_role - Manage database static roles in HashiCorp Vault
- hashicorp.vault.database_static_role_credentials - Read the credentials for a specific static role.
- hashicorp.vault.database_static_role_info - List available static roles or read the configuration for a specific static role
- hashicorp.vault.pki_certificate - Issue, sign, or revoke HashiCorp Vault PKI certificates
- hashicorp.vault.pki_certificate_info - List and read HashiCorp Vault PKI certificates
- hashicorp.vault.vault_namespace - Manage HashiCorp Vault Enterprise namespaces
- hashicorp.vault.vault_namespace_info - List and read HashiCorp Vault Enterprise namespaces

v1.1.1
======

Release Summary
---------------

This release fixes a bug in the ``kv2_secret_get`` lookup plugin's authentication parameters names so parameters must be passed by correct names.

Bugfixes
--------

- Fix parameter names used by authentication methods so parameters must be passed by correct names. See https://github.com/ansible-collections/hashicorp.vault/pull/35 for more details.

v1.1.0
======

Release Summary
---------------

This release includes new modules and lookup plugin for KV1 secret management.

Minor Changes
-------------

- Add an action group for the collection modules ``kv1_secret``, ``kv1_secret_info``, ``kv2_secret``, ``kv2_secret_info`` (https://github.com/ansible-collections/hashicorp.vault/pull/23).
- kv2_secret_info - module will not fail when the requested secret does not exist instead returns an empty response (https://github.com/ansible-collections/hashicorp.vault/pull/23).

New Plugins
-----------

Lookup
~~~~~~

- hashicorp.vault.kv1_secret_get - Look up KV1 secrets stored in HashiCorp Vault.

New Modules
-----------

- hashicorp.vault.kv1_secret - Manage HashiCorp Vault KV version 1 secrets
- hashicorp.vault.kv1_secret_info - Read HashiCorp Vault KV version 1 secrets

v1.0.0
======

Release Summary
---------------

This marks the first release of the hashicorp.vault collection.

New Plugins
-----------

Lookup
~~~~~~

- hashicorp.vault.kv2_secret_get - Look up KV2 secrets stored in HashiCorp Vault.

New Modules
-----------

- hashicorp.vault.kv2_secret - Manage HashiCorp Vault KV version 2 secrets
- hashicorp.vault.kv2_secret_info - Read HashiCorp Vault KV version 2 secrets
