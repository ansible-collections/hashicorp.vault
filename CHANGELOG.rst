=============================
Hashicorp.Vault Release Notes
=============================

.. contents:: Topics

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
