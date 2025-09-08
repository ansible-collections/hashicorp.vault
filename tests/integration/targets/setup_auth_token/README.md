# `setup_auth_token` Role

This role provides reusable authentication functionality for HashiCorp Vault integration tests.
Returns an auth token to cloud-content HashiCorp Vault instance.

## Purpose

This role handles the generation of short-lived Vault tokens using AppRole authentication, which can then be used by individual integration tests.

## Usage

To use this role in your integration test, add it as a dependency in your test's `meta/main.yml`:

```yaml
---
dependencies:
  - setup_auth_token
```

Or include it explicitly in your test tasks:

```yaml
- name: Generate Vault authentication token
  ansible.builtin.include_role:
    name: setup_auth_token
```

## Variables & Output

After running this role, the following fact will be available:

- `vault_token_from_setup_auth_token`: A short-lived Vault token that can be used for authentication in tests

## Requirements

This role expects the following variables. These can be provided as environment variables or as role variables:```
- `VAULT_ADDR` or `vault_url`: Vault server URL
- `VAULT_NAMESPACE` or `vault_namespace`: Vault namespace
- `VAULT_APPROLE_ROLE_ID` or `vault_approle_role_id`: AppRole role ID
- `VAULT_APPROLE_SECRET_ID` or `vault_approle_secret_id`: AppRole secret ID
