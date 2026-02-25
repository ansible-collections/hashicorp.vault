# Continuous Integration (CI)

## HashiCorp Vault Collection Testing

GitHub Actions are used to run the CI for the hashicorp.vault collection. The workflows used for the CI can be found [here](https://github.com/ansible-collections/hashicorp.vault/tree/main/.github/workflows). These workflows include jobs to run the unit tests, sanity tests, linters, integration tests, and changelog checks.

The collection uses reusable workflows from [ansible/ansible-content-actions](https://github.com/ansible/ansible-content-actions) and [ansible-network/github_actions](https://github.com/ansible-network/github_actions) for standardized testing.

### PR Testing Workflows

The following tests run on every pull request:

| Job | Description | Python Versions | ansible-core Versions |
| --- | ----------- | --------------- | --------------------- |
| Changelog | Checks for the presence of changelog fragments | 3.12 | devel |
| Linters | Runs `black`, `flake8`, and `isort` on plugins and tests | 3.11 | N/A |
| Sanity | Runs ansible sanity checks | See compatibility table below | 2.16 |
| Unit tests (galaxy) | Executes unit test cases against galaxy build | See compatibility table below | 2.16 |
| Unit tests (source) | Executes unit test cases against source | >=3.10 | devel, stable-2.17, stable-2.18, stable-2.19, stable-2.20 |
| Integration tests | Executes integration test suites | 3.12 | devel, stable-2.18, stable-2.19 |
| Ansible-lint | Runs ansible-lint on playbooks and roles | 3.12 | devel |

### Python Version Compatibility by ansible-core Version

These are outlined in the collection's [`/tox.ini`](/tox.ini) file and GitHub Actions workflow configurations.

| ansible-core Version | Sanity Tests | Unit Tests |
| -------------------- | ------------ | ---------- |
| 2.16 | 3.10, 3.11, 3.12 | 3.10, 3.11, 3.12 |

### Integration Test Requirements

Integration tests require a live HashiCorp Vault instance. The tests use secrets stored in GitHub to authenticate:
- `VAULT_ADDR` - Vault server address
- `VAULT_NAMESPACE` - Vault namespace (for Vault Enterprise)
- `VAULT_APPROLE_ROLE_ID` - AppRole authentication role ID
- `VAULT_APPROLE_SECRET_ID` - AppRole authentication secret ID

Integration tests are configured via the `integration_config.yml` file, which is generated from `tests/integration/integration_config.yml.template` during the CI run.
