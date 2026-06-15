# Continuous Integration (CI)

## HashiCorp Vault Collection Testing

GitHub Actions are used to run the CI for the hashicorp.vault collection. The workflows used for the CI can be found in the [.github/workflows](.github/workflows) directory.

### PR Testing Workflows

The following tests run on every pull request:

| Workflow | Jobs | Description | Python Versions | ansible-core Versions |
| -------- | ---- | ----------- | --------------- | --------------------- |
| [tests.yml](.github/workflows/tests.yml) | changelog | Checks for changelog fragments (skip with `skip-changelog` label) | Latest Ubuntu runner | N/A |
| [tests.yml](.github/workflows/tests.yml) | build-import | Validates collection build via galaxy-importer | Latest Ubuntu runner | Latest stable |
| [tests.yml](.github/workflows/tests.yml) | ansible-lint | Runs ansible-lint on collection content | 3.14 | Latest available |
| [tests.yml](.github/workflows/tests.yml) | sanity | Runs ansible-test sanity checks via tox-ansible | Per ansible-core support matrix | All supported ansible-core versions (2.16+) |
| [tests.yml](.github/workflows/tests.yml) | unit-galaxy | Executes unit tests via ansible-test and tox-ansible | Per ansible-core support matrix | All supported ansible-core versions (2.16+) |
| [tests.yml](.github/workflows/tests.yml) | unit-source | Executes pytest unit tests from source | 3.10-3.14 (see exclusions) | 2.16-2.20, devel |
| [linters.yml](.github/workflows/linters.yml) | linters | Runs `black`, `flake8`, and `isort` via tox | 3.11 | N/A |
| [integration.yml](.github/workflows/integration.yml) | run-integration-tests | Executes integration test suites against live Vault | 3.12 | milestone |

**Notes:**
- Integration tests require a live HashiCorp Vault instance. The workflow uses GitHub secrets (`VAULT_ADDR`, `VAULT_APPROLE_ROLE_ID`, `VAULT_APPROLE_SECRET_ID`) and targets the `admin/hashicorp-vault-integration-tests` namespace.
- The collection's [tox.ini](tox.ini) file defines linting environments only. Unit and integration tests are run via ansible-test in GitHub Actions workflows, not through tox.
- The integration workflow tests against the `milestone` branch (upcoming ansible-core release) as required by [2026 Ansible collection requirements](https://forum.ansible.com/t/action-required-for-ansible-package-included-collections-ci-add-test-runs-against-devel-or-milestone-branch-of-ansible-core/45599).

### Python Version Compatibility by ansible-core Version

These are defined in the GitHub Actions workflow matrix configurations, not in tox.ini.

**Sanity and Unit-Galaxy Tests**:

The test matrix is provided by [`ansible-network/github_actions`](https://github.com/ansible-network/github_actions) reusable workflows and covers:
- All currently supported ansible-core versions (2.16 through 2.21, plus milestone and devel)
- Correct Python version combinations per ansible-core's support matrix
- Built-in exclusions for incompatible combinations

The workflows automatically test against all ansible-core versions that match the collection's `requires_ansible: ">=2.16.0"` requirement from `meta/runtime.yml`.

**Unit-Source Tests** (pytest from source):
| ansible-core Version | Python Versions |
| -------------------- | --------------- |
| 2.16 | 3.10, 3.11 |
| 2.17 | 3.10, 3.11, 3.12 |
| 2.18 | 3.11, 3.12, 3.13 |
| 2.19 | 3.11, 3.12, 3.13 |
| 2.20 | 3.12, 3.13 |
| devel | 3.12, 3.13 |

**Integration Tests**:
| ansible-core Version | Python Versions |
| -------------------- | --------------- |
| milestone | 3.12 |

**Notes:**
- All test workflows (`sanity`, `unit-galaxy`, `unit-source`) use reusable workflows from [`ansible-network/github_actions`](https://github.com/ansible-network/github_actions) which provides:
  - Comprehensive test matrices covering all supported ansible-core versions (2.16+)
  - Built-in exclusions for incompatible Python/ansible-core combinations
  - Network collection-specific optimizations
  - Consistent test infrastructure across network and infrastructure collections
- Version combinations follow ansible-core's official Python support matrix
- The `tox-ansible.ini` skip list provides additional exclusions for incompatible combinations (e.g., Python 3.12 with devel which requires Python 3.13+)
- All workflows comply with [2026 Ansible collection testing requirements](https://docs.ansible.com/projects/ansible/latest/community/collection_contributors/collection_requirements.html)
