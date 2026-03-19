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
| [tests.yml](.github/workflows/tests.yml) | sanity | Runs ansible-test sanity checks via tox-ansible | 3.10, 3.11, 3.12 | 2.16 |
| [tests.yml](.github/workflows/tests.yml) | unit-galaxy | Executes unit tests via ansible-test and tox-ansible | 3.10, 3.11, 3.12 | 2.16 |
| [tests.yml](.github/workflows/tests.yml) | unit-source | Executes pytest unit tests from source | 3.10-3.14 (see exclusions) | 2.16-2.20, devel |
| [linters.yml](.github/workflows/linters.yml) | linters | Runs `black`, `flake8`, and `isort` via tox | 3.11 | N/A |
| [integration.yml](.github/workflows/integration.yml) | run-integration-tests | Executes integration test suites against live Vault | 3.12 | devel, stable-2.18, stable-2.19 |

**Notes:**
- Integration tests require a live HashiCorp Vault instance. The workflow uses GitHub secrets (`VAULT_ADDR`, `VAULT_APPROLE_ROLE_ID`, `VAULT_APPROLE_SECRET_ID`) and targets the `admin/hashicorp-vault-integration-tests` namespace.
- The collection's [tox.ini](tox.ini) file defines linting environments only. Unit and integration tests are run via ansible-test in GitHub Actions workflows, not through tox.

### Python Version Compatibility by ansible-core Version

These are defined in the GitHub Actions workflow matrix configurations, not in tox.ini.

**Sanity and Unit-Galaxy Tests** (via tox-ansible):
| ansible-core Version | Python Versions |
| -------------------- | --------------- |
| 2.16 | 3.10, 3.11, 3.12 |

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
| devel | 3.12 |
| stable-2.18 | 3.12 |
| stable-2.19 | 3.12 |

**Notes:**
- The `unit-source` workflow uses reusable workflows from `ansible-network/github_actions` which tests against a comprehensive matrix
- Version combinations follow ansible-core's official Python support matrix
- The `unit-galaxy` workflow uses tox-ansible with explicit matrix entries only for 2.16
- All workflows use matrix exclusions to prevent unsupported Python/ansible-core combinations
