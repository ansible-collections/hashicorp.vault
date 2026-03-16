# Continuous Integration (CI)

## HashiCorp Vault Upstream Testing

GitHub Actions are used to run the CI for the hashicorp.vault collection. The workflows used for the CI can be found in the [.github/workflows](.github/workflows) directory.

### PR Testing Workflows

The following tests run on every pull request:

| Job | Description | Python Versions | ansible-core Versions |
| --- | ----------- | --------------- | --------------------- |
| [Changelog](.github/workflows/changelog.yml) | Checks for the presence of changelog fragments | 3.12 | devel |
| [Linters](.github/workflows/linters.yml) | Runs `black`, `flake8`, and `isort` on plugins and tests | 3.11 | N/A |
| [Sanity](.github/workflows/sanity.yml) | Runs ansible sanity checks | See compatibility table below | 2.16 |
| [Unit tests](.github/workflows/units.yml) | Executes unit test cases | See compatibility table below | 2.16, devel, stable-2.17, stable-2.18, stable-2.19, stable-2.20 |
| [Integration](.github/workflows/integration.yml) | Executes integration test suites | 3.12 | devel, stable-2.18, stable-2.19 |

**Note:** Integration tests require a live HashiCorp Vault instance and use GitHub secrets for authentication.

### Python Version Compatibility by ansible-core Version

These are outlined in the collection's [tox.ini](tox.ini) file (`envlist`) and GitHub Actions workflow exclusions.

| ansible-core Version | Sanity Tests | Unit Tests |
| -------------------- | ------------ | ---------- |
| 2.16 | 3.10, 3.11, 3.12 | 3.10, 3.11, 3.12 |
