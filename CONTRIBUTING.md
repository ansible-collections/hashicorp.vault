# Contributing to hashicorp.vault

Thank you for your interest in contributing to the HashiCorp Vault Ansible Collection!

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a feature branch
4. Make your changes
5. Run linters locally: `tox -e linters`
6. Submit a pull request

## Code Style

- Follow PEP 8 guidelines
- Run `tox -e linters` before submitting PRs

## What to Expect

When you submit a PR:

1. Linters, sanity tests, and unit tests run automatically
2. Integration tests require maintainer approval for external PRs (security measure to protect Vault credentials)
3. A maintainer will review your code and approve the integration tests
4. Once all tests pass, your PR will be reviewed for merge

## More Information About Contributing

General information about setting up your Python environment, testing modules,
Ansible coding styles, and more can be found in the [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html).

For general information on running the integration tests see
[this page](https://docs.ansible.com/ansible/latest/community/collection_contributors/test_index.html) and the
[Integration Tests page of the Module Development Guide](https://docs.ansible.com/ansible/devel/dev_guide/testing_integration.html#non-destructive-tests).

### Useful Resources

- [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html) - Details on contributing to Ansible
- [Contributing to Collections](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections) - How to check out collection git repositories correctly
- [Contributing to Ansible-maintained Collections](https://docs.ansible.com/ansible/devel/community/contributing_maintained_collections.html#contributing-maintained-collections)

### Code of Conduct

The `hashicorp.vault` collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

## Questions?

Open an issue if you have questions about contributing.
