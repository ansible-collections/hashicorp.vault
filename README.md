# HashiCorp Vault Collection

## Description

This repository contains the `hashicorp.vault` Ansible Collection. The collection provides Ansible modules and plugins for interacting with HashiCorp Vault, enabling users to manage secrets, authentication, and other Vault operations by using Ansible automation.

## Requirements

Some modules and plugins require external libraries. Please check the requirements for each plugin or module you use in the documentation to find out which requirements are needed.

### Ansible version compatibility
<!--start requires_ansible-->
Tested with the Ansible Core >= 2.16.0 versions.

<!--end requires_ansible-->

### Python version compatibility

Tested with the Python >= 3.9 versions.

## Included content
<!--start collection content-->
### Lookup plugins
Name | Description
--- | ---
[hashicorp.vault.kv2_secret_get](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/lookup/kv2_secret_get.py)|Look up KV2 secrets stored in Hasicorp vault

<!--end collection content-->

### Modules
Name | Description
--- | ---
[hashicorp.vault.kv2_secret](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/kv2_secret.py)|Manage HashiCorp Vault KV version 2 secrets

## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```bash
ansible-galaxy collection install hashicorp.vault
```

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
  - name: hashicorp.vault
```

To upgrade the collection to the latest available version, run the following command:

```bash
ansible-galaxy collection install hashicorp.vault --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax where `X.Y.Z` can be any [available version](https://galaxy.ansible.com/hashicorp/vault):

```bash
ansible-galaxy collection install hashicorp.vault:==X.Y.Z
```

See [Ansible Using Collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Use Cases

Modules in this collection can be used for various operations on HashiCorp Vault.
Currently the collection supports:
- Managing KV2 secrets in HashiCorp Vault (create, read, update, delete [soft-delete])

## Testing

GitHub Actions workflows are used to run tests for the hashicorp.vault collection. These workflows include jobs to run the unit tests, integration tests, sanity tests, linters, changelog check and doc related checks.

To run linter tests locally, run `tox -e linters`. For more information, refer [tox-ansible documentation](https://github.com/ansible/tox-ansible?tab=readme-ov-file#tox-ansible).

To run integration tests locally, copy tests/integration/integration_config.yml.template to tests/integration/integration_config.yml, fill in your Vault details and run the tests using `ansible-test integration <target>`
```
---
vault_url_from_int_config: "<VAULT_URL_HERE>"
vault_namespace_from_int_config: "<VAULT_NAMESPACE_HERE>" # example: admin/hashicorp-vault-integration-tests
vault_approle_role_id_from_int_config: "<VAULT_APPROLE_ROLE_ID_HERE>"
vault_approle_secret_id_from_int_config: "<VAULT_APPROLE_SECRET_ID_HERE>"
```

## Support

As Red Hat Ansible Certified Content, this collection is entitled to support through the Ansible Automation Platform (AAP) using the **Create issue** button on the top right corner. If a support case cannot be opened with Red Hat and the collection has been obtained either from Galaxy or GitHub, there may be community help available on the [Ansible Forum](https://forum.ansible.com/).


## Release Notes and Roadmap

See the [changelog](https://github.com/ansible-collections/hashicorp.vault/tree/main/CHANGELOG.rst).

<!-- Optional. Include the roadmap for this collection, and the proposed release/versioning strategy so users can anticipate the upgrade/update cycle. -->

## Related Information

<!-- List out where the user can find additional information, such as working group meeting times, slack/matrix channels, or documentation for the product this collection automates. At a minimum, link to: -->

- [Ansible collection development forum](https://forum.ansible.com/c/project/collection-development/27)
- [Ansible User guide](https://docs.ansible.com/ansible/devel/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/devel/dev_guide/index.html)
- [Ansible Collections Checklist](https://docs.ansible.com/ansible/devel/community/collection_contributors/collection_requirements.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html)
- [The Bullhorn (the Ansible Contributor newsletter)](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn)
- [News for Maintainers](https://forum.ansible.com/tag/news-for-maintainers)

## License Information

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
