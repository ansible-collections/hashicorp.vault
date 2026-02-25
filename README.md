# HashiCorp Vault Collection
The Ansible HashiCorp Vault collection includes a variety of Ansible content to help automate the management of HashiCorp Vault. This collection is maintained by the Ansible Cloud Content team.

## Contents

- [Description](#description)
- [Requirements](#requirements)
  - [Ansible version compatibility](#ansible-version-compatibility)
  - [Python version compatibility](#python-version-compatibility)
- [Included content](#included-content)
- [Installation](#installation)
- [Use Cases](#use-cases)
- [Testing](#testing)
- [Support](#support)
- [Release notes](#release-notes)
- [Related Information](#related-information)
- [License Information](#license-information)

## Description

The primary purpose of this collection is to provide seamless integration between Ansible Automation Platform and HashiCorp Vault. It contains modules and plugins that support managing secrets, namespaces, authentication, and other Vault operations through Ansible automation.

Being Red Hat Ansible Certified Content, this collection is eligible for support through the [Ansible Automation Platform](https://www.redhat.com/en/technologies/management/ansible).

## Requirements

Some modules and plugins require external libraries. Please check the requirements for each plugin or module you use in the documentation to find out which requirements are needed.

### Ansible version compatibility
<!--start requires_ansible-->
Tested with the Ansible Core >= 2.16.0 versions.

<!--end requires_ansible-->

### Python version compatibility

Tested with the Python >= 3.10 versions.

## Included content
<!--start collection content-->
### Lookup plugins
Name | Description
--- | ---
[hashicorp.vault.kv1_secret_get](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/lookup/kv1_secret_get.py)|Look up KV1 secrets stored in HashiCorp Vault
[hashicorp.vault.kv2_secret_get](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/lookup/kv2_secret_get.py)|Look up KV2 secrets stored in HashiCorp Vault

<!--end collection content-->

### Modules
Name | Description
--- | ---
[hashicorp.vault.kv1_secret](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/kv1_secret.py)|Manage HashiCorp Vault KV version 1 secrets
[hashicorp.vault.kv1_secret_info](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/kv1_secret_info.py)|Read HashiCorp Vault KV version 1 secrets
[hashicorp.vault.kv2_secret](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/kv2_secret.py)|Manage HashiCorp Vault KV version 2 secrets
[hashicorp.vault.kv2_secret_info](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/kv2_secret_info.py)|Read HashiCorp Vault KV version 2 secrets

## Installation

To install this collection from Automation Hub, the following needs to be added to `ansible.cfg`:

```ini
[galaxy]
server_list=automation_hub

[galaxy_server.automation_hub]
url=https://console.redhat.com/api/automation-hub/content/published/
auth_url=https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token
token=<SuperSecretToken>
```

To download contents from Automation Hub using `ansible-galaxy` CLI, you would need to generate and use an offline token.
If you already have a token, please ensure that it has not expired. Visit [Connect to Hub](https://console.redhat.com/ansible/automation-hub/token) to obtain the necessary token.


With this configured and Ansible Galaxy command-line tool installed, run the following command:

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
- Managing KV1 secrets in HashiCorp Vault (create, read, update, delete)
- Managing KV2 secrets in HashiCorp Vault (create, read, update, delete [soft-delete])

## Testing

This collection is tested using GitHub Actions. To learn more about testing, refer to [CI.md](https://github.com/ansible-collections/hashicorp.vault/blob/main/CI.md).

## Support

As Red Hat Ansible Certified Content, this collection is entitled to support through the Ansible Automation Platform (AAP) using the **Create issue** button on the top right corner. If a support case cannot be opened with Red Hat and the collection has been obtained from Galaxy or GitHub, community help may be available on the [Ansible Forum](https://forum.ansible.com/).


## Release notes

See the [changelog](https://github.com/ansible-collections/hashicorp.vault/tree/main/CHANGELOG.rst).

## Related Information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Collection Developer Guide](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)

## License Information

GNU General Public License v3.0 or later.

See [COPYING](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
