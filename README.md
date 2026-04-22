# HashiCorp Vault Collection

This repository contains the `hashicorp.vault` Ansible Collection.

## Description

The primary purpose of this collection is to provide seamless integration between Ansible Automation Platform and HashiCorp Vault. It contains modules and plugins that support managing secrets, namespaces, authentication, and other Vault operations by using Ansible automation.

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
[hashicorp.vault.kv2_secret_get](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/lookup/kv2_secret_get.py)|Look up KV2 secrets stored in Hasicorp vault

<!--end collection content-->

### Modules
Name | Description
--- | ---
[hashicorp.vault.acl_policy](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/acl_policy.py)|Manage HashiCorp Vault ACL policies
[hashicorp.vault.acl_policy_info](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/acl_policy_info.py)|List and read HashiCorp Vault ACL policies
[hashicorp.vault.auth_login](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/auth_login.py)|Authenticate to HashiCorp Vault
[hashicorp.vault.auth_token](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/auth_token.py)|Manage HashiCorp Vault tokens
[hashicorp.vault.auth_token_info](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/auth_token_info.py)|Retrieve information about a specific HashiCorp Vault token
[hashicorp.vault.database_connection](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/database_connection.py)|Manage database secrets engine connections in HashiCorp Vault
[hashicorp.vault.database_connection_info](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/database_connection_info.py)|List available connections or read configuration for a specific connection
[hashicorp.vault.database_static_role](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/database_static_role.py)|Manage database static roles in HashiCorp Vault
[hashicorp.vault.database_static_role_info](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/database_static_role_info.py)|List available static roles or read the configuration for a specific static role
[hashicorp.vault.kv1_secret](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/kv1_secret.py)|Manage HashiCorp Vault KV version 1 secrets
[hashicorp.vault.kv1_secret_info](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/kv1_secret_info.py)|Read HashiCorp Vault KV version 1 secrets
[hashicorp.vault.kv2_secret](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/kv2_secret.py)|Manage HashiCorp Vault KV version 2 secrets
[hashicorp.vault.kv2_secret_info](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/kv2_secret_info.py)|Read HashiCorp Vault KV version 2 secrets
[hashicorp.vault.pki_certificate](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/pki_certificate.py)|Issue, sign, or revoke HashiCorp Vault PKI certificates
[hashicorp.vault.pki_certificate_info](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/pki_certificate_info.py)|List and read HashiCorp Vault PKI certificates
[hashicorp.vault.vault_namespace](https://github.com/ansible-collections/hashicorp.vault/blob/main/plugins/modules/vault_namespace.py)|Manage HashiCorp Vault Enterprise namespaces

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
- Managing KV1 and KV2 secrets in HashiCorp Vault (create, read, update, delete)
- Managing ACL policies in HashiCorp Vault
- Authentication and token management
- Managing database secrets engine connections and static roles
- Managing PKI certificates (issue, sign, revoke, read)
- Managing Vault Enterprise namespaces

## Testing

GitHub Actions workflows run tests for this collection. The CI uses a two-tier approach:

- **Tier 1 (All PRs)**: Linters, sanity tests, and unit tests run automatically
- **Tier 2 (Integration)**: Vault integration tests run automatically for internal PRs; external PRs require maintainer approval

### Running Tests Locally

**Linters:**
```bash
pip install -r requirements-linters.txt
tox -e linters
```

**Unit Tests:**
```bash
pip install -r test-requirements.txt
pytest tests/unit/
```

**Integration Tests:**

Integration tests require a Vault instance.

Copy the integration config template and fill in your Vault details:
```bash
cp tests/integration/integration_config.yml.template tests/integration/integration_config.yml
```

Add you Vault details:
```yaml
vault_url_from_int_config: "<VAULT_URL_HERE>"
vault_namespace_from_int_config: "<VAULT_NAMESPACE_HERE>" # example: admin/hashicorp-vault-integration-tests
vault_approle_role_id_from_int_config: "<VAULT_APPROLE_ROLE_ID_HERE>"
vault_approle_secret_id_from_int_config: "<VAULT_APPROLE_SECRET_ID_HERE>"
```

Run the tests:
```bash
ansible-test integration <target>
```

**Using a Local Vault Instance:**

You can test changes using a local instance of HashiCorp Vault.

Follow this guide to start a local development server:
https://developer.hashicorp.com/vault/tutorials/get-started/setup

Prerequisites:

For running the integration tests locally, you need to:

1. Start a Vault **dev server**
2. Configure **AppRole authentication**
3. Retrieve the **`role_id`** and **`secret_id`**
4. Update `defaults/main.yml` in your integration tests with the required values:

```yaml
# Example values only — replace with real credentials
vault_url: "http://localhost:8200"
vault_namespace: "admin"
vault_approle_role_id: "xxxxxxxx-60da-6224-d270-xxxxxxxx"
vault_approle_secret_id: "xxxxxxxx-2458-14b9-b643-xxxxxxxx"
vault_resource_suffix: ansible-test
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
