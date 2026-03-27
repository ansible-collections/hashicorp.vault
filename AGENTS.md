# Agent Instructions for hashicorp.vault Collection

## Architecture Overview

This collection uses two module patterns:

**Legacy pattern** (existing modules): Standard Ansible modules in `plugins/modules/` that
use wrapper classes in `vault_client.py` (e.g., `VaultAclPolicies`, `VaultDatabaseConnection`).
These run on the target host.

**Action plugin pattern** (new modules): Thin action plugins in `plugins/action/` that run on
the controller. Each module has three files:

1. `plugins/modules/<name>.py` -- DOCUMENTATION, EXAMPLES, RETURN only (no logic)
2. `plugins/action/<name>.py` -- thin plugin that sets `OPERATION` or `OPERATIONS`, inherits `VaultActionBase`
3. `plugins/plugin_utils/generated/<area>.py` -- request dataclasses generated from the OpenAPI spec

The base class `plugins/plugin_utils/vault_action_base.py` handles the entire pipeline:

```
task args -> validate via DOCUMENTATION argspec -> split auth/operation args
          -> VaultClient + authenticate -> dataclass(**operation_args) -> asdict()
          -> filter Nones -> client.request(method, path, json=body) -> raw response
```

All new modules MUST use the action plugin pattern.

## Module Types

### Action modules
One-shot operations (create, renew, revoke, rotate, issue, sign). Always `changed=True` on success.
Set `OPERATION` on the action plugin class.

### Info modules
Read-only operations (lookup, list, read). Always `changed=False`.
Set `OPERATION` and `CHANGED_ON_SUCCESS = False`.

### CRUD modules
State-based resource management (`state: present/absent`).
Set `OPERATIONS` dict with keys `"present"`, `"absent"`, and optionally `"read"`.
The base class handles GET-before-POST idempotency and GET-before-DELETE existence checks.

## How to Add a New Module

### Option A: Add to the generator (preferred)

**Generation is the first step, not the finish line.** The generator produces a working
scaffold, but every new module needs a post-generation audit to reach production quality.

#### Step 1: Generate the scaffold

1. Open `tools/generate_modules.py`
2. Add a `ModuleConfig` entry to the `MODULES` list:
   - `name`: module name (e.g., `vault_pki_role`)
   - `module_type`: `"action"`, `"info"`, or `"crud"`
   - `area`: grouping for the generated dataclass file (e.g., `"pki"`)
   - `operations`: list of `OperationRef` with OpenAPI `operationId` values
   - `path_params`: list of path template parameter names
   - `short_description`: one-line description
   - `manual_schema`: (optional) dict of fields for path params or when endpoint is not in the spec
3. Run: `python -m tools.generate_modules --spec vault-spec-full.json`
4. Add the module name to `meta/runtime.yml` under `action_groups.vault`
5. Generate examples: `python -m tools.generate_examples`
6. Inject examples: `python -m tools.inject_examples`
7. Generate Molecule scenarios: `python -m tools.generate_molecule_scenarios`

#### Step 2: Hand-craft to quality

The generator produces a working scaffold with hardcoded example values, stub
molecule scenarios, and generic RETURN blocks. This step transforms the scaffold
into a production-quality module. Work through each sub-step in order.

**a) Start the test infrastructure**

If not already running, start the Vault dev server and supporting containers:

```bash
ansible-playbook extensions/molecule/default/create.yml -i extensions/molecule/inventory_mock.yml
```

Test the endpoint with `curl` to verify the spec is accurate. The OpenAPI spec
is sometimes wrong -- always confirm against a real server:

```bash
# For a CRUD module, test the write and read endpoints:
curl -s -H "X-Vault-Token: test-root-token" \
  -X POST http://127.0.0.1:18200/v1/<endpoint> -d '{"type":"example"}' | python -m json.tool

curl -s -H "X-Vault-Token: test-root-token" \
  http://127.0.0.1:18200/v1/<endpoint> | python -m json.tool
```

Watch for: endpoints that return 404 or empty bodies when the spec says they
should work, field names that differ from the spec, `-self` variant requirements.

**b) Create `examples/<module>/vars.yml`**

This file is the single source of truth for test data. It is NOT generated --
you must create it by hand. The structure depends on module type:

```yaml
# CRUD module -- config is both input AND expected output
---
name: test-resource          # identifier (path param)
mount_path: database         # if applicable
config:
  field_one: value
  ttl: "1h"                  # human-readable durations, not 3600
  max_ttl: "24h"
```

```yaml
# Action module -- params (input) + expected_response_keys (output)
---
params:
  display_name: my-token
  ttl: "1h"
expected_response_keys:
  - client_token
  - accessor
  - policies
```

```yaml
# Info module -- expected_response_keys or config (if reading a known resource)
---
expected_response_keys:
  - keys
```

```yaml
# Fire-and-forget (revoke, rotate) -- at minimum the input params
---
mount_path: database
name: my-connection
# Rotate is fire-and-forget; Vault returns no meaningful data.
```

**c) Rewrite the generated example playbooks**

The generator produces examples with hardcoded values from `FIELD_SAMPLES`. Replace
them with variables from `vars.yml` and add contract assertions.

For each example file (`present.yml`, `action.yml`, `info.yml`):

1. Add a commented `vars.yml` header showing the contract:
   ```yaml
   # vars_files: [vars.yml]
   #
   # name: test-resource
   # config:
   #   field_one: value
   ```

2. Replace hardcoded module parameters with vars:
   ```yaml
   hashicorp.vault.vault_my_module:
     url: "{{ vault_addr }}"
     token: "{{ vault_token }}"
     name: "{{ name }}"
     field_one: "{{ config.field_one }}"
   ```

3. Add a contract assertion task:
   - CRUD: `(config | hashicorp.vault.vault_config_match(result.data)).match`
   - Action: loop `expected_response_keys` asserting `item in result.data`
   - Info: `vault_config_match` or key presence depending on response shape
   - Fire-and-forget: `result is changed`

4. Re-inject into module docs: `python -m tools.inject_examples`

**d) Fix the action plugin if needed**

Based on what you learned from the curl tests in step (a):

- **No single-resource GET**: Implement list + filter like `vault_auth_method.py`.
  Copy the `_read_auth_method` / `_ensure_present` / `_ensure_absent` pattern.
- **Write returns no body**: Add a read-back after write so `result.data` is
  populated (not just `changed: true`).
- **Field name collision with auth params** (e.g., `token`): Switch to a `-self`
  endpoint variant and set the request schema to `None`.
- **Endpoint path is wrong in the spec**: Override in the `OperationRef` or
  hand-craft the action plugin.

Add `# @hand-crafted` marker to any action plugin you modify.

**e) Add response schema (action modules only)**

For action modules where the response shape differs from the input, the generator
needs an entry in `tools/response_schemas.yaml` to produce a typed RETURN block.

1. Run the module against a real Vault server (via molecule or manually)
2. Inspect `result.data` to see the actual field names and types
3. Add an entry to `response_schemas.yaml`:
   ```yaml
   vault_my_action_module:
     _envelope: data      # or "auth" for token operations
     fields:
       field_name:
         type: str
         description: What this field contains
   ```
4. Re-run the generator: `python -m tools.generate_modules --spec vault-spec-full.json`
5. Re-inject examples: `python -m tools.inject_examples`

For fire-and-forget modules with no meaningful response, use `_opaque: true`.

**f) Enhance molecule scenarios**

The generated scenarios are bare stubs. Enhance each file:

`converge.yml`:
- Add `vars_files` pointing to `examples/<module>/vars.yml`
- Add prerequisite `uri` tasks if the module needs an existing resource (e.g.,
  create a database role before testing its info module, create a child token
  before testing revoke). Use vars from `vars.yml`, not hardcoded values.

`verify.yml`:
- Add `vars_files` pointing to `examples/<module>/vars.yml`
- For CRUD: use `uri` GET to read the resource, then assert with
  `vault_config_match` against `config`
- For action: assert `expected_response_keys` presence in response
- For fire-and-forget: a simple debug message is sufficient (contract is
  enforced by the base class during converge)

`cleanup.yml` (CRUD only):
- Add `vars_files` and include `examples/<module>/absent.yml`

Add `# @hand-crafted` marker to every molecule file you touch.

**g) Run end-to-end**

```bash
molecule test -s <module_name>
```

If the test fails, fix the issue and re-run. After a successful run:
- Inspect the actual `result.data` in the output
- If you discover new response fields, update `response_schemas.yaml`
- Re-run the generator if the RETURN block needs refreshing

#### Step 3: Verify

Use this checklist to confirm every item passes before shipping. If any item
fails, go back to Step 2 and fix it.

**Action plugin:**
- [ ] Endpoint path matches the actual Vault API (tested with `curl`)
- [ ] `# @hand-crafted` marker present on any modified action plugin
- [ ] CRUD modules return `data` (not just `changed`) from `_ensure_present`

**RETURN block:**
- [ ] `data.contains` has typed fields (not bare `type: dict`)
- [ ] `no_log` fields (passwords, tokens) are excluded from `contains`
- [ ] Action modules have an entry in `tools/response_schemas.yaml`

**vars.yml:**
- [ ] `examples/<module>/vars.yml` exists
- [ ] Contains the correct structure for the module type (config / params / expected_response_keys)
- [ ] Durations use human-readable format (`"1h"`, not `3600`)

**Example playbooks:**
- [ ] Use variables from `vars.yml` (no hardcoded values)
- [ ] Include commented `vars.yml` header
- [ ] Assert `result.data` against vars (STRONG assertion, not just `result.raw is defined`)

**Molecule scenarios:**
- [ ] `converge.yml` loads `vars_files` from `examples/<module>/vars.yml`
- [ ] Prerequisites use vars (not hardcoded values)
- [ ] `verify.yml` loads `vars_files` and asserts `result.data`
- [ ] `cleanup.yml` includes `absent.yml` (CRUD modules)
- [ ] All scenario files have `# @hand-crafted` marker

**End-to-end:**
- [ ] `molecule test -s <module_name>` passes against a real Vault dev server
- [ ] `response_schemas.yaml` matches the actual `result.data`

#### Step 4: Protect the hand-crafted work

After verifying, confirm that `# @hand-crafted` is on every file you modified
(action plugins, molecule scenarios). The generators will skip them on future
runs. Verify with:

```bash
python -m tools.generate_modules --spec vault-spec-full.json
python -m tools.generate_molecule_scenarios
```

Look for `Skipped` lines in the output for your files.

### Option B: Hand-write (for unusual cases)

Follow the same three-file structure. Use existing generated modules as templates.
Some modules require custom CRUD logic (e.g., `vault_auth_method` uses list-based
existence checks because Vault has no GET endpoint for individual auth methods).
Still follow Steps 2-4 above.

## OpenAPI Spec

The current spec is `vault-spec-full.json` in the repo root, captured from a Vault v1.21.4
dev server with database and PKI engines enabled.

### Capturing a new spec

```bash
# Start the infra (creates Vault + PostgreSQL containers, mounts engines)
ansible-playbook extensions/molecule/default/create.yml -i extensions/molecule/inventory_mock.yml

# Capture the spec
curl -s -H "X-Vault-Token: test-root-token" \
  "http://127.0.0.1:18200/v1/sys/internal/specs/openapi?generic_mount_paths=false" \
  > vault-spec-full.json
```

The spec output depends on:
- Which secrets engines and auth methods are mounted
- The token's permissions (use a root token for full coverage)
- The Vault version

### Known spec gaps

- **Response schemas**: ~66% of resource-detail GETs have no response schema. Responses
  are returned as `raw` dicts. When response dataclasses exist (Phase 2), add typed returns.
- **Mount-dependent paths**: Database, KV, PKI paths use `{mount_path}` templates.
  The spec uses concrete mount names unless `?generic_mount_paths=true` is set. We override
  paths with `{mount_path}` in the generator's `OperationRef`.

## File Layout

```
plugins/
  action/
    __init__.py
    vault_token_create.py       # thin: OPERATION = Operation(...)
    vault_token_role.py         # thin: OPERATIONS = {...}
    vault_auth_method.py        # custom CRUD (list-based existence)
    vault_pki_issue.py          # PKI certificate issuance
    vault_pki_role.py           # PKI role CRUD
    vault_database_role.py      # DB dynamic role CRUD
    ...
  modules/
    vault_token_create.py       # DOCUMENTATION + EXAMPLES + RETURN only
    ...
  module_utils/
    vault_client.py             # VaultClient with request() method
    args_common.py              # AUTH_ARG_SPEC
    vault_auth_utils.py         # authenticate_module, get_authenticated_client
    authentication.py           # TokenAuthenticator, AppRoleAuthenticator
    vault_exceptions.py         # typed exception hierarchy
  plugin_utils/
    vault_action_base.py        # VaultActionBase -- the pipeline
    operation.py                # Operation dataclass
    base.py                     # VaultLookupBase (for lookup plugins)
    generated/
      __init__.py
      token.py                  # TokenCreateRequest, TokenRenewRequest, ...
      auth.py                   # AuthEnableMethodRequest, ...
      database.py               # DatabaseStaticRoleRequest, DatabaseRoleRequest, ...
      pki.py                    # PkiIssueWithRoleRequest, PkiWriteRoleRequest, ...
  filter/
    vault_config_match.py       # duration-aware subset comparison filter
  doc_fragments/
    vault_auth.py               # shared auth documentation fragment
  lookup/
    kv1_secret_get.py
    kv2_secret_get.py
examples/
  vault_token_role/
    vars.yml                     # config dict (SOT for input + expected output)
    present.yml                  # module call using config + contract assert
    absent.yml                   # teardown using identifiers from vars
  vault_token_create/
    vars.yml                     # params + expected_response_keys
    action.yml                   # module call + key presence assert
  vault_pki_role/
    vars.yml
    present.yml
    absent.yml
  vault_database_role/
    vars.yml
    present.yml
    absent.yml
  ...per module...
tools/
  generate_modules.py           # module generator script
  generate_examples.py          # example playbook generator
  inject_examples.py            # injects examples/ into module EXAMPLES blocks
  generate_molecule_scenarios.py # molecule scenario generator
extensions/
  molecule/
    config.yml                  # shared Molecule config
    inventory_mock.yml          # Vault dev server inventory (localhost:18200)
    inventory_real.yml          # real Vault inventory (env vars)
    default/                    # test infrastructure lifecycle
      molecule.yml
      create.yml                # start Vault + PostgreSQL containers (podman)
      destroy.yml               # stop containers
    vault_token_create/         # per-module scenarios
      molecule.yml
      converge.yml              # includes examples/<module>/action.yml
      verify.yml                # loads examples/<module>/vars.yml, asserts data
    vault_pki_role/
      molecule.yml
      converge.yml              # includes examples/<module>/present.yml
      verify.yml                # loads examples/<module>/vars.yml, asserts data
      cleanup.yml               # CRUD cleanup (includes examples/<module>/absent.yml)
    ...per module...
tests/
  unit/plugins/
    action/                     # tests for action plugins
    module_utils/               # tests for legacy module utils
    lookup/                     # tests for lookup plugins
meta/
  runtime.yml                   # action_groups.vault lists all modules
```

## VaultClient API

New modules use `client.request(method, path, **kwargs)` directly. Do NOT create
new wrapper classes in `vault_client.py`. The `request()` method is the public
interface; it delegates to `_make_request()` which handles:

- URL construction from `vault_address + "/" + path`
- Session headers (`X-Vault-Token`, `X-Vault-Namespace`)
- HTTP error mapping (403 -> VaultPermissionError, 404 -> VaultSecretNotFoundError)
- Connection error handling

## Examples Pipeline

The `examples/` directory is the **source of truth** for all module examples. Examples
are generated from module DOCUMENTATION and then injected into module files.

### Pipeline order (must run sequentially)

```bash
# 1. Generate example playbooks from DOCUMENTATION
python -m tools.generate_examples

# 2. Inject examples into module EXAMPLES blocks
python -m tools.inject_examples

# 3. Generate Molecule scenarios from examples
python -m tools.generate_molecule_scenarios
```

Or use the Makefile shortcuts:

```bash
make examples            # steps 1 + 2
make molecule-scenarios  # step 3
```

### How it works

- `tools/generate_examples.py` reads each `plugins/modules/vault_*.py`, parses the
  DOCUMENTATION YAML, and writes example task files under `examples/<module>/`:
  - **Action modules**: `action.yml`
  - **CRUD modules**: `present.yml` and `absent.yml`
  - **Info modules**: `info.yml`
- `tools/inject_examples.py` reads `examples/<module>/*.yml`, concatenates them, and
  replaces the `EXAMPLES` block in the corresponding module file.
  - `--check` flag exits 1 if any module is stale (for CI enforcement)
  - `--diff` flag shows what would change without writing
- **NEVER edit EXAMPLES in module files directly** -- edit the files under `examples/`
  and run `python -m tools.inject_examples`.

### Field samples and connection vars

The example generator uses `FIELD_SAMPLES` to produce realistic example values.
Connection parameters always use Jinja2 variables: `url: "{{ vault_addr }}"`,
`token: "{{ vault_token }}"`. Fields with `no_log: true` are excluded.

## Molecule Testing

Integration tests use Molecule with a **real Vault dev server** running in a Podman container.
No mock server is used.

### Test infrastructure

The `default/create.yml` playbook sets up:

1. **Podman network** (`molecule-net`) for container-to-container communication
2. **PostgreSQL container** (`postgres-molecule`) with test users for database scenarios
3. **Vault dev container** (`vault-molecule`) with root token `test-root-token`
4. **Database engine** mounted at `database/` with a shared `my-postgres` connection
5. **PKI engine** mounted at `pki/` with a generated root CA

The `default/destroy.yml` playbook tears everything down.

### Scenario atomicity

Each module's scenario is **self-contained and atomic**. Shared infrastructure (Vault,
PostgreSQL, database engine, PKI engine) is set up in `default/create.yml`. Module-specific
prerequisites (e.g., creating a test role before reading it) are set up in the scenario's
own `converge.yml` and cleaned up in its `cleanup.yml`. Scenarios do NOT depend on each other.

### Running tests

```bash
# Start test infrastructure manually
ansible-playbook extensions/molecule/default/create.yml -i extensions/molecule/inventory_mock.yml

# Run a single scenario
molecule test -s vault_token_create

# Run all scenarios
molecule test --all

# Run via tox (handles ade install + collection discovery)
tox -e molecule

# Tear down infrastructure
ansible-playbook extensions/molecule/default/destroy.yml -i extensions/molecule/inventory_mock.yml
```

### Collection discovery

Molecule uses `ANSIBLE_COLLECTIONS_PATH: /dev/null` (in `config.yml`) to force
collection discovery via Python's `sys.path`. The collection is installed in editable
mode via `ade install -e .`, and `containers.podman` is installed via `ade install containers.podman`.

### Development setup

```bash
ade install -e . --venv .venv
ade install containers.podman --venv .venv
source .venv/bin/activate
```

### CI

GitHub Actions workflow at `.github/workflows/molecule.yml` runs `tox -e molecule`.
Podman is available by default on GitHub Actions Ubuntu runners.

### Contract verification pattern (examples/ as SOT)

The `examples/` directory is the **single source of truth** for everything: module
invocation, input data, and expected output. Each module's `examples/<module>/` contains:

```
examples/vault_database_role/
  vars.yml          # config dict (input AND expected output) + identifiers
  present.yml       # module call using config + contract assert
  absent.yml        # teardown using identifiers
```

The `vars.yml` is loaded by both the example tasks and Molecule scenarios via:

```yaml
vars_files:
  - "{{ lookup('env', 'MOLECULE_PROJECT_DIRECTORY') }}/examples/vault_database_role/vars.yml"
```

Example playbooks show the vars content as a commented header so users see the
full contract (input + expected output) in the documentation.

#### CRUD modules: `config` is input AND output

For CRUD modules, `vars.yml` contains a `config` dict with the resource fields.
The same dict is used to populate the module call AND to assert the response matches:

```yaml
# examples/vault_database_role/vars.yml
name: test-dynamic-role
mount_path: database
config:
  db_name: my-postgres
  default_ttl: "1h"
  max_ttl: "24h"
```

```yaml
# present.yml -- module uses config, assert proves the contract
- name: Manage Vault database dynamic roles (present)
  hashicorp.vault.vault_database_role:
    url: "{{ vault_addr }}"
    token: "{{ vault_token }}"
    state: present
    name: "{{ name }}"
    db_name: "{{ config.db_name }}"
    default_ttl: "{{ config.default_ttl }}"
    max_ttl: "{{ config.max_ttl }}"
  register: result

- name: Verify return matches contract
  ansible.builtin.assert:
    that:
      - (config | hashicorp.vault.vault_config_match(result.data)).match
    fail_msg: "{{ ... | to_json }}"
```

The `vault_config_match` filter plugin does a **subset comparison** with automatic
**duration normalization** (e.g., `"1h"` matches `3600`). Extra keys in the response
are fine -- only keys in `config` are checked.

#### Action modules: `expected_response_keys`

For action modules where input != output, `vars.yml` has `params` (input) and
`expected_response_keys` (output keys to assert):

```yaml
# examples/vault_token_create/vars.yml
params:
  display_name: my-service-token
  renewable: true
expected_response_keys: [client_token, accessor, policies, renewable]
```

The example asserts each key exists in `result.data`.

#### Ephemeral modules

Modules that can't be re-invoked (token_renew, token_revoke, rotate_root, etc.) rely
on the runtime contract validation in `VaultActionBase` during converge.

### Filter plugin: `vault_config_match`

`plugins/filter/vault_config_match.py` provides the `vault_config_match` filter for
duration-aware subset comparison. It handles:

- Exact value matching for non-duration fields
- Duration normalization: `"1h"` == `3600`, `"24h"` == `86400`, `"72h"` == `259200`
- Subset semantics: only keys in `expected` are checked
- Returns `{match: bool, mismatches: dict, extras: list}`

### Generating scenarios

`tools/generate_molecule_scenarios.py` reads `examples/<module>/` and generates the
appropriate scenario files based on module type (action, crud, info). After generation,
scenarios typically need manual enhancement:

- **Prerequisites**: converge files for info/creds/rotate modules need `uri` tasks to
  create the resource they will read/rotate
- **Verify files**: must be hand-crafted to load vars from `examples/<module>/vars.yml`
- **Vars files**: must be hand-crafted in `examples/<module>/vars.yml` with expected response values
- **Response comments**: add expected response as inline comments in example playbooks

## Unit Testing

Unit tests mock `VaultClient` at the class level:

```python
MOCK_VAULT_CLIENT = (
    "ansible_collections.hashicorp.vault.plugins.plugin_utils"
    ".vault_action_base.VaultClient"
)
```

Test that:
1. The action plugin has OPERATION or OPERATIONS defined
2. The correct HTTP method and path are used
3. The request body contains the right fields
4. Auth args are separated from operation args

## Response Handling and Runtime Contract Validation

Every module returns two keys:

- `data` -- the extracted payload from the Vault response envelope (`data` or `auth` key,
  whichever is populated). This is the argspec-shaped dict consumers should use.
- `raw` -- the full JSON response from Vault (envelope intact).

### Runtime contract validation (hand-crafted)

`VaultActionBase` enforces a **runtime response contract** on every API call. After
extracting `data` from the Vault response, the base class:

1. Builds a relaxed argspec from the module's `DOCUMENTATION` (all fields optional,
   `no_log` stripped, auth/state keys excluded)
2. Filters the response to only include keys present in the argspec
3. Runs the filtered response through `ArgumentSpecValidator`
4. Raises `AnsibleActionFail` if any type mismatches are found

This means **if Vault returns a value whose type doesn't match the module's declared
argspec, the task fails immediately**. The contract is enforced in `_run_action` (action
and info modules) and `_ensure_present` (CRUD modules). The implementation lives in
`_extract_data`, `_build_response_spec`, and `_validate_response_contract` in
`plugins/plugin_utils/vault_action_base.py`.

This is hand-crafted code, not generated. It must be preserved across generator runs.

## Coding Standards

- Python 3.10+, `from __future__ import absolute_import, division, print_function`
- `__metaclass__ = type` in every file
- Formatting: black, isort, flake8 (run via `tox -e linters`)
- Generated files have a header: `# This file is auto-generated by tools/generate_modules.py`
- All sensitive fields use `no_log: true` in DOCUMENTATION and the generator
  matches on field names: `token`, `secret_id`, `password`, `client_secret`, `hmac_key`

## Non-Generated (Hand-Crafted) Code

### Generator safeguards

Files containing the comment `# @hand-crafted` in the first 1 KB are **never
overwritten** by `tools/generate_modules.py`. The generator prints
`Skipped <path>  (@hand-crafted)` so you can verify. Generated files carry
`# @generated` instead.

### Learned API response schemas

**`tools/response_schemas.yaml`** stores the actual response shapes captured from
Vault dev-server molecule runs. The generator reads this file to produce typed
`RETURN` blocks (with `data.contains`) for action modules where input != output.
CRUD/info modules derive their return types from the input argspec automatically.

To refresh: run a molecule scenario, inspect `result.data`/`result.raw`, and
update the YAML. Fields list `type`, `description`, and optional `elements`.
Modules marked `_opaque: true` get a generic `type: dict` return.

### Action plugin overrides

These action plugins carry `# @hand-crafted` and are skipped by the generator:

- **`plugins/action/vault_auth_method.py`**: Entirely hand-crafted CRUD logic.
  Vault has no `GET /v1/sys/auth/{path}` endpoint for individual auth methods.
  Uses `GET /v1/sys/auth` (list all) and searches for the path key. Custom
  `_auth_method_exists`, `_ensure_present`, `_ensure_absent` methods.
- **`plugins/action/vault_token_lookup.py`**: Endpoint changed to
  `POST /v1/auth/token/lookup-self` and request schema set to `None` to avoid
  the `token` parameter collision (auth token vs lookup token).
- **`plugins/action/vault_token_renew.py`**: Endpoint changed to
  `POST /v1/auth/token/renew-self` for the same collision reason.
- **`plugins/action/vault_token_revoke.py`**: Endpoint changed to
  `POST /v1/auth/token/revoke-self` and request schema set to `None`.

### Base class and filter plugin (hand-crafted)

- **`plugins/plugin_utils/vault_action_base.py`**: Not generated. All runtime
  contract validation, response extraction, and the action/CRUD pipeline live here.
  This is the most critical hand-crafted file.
- **`plugins/filter/vault_config_match.py`**: Duration-aware subset comparison filter.
  Used by example playbooks and Molecule verify to assert `config` matches `result.data`.

### Example playbooks (hand-edited)

The following examples were generated but required manual fixes:

- **`examples/vault_auth_method/present.yml`**: Changed `type: service` to
  `type: userpass` (the generator used an invalid backend type).
- **`examples/vault_database_role/present.yml`**: Added Jinja2 escaping for Vault
  template variables in `creation_statements` (`{{ '{{name}}' }}` syntax).
- **`examples/vault_auth_method/absent.yml`**: Changed assertion from `result is changed`
  to `result is not failed` for cleanup resilience.

### Molecule scenarios (hand-crafted)

Generated Molecule scenarios only provide the basic `include_tasks` structure. The
following were manually enhanced:

- **`default/create.yml`**: Entirely hand-crafted. Sets up Podman network, PostgreSQL
  container, Vault dev container, database users, engine mounts, PKI root CA, and
  the shared database connection. All tasks are idempotent.
- **`default/destroy.yml`**: Entirely hand-crafted. Tears down all containers and network.
- **13 converge files** with hand-crafted prerequisites: scenarios that need a resource
  to exist before testing (e.g., creating a dynamic role before reading its info,
  creating a child token before revoking it, generating a CSR before signing it).
  These include: `vault_database_creds`, `vault_database_role_info`,
  `vault_database_static_role_creds`, `vault_database_static_role_info`,
  `vault_database_static_role_rotate`, `vault_database_rotate_root`,
  `vault_pki_cert_info`, `vault_pki_issue`, `vault_pki_role_info`, `vault_pki_sign`,
  `vault_token_role_info`, `vault_token_renew`, `vault_token_revoke`.
- **All `verify.yml` files**: Entirely hand-crafted, load vars from `examples/<module>/vars.yml`.
- **All `examples/<module>/vars.yml` files**: Entirely hand-crafted config dicts + identifiers.
  These live in examples/ (not molecule/) because examples/ is the single source of truth.
- **All example playbooks**: Hand-edited to reference `config` from vars and include
  the contract assert (`vault_config_match` for CRUD, key presence for action).

## Relevant Epics

- **ACA-5341** Token Management -- fully generated from spec
- **ACA-5345** Authentication and Login -- auth method enable/disable generated;
  per-method login modules deferred (need design decision on one module vs per-method)
- **ACA-5348** Database Credential Rotation -- generated from spec (rotate-root, creds)
- **ACA-5351** Database Static Roles Management -- generated from spec (static role CRUD, creds, info, rotate)
- **ACA-5355** Database Dynamic Roles Management -- generated from spec (role CRUD, role_info)
- **ACA-5359** PKI Certificate Generation -- generated from spec (issue, sign, role CRUD, role_info, cert_info)
