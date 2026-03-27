#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Generate Ansible action plugins, module docs, request dataclasses, and
test scaffolding from a HashiCorp Vault OpenAPI specification.

Usage:
    python -m tools.generate_modules --spec ../hashi_vault_research/vault-spec.json

The spec file is the raw JSON response from Vault's
``/v1/sys/internal/specs/openapi`` endpoint.  The real OpenAPI document
lives under the ``data`` key of that envelope.
"""

from __future__ import annotations

import argparse
import json
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

COLLECTION_ROOT = Path(__file__).resolve().parent.parent
RESPONSE_SCHEMAS_PATH = Path(__file__).resolve().parent / "response_schemas.yaml"

HAND_CRAFTED_MARKER = "# @hand-crafted"
GENERATED_MARKER = "# @generated"

# ---------------------------------------------------------------------------
# Type mapping: OpenAPI -> Python / Ansible
# ---------------------------------------------------------------------------

OPENAPI_TO_PYTHON = {
    "string": "str",
    "boolean": "bool",
    "integer": "int",
    "number": "float",
}

OPENAPI_TO_ANSIBLE = {
    "string": "str",
    "boolean": "bool",
    "integer": "int",
    "number": "float",
}

NO_LOG_FIELDS = frozenset({"token", "secret_id", "password", "client_secret", "hmac_key"})

DEPRECATED_FIELDS = frozenset({"lease"})

# Fields that collide with Python builtins; the dataclass uses a trailing
# underscore while the Ansible option and JSON body keep the original name.
PYTHON_RESERVED = frozenset({"type", "id", "format", "list"})

# ---------------------------------------------------------------------------
# Module configuration
# ---------------------------------------------------------------------------


@dataclass
class OperationRef:
    """Reference to a single OpenAPI operation for code generation."""

    operation_id: str
    method: str = ""
    path: str = ""
    schema_ref: str = ""
    summary: str = ""


@dataclass
class ModuleConfig:
    """Configuration describing a module to generate."""

    name: str
    module_type: str  # "action", "crud", "info"
    area: str  # grouping for generated dataclass files (e.g. "token", "auth")
    operations: List[OperationRef] = field(default_factory=list)
    path_params: List[str] = field(default_factory=list)
    short_description: str = ""
    manual_schema: Optional[Dict[str, Any]] = None


# fmt: off
MODULES: List[ModuleConfig] = [
    # -- Token Management (ACA-5341) ----------------------------------------
    ModuleConfig(
        name="vault_token_create",
        module_type="action",
        area="token",
        operations=[OperationRef("token-create")],
        short_description="Create a new Vault token",
    ),
    ModuleConfig(
        name="vault_token_lookup",
        module_type="action",
        area="token",
        operations=[OperationRef("token-look-up")],
        short_description="Look up information about a Vault token",
    ),
    ModuleConfig(
        name="vault_token_renew",
        module_type="action",
        area="token",
        operations=[OperationRef("token-renew")],
        short_description="Renew a Vault token",
    ),
    ModuleConfig(
        name="vault_token_revoke",
        module_type="action",
        area="token",
        operations=[OperationRef("token-revoke")],
        short_description="Revoke a Vault token",
    ),
    ModuleConfig(
        name="vault_token_list_accessors",
        module_type="info",
        area="token",
        operations=[OperationRef("token-list-accessors")],
        short_description="List all token accessors",
    ),
    ModuleConfig(
        name="vault_token_role",
        module_type="crud",
        area="token",
        operations=[
            OperationRef("token-write-role"),
            OperationRef("token-read-role"),
            OperationRef("token-delete-role"),
        ],
        path_params=["role_name"],
        short_description="Manage Vault token roles",
    ),
    ModuleConfig(
        name="vault_token_role_info",
        module_type="info",
        area="token",
        operations=[OperationRef("token-read-role"), OperationRef("token-list-roles")],
        path_params=["role_name"],
        short_description="Read or list Vault token roles",
    ),
    # -- Authentication (ACA-5345) ------------------------------------------
    ModuleConfig(
        name="vault_auth_method",
        module_type="crud",
        area="auth",
        operations=[
            OperationRef("auth-enable-method"),
            OperationRef("auth-read-configuration"),
            OperationRef("auth-disable-method"),
        ],
        path_params=["path"],
        short_description="Manage Vault auth methods",
    ),
    ModuleConfig(
        name="vault_auth_method_info",
        module_type="info",
        area="auth",
        operations=[OperationRef("auth-list-enabled-methods")],
        short_description="List enabled Vault auth methods",
    ),
    # -- Database Credential Rotation (ACA-5348) ----------------------------
    ModuleConfig(
        name="vault_database_rotate_root",
        module_type="action",
        area="database",
        operations=[OperationRef("database-rotate-root", method="POST",
                                 path="v1/{mount_path}/rotate-root/{name}")],
        path_params=["name", "mount_path"],
        short_description="Rotate the root credentials for a database connection",
        manual_schema={"name": {"type": "string", "description": "Name of the database connection", "required": True},
                       "mount_path": {"type": "string", "description": "Mount path of the database secrets engine", "default": "database"}},
    ),
    ModuleConfig(
        name="vault_database_creds",
        module_type="info",
        area="database",
        operations=[OperationRef("database-creds", method="GET",
                                 path="v1/{mount_path}/creds/{role_name}")],
        path_params=["role_name", "mount_path"],
        short_description="Generate dynamic database credentials",
        manual_schema={"role_name": {"type": "string", "description": "Name of the database role", "required": True},
                       "mount_path": {"type": "string", "description": "Mount path of the database secrets engine", "default": "database"}},
    ),
    # -- Database Static Roles (ACA-5351) -----------------------------------
    ModuleConfig(
        name="vault_database_static_role",
        module_type="crud",
        area="database",
        operations=[
            OperationRef("database-write-static-role", method="POST",
                         path="v1/{mount_path}/static-roles/{name}"),
            OperationRef("database-read-static-role", method="GET",
                         path="v1/{mount_path}/static-roles/{name}"),
            OperationRef("database-delete-static-role", method="DELETE",
                         path="v1/{mount_path}/static-roles/{name}"),
        ],
        path_params=["name", "mount_path"],
        short_description="Manage Vault database static roles",
        manual_schema={
            "name": {"type": "string", "description": "Name of the static role", "required": True},
            "mount_path": {"type": "string", "description": "Mount path of the database secrets engine", "default": "database"},
            "db_name": {"type": "string", "description": "Name of the database connection to use"},
            "username": {"type": "string", "description": "Database username that this role corresponds to"},
            "rotation_period": {
                "type": "string",
                "description": "Period for automatic credential rotation (e.g. '24h'). "
                "Mutually exclusive with rotation_schedule.",
            },
            "rotation_schedule": {
                "type": "string",
                "description": "Cron-style schedule for credential rotation. "
                "Mutually exclusive with rotation_period.",
            },
            "rotation_window": {"type": "integer", "description": "Window in seconds for scheduled rotation"},
            "rotation_statements": {"type": "array", "items": {"type": "string"}, "description": "SQL statements to rotate the password"},
            "credential_type": {"type": "string", "description": "Type of credential to manage (e.g. 'password')"},
            "credential_config": {"type": "object", "description": "Configuration for the credential type"},
        },
    ),
    ModuleConfig(
        name="vault_database_static_role_info",
        module_type="info",
        area="database",
        operations=[
            OperationRef("database-read-static-role", method="GET",
                         path="v1/{mount_path}/static-roles/{name}"),
            OperationRef("database-list-static-roles", method="LIST",
                         path="v1/{mount_path}/static-roles"),
        ],
        path_params=["name", "mount_path"],
        short_description="Read or list Vault database static roles",
        manual_schema={
            "name": {"type": "string", "description": "Name of the static role. Omit to list all."},
            "mount_path": {"type": "string", "description": "Mount path of the database secrets engine", "default": "database"},
        },
    ),
    ModuleConfig(
        name="vault_database_static_role_creds",
        module_type="info",
        area="database",
        operations=[OperationRef("database-static-role-creds", method="GET",
                                 path="v1/{mount_path}/static-creds/{name}")],
        path_params=["name", "mount_path"],
        short_description="Read current credentials for a database static role",
        manual_schema={
            "name": {"type": "string", "description": "Name of the static role", "required": True},
            "mount_path": {"type": "string", "description": "Mount path of the database secrets engine", "default": "database"},
        },
    ),
    ModuleConfig(
        name="vault_database_static_role_rotate",
        module_type="action",
        area="database",
        operations=[OperationRef("database-rotate-static-role", method="POST",
                                 path="v1/{mount_path}/rotate-role/{name}")],
        path_params=["name", "mount_path"],
        short_description="Force rotation of database static role credentials",
        manual_schema={
            "name": {"type": "string", "description": "Name of the static role", "required": True},
            "mount_path": {"type": "string", "description": "Mount path of the database secrets engine", "default": "database"},
        },
    ),
    # -- Database Dynamic Roles (ACA-5355) -----------------------------------
    ModuleConfig(
        name="vault_database_role",
        module_type="crud",
        area="database",
        operations=[
            OperationRef("database-write-role", method="POST",
                         path="v1/{mount_path}/roles/{name}"),
            OperationRef("database-read-role", method="GET",
                         path="v1/{mount_path}/roles/{name}"),
            OperationRef("database-delete-role", method="DELETE",
                         path="v1/{mount_path}/roles/{name}"),
        ],
        path_params=["name", "mount_path"],
        short_description="Manage Vault database dynamic roles",
        manual_schema={
            "name": {"type": "string", "description": "Name of the dynamic role", "required": True},
            "mount_path": {"type": "string", "description": "Mount path of the database secrets engine", "default": "database"},
            "db_name": {"type": "string", "description": "Name of the database connection to use"},
            "creation_statements": {"type": "array", "items": {"type": "string"}, "description": "Database statements to create and configure a user"},
            "revocation_statements": {"type": "array", "items": {"type": "string"}, "description": "Database statements to revoke a user"},
            "renew_statements": {"type": "array", "items": {"type": "string"}, "description": "Database statements to renew a user"},
            "rollback_statements": {"type": "array", "items": {"type": "string"}, "description": "Database statements to rollback a create operation"},
            "credential_type": {"type": "string", "description": "Type of credential to manage", "default": "password"},
            "credential_config": {"type": "object", "description": "Configuration for the credential type"},
            "default_ttl": {"type": "string", "description": "Default TTL for generated credentials"},
            "max_ttl": {"type": "string", "description": "Maximum TTL for generated credentials"},
        },
    ),
    ModuleConfig(
        name="vault_database_role_info",
        module_type="info",
        area="database",
        operations=[
            OperationRef("database-read-role", method="GET",
                         path="v1/{mount_path}/roles/{name}"),
            OperationRef("database-list-roles", method="LIST",
                         path="v1/{mount_path}/roles/"),
        ],
        path_params=["name", "mount_path"],
        short_description="Read or list Vault database dynamic roles",
        manual_schema={
            "name": {"type": "string", "description": "Name of the dynamic role. Omit to list all."},
            "mount_path": {"type": "string", "description": "Mount path of the database secrets engine", "default": "database"},
        },
    ),
    # -- PKI Certificate Generation (ACA-5359) ------------------------------
    ModuleConfig(
        name="vault_pki_issue",
        module_type="action",
        area="pki",
        operations=[OperationRef("pki-issue-with-role", method="POST",
                                 path="v1/{mount_path}/issue/{role}",
                                 schema_ref="#/components/schemas/PkiIssueWithRoleRequest")],
        path_params=["role", "mount_path"],
        short_description="Issue a certificate from a PKI role",
        manual_schema={
            "role": {"type": "string", "description": "Name of the PKI role to issue against", "required": True},
            "mount_path": {"type": "string", "description": "Mount path of the PKI secrets engine", "default": "pki"},
        },
    ),
    ModuleConfig(
        name="vault_pki_sign",
        module_type="action",
        area="pki",
        operations=[OperationRef("pki-sign-with-role", method="POST",
                                 path="v1/{mount_path}/sign/{role}",
                                 schema_ref="#/components/schemas/PkiSignWithRoleRequest")],
        path_params=["role", "mount_path"],
        short_description="Sign a CSR using a PKI role",
        manual_schema={
            "role": {"type": "string", "description": "Name of the PKI role to sign with", "required": True},
            "mount_path": {"type": "string", "description": "Mount path of the PKI secrets engine", "default": "pki"},
        },
    ),
    ModuleConfig(
        name="vault_pki_role",
        module_type="crud",
        area="pki",
        operations=[
            OperationRef("pki-write-role", method="POST",
                         path="v1/{mount_path}/roles/{name}",
                         schema_ref="#/components/schemas/PkiWriteRoleRequest"),
            OperationRef("pki-read-role", method="GET",
                         path="v1/{mount_path}/roles/{name}"),
            OperationRef("pki-delete-role", method="DELETE",
                         path="v1/{mount_path}/roles/{name}"),
        ],
        path_params=["name", "mount_path"],
        short_description="Manage Vault PKI roles",
        manual_schema={
            "name": {"type": "string", "description": "Name of the PKI role", "required": True},
            "mount_path": {"type": "string", "description": "Mount path of the PKI secrets engine", "default": "pki"},
        },
    ),
    ModuleConfig(
        name="vault_pki_role_info",
        module_type="info",
        area="pki",
        operations=[
            OperationRef("pki-read-role", method="GET",
                         path="v1/{mount_path}/roles/{name}"),
            OperationRef("pki-list-roles", method="LIST",
                         path="v1/{mount_path}/roles/"),
        ],
        path_params=["name", "mount_path"],
        short_description="Read or list Vault PKI roles",
        manual_schema={
            "name": {"type": "string", "description": "Name of the PKI role. Omit to list all."},
            "mount_path": {"type": "string", "description": "Mount path of the PKI secrets engine", "default": "pki"},
        },
    ),
    ModuleConfig(
        name="vault_pki_cert_info",
        module_type="info",
        area="pki",
        operations=[OperationRef("pki-read-cert", method="GET",
                                 path="v1/{mount_path}/cert/{serial}")],
        path_params=["serial", "mount_path"],
        short_description="Read a PKI certificate by serial number",
        manual_schema={
            "serial": {"type": "string", "description": "Serial number of the certificate to read", "required": True},
            "mount_path": {"type": "string", "description": "Mount path of the PKI secrets engine", "default": "pki"},
        },
    ),
]
# fmt: on


# ---------------------------------------------------------------------------
# Spec parsing
# ---------------------------------------------------------------------------


def load_spec(spec_path: str) -> Dict[str, Any]:
    """Load a Vault OpenAPI spec, stripping the response envelope."""
    with open(spec_path) as f:
        raw = json.load(f)
    return raw.get("data", raw)


def resolve_ref(spec: Dict[str, Any], ref: str) -> Dict[str, Any]:
    """Resolve a $ref like '#/components/schemas/Foo' to the schema dict."""
    parts = ref.lstrip("#/").split("/")
    obj = spec
    for part in parts:
        obj = obj[part]
    return obj


def find_operation(spec: Dict[str, Any], operation_id: str):
    """Find a path+method+operation by operationId.

    Vault models LIST operations as GET with a required ``list=true``
    query parameter.  This function detects that pattern and returns
    ``"LIST"`` as the method so callers emit the right HTTP verb.
    """
    for path, path_item in spec.get("paths", {}).items():
        for method in ("get", "post", "put", "delete", "patch", "list"):
            op = path_item.get(method)
            if op and op.get("operationId") == operation_id:
                params = path_item.get("parameters", [])
                effective_method = method.upper()
                if effective_method == "GET":
                    op_params = op.get("parameters", [])
                    for p in op_params:
                        if p.get("name") == "list" and p.get("required"):
                            effective_method = "LIST"
                            break
                return path, effective_method, op, params
    return None, None, None, None


def extract_schema(spec: Dict[str, Any], operation: Dict[str, Any]):
    """Extract the request body schema ref and resolved schema for an operation."""
    rb = operation.get("requestBody", {})
    content = rb.get("content", {}).get("application/json", {})
    schema_info = content.get("schema", {})
    ref = schema_info.get("$ref", "")
    if ref:
        return ref, resolve_ref(spec, ref)
    return "", schema_info if schema_info else {}


def enrich_operations(spec: Dict[str, Any], module: ModuleConfig):
    """Fill in method/path/schema_ref from the spec for each operation."""
    for op_ref in module.operations:
        if op_ref.method and op_ref.path:
            continue
        path, method, op, _params = find_operation(spec, op_ref.operation_id)
        if op is None:
            print(f"  WARNING: operationId '{op_ref.operation_id}' not found in spec")
            continue
        op_ref.method = method
        op_ref.path = f"v1{path}"
        op_ref.summary = op.get("summary", "")
        ref, _schema = extract_schema(spec, op)
        op_ref.schema_ref = ref


# ---------------------------------------------------------------------------
# Schema -> field list
# ---------------------------------------------------------------------------


@dataclass
class FieldDef:
    name: str
    python_type: str
    ansible_type: str
    description: str = ""
    default: Any = None
    has_default: bool = False
    required: bool = False
    no_log: bool = False
    deprecated: bool = False
    elements: str = ""
    is_path_param: bool = False


def schema_to_fields(
    schema: Dict[str, Any],
    path_params: List[str],
) -> List[FieldDef]:
    """Convert an OpenAPI schema's properties to a list of FieldDefs."""
    fields = []
    props = schema.get("properties", {})
    required_set = set(schema.get("required", []))

    for name, prop in sorted(props.items()):
        if name in DEPRECATED_FIELDS:
            continue

        oa_type = prop.get("type", "string")
        python_type = OPENAPI_TO_PYTHON.get(oa_type, "str")
        ansible_type = OPENAPI_TO_ANSIBLE.get(oa_type, "str")
        elements = ""

        if oa_type == "array":
            items_type = prop.get("items", {}).get("type", "string")
            python_type = f"List[{OPENAPI_TO_PYTHON.get(items_type, 'str')}]"
            ansible_type = "list"
            elements = OPENAPI_TO_ANSIBLE.get(items_type, "str")

        if oa_type == "object":
            fmt = prop.get("format", "")
            if fmt in ("kvpairs", "map"):
                python_type = "Dict[str, str]"
                ansible_type = "dict"
            else:
                python_type = "dict"
                ansible_type = "dict"

        default = prop.get("default")
        has_default = "default" in prop
        if has_default and oa_type == "string" and not isinstance(default, str):
            default = str(default)

        fd = FieldDef(
            name=name,
            python_type=python_type,
            ansible_type=ansible_type,
            description=prop.get("description", ""),
            default=default,
            has_default=has_default,
            required=name in required_set or prop.get("required", False),
            no_log=name in NO_LOG_FIELDS,
            deprecated=prop.get("deprecated", False),
            elements=elements,
            is_path_param=name in path_params,
        )
        fields.append(fd)

    return fields


# ---------------------------------------------------------------------------
# Code generation helpers
# ---------------------------------------------------------------------------


def python_field_name(name: str) -> str:
    """Return a safe Python identifier for a field name."""
    if name in PYTHON_RESERVED:
        return f"{name}_"
    return name


def _indent(text: str, spaces: int = 4) -> str:
    return textwrap.indent(text, " " * spaces)


def _wrap_description(desc: str, width: int = 72) -> str:
    if not desc:
        return ""
    lines = textwrap.wrap(desc, width=width)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Generate: request dataclasses
# ---------------------------------------------------------------------------


def generate_dataclass_file(area: str, schemas: Dict[str, List[FieldDef]]) -> str:
    """Generate a Python file with request dataclasses for an API area."""
    lines = [
        "# -*- coding: utf-8 -*-",
        "",
        "# @generated",
        "# This file is auto-generated by tools/generate_modules.py",
        "# Do not edit manually -- re-run the generator instead.",
        "",
        "from __future__ import absolute_import, division, print_function",
        "",
        "__metaclass__ = type",
        "",
        "from dataclasses import dataclass, field",
        "from typing import Dict, List, Optional",
        "",
        "",
    ]

    for schema_name, fields in sorted(schemas.items()):
        lines.append("@dataclass")
        lines.append(f"class {schema_name}:")
        # Docstring
        lines.append(f'    """Request body for the {schema_name} operation."""')
        lines.append("")

        required_fields = [f for f in fields if f.required and not f.has_default]
        optional_fields = [f for f in fields if not f.required or f.has_default]

        for fd in required_fields + optional_fields:
            pname = python_field_name(fd.name)
            if fd.required and not fd.has_default:
                type_str = fd.python_type
                default_str = ""
            elif fd.has_default:
                type_str = f"Optional[{fd.python_type}]"
                default_val = repr(fd.default)
                if isinstance(fd.default, (list, dict)):
                    default_str = f" = field(default_factory=lambda: {default_val})"
                else:
                    default_str = f" = field(default={default_val})"
            else:
                type_str = f"Optional[{fd.python_type}]"
                default_str = " = None"
            lines.append(f"    {pname}: {type_str}{default_str}")

        lines.append("")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Generate: module documentation (plugins/modules/<name>.py)
# ---------------------------------------------------------------------------


def _contains_from_response_schema(schema: Dict[str, Any]) -> str:
    """Build RETURN ``contains`` YAML from a response_schemas.yaml entry."""
    lines = []
    for fname, fdef in schema.get("fields", {}).items():
        lines.append(f"    {fname}:")
        desc = fdef.get("description", f"The {fname.replace('_', ' ')} value")
        if ": " in desc or '"' in desc:
            desc = desc.replace("'", "''")
            lines.append(f"      description: '{desc}'")
        else:
            lines.append(f"      description: {desc}")
        lines.append(f"      type: {fdef['type']}")
        lines.append("      returned: success")
        if "elements" in fdef:
            lines.append(f"      elements: {fdef['elements']}")
    return "\n".join(lines)


def _generate_return_block(
    module: ModuleConfig,
    fields: List[FieldDef],
    response_schemas: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate a typed RETURN block.

    Resolution order:
    1. ``response_schemas`` (tools/response_schemas.yaml) -- authoritative
       for action modules and special info modules.
    2. Input argspec fields -- used for CRUD/info modules where input == output.
    3. Generic fallback -- bare ``type: dict`` when nothing else is available.
    """
    response_schemas = response_schemas or {}
    rs = response_schemas.get(module.name)

    # --- learned schema from response_schemas.yaml -----------------------
    if rs and not rs.get("_opaque") and rs.get("fields"):
        contains_yaml = _contains_from_response_schema(rs)
        envelope = rs.get("_envelope", "data")
        custom_desc = rs.get("_description")
        if custom_desc:
            desc_block = f"  description: >-\n    {custom_desc.strip()}"
        else:
            desc_block = (
                f"  description: >-\n"
                f"    Extracted payload from the Vault C({envelope}) response envelope.\n"
                f"    Validated against the module argspec at runtime."
            )
        return f'''RETURN = """
data:
{desc_block}
  returned: success
  type: dict
  contains:
{contains_yaml}
raw:
  description: The full JSON response from Vault including the envelope.
  returned: success
  type: dict
"""'''

    # --- CRUD/info: derive from input argspec ----------------------------
    skip_fields = {"state"}
    return_fields = [
        fd
        for fd in fields
        if not fd.deprecated and not fd.no_log and not fd.is_path_param and fd.name not in skip_fields
    ]

    if return_fields and module.module_type in ("crud", "info"):
        contains_lines = []
        for fd in return_fields:
            contains_lines.append(f"    {fd.name}:")
            if fd.description:
                short = fd.description.split(".")[0].strip()
                if len(short) > 70:
                    short = short[:67] + "..."
                if ": " in short or '"' in short:
                    short = short.replace("'", "''")
                    contains_lines.append(f"      description: '{short}'")
                else:
                    contains_lines.append(f"      description: {short}")
            else:
                contains_lines.append(f"      description: The {fd.name.replace('_', ' ')} value")
            contains_lines.append(f"      type: {fd.ansible_type}")
            contains_lines.append("      returned: success")
            if fd.elements:
                contains_lines.append(f"      elements: {fd.elements}")

        contains_yaml = "\n".join(contains_lines)
        return f'''RETURN = """
data:
  description: >-
    Extracted payload from the Vault response envelope.
    Validated against the module argspec at runtime.
  returned: success
  type: dict
  contains:
{contains_yaml}
raw:
  description: The full JSON response from Vault including the envelope.
  returned: success
  type: dict
"""'''

    # --- fallback: generic dict ------------------------------------------
    return '''RETURN = """
data:
  description: >-
    Extracted payload from the Vault response envelope. Contains the
    resource fields from the C(data) or C(auth) key of the API response.
    Validated against the module argspec at runtime.
  returned: success
  type: dict
raw:
  description: The full JSON response from Vault including the envelope.
  returned: success
  type: dict
"""'''


def generate_module_doc(
    module: ModuleConfig,
    fields: List[FieldDef],
    response_schemas: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate the module documentation file (DOCUMENTATION only)."""
    option_lines = []
    for fd in fields:
        if fd.deprecated:
            continue
        opt = [f"    {fd.name}:"]
        if fd.description:
            wrapped = _wrap_description(fd.description, width=60)
            desc_lines = wrapped.split("\n")
            if len(desc_lines) == 1:
                val = desc_lines[0]
                if ": " in val or '"' in val:
                    escaped = val.replace("'", "''")
                    opt.append(f"      description: '{escaped}'")
                else:
                    opt.append(f"      description: {val}")
            else:
                opt.append("      description:")
                for dl in desc_lines:
                    if '"' in dl or ": " in dl:
                        escaped = dl.replace("'", "''")
                        opt.append(f"        - '{escaped}'")
                    else:
                        opt.append(f"        - {dl}")
        opt.append(f"      type: {fd.ansible_type}")
        if fd.elements:
            opt.append(f"      elements: {fd.elements}")
        if fd.required:
            opt.append("      required: true")
        if fd.has_default and fd.default is not None:
            default_val = str(fd.default).lower() if isinstance(fd.default, bool) else fd.default
            opt.append(f"      default: {default_val}")
        if fd.no_log:
            opt.append("      no_log: true")
        option_lines.append("\n".join(opt))

    options_yaml = "\n".join(option_lines)

    state_option = ""
    if module.module_type == "crud":
        state_option = """\
    state:
      description: Desired state of the resource.
      type: str
      choices: ['present', 'absent']
      default: present"""

    all_options = "\n".join(filter(None, [state_option, options_yaml]))
    options_block = f"options:\n{all_options}" if all_options.strip() else ""

    # Build EXAMPLES
    example_args = []
    for fd in fields:
        if fd.deprecated or fd.is_path_param:
            continue
        if fd.required:
            if fd.ansible_type == "str":
                example_args.append(f"    {fd.name}: example_{fd.name}")
            elif fd.ansible_type == "list":
                example_args.append(f"    {fd.name}:\n      - example")
            elif fd.ansible_type == "bool":
                example_args.append(f"    {fd.name}: true")
            elif fd.ansible_type == "int":
                example_args.append(f"    {fd.name}: 0")
    for fd in fields:
        if fd.is_path_param and fd.required:
            example_args.append(f"    {fd.name}: example_{fd.name}")
    if module.module_type == "crud":
        example_args.insert(0, "    state: present")
    example_str = "\n".join(example_args) if example_args else "    {}"

    is_manual = module.manual_schema is not None
    todo_marker = (
        "\n# TODO: update from captured OpenAPI spec when database engine paths are available" if is_manual else ""
    )

    return f'''\
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# @generated
# This file is auto-generated by tools/generate_modules.py
# Do not edit manually -- re-run the generator instead.{todo_marker}

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: {module.name}
short_description: {module.short_description}
description:
  - {module.short_description} using the Vault HTTP API.
version_added: "2.0.0"
author:
  - HashiCorp Vault Collection Contributors
extends_documentation_fragment:
  - hashicorp.vault.vault_auth.modules
{options_block}
"""

EXAMPLES = """
- name: {module.short_description}
  hashicorp.vault.{module.name}:
    url: https://vault.example.com:8200
    token: hvs.example
{example_str}
"""

{_generate_return_block(module, fields, response_schemas)}
'''


# ---------------------------------------------------------------------------
# Generate: action plugin (plugins/action/<name>.py)
# ---------------------------------------------------------------------------


def _operation_import(op_ref: OperationRef) -> str:
    """Build the Operation() constructor call for an operation ref."""
    schema_name = op_ref.schema_ref.split("/")[-1] if op_ref.schema_ref else ""
    schema_arg = schema_name if schema_name else "None"
    return f'Operation("{op_ref.method}", "{op_ref.path}", {schema_arg})'


def generate_action_plugin(module: ModuleConfig, schemas_in_area: set) -> str:
    """Generate the action plugin file."""
    # Collect schema imports
    schema_imports = set()
    for op in module.operations:
        if op.schema_ref:
            schema_name = op.schema_ref.split("/")[-1]
            if schema_name in schemas_in_area:
                schema_imports.add(schema_name)

    import_lines = []
    if schema_imports:
        names = ", ".join(sorted(schema_imports))
        import_lines.append(
            f"from ansible_collections.hashicorp.vault.plugins.plugin_utils.generated.{module.area} import ("
        )
        for s in sorted(schema_imports):
            import_lines.append(f"    {s},")
        import_lines.append(")")

    imports_block = "\n".join(import_lines)

    is_manual = module.manual_schema is not None
    todo_marker = (
        "\n# TODO: update from captured OpenAPI spec when database engine paths are available" if is_manual else ""
    )

    if module.module_type == "action" or module.module_type == "info":
        op = module.operations[0]
        op_str = _operation_import(op)

        changed_line = ""
        if module.module_type == "info":
            changed_line = "\n    CHANGED_ON_SUCCESS = False"

        return f'''\
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# @generated
# This file is auto-generated by tools/generate_modules.py
# Do not edit manually -- re-run the generator instead.{todo_marker}

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.hashicorp.vault.plugins.plugin_utils.operation import Operation
from ansible_collections.hashicorp.vault.plugins.plugin_utils.vault_action_base import VaultActionBase
{imports_block}


class ActionModule(VaultActionBase):
    """{module.short_description}."""

    OPERATION = {op_str}{changed_line}
'''

    elif module.module_type == "crud":
        # Find the write, read, and delete operations
        write_op = next((o for o in module.operations if o.method == "POST"), None)
        read_op = next((o for o in module.operations if o.method == "GET"), None)
        delete_op = next((o for o in module.operations if o.method == "DELETE"), None)

        ops_lines = ["    OPERATIONS = {"]
        if write_op:
            ops_lines.append(f'        "present": {_operation_import(write_op)},')
        if read_op:
            ops_lines.append(f'        "read": {_operation_import(read_op)},')
        if delete_op:
            ops_lines.append(f'        "absent": {_operation_import(delete_op)},')
        ops_lines.append("    }")

        ops_block = "\n".join(ops_lines)

        return f'''\
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# @generated
# This file is auto-generated by tools/generate_modules.py
# Do not edit manually -- re-run the generator instead.{todo_marker}

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.hashicorp.vault.plugins.plugin_utils.operation import Operation
from ansible_collections.hashicorp.vault.plugins.plugin_utils.vault_action_base import VaultActionBase
{imports_block}


class ActionModule(VaultActionBase):
    """{module.short_description}."""

{ops_block}
'''

    return ""


# ---------------------------------------------------------------------------
# Generate: unit test scaffolding
# ---------------------------------------------------------------------------


def generate_test(module: ModuleConfig) -> str:
    """Generate a unit test file for an action plugin."""
    op = module.operations[0]

    return f'''\
# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# @generated
# This file is auto-generated by tools/generate_modules.py
# Extend with additional test cases as needed.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest


MOCK_VAULT_CLIENT = "ansible_collections.hashicorp.vault.plugins.plugin_utils.vault_action_base.VaultClient"


@pytest.fixture
def action_module():
    """Create an instance of the action plugin with mocked Ansible internals."""
    from ansible_collections.hashicorp.vault.plugins.action.{module.name} import ActionModule

    task = MagicMock()
    task.action = "hashicorp.vault.{module.name}"
    task.args = {{
        "url": "https://vault.example.com:8200",
        "namespace": "admin",
        "auth_method": "token",
        "token": "hvs.test-token",
    }}
    connection = MagicMock()
    play_context = MagicMock()
    loader = MagicMock()
    templar = MagicMock()
    shared_loader_obj = MagicMock()

    action = ActionModule(
        task=task,
        connection=connection,
        play_context=play_context,
        loader=loader,
        templar=templar,
        shared_loader_obj=shared_loader_obj,
    )
    return action, task


class TestActionModule:
    """Tests for {module.name} action plugin."""

    def test_operation_defined(self, action_module):
        """Verify the action plugin has an operation configured."""
        action, _task = action_module
        if hasattr(action, "OPERATION") and action.OPERATION is not None:
            assert action.OPERATION.method == "{op.method}"
            assert "{op.path}" in action.OPERATION.path
        elif hasattr(action, "OPERATIONS") and action.OPERATIONS is not None:
            assert len(action.OPERATIONS) > 0
        else:
            pytest.fail("ActionModule must define OPERATION or OPERATIONS")
'''


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------


def _is_hand_crafted(path: Path) -> bool:
    """Return True if *path* exists and contains the @hand-crafted marker."""
    if not path.exists():
        return False
    try:
        head = path.read_text()[:1024]
    except OSError:
        return False
    return HAND_CRAFTED_MARKER in head


def _safe_write(path: Path, content: str, *, dry_run: bool = False) -> bool:
    """Write *content* to *path*, respecting the @hand-crafted marker.

    Returns True if the file was written, False if it was skipped.
    """
    if _is_hand_crafted(path):
        print(f"  Skipped {path}  (@hand-crafted)")
        return False
    if dry_run:
        print(f"\n--- {path} ---")
        print(content[:500] + "...")
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    print(f"  Generated {path}")
    return True


def _load_response_schemas() -> Dict[str, Any]:
    """Load learned response schemas from tools/response_schemas.yaml."""
    if not RESPONSE_SCHEMAS_PATH.exists():
        return {}
    with open(RESPONSE_SCHEMAS_PATH) as fh:
        return yaml.safe_load(fh) or {}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--spec",
        default=str(Path(__file__).resolve().parent.parent.parent / "hashi_vault_research" / "vault-spec.json"),
        help="Path to the Vault OpenAPI spec JSON file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be generated without writing files",
    )
    args = parser.parse_args()

    spec = load_spec(args.spec)
    print(
        f"Loaded spec: {spec.get('info', {}).get('title', 'unknown')} " f"v{spec.get('info', {}).get('version', '?')}"
    )

    # Enrich operation refs from spec
    for module in MODULES:
        enrich_operations(spec, module)

    # Group schemas by area
    area_schemas: Dict[str, Dict[str, List[FieldDef]]] = {}

    for module in MODULES:
        if module.manual_schema:
            fields = schema_to_fields(
                {"properties": module.manual_schema},
                module.path_params,
            )
            schema_name = f"{module.name.replace('vault_', '').title().replace('_', '')}Request"
            area_schemas.setdefault(module.area, {})[schema_name] = fields
            for op in module.operations:
                if op.method == "POST" and not op.schema_ref:
                    op.schema_ref = f"#/components/schemas/{schema_name}"

        for op_ref in module.operations:
            if not op_ref.schema_ref:
                continue
            schema_name = op_ref.schema_ref.split("/")[-1]
            if schema_name in area_schemas.get(module.area, {}):
                continue
            try:
                schema = resolve_ref(spec, op_ref.schema_ref)
            except (KeyError, TypeError):
                print(f"  WARNING: could not resolve {op_ref.schema_ref}")
                continue
            fields = schema_to_fields(schema, module.path_params)
            area_schemas.setdefault(module.area, {})[schema_name] = fields

    # Generate dataclass files
    generated_dir = COLLECTION_ROOT / "plugins" / "plugin_utils" / "generated"
    generated_dir.mkdir(parents=True, exist_ok=True)
    (generated_dir / "__init__.py").touch()

    for area, schemas in area_schemas.items():
        content = generate_dataclass_file(area, schemas)
        out_path = generated_dir / f"{area}.py"
        _safe_write(out_path, content, dry_run=args.dry_run)

    response_schemas = _load_response_schemas()

    # Generate module docs, action plugins, and tests
    for module in MODULES:
        schemas_in_area = set(area_schemas.get(module.area, {}).keys())

        # Collect all fields for this module's docs
        all_fields = []
        seen_field_names = set()

        # Add path params that aren't from the schema
        for pp in module.path_params:
            if pp not in seen_field_names:
                desc = f"Path parameter: {pp}"
                if module.manual_schema and pp in module.manual_schema:
                    desc = module.manual_schema[pp].get("description", desc)
                req = True
                default = None
                has_default = False
                if module.manual_schema and pp in module.manual_schema:
                    req = module.manual_schema[pp].get("required", False)
                    if "default" in module.manual_schema[pp]:
                        default = module.manual_schema[pp]["default"]
                        has_default = True
                        req = False
                all_fields.append(
                    FieldDef(
                        name=pp,
                        python_type="str",
                        ansible_type="str",
                        description=desc,
                        required=req,
                        default=default,
                        has_default=has_default,
                        is_path_param=True,
                    )
                )
                seen_field_names.add(pp)

        # Add fields from schemas
        for op_ref in module.operations:
            if not op_ref.schema_ref:
                continue
            schema_name = op_ref.schema_ref.split("/")[-1]
            schema_fields = area_schemas.get(module.area, {}).get(schema_name, [])
            for fd in schema_fields:
                if fd.name not in seen_field_names and not fd.is_path_param:
                    all_fields.append(fd)
                    seen_field_names.add(fd.name)

        # Module doc
        mod_content = generate_module_doc(module, all_fields, response_schemas)
        mod_path = COLLECTION_ROOT / "plugins" / "modules" / f"{module.name}.py"
        _safe_write(mod_path, mod_content, dry_run=args.dry_run)

        # Action plugin
        action_content = generate_action_plugin(module, schemas_in_area)
        action_dir = COLLECTION_ROOT / "plugins" / "action"
        action_dir.mkdir(parents=True, exist_ok=True)
        action_path = action_dir / f"{module.name}.py"
        _safe_write(action_path, action_content, dry_run=args.dry_run)

        # Test
        test_content = generate_test(module)
        test_dir = COLLECTION_ROOT / "tests" / "unit" / "plugins" / "action"
        test_dir.mkdir(parents=True, exist_ok=True)
        (test_dir / "__init__.py").touch()
        test_path = test_dir / f"test_{module.name}.py"
        _safe_write(test_path, test_content, dry_run=args.dry_run)

    print(f"\nDone. Generated {len(MODULES)} modules.")


if __name__ == "__main__":
    main()
