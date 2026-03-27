# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Generate example playbook fragments from module DOCUMENTATION.

Reads every ``plugins/modules/vault_*.py`` file, parses the DOCUMENTATION
YAML, and writes example task files under ``examples/<module>/``.

The ``examples/`` directory is the **source of truth** for all examples.
Use ``tools/inject_examples.py`` to sync them back into module files.

Usage:
    python -m tools.generate_examples
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List

import yaml

COLLECTION_ROOT = Path(__file__).resolve().parent.parent
MODULES_DIR = COLLECTION_ROOT / "plugins" / "modules"
EXAMPLES_DIR = COLLECTION_ROOT / "examples"

DOC_PATTERN = re.compile(
    r'DOCUMENTATION\s*=\s*(?:r)?(?:"""|\'\'\')(\n.*?)(?:"""|\'\'\')',
    re.DOTALL,
)

FQCN_PREFIX = "hashicorp.vault"

AUTH_OPTION_NAMES = frozenset(
    {
        "url",
        "namespace",
        "auth_method",
        "token",
        "role_id",
        "secret_id",
        "vault_approle_path",
    }
)

FIELD_SAMPLES: Dict[str, Any] = {
    "display_name": "my-service-token",
    "ttl": "1h",
    "explicit_max_ttl": "24h",
    "policies": ["default"],
    "allowed_policies": ["default"],
    "role_name": "test-role",
    "name": "test-resource",
    "path": "userpass",
    "mount_path": "database",
    "db_name": "my-postgres",
    "username": "vault-user",
    "rotation_period": "24h",
    "rotation_schedule": "0 */6 * * *",
    "credential_type": "password",
    "num_uses": 10,
    "period": "1h",
    "orphan": True,
    "renewable": True,
    "no_parent": False,
    "no_default_policy": False,
    "increment": "1h",
    "type": "service",
    "plugin_name": "userpass",
    "description": "Managed by Ansible",
    "allowed_entity_aliases": ["entity-*"],
    "token_type": "default-service",
    "rotation_statements": ["ALTER USER ..."],
}

CONNECTION_VARS = {
    "url": '{{ vault_addr }}',
    "token": '{{ vault_token }}',
}

FILE_ORDER = {
    "action": ["action"],
    "crud": ["present", "absent"],
    "info": ["info"],
}


def load_module_documentation(module_path: Path) -> dict:
    """Load and parse the DOCUMENTATION string from a module file via regex."""
    source = module_path.read_text()
    match = DOC_PATTERN.search(source)
    if not match:
        return {}
    try:
        return yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError:
        return {}


def detect_module_type(doc: dict) -> str:
    """Detect whether a module is action, crud, or info based on DOCUMENTATION."""
    options = doc.get("options", {}) or {}
    if "state" in options:
        return "crud"
    module_name = doc.get("module", "")
    if "_info" in module_name or "list_" in module_name:
        return "info"
    return "action"


def sample_value(name: str, opt: dict) -> Any:
    """Generate a sample value for an option."""
    if name in FIELD_SAMPLES:
        return FIELD_SAMPLES[name]

    opt_type = opt.get("type", "str")
    if "default" in opt and opt["default"] is not None:
        return opt["default"]

    if opt_type == "str":
        return f"example-{name.replace('_', '-')}"
    elif opt_type == "bool":
        return True
    elif opt_type == "int":
        return 0
    elif opt_type == "list":
        return [f"example-{name.replace('_', '-')}"]
    elif opt_type == "dict":
        return {"key": "value"}
    return f"example-{name}"


def build_task_args(doc: dict, include_state: str = None, max_fields: int = 8) -> dict:
    """Build a dict of task arguments from DOCUMENTATION options."""
    options = doc.get("options", {}) or {}
    args = {}

    for name in CONNECTION_VARS:
        if name in options or name in AUTH_OPTION_NAMES:
            args[name] = CONNECTION_VARS[name]

    if include_state:
        args["state"] = include_state

    field_count = 0
    for name, opt in sorted(options.items()):
        if name in AUTH_OPTION_NAMES or name == "state":
            continue
        if opt.get("no_log"):
            continue
        if field_count >= max_fields:
            break

        if opt.get("required"):
            args[name] = sample_value(name, opt)
            field_count += 1
        elif name in FIELD_SAMPLES and field_count < max_fields:
            args[name] = sample_value(name, opt)
            field_count += 1

    return args


def format_yaml_value(value: Any, indent: int = 4) -> str:
    """Format a Python value as YAML inline."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        if "{{" in value:
            return f'"{value}"'
        return value
    if isinstance(value, list):
        lines = []
        for item in value:
            lines.append(f"\n{' ' * indent}  - {item}")
        return "".join(lines)
    if isinstance(value, dict):
        lines = []
        for k, v in value.items():
            lines.append(f"\n{' ' * indent}  {k}: {v}")
        return "".join(lines)
    return str(value)


def render_task(module_name: str, short_desc: str, args: dict) -> str:
    """Render a single Ansible task as YAML."""
    lines = [f"- name: {short_desc}"]
    lines.append(f"  {FQCN_PREFIX}.{module_name}:")

    for name, value in args.items():
        formatted = format_yaml_value(value)
        lines.append(f"    {name}: {formatted}")

    lines.append("  register: result")
    return "\n".join(lines)


def render_assert(conditions: List[str]) -> str:
    """Render an assertion task."""
    lines = ["- name: Verify result"]
    lines.append("  ansible.builtin.assert:")
    lines.append("    that:")
    for cond in conditions:
        lines.append(f"      - {cond}")
    return "\n".join(lines)


def generate_action_example(doc: dict, module_name: str) -> str:
    """Generate example for an action module."""
    short_desc = doc.get("short_description", f"Run {module_name}")
    args = build_task_args(doc)

    task = render_task(module_name, short_desc, args)
    assertions = ["result is changed", "result.raw is defined"]
    if "_revoke" in module_name:
        assertions = ["result is changed"]
    verify = render_assert(assertions)

    return f"---\n{task}\n\n{verify}\n"


def generate_info_example(doc: dict, module_name: str) -> str:
    """Generate example for an info module."""
    short_desc = doc.get("short_description", f"Run {module_name}")
    args = build_task_args(doc)

    task = render_task(module_name, short_desc, args)
    verify = render_assert(["result is not changed", "result.raw is defined"])

    return f"---\n{task}\n\n{verify}\n"


def generate_present_example(doc: dict, module_name: str) -> str:
    """Generate present-state example for a CRUD module."""
    short_desc = doc.get("short_description", f"Create {module_name}")
    args = build_task_args(doc, include_state="present")

    task = render_task(module_name, f"{short_desc} (present)", args)
    verify = render_assert(["result is changed"])

    return f"---\n{task}\n\n{verify}\n"


def generate_absent_example(doc: dict, module_name: str) -> str:
    """Generate absent-state example for a CRUD module."""
    short_desc = doc.get("short_description", f"Remove {module_name}")
    options = doc.get("options", {}) or {}
    args = {}

    for name in CONNECTION_VARS:
        if name in options or name in AUTH_OPTION_NAMES:
            args[name] = CONNECTION_VARS[name]

    args["state"] = "absent"

    for name, opt in options.items():
        if name in AUTH_OPTION_NAMES or name == "state":
            continue
        if opt.get("required"):
            args[name] = sample_value(name, opt)

    task = render_task(module_name, f"{short_desc} (absent)", args)
    verify = render_assert(["result is changed"])

    return f"---\n{task}\n\n{verify}\n"


def main():
    EXAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    module_files = sorted(MODULES_DIR.glob("vault_*.py"))
    if not module_files:
        print("No vault_*.py modules found")
        return

    count = 0
    for module_path in module_files:
        module_name = module_path.stem
        doc = load_module_documentation(module_path)
        if not doc:
            print(f"  SKIP {module_name}: no DOCUMENTATION")
            continue

        module_type = detect_module_type(doc)
        example_dir = EXAMPLES_DIR / module_name
        example_dir.mkdir(parents=True, exist_ok=True)

        if module_type == "action":
            content = generate_action_example(doc, module_name)
            (example_dir / "action.yml").write_text(content)
        elif module_type == "crud":
            present = generate_present_example(doc, module_name)
            absent = generate_absent_example(doc, module_name)
            (example_dir / "present.yml").write_text(present)
            (example_dir / "absent.yml").write_text(absent)
        elif module_type == "info":
            content = generate_info_example(doc, module_name)
            (example_dir / "info.yml").write_text(content)

        count += 1
        print(f"  Generated examples/{module_name}/")

    print(f"\nDone. Generated examples for {count} modules.")


if __name__ == "__main__":
    main()
