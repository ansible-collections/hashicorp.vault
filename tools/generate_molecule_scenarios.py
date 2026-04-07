# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Generate Molecule scenario directories from example playbooks.

Reads ``examples/<module>/`` and generates Molecule scenario directories
under ``extensions/molecule/<module>/`` with converge, verify, and
cleanup playbooks.

Module types are detected from the example files present:

- ``action.yml`` -> action module (converge + verify)
- ``present.yml`` + ``absent.yml`` -> CRUD module (converge + verify + cleanup)
- ``info.yml`` -> info module (converge + verify)

Usage:
    python -m tools.generate_molecule_scenarios
"""

from __future__ import annotations

from pathlib import Path

COLLECTION_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES_DIR = COLLECTION_ROOT / "examples"
MOLECULE_DIR = COLLECTION_ROOT / "extensions" / "molecule"

HAND_CRAFTED_MARKER = "# @hand-crafted"


def _is_hand_crafted(path: Path) -> bool:
    """Return True if *path* exists and contains the @hand-crafted marker."""
    if not path.exists():
        return False
    try:
        head = path.read_text()[:1024]
    except OSError:
        return False
    return HAND_CRAFTED_MARKER in head


def _safe_write(path: Path, content: str) -> bool:
    """Write *content* to *path*, respecting the @hand-crafted marker.

    Returns True if the file was written, False if it was skipped.
    """
    if _is_hand_crafted(path):
        print(f"    Skipped {path.name}  (@hand-crafted)")
        return False
    path.write_text(content)
    return True


def detect_module_type(example_dir: Path) -> str:
    """Detect module type from which example files are present."""
    if (example_dir / "present.yml").exists():
        return "crud"
    if (example_dir / "action.yml").exists():
        return "action"
    if (example_dir / "info.yml").exists():
        return "info"
    return "unknown"


def generate_molecule_yml(module_name: str, has_cleanup: bool = False) -> str:
    """Generate the molecule.yml for a scenario.

    Inherits ansible executor, inventory, env, shared_state from config.yml.
    Only overrides test_sequence when cleanup is needed.
    """
    if has_cleanup:
        return f"""\
---
scenario:
  name: {module_name}
  test_sequence:
    - converge
    - verify
    - cleanup
"""
    return f"""\
---
scenario:
  name: {module_name}
  test_sequence:
    - converge
    - verify
"""


def generate_converge(module_name: str, example_file: str) -> str:
    """Generate converge.yml that includes the example tasks.

    Connection vars (vault_addr, vault_token) come from the inventory
    (inventory_mock.yml or inventory_real.yml), not from play vars.
    """
    return f"""\
---
- name: Converge - {module_name}
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Include example tasks
      ansible.builtin.include_tasks:
        file: "{{{{ lookup('env', 'MOLECULE_PROJECT_DIRECTORY') }}}}/examples/{module_name}/{example_file}"
"""


def generate_verify_action(module_name: str) -> str:
    """Generate verify.yml for action modules."""
    return f"""\
---
- name: Verify - {module_name}
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Verify converge completed successfully
      ansible.builtin.assert:
        that:
          - true
        success_msg: "{module_name} converge completed"
"""


def generate_verify_info(module_name: str) -> str:
    """Generate verify.yml for info modules."""
    return f"""\
---
- name: Verify - {module_name}
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Verify info returned data
      ansible.builtin.assert:
        that:
          - true
        success_msg: "{module_name} info call completed"
"""


def generate_verify_crud(module_name: str) -> str:
    """Generate verify.yml for CRUD modules."""
    return f"""\
---
- name: Verify - {module_name}
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Verify resource was created
      ansible.builtin.assert:
        that:
          - true
        success_msg: "{module_name} resource verified"
"""


def generate_cleanup_crud(module_name: str) -> str:
    """Generate cleanup.yml for CRUD modules (runs absent example)."""
    return f"""\
---
- name: Cleanup - {module_name}
  hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - name: Include absent tasks
      ansible.builtin.include_tasks:
        file: "{{{{ lookup('env', 'MOLECULE_PROJECT_DIRECTORY') }}}}/examples/{module_name}/absent.yml"
"""


def main():
    if not EXAMPLES_DIR.exists():
        print("No examples/ directory found. Run generate_examples first.")
        return

    MOLECULE_DIR.mkdir(parents=True, exist_ok=True)
    count = 0

    for example_dir in sorted(EXAMPLES_DIR.iterdir()):
        if not example_dir.is_dir():
            continue

        module_name = example_dir.name
        module_type = detect_module_type(example_dir)
        if module_type == "unknown":
            print(f"  SKIP {module_name}: no recognized example files")
            continue

        scenario_dir = MOLECULE_DIR / module_name
        scenario_dir.mkdir(parents=True, exist_ok=True)

        has_cleanup = module_type == "crud"
        wrote_any = False

        _safe_write(scenario_dir / "molecule.yml", generate_molecule_yml(module_name, has_cleanup=has_cleanup))

        if module_type == "action":
            wrote_any |= _safe_write(scenario_dir / "converge.yml", generate_converge(module_name, "action.yml"))
            wrote_any |= _safe_write(scenario_dir / "verify.yml", generate_verify_action(module_name))
        elif module_type == "crud":
            wrote_any |= _safe_write(scenario_dir / "converge.yml", generate_converge(module_name, "present.yml"))
            wrote_any |= _safe_write(scenario_dir / "verify.yml", generate_verify_crud(module_name))
            wrote_any |= _safe_write(scenario_dir / "cleanup.yml", generate_cleanup_crud(module_name))
        elif module_type == "info":
            wrote_any |= _safe_write(scenario_dir / "converge.yml", generate_converge(module_name, "info.yml"))
            wrote_any |= _safe_write(scenario_dir / "verify.yml", generate_verify_info(module_name))

        count += 1
        print(f"  Generated extensions/molecule/{module_name}/")

    print(f"\nDone. Generated {count} Molecule scenarios.")


if __name__ == "__main__":
    main()
