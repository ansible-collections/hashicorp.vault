# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# @hand-crafted
# Vault has no GET /v1/sys/auth/{path} for individual methods.
# Uses GET /v1/sys/auth (list all) and searches for the path key.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.hashicorp.vault.plugins.plugin_utils.generated.auth import (
    AuthEnableMethodRequest,
)
from ansible_collections.hashicorp.vault.plugins.plugin_utils.operation import Operation
from ansible_collections.hashicorp.vault.plugins.plugin_utils.vault_action_base import VaultActionBase


class ActionModule(VaultActionBase):
    """Manage Vault auth methods."""

    OPERATIONS = {
        "present": Operation("POST", "v1/sys/auth/{path}", AuthEnableMethodRequest),
        "absent": Operation("DELETE", "v1/sys/auth/{path}", None),
    }

    _LIST_OP = Operation("GET", "v1/sys/auth", None)

    def _read_auth_method(self, client, params):
        """Read a single auth method config by listing all and extracting by path key."""
        response = self._execute(client, self._LIST_OP, params)
        path_key = params.get("path", "").rstrip("/") + "/"
        all_methods = response or {}
        return all_methods.get(path_key)

    def _ensure_present(self, client, params):
        write_op = self.OPERATIONS["present"]

        existing = self._read_auth_method(client, params)
        if existing is not None:
            return {
                "changed": False,
                "data": existing,
                "raw": existing,
            }

        self._execute(client, write_op, params)
        read_back = self._read_auth_method(client, params) or {}
        return {
            "changed": True,
            "data": read_back,
            "raw": read_back,
        }

    def _ensure_absent(self, client, params):
        delete_op = self.OPERATIONS["absent"]

        existing = self._read_auth_method(client, params)
        if existing is None:
            return {"changed": False, "data": {}, "raw": {}}

        self._execute(client, delete_op, params)
        return {"changed": True, "data": {}, "raw": {}}
