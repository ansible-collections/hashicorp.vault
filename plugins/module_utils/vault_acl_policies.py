# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

__all__ = ['VaultAclPolicies']


class VaultAclPolicies:
    """
    Handles interactions with the Vault ACL policy HTTP API (/sys/policy).

    Used by the ACL policy Ansible module and ACL policy _info module for
    create, update, delete, list, and read operations. Integrates with the
    collection's connection and authentication (base URL, token,
    X-Vault-Namespace).
    """

    def __init__(self, client):
        """
        Initializes the Vault ACL policies API client.

        Args:
            client (VaultClient): An authenticated instance of the main VaultClient.
        """
        self._client = client

    def list_acl_policies(self) -> List[str]:
        """
        List all Vault ACL policy names via GET /sys/policy.

        Returns:
            list: ACL policy names sorted lexicographically.
        """
        response = self._client._make_request("GET", "v1/sys/policy")
        # HCP commonly returns top-level "policies"; keeping a small fallback for data.policies.
        names = response.get("policies") or response.get("data", {}).get("policies") or []
        names = [name for name in names if isinstance(name, str)]
        return sorted(names)

    def read_acl_policy(self, name: str) -> dict:
        """
        Read a Vault ACL policy by name via GET /sys/policy/:name.

        Args:
            name (str): The name of the ACL policy to read.

        Returns:
            dict: ACL policy data with "name" and "rules" keys.
        """
        path = f"v1/sys/policy/{name}"
        raw = self._client._make_request("GET", path)
        data = raw.get("data") or {}
        rules = raw.get("rules") or raw.get("policy") or data.get("rules") or data.get("policy") or ""
        return {"name": name, "rules": rules.strip()}

    def create_or_update_acl_policy(self, name: str, acl_policy_rules: str) -> dict:
        """
        Create a new Vault ACL policy or update an existing one.

        Args:
            name (str): The name of the ACL policy (URL path segment).
            acl_policy_rules (str): The ACL policy rules string (request JSON field ``policy``).

        Returns:
            dict: The JSON response from Vault (often empty for success).

        Raises:
            TypeError: If the ACL policy rules are not a string.
        """
        if not isinstance(acl_policy_rules, str):
            raise TypeError("ACL policy rules must be a string")

        path = f"v1/sys/policy/{name}"
        body: Dict[str, Any] = {"policy": acl_policy_rules}
        logger.debug("POST ACL policy at %s", name)
        return self._client._make_request("POST", path, json=body)

    def delete_acl_policy(self, name: str) -> None:
        """
        Delete a Vault ACL policy by name.

        Args:
            name (str): The name of the ACL policy to delete.

        Returns:
            None
        """
        path = f"v1/sys/policy/{name}"
        self._client._make_request("DELETE", path)
