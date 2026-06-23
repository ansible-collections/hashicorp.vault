# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from typing import Any, Dict, Optional


class VaultKubernetes:
    """
    Client for interacting with Vault's Kubernetes secrets engine.
    """

    def __init__(self, client, mount_path="kubernetes"):
        """
        Initialize the Kubernetes secrets engine client.

        Args:
            client (VaultClient): An authenticated Vault client.
            mount_path (str): The mount path of the Kubernetes secrets engine.
                Defaults to "kubernetes".
        """
        self._client = client
        self._mount_path = (mount_path or "kubernetes").strip().strip("/")

    def generate_token(
        self,
        name: str,
        kubernetes_namespace: Optional[str] = None,
        ttl: Optional[str] = None,
        audience: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a Kubernetes service account token from a Vault Kubernetes role.

        Args:
            name (str): The name of the Vault Kubernetes role.
            kubernetes_namespace (str, optional): Kubernetes namespace to request
                credentials for.
            ttl (str, optional): Requested TTL for the generated token.
            audience (str, optional): Requested audience for the generated token.

        Returns:
            Dict[str, Any]: The generated token data merged with lease metadata.

        Example:
            token = kube.generate_token(
                "superuser",
                kubernetes_namespace="kube-system",
                ttl="1h",
                audience="openshift",
            )
        """
        path = f"v1/{self._mount_path}/creds/{name}"
        params = {
            "kubernetes_namespace": kubernetes_namespace,
            "ttl": ttl,
            "audience": audience,
        }
        payload = {key: value for key, value in params.items() if value is not None}

        # Only send json parameter if we have data to send
        # Some Vault endpoints reject empty JSON bodies
        if payload:
            response_data = self._client._make_request("POST", path, json=payload)
        else:
            response_data = self._client._make_request("POST", path)
        out = dict(response_data.get("data", {}))
        for key in ("lease_id", "lease_duration", "renewable"):
            if key in response_data:
                out[key] = response_data[key]
        return out
