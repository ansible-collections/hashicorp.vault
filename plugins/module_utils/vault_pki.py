# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import quote

logger = logging.getLogger(__name__)

__all__ = ['VaultPki']


class VaultPki:
    """
    Handles interactions with the Vault PKI secrets engine (certificate issue, sign, revoke, read, list).

    Supporting documentation (HashiCorp Developer, PKI secrets engine HTTP API):

    - Generate Certificate: https://developer.hashicorp.com/vault/api-docs/secret/pki#generate-certificate-and-key
    - Sign CSR: https://developer.hashicorp.com/vault/api-docs/secret/pki#sign-certificate
    - Revoke Certificate: https://developer.hashicorp.com/vault/api-docs/secret/pki#revoke-certificate
    - Read Certificate: https://developer.hashicorp.com/vault/api-docs/secret/pki#read-certificate
    - List Certificates: https://developer.hashicorp.com/vault/api-docs/secret/pki#list-certificates
    - PKI - Secrets Engines - HTTP API: https://developer.hashicorp.com/vault/api-docs/secret/pki
    """

    @staticmethod
    def _require_str(param: str, value: Any) -> None:
        """Raise TypeError if value is not a str (strict runtime check for API path/body inputs)."""
        if not isinstance(value, str):
            raise TypeError("{0} must be a str".format(param))

    @staticmethod
    def _require_optional_dict(param: str, value: Any) -> None:
        """Raise TypeError if value is provided and not a dict."""
        if value is not None and not isinstance(value, dict):
            raise TypeError("{0} must be a dict".format(param))

    @staticmethod
    def _require_pki_role_name(param: str, value: Any) -> None:
        """
        Validate a PKI role name before it is interpolated into a request path.

        Rejects values that would produce ambiguous or multi-segment paths (e.g. empty
        or containing ``/``).
        """
        VaultPki._require_str(param, value)
        if value != value.strip():
            raise ValueError("{0} must not have leading or trailing whitespace".format(param))
        if not value:
            raise ValueError("{0} must be non-empty".format(param))
        if "/" in value:
            raise ValueError("{0} must not contain '/'".format(param))

    def __init__(self, client, mount_path: str = "pki") -> None:
        """
        Initialize the PKI client.

        Args:
            client (VaultClient): An authenticated VaultClient instance.
            mount_path (str): PKI secrets engine mount path. Defaults to ``pki``.

        Raises:
            TypeError: If ``mount_path`` is not a string after applying the default for falsy values.
        """
        self._client = client
        coalesced = mount_path if mount_path else "pki"
        self._require_str("mount_path", coalesced)
        self._mount_path = coalesced.strip().strip("/")

    def generate_certificate(
        self, role: str, common_name: str, extra: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generate a new private key and certificate via POST ``/issue/:role``.

        Args:
            role (str): PKI role name (URL path segment after ``issue/``).
            common_name (str): Common name for the issued certificate.
            extra (dict, optional): Additional JSON body fields (e.g. ``alt_names``, ``ip_sans``, ``ttl``, ``format``).

        Returns:
            dict: Full Vault JSON response (``data`` typically contains ``certificate``, ``private_key``, ``issuing_ca``, etc.).

        Raises:
            TypeError: If ``role`` or ``common_name`` is not a string, or ``extra`` is not a dict when provided.
            ValueError: If ``role`` is empty, has leading/trailing whitespace, or contains ``/``.
        """
        self._require_pki_role_name("role", role)
        self._require_str("common_name", common_name)
        self._require_optional_dict("extra", extra)

        body: Dict[str, Any] = {"common_name": common_name}
        if extra is not None:
            body.update(extra)

        path = f"v1/{self._mount_path}/issue/{role}"
        logger.debug("POST PKI issue %s at role %s", path, role)
        return self._client._make_request("POST", path, json=body)

    def sign_certificate(
        self, role: str, csr: str, common_name: str, extra: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Sign a certificate signing request via POST ``/sign/:role``.

        Args:
            role (str): PKI role name (URL path segment after ``sign/``).
            csr (str): PEM-encoded certificate signing request.
            common_name (str): Common name for the signed certificate (required by the Vault PKI API).
            extra (dict, optional): Additional JSON body fields (e.g. ``alt_names``, ``ip_sans``, ``ttl``, ``format``).
                If ``common_name`` is present in ``extra``, it overrides this argument.

        Returns:
            dict: Full Vault JSON response (``data`` typically contains ``certificate``, ``issuing_ca``, etc.).

        Raises:
            TypeError: If ``role``, ``csr``, or ``common_name`` is not a string, or ``extra`` is not a dict when provided.
            ValueError: If ``role`` is empty, has leading/trailing whitespace, or contains ``/``.
        """
        self._require_pki_role_name("role", role)
        self._require_str("csr", csr)
        self._require_str("common_name", common_name)
        self._require_optional_dict("extra", extra)

        body: Dict[str, Any] = {"csr": csr, "common_name": common_name}
        if extra is not None:
            body.update(extra)

        path = f"v1/{self._mount_path}/sign/{role}"
        logger.debug("POST PKI sign %s at role %s", path, role)
        return self._client._make_request("POST", path, json=body)

    def revoke_certificate(
        self,
        serial_number: Optional[str] = None,
        certificate: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Revoke a certificate via POST ``/revoke`` on the PKI mount (see Vault PKI HTTP API).

        The request body must include exactly one of ``serial_number`` or ``certificate``.

        Args:
            serial_number (str, optional): Certificate serial in Vault format (colon-separated hex). Omit when using ``certificate``.
            certificate (str, optional): PEM-encoded certificate to revoke. Omit when using ``serial_number``.

        Returns:
            dict: Full Vault JSON response.

        Raises:
            TypeError: If the provided argument is not a string.
            ValueError: If both or neither of ``serial_number`` and ``certificate`` are set.
        """
        if serial_number is not None:
            self._require_str("serial_number", serial_number)
        if certificate is not None:
            self._require_str("certificate", certificate)

        has_serial = serial_number is not None
        has_cert = certificate is not None
        if has_serial == has_cert:
            raise ValueError("Exactly one of serial_number and certificate must be provided")

        path = f"v1/{self._mount_path}/revoke"
        if has_serial:
            body: Dict[str, Any] = {"serial_number": serial_number}
            logger.debug("POST PKI revoke by serial %s", serial_number)
        else:
            body = {"certificate": certificate}
            logger.debug("POST PKI revoke by certificate PEM (%d chars)", len(certificate or ""))
        logger.debug("POST PKI revoke %s", path)
        return self._client._make_request("POST", path, json=body)

    def read_certificate(self, serial_number: str) -> Dict[str, Any]:
        """
        Read certificate metadata and PEM by serial via GET ``/cert/:serial``.

        Args:
            serial_number (str): Certificate serial (colon-separated hex or Vault ``certs`` list key).

        Returns:
            dict: Full Vault JSON response (``data`` typically contains ``certificate``).

        Raises:
            TypeError: If ``serial_number`` is not a string.
        """
        self._require_str("serial_number", serial_number)

        encoded_serial = quote(serial_number, safe="")
        path = f"v1/{self._mount_path}/cert/{encoded_serial}"
        logger.debug("GET PKI cert %s", serial_number)
        logger.debug("GET PKI cert %s", path)
        return self._client._make_request("GET", path)

    def list_certificates(self) -> List[str]:
        """
        List stored certificate serial numbers via LIST ``/certs`` (see Vault PKI HTTP API).

        Returns:
            list: Serial numbers (``keys`` from the LIST response ``data``).
        """
        path = f"v1/{self._mount_path}/certs"
        response_data = self._client._make_request("LIST", path)
        keys = response_data.get("data", {}).get("keys", [])
        return [k for k in keys if isinstance(k, str)]
