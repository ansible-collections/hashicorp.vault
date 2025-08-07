# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class VaultError(Exception):
    """
    Base exception for all Vault-related errors.
    """

    pass


class VaultConfigurationError(VaultError):
    """
    Raised when Vault configuration is invalid or incomplete.

    This exception is raised when there are issues with:
    - Missing required configuration parameters
    - Invalid URLs or paths
    - Misconfigured authentication parameters
    - Missing environment variables
    """

    pass


class VaultCredentialsError(VaultError):
    """
    Raised when there are credential-related issues.

    This exception is raised when:
    - Required credentials are missing (role_id, secret_id, token)
    - Credentials are in invalid format
    - Authentication method is not supported
    - Conflicting authentication methods are provided
    """

    pass


class VaultAppRoleLoginError(VaultError):
    """
    Raised when AppRole authentication fails.

    Attributes:
        status_code (int, optional): HTTP status code if applicable
        response_text (str, optional): Response body text if available
    """

    def __init__(self, message: str, status_code: int = None, response_text: str = None):
        """
        Initialize AppRole login error.

        Args:
            message (str): Error description
            status_code (int, optional): HTTP status code if applicable
            response_text (str, optional): Response body text if available
        """
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


class VaultConnectionError(VaultError):
    """
    Raised when there are network/connection issues with Vault.

    This exception is raised when:
    - Cannot connect to Vault server
    - Network timeouts occur
    - SSL/TLS certificate issues
    - DNS resolution problems
    """

    pass
