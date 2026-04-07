# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Operation:
    """Describes a single Vault API operation.

    Attributes:
        method: HTTP method (GET, POST, DELETE, LIST).
        path: URL path with optional {templates} for path params
              (e.g., "v1/auth/token/roles/{role_name}").
        request_schema: Optional dataclass type whose fields define the
                        JSON request body.  ``None`` for operations
                        that have no request body (reads, deletes).
    """

    method: str
    path: str
    request_schema: Optional[type] = None
