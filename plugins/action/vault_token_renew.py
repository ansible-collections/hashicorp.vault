# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# @hand-crafted
# Endpoint changed to renew-self (token param collision).

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.hashicorp.vault.plugins.plugin_utils.generated.token import (
    TokenRenewRequest,
)
from ansible_collections.hashicorp.vault.plugins.plugin_utils.operation import Operation
from ansible_collections.hashicorp.vault.plugins.plugin_utils.vault_action_base import VaultActionBase


class ActionModule(VaultActionBase):
    """Renew a Vault token."""

    OPERATION = Operation("POST", "v1/auth/token/renew-self", TokenRenewRequest)
