# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.basic import env_fallback

# Authentication parameters
AUTH_ARG_SPEC = {
    "url": {
        "required": True,
        "aliases": ["vault_address"],
    },
    "namespace": {"default": "admin", "aliases": ["vault_namespace"]},
    "auth_method": {"choices": ["token", "approle"], "default": "token"},
    "token": {"no_log": True, "fallback": (env_fallback, ["VAULT_TOKEN"])},
    "role_id": {
        "aliases": ["approle_role_id"],
        "fallback": (env_fallback, ["VAULT_APPROLE_ROLE_ID"]),
    },
    "secret_id": {
        "no_log": True,
        "aliases": ["approle_secret_id"],
        "fallback": (env_fallback, ["VAULT_APPROLE_SECRET_ID"]),
    },
    "vault_approle_path": {"default": "approle"},
    "ca_cert": {
        "aliases": ["cacert", "ssl_ca_cert"],
        "fallback": (env_fallback, ["VAULT_CACERT"]),
    },
    "tls_skip_verify": {
        "type": "bool",
        "default": False,
        "fallback": (env_fallback, ["VAULT_SKIP_VERIFY"]),
    },
}
