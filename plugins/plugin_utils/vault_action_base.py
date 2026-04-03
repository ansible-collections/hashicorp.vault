# -*- coding: utf-8 -*-

# Copyright (c) 2025 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# @hand-crafted

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import copy
import importlib
import os
from dataclasses import asdict

import yaml
from ansible.errors import AnsibleActionFail
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.plugins.action import ActionBase

from ansible_collections.hashicorp.vault.plugins.module_utils.args_common import AUTH_ARG_SPEC
from ansible_collections.hashicorp.vault.plugins.module_utils.authentication import (
    AppRoleAuthenticator,
    TokenAuthenticator,
)
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_client import VaultClient
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import (
    VaultApiError,
    VaultConfigurationError,
    VaultConnectionError,
    VaultCredentialsError,
    VaultPermissionError,
    VaultSecretNotFoundError,
)

_AUTH_KEYS = frozenset(AUTH_ARG_SPEC.keys())


class VaultActionBase(ActionBase):
    """Base action plugin for Vault API operations.

    Subclasses set class-level attributes to describe the operation(s)
    they perform.  This base class handles argument validation,
    authentication, request construction, and response handling.

    For simple *action* modules (one endpoint, always ``changed=True``),
    set ``OPERATION`` to a single :class:`Operation`.

    For *CRUD* modules (``state: present/absent``), set
    ``OPERATIONS`` to a dict keyed by ``"present"``, ``"absent"``, and
    optionally ``"read"``::

        OPERATIONS = {
            "present": Operation("POST", "v1/.../{name}", MyRequest),
            "absent":  Operation("DELETE", "v1/.../{name}"),
            "read":    Operation("GET", "v1/.../{name}"),
        }

    For *info* modules (read-only), set ``OPERATION`` with a GET/LIST
    and override ``_handle_response`` if needed.
    """

    OPERATION = None
    OPERATIONS = None

    CHANGED_ON_SUCCESS = True

    def run(self, tmp=None, task_vars=None):
        super().run(tmp, task_vars)
        result = {}

        try:
            args = self._validate_args()
            auth_args, operation_args = self._split_args(args)
            client = self._build_client(auth_args)

            if self.OPERATIONS:
                result = self._run_crud(client, operation_args)
            elif self.OPERATION:
                result = self._run_action(client, operation_args)
            else:
                raise AnsibleActionFail("Subclass must set OPERATION or OPERATIONS")

        except VaultPermissionError as e:
            result = {"failed": True, "msg": f"Permission denied: {e}"}
        except VaultSecretNotFoundError as e:
            result = {"failed": True, "msg": f"Not found: {e}"}
        except VaultApiError as e:
            result = {"failed": True, "msg": f"Vault API error: {e}"}
        except VaultCredentialsError as e:
            result = {"failed": True, "msg": f"Vault authentication error: {e}"}
        except VaultConfigurationError as e:
            result = {"failed": True, "msg": f"Vault configuration error: {e}"}
        except VaultConnectionError as e:
            result = {"failed": True, "msg": f"Vault connection error: {e}"}
        except AnsibleActionFail:
            raise
        except Exception as e:
            result = {"failed": True, "msg": f"Unexpected error: {e}"}

        return result

    # -- argument handling ---------------------------------------------------

    def _validate_args(self):
        """Parse DOCUMENTATION from the companion module and validate task args."""
        doc_string = self._get_module_documentation()
        doc = yaml.safe_load(doc_string)
        self._module_options = doc.get("options") or {}
        arg_spec = self._build_arg_spec(self._module_options)

        validator = ArgumentSpecValidator(arg_spec)
        validation = validator.validate(self._task.args)

        if validation.error_messages:
            raise AnsibleActionFail(f"Argument validation failed: {'; '.join(validation.error_messages)}")

        return validation.validated_parameters

    def _get_module_documentation(self):
        """Load the DOCUMENTATION string from the companion module file."""
        module_name = self._task.action.split(".")[-1]
        collection_path = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        module_path = os.path.join(collection_path, "plugins", "modules", f"{module_name}.py")

        mod_spec = importlib.util.spec_from_file_location(module_name, module_path)
        mod = importlib.util.module_from_spec(mod_spec)
        mod_spec.loader.exec_module(mod)
        return getattr(mod, "DOCUMENTATION", "")

    @staticmethod
    def _build_arg_spec(options):
        """Convert DOCUMENTATION options to an Ansible argument_spec dict."""
        merged = copy.deepcopy(AUTH_ARG_SPEC)

        for name, spec in options.items():
            if name in merged:
                continue
            entry = {}
            if "type" in spec:
                entry["type"] = spec["type"]
            if "required" in spec:
                entry["required"] = spec["required"]
            if "default" in spec:
                entry["default"] = spec["default"]
            if "choices" in spec:
                entry["choices"] = spec["choices"]
            if "aliases" in spec:
                entry["aliases"] = spec["aliases"]
            if "elements" in spec:
                entry["elements"] = spec["elements"]
            if "no_log" in spec:
                entry["no_log"] = spec["no_log"]
            merged[name] = entry

        return merged

    @staticmethod
    def _split_args(args):
        """Separate connection/auth args from operation-specific args."""
        auth_args = {}
        operation_args = {}
        for key, value in args.items():
            if key in _AUTH_KEYS:
                auth_args[key] = value
            else:
                operation_args[key] = value
        return auth_args, operation_args

    # -- client construction -------------------------------------------------

    @staticmethod
    def _build_client(auth_args):
        """Create and authenticate a VaultClient from auth args."""
        client = VaultClient(
            vault_address=auth_args["url"],
            vault_namespace=auth_args.get("namespace", "admin"),
        )

        auth_method = auth_args.get("auth_method", "token")
        if auth_method == "token":
            token = auth_args.get("token")
            if not token:
                raise VaultCredentialsError(
                    "Token authentication requires 'token' parameter or VAULT_TOKEN environment variable"
                )
            TokenAuthenticator().authenticate(client, token=token)
        else:
            params = {
                "vault_address": auth_args["url"],
                "role_id": auth_args.get("role_id"),
                "secret_id": auth_args.get("secret_id"),
            }
            if not params["role_id"] or not params["secret_id"]:
                raise VaultCredentialsError("AppRole authentication requires 'role_id' and 'secret_id' parameters")
            namespace = auth_args.get("namespace")
            if namespace is not None:
                params["vault_namespace"] = namespace
            approle_path = auth_args.get("vault_approle_path")
            if approle_path is not None:
                params["approle_path"] = approle_path
            AppRoleAuthenticator().authenticate(client, **params)

        return client

    # -- request helpers -----------------------------------------------------

    @staticmethod
    def _build_body(operation, params):
        """Build a JSON body dict from operation params and the request schema.

        Handles the convention where Python-reserved names get a trailing
        underscore in the dataclass (e.g., ``type_``, ``id_``) but the
        Vault API expects the original name (``type``, ``id``).
        """
        if operation.request_schema is None:
            return None

        schema_fields = set(operation.request_schema.__dataclass_fields__.keys())

        filtered = {}
        for k, v in params.items():
            if v is None:
                continue
            if k in schema_fields:
                filtered[k] = v
            elif f"{k}_" in schema_fields:
                filtered[f"{k}_"] = v

        if not filtered:
            return None

        instance = operation.request_schema(**filtered)
        body = {}
        for k, v in asdict(instance).items():
            if v is None:
                continue
            api_key = k.rstrip("_") if k.endswith("_") and k[:-1] not in schema_fields else k
            body[api_key] = v
        return body or None

    @staticmethod
    def _resolve_path(path_template, params):
        """Replace {placeholders} in path with values from params."""
        resolved = path_template
        for key, value in params.items():
            placeholder = "{" + key + "}"
            if placeholder in resolved:
                resolved = resolved.replace(placeholder, str(value))
        return resolved

    def _execute(self, client, operation, params):
        """Build and send a single Vault API request."""
        path = self._resolve_path(operation.path, params)
        body = self._build_body(operation, params)

        kwargs = {}
        if body is not None:
            kwargs["json"] = body

        return client.request(operation.method, path, **kwargs)

    # -- response helpers ----------------------------------------------------

    @staticmethod
    def _extract_data(response):
        """Extract the payload from the Vault response envelope.

        Vault wraps results in ``{request_id, lease_id, data, auth, ...}``.
        CRUD reads and info lookups return under ``data``; token-create
        returns under ``auth``.  This method returns whichever is populated
        so callers get the argspec-shaped dict directly.
        """
        if not isinstance(response, dict):
            return response
        data = response.get("data")
        if data is not None:
            return data
        auth = response.get("auth")
        if auth is not None:
            return auth
        return response

    _SKIP_CONTRACT_KEYS = frozenset({"state"}) | _AUTH_KEYS

    def _build_response_spec(self):
        """Build a relaxed argspec for validating API responses.

        Same fields as the module argspec but nothing is required and
        ``no_log`` is stripped so the validator never redacts response
        values.
        """
        spec = {}
        for name, opt in self._module_options.items():
            if name in self._SKIP_CONTRACT_KEYS:
                continue
            entry = {}
            if "type" in opt:
                entry["type"] = opt["type"]
            if "elements" in opt:
                entry["elements"] = opt["elements"]
            if "choices" in opt:
                entry["choices"] = opt["choices"]
            spec[name] = entry
        return spec

    def _validate_response_contract(self, response_data):
        """Run the Vault API response through ArgumentSpecValidator.

        Only the intersection of response keys and argspec keys is
        checked — extra keys in the response are ignored, and argspec
        keys absent from the response are fine (nothing is required).
        A validation failure means Vault returned a value whose type
        does not match the module's declared argspec.
        """
        if not isinstance(response_data, dict) or not response_data:
            return
        response_spec = self._build_response_spec()
        if not response_spec:
            return
        filtered = {k: v for k, v in response_data.items() if k in response_spec and v is not None}
        if not filtered:
            return
        validator = ArgumentSpecValidator(response_spec)
        validation = validator.validate(filtered)
        if validation.error_messages:
            raise AnsibleActionFail(
                f"Response contract violation: Vault API response "
                f"failed argspec validation: "
                f"{'; '.join(validation.error_messages)}"
            )

    # -- action module (single operation) ------------------------------------

    def _run_action(self, client, params):
        """Execute a single-operation action module."""
        response = self._execute(client, self.OPERATION, params)
        data = self._extract_data(response)
        self._validate_response_contract(data)
        return {
            "changed": self.CHANGED_ON_SUCCESS,
            "data": data,
            "raw": response,
        }

    # -- CRUD module (state-based) -------------------------------------------

    def _run_crud(self, client, params):
        """Dispatch to present/absent based on state param."""
        state = params.pop("state", "present")

        if state == "present":
            return self._ensure_present(client, params)
        elif state == "absent":
            return self._ensure_absent(client, params)
        else:
            raise AnsibleActionFail(f"Unsupported state: {state}")

    def _ensure_present(self, client, params):
        """Create or update a resource. GET-before-POST for idempotency."""
        read_op = self.OPERATIONS.get("read")
        write_op = self.OPERATIONS["present"]

        existing = None
        if read_op:
            try:
                existing = self._execute(client, read_op, params)
            except VaultSecretNotFoundError:
                existing = None

        response = self._execute(client, write_op, params)

        after = None
        if read_op:
            try:
                after = self._execute(client, read_op, params)
            except VaultSecretNotFoundError:
                after = response

        changed = existing is None or existing != after
        action = "created" if existing is None else "updated"
        final = after if after is not None else response
        data = self._extract_data(final)
        self._validate_response_contract(data)
        return {
            "changed": changed,
            "msg": f"Resource {action} successfully",
            "data": data,
            "raw": final,
        }

    def _ensure_absent(self, client, params):
        """Delete a resource if it exists."""
        read_op = self.OPERATIONS.get("read")
        delete_op = self.OPERATIONS["absent"]

        if read_op:
            try:
                self._execute(client, read_op, params)
            except VaultSecretNotFoundError:
                return {"changed": False, "msg": "Resource already absent"}

        self._execute(client, delete_op, params)
        return {"changed": True, "msg": "Resource deleted successfully"}
