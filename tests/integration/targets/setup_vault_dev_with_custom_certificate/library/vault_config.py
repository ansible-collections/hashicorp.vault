#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = r'''
---
module: vault_config
short_description: Manages HashiCorp Vault engine status and secrets
description:
    - This module ensures a Vault Secrets Engine (KV-V2) is enabled.
author: "Aubin Bikouo (@abikouo)"
options:
    url:
        description: The full URL to the Vault server.
        type: str
        default: "https://127.0.0.1:8200"
    ca_cert:
        description: Path to the CA certificate for TLS verification.
        required: true
        type: str
    engine_path:
        description: The path where the KV-V2 engine is (or should be) mounted.
        default: secret
        type: str
'''

EXAMPLES = r'''
- name: Configure Vault and enable KV-V2 secret on default path
  vault_config:
    ca_cert: "/app/certs/vault.crt"

- name: Configure Vault and enable KV-V2 secret on 'ansible-test-kv-v2'
  vault_config:
    ca_cert: "/app/certs/vault.crt"
    engine_path: "ansible-test-kv-v2"
'''

RETURN = r'''
root_token:
    description: The root token generated on server initialization.
    returned: always
    type: str
'''


from ansible.module_utils.basic import AnsibleModule, missing_required_lib

try:
    REQUESTS_IMPORT_ERR = None
    import requests
except Exception as e:
    REQUESTS_IMPORT_ERR = e
import time


class VaultConfig:

    def __init__(self, module):

        self.module = module

        self.server_url = module.params['url'].rstrip('/')
        self.ca_cert = module.params['ca_cert']
        self.engine_path = module.params["engine_path"]
        self.root_token = None

    def _send_request(self, **kwargs):

        method = kwargs.get("method", "GET")
        url = kwargs.get("endpoint")
        payload = kwargs.get("payload") or {}

        session = requests.Session()
        if self.root_token:
            session.headers.update({"X-Vault-Token": self.root_token})

        full_url = f"{self.server_url}/{url}"
        response = session.request(method=method, url=full_url, verify=self.ca_cert, json=payload, timeout=5)
        response.raise_for_status()
        return response

    def init_vault_server(self):

        # Init Vault server
        result = self._send_request(
            method="PUT", endpoint="v1/sys/init", payload={"secret_shares": 5, "secret_threshold": 3}
        )
        raw_data = result.json()
        unseal_keys = raw_data.get("keys")
        self.root_token = raw_data.get("root_token")

        # Unseal vault
        for id in range(3):
            payload = {"key": unseal_keys[id]}
            self._send_request(method="PUT", endpoint="v1/sys/unseal", payload=payload)

    def wait_for_vault(self, max_retries=30, sleep_interval=2):
        """
        Retries connecting to Vault until it is unsealed and ready (HTTP 200).
        """
        url = f"{self.server_url}/v1/sys/health"
        attempt = 0
        changed = False
        while attempt < max_retries:
            try:
                response = requests.get(url, verify=self.ca_cert, timeout=5)
                if response.status_code == 200:
                    return changed
                elif response.status_code == 503:
                    self.init_vault_server()
                    changed = True
                    return changed
                elif response.status_code == 501:
                    self.init_vault_server()
                    changed = True
                    return changed
            except Exception:
                pass

            attempt += 1
            time.sleep(sleep_interval)

        self.module.fail_json(msg="Max retries reached. Vault did not become ready in time.")

    def enable_kv2_secret(self):
        # Read current status
        changed = False
        msg = None
        response = self._send_request(endpoint="v1/sys/mounts")
        if response.status_code == 200 and f"{self.engine_path}/" in response.json().get("data", {}):
            msg = f"Engine '{self.engine_path}' is already enabled."
        else:
            payload = {"type": "kv", "options": {"version": "2"}}
            response = self._send_request(method="POST", endpoint=f"v1/sys/mounts/{self.engine_path}", payload=payload)
            if response.status_code == 204:
                msg = f"Successfully enabled KV-V2 engine at '{self.engine_path}/'"
                changed = True
            else:
                self.module.fail_json(msg=f"Failed to enable engine: {response.text}")

        return changed, msg


def run_module():
    module_args = dict(
        url=dict(type='str', default="https://127.0.0.1:8200"),
        ca_cert=dict(type='str', required=True),
        engine_path=dict(type='str', default='secret'),
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=False)
    if REQUESTS_IMPORT_ERR:
        module.fail_json(msg=missing_required_lib("requests"), exception=REQUESTS_IMPORT_ERR)

    config = VaultConfig(module=module)
    # Read vault status
    config.wait_for_vault()

    # Enable KV2 secret engine
    changed, msg = config.enable_kv2_secret()
    result = {"msg": msg}
    if config.root_token:
        result.update({"root_token": config.root_token})
    module.exit_json(changed=changed, **result)


if __name__ == '__main__':
    run_module()
