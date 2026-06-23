.. _hashicorp.vault.kubernetes_token_module:


********************************
hashicorp.vault.kubernetes_token
********************************

**Generate a Kubernetes bearer token from the Kubernetes secrets engine.**

.. contents::
   :local:
   :depth: 1


Synopsis
--------

- Generates a short-lived Kubernetes bearer token for a Vault Kubernetes secrets engine role.
- Each invocation generates a new token with a unique lease.
- Supports Vault token and AppRole authentication through the standard collection authentication options.


Requirements
------------

The below requirements are needed on the host that executes this module.

- requests


Parameters
----------

.. raw:: html

   <table>
     <thead>
       <tr>
         <th>Parameter</th>
         <th>Choices/Defaults</th>
         <th>Comments</th>
       </tr>
     </thead>
     <tbody>
       <tr>
         <td><b>audience</b></td>
         <td></td>
         <td>
           <div>Audience claim to request for the generated Kubernetes token.</div>
           <div>type: str</div>
         </td>
       </tr>
       <tr>
         <td><b>auth_method</b></td>
         <td>
           <ul>
             <li>Choices:
               <ul>
                 <li><code>token</code></li>
                 <li><code>approle</code></li>
               </ul>
             </li>
             <li>Default: <code>token</code></li>
           </ul>
         </td>
         <td>
           <div>Authentication method to use.</div>
           <div>type: str</div>
         </td>
       </tr>
       <tr>
         <td><b>ca_cert</b></td>
         <td></td>
         <td>
           <div>The path to a PEM-encoded CA certificate file to use for TLS verification.</div>
           <div>type: str</div>
         </td>
       </tr>
       <tr>
         <td><b>kubernetes_mount_path</b></td>
         <td><div>Default: <code>kubernetes</code></div></td>
         <td>
           <div>Kubernetes secrets engine mount path.</div>
           <div>aliases: path</div>
           <div>type: str</div>
         </td>
       </tr>
       <tr>
         <td><b>kubernetes_namespace</b></td>
         <td></td>
         <td>
           <div>Kubernetes namespace to request credentials for.</div>
           <div>When omitted, Vault uses the role or engine defaults.</div>
           <div>type: str</div>
         </td>
       </tr>
       <tr>
         <td><b>name</b></td>
         <td></td>
         <td>
           <div>The name of the Kubernetes role to generate a token for.</div>
           <div>aliases: role</div>
           <div>type: str</div>
           <div>required: true</div>
         </td>
       </tr>
       <tr>
         <td><b>namespace</b></td>
         <td><div>Default: <code>admin</code></div></td>
         <td>
           <div>Vault namespace.</div>
           <div>aliases: vault_namespace</div>
           <div>type: str</div>
         </td>
       </tr>
       <tr>
         <td><b>proxies</b></td>
         <td></td>
         <td>
           <div>URL(s) to the proxies used to access the Vault service.</div>
           <div>type: raw</div>
         </td>
       </tr>
       <tr>
         <td><b>retries</b></td>
         <td></td>
         <td>
           <div>Number of retries to perform on failed requests, or a dictionary of retry configuration.</div>
           <div>type: raw</div>
         </td>
       </tr>
       <tr>
         <td><b>role_id</b></td>
         <td></td>
         <td>
           <div>Role ID for AppRole authentication.</div>
           <div>aliases: approle_role_id</div>
           <div>type: str</div>
         </td>
       </tr>
       <tr>
         <td><b>secret_id</b></td>
         <td></td>
         <td>
           <div>Secret ID for AppRole authentication.</div>
           <div>aliases: approle_secret_id</div>
           <div>type: str</div>
         </td>
       </tr>
       <tr>
         <td><b>timeout</b></td>
         <td></td>
         <td>
           <div>Timeout for Vault API requests in seconds.</div>
           <div>type: int</div>
         </td>
       </tr>
       <tr>
         <td><b>tls_skip_verify</b></td>
         <td><div>Default: <code>false</code></div></td>
         <td>
           <div>Controls whether the module verifies the TLS certificate presented by the Vault server.</div>
           <div>type: bool</div>
         </td>
       </tr>
       <tr>
         <td><b>token</b></td>
         <td></td>
         <td>
           <div>Vault token for authentication.</div>
           <div>type: str</div>
         </td>
       </tr>
       <tr>
         <td><b>ttl</b></td>
         <td></td>
         <td>
           <div>Requested TTL for the generated token.</div>
           <div>The effective TTL is still subject to Vault role and mount limits.</div>
           <div>type: str</div>
         </td>
       </tr>
       <tr>
         <td><b>url</b></td>
         <td></td>
         <td>
           <div>Vault server URL.</div>
           <div>aliases: vault_address</div>
           <div>type: str</div>
           <div>required: true</div>
         </td>
       </tr>
       <tr>
         <td><b>vault_approle_path</b></td>
         <td><div>Default: <code>approle</code></div></td>
         <td>
           <div>AppRole auth method mount path.</div>
           <div>type: str</div>
         </td>
       </tr>
     </tbody>
   </table>


Notes
-----

- For security reasons, this module should be used with ``no_log=true`` and ``register``.
- This module is not idempotent; each call generates a new token with a new lease.
- This module returns a Kubernetes bearer token from the Vault Kubernetes secrets engine, not a Vault auth token.


Examples
--------

.. code-block:: yaml+jinja

    - name: Generate a Kubernetes token using Vault token authentication
      hashicorp.vault.kubernetes_token:
        url: https://vault.example.com:8200
        token: "{{ vault_token }}"
        kubernetes_mount_path: myOcpCluster
        name: superuser
        audience: openshift
        ttl: 1h
        kubernetes_namespace: vault-test
        namespace: root
      no_log: true
      register: result

    - name: Generate a Kubernetes token using AppRole authentication
      hashicorp.vault.kubernetes_token:
        url: https://vault.example.com:8200
        auth_method: approle
        role_id: "{{ vault_role_id }}"
        secret_id: "{{ vault_secret_id }}"
        kubernetes_mount_path: myOcpCluster
        name: superuser
        kubernetes_namespace: kube-system
        ttl: 1h
      no_log: true
      register: result

    - name: Use the generated bearer token
      ansible.builtin.debug:
        msg: "{{ result.kubernetes_token.service_account_token }}"
      no_log: true


Return Values
-------------

.. raw:: html

   <table>
     <thead>
       <tr>
         <th>Key</th>
         <th>Returned</th>
         <th>Description</th>
       </tr>
     </thead>
     <tbody>
       <tr>
         <td><b>kubernetes_token</b></td>
         <td>always</td>
         <td>
           <div>The generated Kubernetes token data and lease information.</div>
           <div>type: dict</div>
           <div>sample:</div>
           <pre>{
    "service_account_name": "vault-secrets-superuser",
    "service_account_namespace": "kube-system",
    "service_account_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9...",
    "lease_id": "kubernetes/creds/superuser/abc123",
    "lease_duration": 3600,
    "renewable": false
        }</pre>
         </td>
       </tr>
     </tbody>
   </table>
