.. _hashicorp.vault.kv2_secret_module:


**************************
hashicorp.vault.kv2_secret
**************************

**Manage HashiCorp Vault KV version 2 secrets**


Version added: 1.0.0

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- Create, update, or delete (soft-delete) secrets in HashiCorp Vault KV version 2 secrets engine.
- This module is designed for writing operations only. To read secrets, use the P(hashicorp.vault.kv2_secret_get#lookup) lookup plugin.
- Supports token and AppRole authentication methods.
- It does not create the secret engine if it does not exist and will fail if the secret engine path (engine_mount_point) is not enabled.




Parameters
----------

.. raw:: html

    <table  border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="1">Parameter</th>
            <th>Choices/<font color="blue">Defaults</font></th>
            <th width="100%">Comments</th>
        </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>auth_method</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li><div style="color: blue"><b>token</b>&nbsp;&larr;</div></li>
                                    <li>approle</li>
                        </ul>
                </td>
                <td>
                        <div>Authentication method to use.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>cas</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Check-and-Set value for conditional updates.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>data</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">dictionary</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Secret data as key-value pairs.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>engine_mount_point</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">"secret"</div>
                </td>
                <td>
                        <div>KV secrets engine mount point.</div>
                        <div style="font-size: small; color: darkgreen"><br/>aliases: secret_mount_path</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>namespace</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">"admin"</div>
                </td>
                <td>
                        <div>Vault namespace.</div>
                        <div style="font-size: small; color: darkgreen"><br/>aliases: vault_namespace</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>path</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                         / <span style="color: red">required</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Path to the secret.</div>
                        <div style="font-size: small; color: darkgreen"><br/>aliases: secret_path</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>role_id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Role ID for AppRole authentication.</div>
                        <div>AppRole O(role_id) can be provided as parameters or as environment variables E(VAULT_APPROLE_ROLE_ID).</div>
                        <div style="font-size: small; color: darkgreen"><br/>aliases: approle_role_id</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>secret_id</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Secret ID for AppRole authentication.</div>
                        <div>AppRole O(secret_id) can be provided as parameters or as environment variables E(VAULT_APPROLE_SECRET_ID).</div>
                        <div style="font-size: small; color: darkgreen"><br/>aliases: approle_secret_id</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>state</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <ul style="margin: 0; padding: 0"><b>Choices:</b>
                                    <li><div style="color: blue"><b>present</b>&nbsp;&larr;</div></li>
                                    <li>absent</li>
                        </ul>
                </td>
                <td>
                        <div>Desired state of the secret.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>token</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Vault token for authentication.</div>
                        <div>Token can be provided as a parameter or as an environment variable E(VAULT_TOKEN).</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>url</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                         / <span style="color: red">required</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>Vault server URL.</div>
                        <div style="font-size: small; color: darkgreen"><br/>aliases: vault_address</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>vault_approle_path</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                    </div>
                </td>
                <td>
                        <b>Default:</b><br/><div style="color: blue">"approle"</div>
                </td>
                <td>
                        <div>AppRole auth method mount path.</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>versions</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">list</span>
                         / <span style="color: purple">elements=integer</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>One or more versions of the secret to delete. Used with O(state=absent).</div>
                </td>
            </tr>
    </table>
    <br/>


Notes
-----

.. note::
   - Authentication is required for all Vault operations.
   - Token authentication is the default method.
   - For AppRole authentication, both O(role_id) and O(secret_id) are required.
   - Module parameters take precedence over environment variables when both are provided.



Examples
--------

.. code-block:: yaml

    - name: Create a secret with token authentication
      hashicorp.vault.kv2_secret:
        url: https://vault.example.com:8200
        token: "{{ vault_token }}"
        path: myapp/config
        data:
          username: admin
          password: secret123

    - name: Create a secret with token authentication (using env var for auth)
      hashicorp.vault.kv2_secret:
        url: https://vault.example.com:8200
        path: myapp/config
        data:
          username: admin
          password: secret123

    - name: Create a secret with AppRole authentication
      hashicorp.vault.kv2_secret:
        url: https://vault.example.com:8200
        auth_method: approle
        role_id: "{{ vault_role_id }}"
        secret_id: "{{ vault_secret_id }}"
        path: myapp/config
        data:
          api_key: secret-api-key

    - name: Delete a secret
      hashicorp.vault.kv2_secret:
        url: https://vault.example.com:8200
        path: myapp/config
        state: absent



Return Values
-------------
Common return values are documented `here <https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html#common-return-values>`_, the following are the fields unique to this module:

.. raw:: html

    <table border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="1">Key</th>
            <th>Returned</th>
            <th width="100%">Description</th>
        </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>data</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">dictionary</span>
                    </div>
                </td>
                <td>changed and state=absent</td>
                <td>
                            <div>The raw result of the delete against the given path.</div>
                            <div>This is usually empty, but may contain warnings or other information.</div>
                            <div>Successful delete on Vault KV2 API returns 204 No Content, so the module returns an empty dictionary on successful deletion.</div>
                    <br/>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="return-"></div>
                    <b>raw</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">dictionary</span>
                    </div>
                </td>
                <td>changed and state=present</td>
                <td>
                            <div>The raw Vault response.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">{&#x27;auth&#x27;: None, &#x27;data&#x27;: {&#x27;created_time&#x27;: &#x27;2023-02-21T19:51:50.801757862Z&#x27;, &#x27;custom_metadata&#x27;: None, &#x27;deletion_time&#x27;: &#x27;&#x27;, &#x27;destroyed&#x27;: False, &#x27;version&#x27;: 1}, &#x27;lease_duration&#x27;: 0, &#x27;lease_id&#x27;: &#x27;&#x27;, &#x27;renewable&#x27;: False, &#x27;request_id&#x27;: &#x27;52eb1aa7-5a38-9a02-9246-efc5bf9581ec&#x27;, &#x27;warnings&#x27;: None, &#x27;wrap_info&#x27;: None}</div>
                </td>
            </tr>
    </table>
    <br/><br/>


Status
------


Authors
~~~~~~~

- Mandar Vijay Kulkarni (@mandar242)
