.. _hashicorp.vault.kv2_secret_info_module:


*******************************
hashicorp.vault.kv2_secret_info
*******************************

**Read HashiCorp Vault KV version 2 secrets**


Version added: 1.0.0

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- Read secrets in HashiCorp Vault KV version 2 secrets engine.




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
                    <b>version</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">integer</span>
                    </div>
                </td>
                <td>
                </td>
                <td>
                        <div>The version to retrieve.</div>
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

    - name: Read a secret with token authentication
      hashicorp.vault.kv2_secret_info:
        url: https://vault.example.com:8200
        token: "{{ vault_token }}"
        path: myapp/config

    - name: Read a secret with a specific version
      hashicorp.vault.kv2_secret_info:
        url: https://vault.example.com:8200
        path: myapp/config
        version: 1



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
                    <b>secret</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">dictionary</span>
                    </div>
                </td>
                <td>always</td>
                <td>
                            <div>The secret data and metadata when reading existing secrets.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">{&#x27;data&#x27;: {&#x27;env&#x27;: &#x27;test&#x27;, &#x27;password&#x27;: &#x27;initial_pass&#x27;, &#x27;username&#x27;: &#x27;testuser&#x27;}, &#x27;metadata&#x27;: {&#x27;created_time&#x27;: &#x27;2025-09-01T22:04:48.74947241Z&#x27;, &#x27;custom_metadata&#x27;: None, &#x27;deletion_time&#x27;: &#x27;&#x27;, &#x27;destroyed&#x27;: False, &#x27;version&#x27;: 42}}</div>
                </td>
            </tr>
    </table>
    <br/><br/>


Status
------


Authors
~~~~~~~

- Aubin Bikouo (@abikouo)
