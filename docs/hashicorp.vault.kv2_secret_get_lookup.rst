.. _hashicorp.vault.kv2_secret_get_lookup:


******************************
hashicorp.vault.kv2_secret_get
******************************

**Look up KV2 secrets stored in HashiCorp Vault.**


Version added: 1.0.0

.. contents::
   :local:
   :depth: 1


Synopsis
--------
- Look up KV2 secrets stored in HashiCorp Vault.
- The plugin supports reading latest version as well as specific version of the KV2 secret.




Parameters
----------

.. raw:: html

    <table  border=0 cellpadding=0 class="documentation-table">
        <tr>
            <th colspan="1">Parameter</th>
            <th>Choices/<font color="blue">Defaults</font></th>
                <th>Configuration</th>
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
                    </td>
                <td>
                        <div>The mount path of the KV2 secrets engine.</div>
                        <div>Secret paths are relative to this mount point.</div>
                        <div style="font-size: small; color: darkgreen"><br/>aliases: mount_point, secret_mount_path</div>
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
                    </td>
                <td>
                        <div>Vault namespace.</div>
                        <div style="font-size: small; color: darkgreen"><br/>aliases: vault_namespace</div>
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
                                <div>env:VAULT_APPROLE_ROLE_ID</div>
                    </td>
                <td>
                        <div>Role ID for AppRole authentication.</div>
                        <div>Required when O(auth_method=approle).</div>
                        <div style="font-size: small; color: darkgreen"><br/>aliases: approle_role_id</div>
                </td>
            </tr>
            <tr>
                <td colspan="1">
                    <div class="ansibleOptionAnchor" id="parameter-"></div>
                    <b>secret</b>
                    <a class="ansibleOptionLink" href="#parameter-" title="Permalink to this option"></a>
                    <div style="font-size: small">
                        <span style="color: purple">string</span>
                         / <span style="color: red">required</span>
                    </div>
                </td>
                <td>
                </td>
                    <td>
                    </td>
                <td>
                        <div>Vault path to the secret being requested.</div>
                        <div>Path is relative to the engine_mount_point.</div>
                        <div style="font-size: small; color: darkgreen"><br/>aliases: secret_path</div>
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
                                <div>env:VAULT_APPROLE_SECRET_ID</div>
                    </td>
                <td>
                        <div>Secret ID for AppRole authentication.</div>
                        <div>Required when O(auth_method=approle).</div>
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
                                <div>env:VAULT_TOKEN</div>
                    </td>
                <td>
                        <div>Vault token for authentication.</div>
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
                                <div>env:VAULT_ADDR</div>
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
                                <div>env:VAULT_APPROLE_PATH</div>
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
                    </td>
                <td>
                        <div>Specifies the version to return. If not set the latest is returned.</div>
                </td>
            </tr>
    </table>
    <br/>


Notes
-----

.. note::
   - Authentication is required for all Vault operations.



Examples
--------

.. code-block:: yaml

    - name: Return latest KV2 secret from path
      ansible.builtin.debug:
        msg: "{{ lookup('hashicorp.vault.kv2_secret_get',
                        secret='hello',
                        url='https://myvault_url:8200') }}"

    - name: Return a specific version of the KV2 secret from path
      ansible.builtin.debug:
        msg: "{{ lookup('hashicorp.vault.kv2_secret_get',
                        secret='bar',
                        version=3,
                        url='https://myvault_url:8200') }}"

    - name: Return a secret using AppRole authentication
      ansible.builtin.debug:
        msg: "{{ lookup('hashicorp.vault.kv2_secret_get',
                        secret='foo',
                        auth_method='approle',
                        vault_approle_role_id='role-123',
                        vault_approle_secret_id='secret-456',
                        url='https://myvault_url:8200') }}"



Return Values
-------------
Common return values are documented `here <https://docs.ansible.com/ansible/latest/reference_appendices/common_return_values.html#common-return-values>`_, the following are the fields unique to this lookup:

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
                    <b>_raw</b>
                    <a class="ansibleOptionLink" href="#return-" title="Permalink to this return value"></a>
                    <div style="font-size: small">
                      <span style="color: purple">list</span>
                       / <span style="color: purple">elements=dictionary</span>
                    </div>
                </td>
                <td></td>
                <td>
                            <div>A list of dictionary containing the KV2 secret data and metadata stored in HashiCorp Vault.</div>
                            <div>The &#x27;data&#x27; key contains the actual secret key-value pairs.</div>
                            <div>The &#x27;metadata&#x27; key contains version information, timestamps, and other metadata.</div>
                    <br/>
                        <div style="font-size: smaller"><b>Sample:</b></div>
                        <div style="font-size: smaller; color: blue; word-wrap: break-word; word-break: break-all;">{&#x27;data&#x27;: {&#x27;foo&#x27;: &#x27;bar&#x27;}, &#x27;metadata&#x27;: {&#x27;created_time&#x27;: &#x27;2025-09-08T18:09:19.403229608Z&#x27;, &#x27;custom_metadata&#x27;: None, &#x27;deletion_time&#x27;: &#x27;&#x27;, &#x27;destroyed&#x27;: False, &#x27;version&#x27;: 1}}</div>
                </td>
            </tr>
    </table>
    <br/><br/>


Status
------


Authors
~~~~~~~

- Aubin Bikouo (@abikouo)


.. hint::
    Configuration entries for each entry type have a low to high priority order. For example, a variable that is lower in the list will override a variable that is higher up.
