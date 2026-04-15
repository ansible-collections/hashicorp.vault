# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: postgres_connect
short_description: Validate connection to PostGreSQL database.
author: Aubin Bikouo (@abikouo)
description:
  - This module is used to validate login to a postgresql database.
  - The module is restricted to be used for integration tests for the hashicorp.vault collection.
options:
  db_host:
    description: The database host.
    type: str
    default: localhost
  db_name:
    description: The database name:
    default: postgres
  db_port:
    description: The database port.
    type: int
    default: 5432
  db_user:
    description: The database user.
    required: true
    type: str
    aliases: ['user', 'username']
  db_user_password:
    description: The database user password.
    required: true
    aliases: ['password']
"""

import time

from ansible.module_utils.basic import AnsibleModule

try:
    import psycopg

    PSYCOG_IMPORT_ERROR = None
    HAS_PSYCOPG = True
except ImportError as e:
    HAS_PSYCOPG = False
    PSYCOG_IMPORT_ERROR = e


def connect_with_retry(module, connection_retries=10, connection_retries_delay=2, **kwargs):
    """
    Attempts to connect to Postgres with delay.
    """
    last_e = None
    conn = None
    for attempt in range(0, connection_retries + 1):
        try:
            # Create the connection
            conn = psycopg.connect(**kwargs)
            return conn
        except psycopg.OperationalError as e:
            if attempt >= connection_retries:
                raise e
            time.sleep(connection_retries_delay)
            last_e = None
    module.fail_json(msg=f"Failed to connect to PostGreSQL database: {last_e}")


def main():

    argument_spec = dict(
        db_host=dict(type="str", default="localhost"),
        db_name=dict(type="str", default="postgres"),
        db_port=dict(type="int", default=5432),
        db_user=dict(type="str", required=True, aliases=['user', 'username']),
        db_user_password=dict(type="str", required=True, aliases=['password'], no_log=True),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
    )

    if not HAS_PSYCOPG:
        raise ImportError(f"Missing required library psycopg: {PSYCOG_IMPORT_ERROR}")

    params = {
        "host": module.params.get("db_host"),
        "dbname": module.params.get("db_name"),
        "user": module.params.get("db_user"),
        "password": module.params.get("db_user_password"),
        "port": int(module.params.get("db_port")),
    }

    conn = connect_with_retry(module, **params)
    with conn.cursor() as cur:
        # Execute a command
        cur.execute("SELECT version();")

        # Fetch the result
        db_version = cur.fetchone()
        conn.close()
        module.exit_json(changed=True, msg=f"Connected! Database version: {db_version}")


if __name__ == "__main__":
    main()
