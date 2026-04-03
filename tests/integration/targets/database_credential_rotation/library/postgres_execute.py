# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: postgres_execute
short_description: Login and execute command into PostgreSQL database.
author: Aubin Bikouo (@abikouo)
description:
  - This module is used to validate login to a postgresql database.
  - When command is provided, the module execute the corresponding command.
  - The module is restricted to be used for integration tests for the hashicorp.vault collection.
  - Required the psycopg python library.
options:
  database_host:
    description: The database host.
    type: str
    default: localhost
  database_port:
    description: The database port.
    type: int
    default: 5432
  database_name:
    description: The database name.
    type: str
    default: postgres
  database_user:
    description: The database user.
    required: true
    type: str
    aliases: ['user', 'username']
  database_user_password:
    description: The database user password.
    required: true
    aliases: ['password']
  commands:
    description: The list of command to execute into the database.
    type: list
    elements: str
  connection_retries:
    description: The number of retries to perform on connection
    type: int
    default: 0
  connection_retries_delay:
    description: The delay between each retry operation
    type: int
    default: 3
"""

EXAMPLES = """
"""

RETURN = """
msg:
  description: A message describing the result of the login operation.
  returned: success
  type: str
"""

import time

try:
    import psycopg

    PSYCOG_IMPORT_ERROR = None
    HAS_PSYCOPG = True
except ImportError as e:
    HAS_PSYCOPG = False
    PSYCOG_IMPORT_ERROR = e

from ansible.module_utils.basic import AnsibleModule, missing_required_lib


def connect_with_retry(module, **connection_params):
    """
    Attempts to connect to Postgres with delay.
    """
    connection_retries = module.params.get("connection_retries")
    connection_retries_delay = module.params.get("connection_retries_delay")
    last_e = None
    conn = None
    for attempt in range(0, connection_retries + 1):
        try:
            # Create the connection
            conn = psycopg.connect(**connection_params)
            return conn
        except psycopg.OperationalError as e:
            if attempt >= connection_retries:
                module.fail_json(msg=f"Error connecting to database: {e}")
            time.sleep(connection_retries_delay)
            last_e = None

    module.fail_json(msg=f"Error connecting to database: {last_e}")


def main():

    argument_spec = dict(
        database_host=dict(type="str", default="localhost"),
        database_port=dict(type="int", default=5432),
        database_name=dict(type="str", default="postgres"),
        database_user=dict(type="str", required=True, aliases=['user', 'username']),
        database_user_password=dict(type="str", required=True, aliases=['password'], no_log=True),
        commands=dict(type="list", elements="str"),
        connection_retries=dict(type="int", default=0),
        connection_retries_delay=dict(type="int", default=3),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
    )

    if not HAS_PSYCOPG:
        module.fail_json(msg=missing_required_lib("psycopg"), exception=PSYCOG_IMPORT_ERROR)

    connection_params = {
        "host": module.params.get("database_host"),
        "dbname": module.params.get("database_name"),
        "user": module.params.get("database_user"),
        "password": module.params.get("database_user_password"),
        "port": module.params.get("database_port"),
    }
    commands = module.params.get("commands")

    try:
        conn = connect_with_retry(module, **connection_params)
        with conn.cursor() as cur:
            # Execute a command
            cur.execute("SELECT version();")

            # Fetch the result
            db_version = cur.fetchone()
            if not commands:
                conn.close()
                module.exit_json(msg=f"Connected! Database version: {db_version}", changed=False)

            # Execute command into database
            for item in commands:
                cur.execute(item)
            # Commit the changes (psycopg3 does not autocommit by default)
            conn.commit()
            conn.close()

            module.exit_json(changed=True, msg="Commands successfully executed.")

    except Exception as e:
        module.fail_json(msg=f"Module failed with: {e}")


if __name__ == "__main__":
    main()
