# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import subprocess
from unittest.mock import patch

import pytest

from ansible_collections.hashicorp.vault.plugins.module_utils.tpm_device import (
    TpmDeviceError,
    read_endorsement_key_pem,
)

PEM = "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n"


def _completed(command, **_kwargs):
    if command[0] == "tpm2_createek":
        context = command[command.index("-c") + 1]
        with open(context, "w", encoding="utf-8") as handle:
            handle.write("ctx")
    if command[0] == "tpm2_readpublic":
        pem_path = command[command.index("-o") + 1]
        with open(pem_path, "w", encoding="utf-8") as pem_file:
            pem_file.write("  " + PEM.strip() + "  ")
    return subprocess.CompletedProcess(command, 0, "", "")


@patch("ansible_collections.hashicorp.vault.plugins.module_utils.tpm_device.subprocess.run")
def test_read_endorsement_key_pem(mock_run):
    mock_run.side_effect = _completed
    pem = read_endorsement_key_pem("/dev/tpmrm0")
    assert pem == PEM
    create = mock_run.call_args_list[0]
    assert create.args[0][:2] == ["tpm2_createek", "-G"]
    assert create.kwargs["env"]["TPM2TOOLS_TCTI"] == "device:/dev/tpmrm0"
    assert mock_run.call_args_list[1].args[0][0] == "tpm2_readpublic"
    assert mock_run.call_args_list[2].args[0][0] == "tpm2_flushcontext"


@patch("ansible_collections.hashicorp.vault.plugins.module_utils.tpm_device.subprocess.run")
def test_read_endorsement_key_reports_a_missing_binary(mock_run):
    mock_run.side_effect = FileNotFoundError("tpm2_createek")
    with pytest.raises(TpmDeviceError, match="tpm2-tools"):
        read_endorsement_key_pem("/dev/tpmrm0")


@patch("ansible_collections.hashicorp.vault.plugins.module_utils.tpm_device.subprocess.run")
def test_read_endorsement_key_reports_tpm_errors(mock_run):
    mock_run.side_effect = subprocess.CalledProcessError(1, ["tpm2_createek"], stderr="no such device")
    with pytest.raises(TpmDeviceError, match="no such device"):
        read_endorsement_key_pem("/dev/tpm0")


def test_read_endorsement_key_requires_a_path():
    with pytest.raises(TpmDeviceError, match="device_path is required"):
        read_endorsement_key_pem("  ")
