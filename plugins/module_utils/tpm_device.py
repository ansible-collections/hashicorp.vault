# -*- coding: utf-8 -*-

# Copyright (c) 2026 Red Hat, Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Read a TPM 2.0 endorsement key from the local device."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import subprocess
import tempfile

from ansible_collections.hashicorp.vault.plugins.module_utils.vault_exceptions import VaultError
from ansible_collections.hashicorp.vault.plugins.module_utils.vault_tpm import normalize_pem

__all__ = ["TpmDeviceError", "read_endorsement_key_pem"]


class TpmDeviceError(VaultError):
    """Raised when the local TPM endorsement key cannot be read."""


def read_endorsement_key_pem(device_path: str) -> str:
    """
    Return the RSA endorsement public key at device_path as a PEM string.

    vault tpm enroll reads this key and posts it to identity/tpm. The same read
    is done here with tpm2-tools so the module does not shell out to the Vault CLI.
    tpm2_createek derives the standard RSA EK; tpm2_readpublic writes it as PEM.
    The transient handle is flushed before returning.
    """
    if not device_path or not str(device_path).strip():
        raise TpmDeviceError("device_path is required to read a TPM endorsement key")

    env = os.environ.copy()
    env["TPM2TOOLS_TCTI"] = f"device:{device_path}"
    try:
        with tempfile.TemporaryDirectory() as tmp:
            context = os.path.join(tmp, "ek.ctx")
            public_path = os.path.join(tmp, "ek.pub")
            pem_path = os.path.join(tmp, "ek.pem")
            try:
                _run(["tpm2_createek", "-G", "rsa", "-c", context, "-u", public_path], env)
                _run(["tpm2_readpublic", "-c", context, "-f", "pem", "-o", pem_path], env)
                with open(pem_path, encoding="utf-8") as pem_file:
                    pem = pem_file.read()
            finally:
                if os.path.exists(context):
                    try:
                        subprocess.run(
                            ["tpm2_flushcontext", "-c", context],
                            env=env,
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                    except (OSError, subprocess.SubprocessError):
                        pass
    except FileNotFoundError as exc:
        raise TpmDeviceError(
            "Reading a TPM endorsement key requires tpm2-tools (tpm2_createek and tpm2_readpublic) "
            "on the managed node. Pass tpm_ek_public_key instead of device_path to enroll from a PEM."
        ) from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or str(exc)).strip()
        raise TpmDeviceError(f"Failed to read the TPM endorsement key from {device_path}: {detail}") from exc
    except OSError as exc:
        raise TpmDeviceError(f"Failed to read the TPM endorsement key from {device_path}: {exc}") from exc

    if "BEGIN PUBLIC KEY" not in pem:
        raise TpmDeviceError(f"tpm2_readpublic did not return a PEM public key from {device_path}")
    return normalize_pem(pem)


def _run(command, env) -> None:
    subprocess.run(command, env=env, capture_output=True, text=True, check=True)
