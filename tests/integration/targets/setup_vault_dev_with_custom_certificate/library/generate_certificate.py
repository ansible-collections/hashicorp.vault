#!/usr/bin/python
# -*- coding: utf-8 -*-

DOCUMENTATION = r'''
---
module: generate_certificate
short_description: Generate custom certificate.
description:
    - Generates custom certificate to test C(hashicorp.vault) ansible collection.
author: "Aubin Bikouo (@abikouo)"
options:
    cert_path:
        description: The path to the certificate file.
        type: str
        required: true
    key_path:
        description: The path to the key file.
        required: true
        type: str
'''


import datetime
import ipaddress

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

try:
    CRYPTO_IMPORT_ERR = None
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except Exception as e:
    CRYPTO_IMPORT_ERR = e


def run_module():
    module_args = dict(
        cert_path=dict(type='str', required=True),
        key_path=dict(type='str', required=True),
    )

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=False)
    if CRYPTO_IMPORT_ERR:
        module.fail_json(msg=missing_required_lib("cryptography"), exception=CRYPTO_IMPORT_ERR)

    cert_path = module.params["cert_path"]
    key_path = module.params["key_path"]

    # 1. Generate Private Key (equivalent to -newkey rsa:4096)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # 2. Setup Subject and Issuer (equivalent to -subj '/CN=localhost')
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    # 3. Build the Certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        # Equivalent to -days 365
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        # Equivalent to -addext 'subjectAltName = DNS:localhost,IP:127.0.0.1'
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        # Sign the certificate with the private key
        .sign(private_key, hashes.SHA256())
    )

    # 4. Write Private Key to File (equivalent to -keyout and -nodes)
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),  # equivalent to -nodes
            )
        )

    # 5. Write Certificate to File (equivalent to -out)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    module.exit_json(changed=True, msg="Certificates generated successfully!")


if __name__ == '__main__':
    run_module()
