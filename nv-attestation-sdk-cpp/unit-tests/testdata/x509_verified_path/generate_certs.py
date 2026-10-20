#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 sol pbc
# SPDX-License-Identifier: Apache-2.0
"""Regenerate the certificate fixtures for verified_path_test.cpp.

A five-certificate chain shaped like a GPU device chain
(root -> l2 -> l3 -> l4 -> leaf), an unrelated certificate issued by l3, and
a second, unrelated root. Keys are fresh on every run.

    pip install cryptography && python3 generate_certs.py
"""

import datetime as dt
import pathlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

OUT = pathlib.Path(__file__).resolve().parent
NOT_BEFORE = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
NOT_AFTER = dt.datetime(2049, 12, 31, tzinfo=dt.timezone.utc)


def certificate(subject, key, issuer_cert, issuer_key, ca):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name if issuer_cert is None else issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if issuer_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA384())


def main():
    keys = {label: ec.generate_private_key(ec.SECP384R1()) for label in
            ("root", "l2", "l3", "l4", "leaf", "unrelated", "stranger_root")}
    certs = {}
    certs["root"] = certificate("Test Device Identity CA", keys["root"], None, keys["root"], True)
    certs["l2"] = certificate("Test Identity", keys["l2"], certs["root"], keys["root"], True)
    certs["l3"] = certificate("Test Provisioner ICA", keys["l3"], certs["l2"], keys["l2"], True)
    certs["l4"] = certificate("Test Device", keys["l4"], certs["l3"], keys["l3"], True)
    certs["leaf"] = certificate("Test Device Alias", keys["leaf"], certs["l4"], keys["l4"], False)
    certs["unrelated"] = certificate("Test Unrelated", keys["unrelated"], certs["l3"], keys["l3"], False)
    certs["stranger_root"] = certificate("Test Stranger CA", keys["stranger_root"], None, keys["stranger_root"], True)
    for label, cert in certs.items():
        (OUT / f"{label}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    main()
