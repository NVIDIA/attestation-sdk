#!/usr/bin/env python3
"""COSE_Sign1-wrapped CoRIM fixtures.

Unsigned CoRIM/CoMID fixtures live as `.diag` text alongside this file and are
materialised to `.cbor` by `cbor-diag` (see `make prepare-test-data`). This
script then wraps a selected subset in COSE_Sign1 using the ES384 test chain
from `unit-tests/testdata/x509_cert_chain/`.

Signed fixtures are non-deterministic (ECDSA nonce) and therefore gitignored.
"""
import hashlib
import os
from pathlib import Path

import cbor2
from cbor2 import CBORTag
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

_HERE = Path(__file__).resolve().parent
_X509_CHAIN_DIR = _HERE.parent.parent / "x509_cert_chain"
_LEAF_KEY_PEM = _X509_CHAIN_DIR / "cose_signing_leaf_key.pem"
_LEAF_CERT_PEM = _X509_CHAIN_DIR / "cose_signing_leaf.crt"
_ROOT_CERT_PEM = _X509_CHAIN_DIR / "cose_signing_root.crt"

# COSE header labels / algorithm IDs (RFC 9052/9053/9360).
COSE_HEADER_ALG = 1
COSE_HEADER_X5CHAIN = 33
COSE_HEADER_X5T = 34
COSE_TAG_SIGN1 = 18
CWT_TAG = 61              # RFC 8392 CWT tag
SELF_DESCRIBED_CBOR_TAG = 55799  # RFC 8949 self-described CBOR tag
ALG_ES384 = -35
ALG_ES256 = -7
HASH_SHA256 = -16
HASH_SHA384 = -43
HASH_SHA512 = -44
P384_COORD_BYTES = 48


_signing_material_cache = None


def _load_signing_material():
    global _signing_material_cache
    if _signing_material_cache is not None:
        return _signing_material_cache
    if not _LEAF_KEY_PEM.exists() or not _LEAF_CERT_PEM.exists():
        raise FileNotFoundError(
            f"missing ES384 signing chain at {_X509_CHAIN_DIR}; run "
            f"unit-tests/testdata/x509_cert_chain/generate_test_certs.sh first"
        )
    leaf_key = serialization.load_pem_private_key(_LEAF_KEY_PEM.read_bytes(), password=None)
    leaf_cert = x509.load_pem_x509_certificate(_LEAF_CERT_PEM.read_bytes())
    leaf_cert_der = leaf_cert.public_bytes(serialization.Encoding.DER)
    _signing_material_cache = (leaf_key, leaf_cert_der)
    return _signing_material_cache


_root_cert_der_cache = None


def _load_root_cert_der():
    global _root_cert_der_cache
    if _root_cert_der_cache is not None:
        return _root_cert_der_cache
    if not _ROOT_CERT_PEM.exists():
        raise FileNotFoundError(f"missing {_ROOT_CERT_PEM}")
    cert = x509.load_pem_x509_certificate(_ROOT_CERT_PEM.read_bytes())
    _root_cert_der_cache = cert.public_bytes(serialization.Encoding.DER)
    return _root_cert_der_cache


def _ecdsa_der_to_raw(der_sig, key_size_bytes):
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(key_size_bytes, "big") + s.to_bytes(key_size_bytes, "big")


def _read_payload(name):
    """Read a CBOR fixture by basename from the corim/ directory."""
    path = _HERE / f"{name}.cbor"
    if not path.exists():
        raise FileNotFoundError(
            f"missing {path}; run `make prepare-test-data` to materialise "
            f"unsigned fixtures from their `.diag` sources first"
        )
    return path.read_bytes()


def _sign_cose1(payload, *, alg=ALG_ES384, include_x5chain=True,
                chain_with_root=False, x5chain_in_unprotected=False,
                x5chain_in_both=False, x5t_hash_alg=HASH_SHA384,
                x5t_thumbprint_override=None, payload_nil=False,
                protected_empty=False, x5chain_cert_override=None,
                extra_protected_headers=None,
                tamper=None):
    """Wrap `payload` in COSE_Sign1 using the test ES384 leaf.

    Flag matrix (mostly orthogonal):
      chain_with_root        — emit x5chain as [leaf, root] array, not bare bstr
      x5chain_in_unprotected — x5chain in unprotected map; protected carries x5t
      x5chain_in_both        — error path: x5chain present in both maps
      x5t_hash_alg           — hash alg for x5t binding (default SHA-384)
      x5t_thumbprint_override — emit a wrong thumbprint (negative test)
      payload_nil            — emit COSE nil payload (rejected: detached not supported)
      protected_empty        — emit empty protected bstr (rejected: no alg)
      x5chain_cert_override  — substitute the leaf cert with arbitrary bytes
      tamper                 — "bad_sig" | "tampered_payload"
    """
    leaf_key, leaf_cert_der = _load_signing_material()
    chain_cert = x5chain_cert_override if x5chain_cert_override is not None else leaf_cert_der

    def _x5chain_value():
        if chain_with_root:
            return [chain_cert, _load_root_cert_der()]
        return chain_cert

    if protected_empty:
        protected = b""
    else:
        protected_header = {COSE_HEADER_ALG: alg}
        if extra_protected_headers:
            protected_header.update(extra_protected_headers)
        if include_x5chain and not x5chain_in_unprotected:
            protected_header[COSE_HEADER_X5CHAIN] = _x5chain_value()
        if include_x5chain and (x5chain_in_unprotected or x5chain_in_both):
            digest = hashlib.sha384(chain_cert) if x5t_hash_alg == HASH_SHA384 \
                else hashlib.sha256(chain_cert) if x5t_hash_alg == HASH_SHA256 \
                else hashlib.sha512(chain_cert)
            thumb = digest.digest()
            if x5t_thumbprint_override is not None:
                thumb = x5t_thumbprint_override
            protected_header[COSE_HEADER_X5T] = [x5t_hash_alg, thumb]
        protected = cbor2.dumps(protected_header)

    unprotected = {}
    if include_x5chain and (x5chain_in_unprotected or x5chain_in_both):
        unprotected[COSE_HEADER_X5CHAIN] = _x5chain_value()

    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    der_sig = leaf_key.sign(sig_structure, ec.ECDSA(hashes.SHA384()))
    raw_sig = _ecdsa_der_to_raw(der_sig, P384_COORD_BYTES)
    if tamper == "bad_sig":
        raw_sig = raw_sig[:-1] + bytes([raw_sig[-1] ^ 0x01])
    elif tamper == "truncate_sig":
        raw_sig = raw_sig[:64]

    transmit_payload = payload
    if tamper == "tampered_payload":
        if not payload:
            raise ValueError("cannot tamper an empty payload")
        transmit_payload = payload[:-1] + bytes([payload[-1] ^ 0x01])

    if payload_nil:
        cose_sign1 = [protected, unprotected, None, raw_sig]
    else:
        cose_sign1 = [protected, unprotected, transmit_payload, raw_sig]
    return cbor2.dumps(CBORTag(COSE_TAG_SIGN1, cose_sign1))


# ---------------- Signed-path fixtures ----------------

def make_signed_full():
    return _sign_cose1(_read_payload("full"))


def make_signed_full_chained():
    return _sign_cose1(_read_payload("full"), chain_with_root=True)


def make_signed_x5chain_unprotected():
    return _sign_cose1(_read_payload("full"), x5chain_in_unprotected=True)


def make_signed_x5chain_unprotected_sha256():
    return _sign_cose1(_read_payload("full"), x5chain_in_unprotected=True,
                       x5t_hash_alg=HASH_SHA256)


def make_signed_x5chain_unprotected_sha512():
    return _sign_cose1(_read_payload("full"), x5chain_in_unprotected=True,
                       x5t_hash_alg=HASH_SHA512)


def make_signed_reject_x5chain_in_both():
    return _sign_cose1(_read_payload("full"), x5chain_in_both=True)


def make_signed_reject_x5t_mismatch():
    return _sign_cose1(_read_payload("full"), x5chain_in_unprotected=True,
                       x5t_thumbprint_override=b"\x00" * 48)


def make_signed_x5chain_unprotected_no_x5t():
    # Hand-roll x5chain in the unprotected header without x5t.
    leaf_key, leaf_cert_der = _load_signing_material()
    payload = _read_payload("full")
    protected = cbor2.dumps({COSE_HEADER_ALG: ALG_ES384})
    unprotected = {COSE_HEADER_X5CHAIN: leaf_cert_der}
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    der_sig = leaf_key.sign(sig_structure, ec.ECDSA(hashes.SHA384()))
    raw_sig = _ecdsa_der_to_raw(der_sig, P384_COORD_BYTES)
    return cbor2.dumps(CBORTag(COSE_TAG_SIGN1,
                               [protected, unprotected, payload, raw_sig]))


def make_signed_reject_unknown_x5t_alg():
    return _sign_cose1(_read_payload("full"), x5chain_in_unprotected=True,
                       x5t_hash_alg=-99)


def make_signed_reject_detached_payload():
    return _sign_cose1(_read_payload("full"), payload_nil=True)


def make_signed_reject_empty_protected():
    return _sign_cose1(_read_payload("full"), protected_empty=True)


def make_signed_reject_invalid_cert_in_x5chain():
    return _sign_cose1(_read_payload("full"), x5chain_cert_override=b"\x00" * 64)


def make_signed_extended():
    return _sign_cose1(_read_payload("extended"))


def make_signed_with_profile():
    return _sign_cose1(_read_payload("with_profile"))


def make_signed_reject_bad_sig():
    return _sign_cose1(_read_payload("full"), tamper="bad_sig")


def make_signed_reject_wrong_alg():
    return _sign_cose1(_read_payload("full"), alg=ALG_ES256)


def make_signed_reject_missing_x5chain():
    return _sign_cose1(_read_payload("full"), include_x5chain=False)


def make_signed_reject_tampered_payload():
    return _sign_cose1(_read_payload("full"), tamper="tampered_payload")


def make_signed_with_extra_protected_headers():
    # Protected header keys 1 (alg), 3 (content_type), 8 (custom bstr), 33 (x5chain).
    # Exercises the CDDL tolerance added for keys that appear between alg and x5chain.
    return _sign_cose1(_read_payload("full"),
                       extra_protected_headers={3: "application/rim+cbor", 8: b"custom"})


def make_signed_reject_truncated_sig():
    # 64-byte signature on a P-384 leaf: EVP_DigestVerifyFinal rejects it as
    # an invalid signature. Demonstrates that the verifier itself enforces
    # the alg/sig-width constraint — no separate gate needed in the SDK.
    return _sign_cose1(_read_payload("full"), tamper="truncate_sig")


# ---------------- EAT signed-path fixtures ----------------

_EAT_DIR = _HERE.parent / "eat"


def _read_ocp_payload(name):
    """Read a CBOR fixture by basename from the sibling eat/ directory."""
    path = _EAT_DIR / f"{name}.cbor"
    if not path.exists():
        raise FileNotFoundError(
            f"missing {path}; run `make prepare-test-data` to materialise "
            f"unsigned EAT fixtures from their `.diag` sources first"
        )
    return path.read_bytes()


def make_eat_bare_cose():
    """Bare #6.18(COSE_Sign1) over the OCP claims-set: no 61/55799 wrap.

    Used to prove parse_eat_from_cwt rejects a missing outer tag stack.
    """
    return _sign_cose1(_read_ocp_payload("full"))


def make_eat_full_signed():
    """55799(61(18([...]))) over the OCP `full` claims-set, ES384-signed.

    The tag stack is self-described-CBOR (55799) wrapping CWT (61) wrapping
    the COSE_Sign1 tag (18), matching the EAT profile.
    """
    cose_sign1_tagged = _sign_cose1(_read_ocp_payload("full"))
    inner = cbor2.loads(cose_sign1_tagged)  # CBORTag(18, [...])
    cwt = CBORTag(CWT_TAG, inner)
    self_described = CBORTag(SELF_DESCRIBED_CBOR_TAG, cwt)
    return cbor2.dumps(self_described)


OCP_EAT_FIXTURES = [
    ("bare_cose",   make_eat_bare_cose),
    ("full_signed", make_eat_full_signed),
]


# ---------------- CoEV signed-path fixtures ----------------

_COEV_DIR = _HERE.parent / "coev"


def _read_coev_payload(name):
    """Read a CBOR fixture by basename from the sibling coev/ directory."""
    path = _COEV_DIR / f"{name}.cbor"
    if not path.exists():
        raise FileNotFoundError(
            f"missing {path}; run `make prepare-test-data` to materialise "
            f"unsigned CoEV fixtures from their `.diag` sources first"
        )
    return path.read_bytes()


def make_signed_coev_blackwell_fsp():
    return _sign_cose1(_read_coev_payload("blackwell_fsp_real"))


def make_signed_coev_blackwell_fsp_bad_sig():
    return _sign_cose1(_read_coev_payload("blackwell_fsp_real"), tamper="bad_sig")


COEV_FIXTURES = [
    ("blackwell_fsp_real",         make_signed_coev_blackwell_fsp),
    ("blackwell_fsp_real_bad_sig", make_signed_coev_blackwell_fsp_bad_sig),
]


# ---------------- Driver ----------------

FIXTURES = [
    ("signed_full",                              make_signed_full),
    ("signed_full_chained",                      make_signed_full_chained),
    ("signed_x5chain_unprotected",               make_signed_x5chain_unprotected),
    ("signed_x5chain_unprotected_sha256",        make_signed_x5chain_unprotected_sha256),
    ("signed_x5chain_unprotected_sha512",        make_signed_x5chain_unprotected_sha512),
    ("signed_reject_x5chain_in_both",            make_signed_reject_x5chain_in_both),
    ("signed_reject_x5t_mismatch",               make_signed_reject_x5t_mismatch),
    ("signed_x5chain_unprotected_no_x5t",        make_signed_x5chain_unprotected_no_x5t),
    ("signed_reject_unknown_x5t_alg",            make_signed_reject_unknown_x5t_alg),
    ("signed_reject_detached_payload",           make_signed_reject_detached_payload),
    ("signed_reject_empty_protected",            make_signed_reject_empty_protected),
    ("signed_reject_invalid_cert_in_x5chain",    make_signed_reject_invalid_cert_in_x5chain),
    ("signed_extended",                          make_signed_extended),
    ("signed_with_profile",                      make_signed_with_profile),
    ("signed_reject_bad_sig",                    make_signed_reject_bad_sig),
    ("signed_reject_wrong_alg",                  make_signed_reject_wrong_alg),
    ("signed_reject_missing_x5chain",            make_signed_reject_missing_x5chain),
    ("signed_reject_tampered_payload",           make_signed_reject_tampered_payload),
    ("signed_reject_truncated_sig",              make_signed_reject_truncated_sig),
    ("signed_with_extra_protected_headers",      make_signed_with_extra_protected_headers),
]


def main():
    out_dir = _HERE.parent / "corim_signed"
    out_dir.mkdir(exist_ok=True)
    for name, fn in FIXTURES:
        path = out_dir / f"{name}.cbor"
        data = fn()
        path.write_bytes(data)
        print(f"Wrote {len(data):>5} bytes to {path}")

    for name, fn in OCP_EAT_FIXTURES:
        path = _EAT_DIR / f"{name}.cbor"
        data = fn()
        path.write_bytes(data)
        print(f"Wrote {len(data):>5} bytes to {path}")

    coev_signed_dir = _HERE.parent / "coev_signed"
    coev_signed_dir.mkdir(exist_ok=True)
    for name, fn in COEV_FIXTURES:
        path = coev_signed_dir / f"{name}.cbor"
        data = fn()
        path.write_bytes(data)
        print(f"Wrote {len(data):>5} bytes to {path}")


if __name__ == "__main__":
    main()
