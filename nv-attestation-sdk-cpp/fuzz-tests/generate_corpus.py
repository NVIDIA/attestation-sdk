#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Populates fuzz-test seed corpora into a destination directory.

Real-capture seeds are copied from unit-tests/testdata (the source of truth
for the SDK's own tests). Synthetic seeds for parsers that don't have a
captured payload (hex_to_bytes, gpu_opaque, switch_opaque) are emitted
inline. Signed-CoRIM seeds come from
unit-tests/testdata/sample_rims/corim_signed/, which is populated by
generate_fixtures.py — run `make prepare-test-data` (or its underlying
scripts) before this script if that dir is empty.

Usage:
  python3 fuzz-tests/generate_corpus.py <dest_dir>
  python3 fuzz-tests/generate_corpus.py --verify <dest_dir>

<dest_dir> is typically $(BUILD_DIR)/fuzz-tests/corpus.
"""

from __future__ import annotations

import argparse
import shutil
import struct
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
TESTDATA = REPO_ROOT / "unit-tests" / "testdata"
CORIM_TESTDATA = TESTDATA / "sample_rims" / "corim"
COMID_TESTDATA = TESTDATA / "sample_rims" / "comid"
CORIM_SIGNED_TESTDATA = TESTDATA / "sample_rims" / "corim_signed"
EAT_TESTDATA = TESTDATA / "sample_rims" / "eat"

# Signed-token EAT fixtures (55799/61/COSE tag stack); every other .cbor in the
# eat/ dir is a bare claims-set payload for the unsigned harness.
EAT_SIGNED_NAMES = {"full_signed.cbor", "bare_cose.cbor"}

# Must match SpdmMeasurementRequestMessage11::kRequestLength
# (include/nv_attestation/spdm/spdm_req.hpp).
SPDM_REQUEST_LEN = 37

CORIM_FILES = sorted(p.name for p in CORIM_TESTDATA.glob("*.cbor"))
COMID_FILES = sorted(p.name for p in COMID_TESTDATA.glob("*.cbor"))


# ---------------------------------------------------------------------------
# Real-capture seeds: copied / derived from unit-tests/testdata.
# ---------------------------------------------------------------------------

# RIM XML documents — used verbatim by RimDocument::create_from_rim_data.
RIM_FILES = [
    "NV_GPU_DRIVER_GH100_550.144.03.xml",
    "incorrect_cert_chain_driver_rim.xml",
    "incorrect_signature_driver_rim.xml",
    "switchVBIOSRim_NV_SWITCH_BIOS_5612_0002_890_9610550001.xml",
]

# (source, subdir) pairs. Same two cert chains seed both X.509 harnesses.
CERT_CHAIN_COPIES = [
    ("hopperCertChain.txt", "x509_cert_chain"),
    ("switchCertChain.txt", "x509_cert_chain"),
    ("hopperCertChain.txt", "x509_from_cert"),
    ("switchCertChain.txt", "x509_from_cert"),
]

# SPDM captures live as hex in AttestationReport.txt. First kRequestLength
# bytes are the request; the rest is the response. See unit-tests/gpu/spdm/
# spdm_req_test.cpp and spdm_resp_test.cpp for the same split logic.
SPDM_CAPTURES = [
    ("hopperAttestationReport.txt", "hopper"),
    ("switchAttestationReport.txt", "switch"),
]


def copy_real_captures(dest: Path) -> None:
    for name in RIM_FILES:
        _copy(TESTDATA / name, dest / "rim_document" / name)

    for name, subdir in CERT_CHAIN_COPIES:
        _copy(TESTDATA / name, dest / subdir / name)

    for report_name, label in SPDM_CAPTURES:
        src = TESTDATA / report_name
        hex_str = src.read_text().strip()
        raw = bytes.fromhex(hex_str)
        if len(raw) < SPDM_REQUEST_LEN:
            raise RuntimeError(f"{src} too short: {len(raw)} < {SPDM_REQUEST_LEN}")
        req, resp = raw[:SPDM_REQUEST_LEN], raw[SPDM_REQUEST_LEN:]
        _write(dest / "spdm_req" / f"{label}_req.bin", req)
        _write(dest / "spdm_resp" / f"{label}_resp.bin", resp)

    for name in CORIM_FILES:
        _copy(CORIM_TESTDATA / name, dest / "corim_unsigned" / name)

    for name in COMID_FILES:
        _copy(COMID_TESTDATA / name, dest / "corim_comid" / name)

    # Signed-CoRIM seeds are produced by generate_fixtures.py (gitignored).
    # Empty dir is fine — libFuzzer just starts that harness from zero.
    signed_files = sorted(p.name for p in CORIM_SIGNED_TESTDATA.glob("*.cbor"))
    if signed_files:
        for name in signed_files:
            _copy(CORIM_SIGNED_TESTDATA / name, dest / "corim_signed" / name)
    else:
        print(f"WARNING: no signed CoRIM seeds at {CORIM_SIGNED_TESTDATA}; "
              "run `make prepare-test-data` to populate")
        (dest / "corim_signed").mkdir(parents=True, exist_ok=True)

    # EAT seeds are generated (.diag -> .cbor by prepare-test-data.sh; the signed
    # tokens by generate_fixtures.py). Split claims-set fixtures (fuzz_eat) from
    # signed-token fixtures (fuzz_eat_signed). Empty dirs are fine — libFuzzer
    # starts that harness from zero.
    eat_files = sorted(p.name for p in EAT_TESTDATA.glob("*.cbor"))
    for name in eat_files:
        subdir = "eat_signed" if name in EAT_SIGNED_NAMES else "eat"
        _copy(EAT_TESTDATA / name, dest / subdir / name)
    for subdir in ("eat", "eat_signed"):
        (dest / subdir).mkdir(parents=True, exist_ok=True)
    if not eat_files:
        print(f"WARNING: no EAT seeds at {EAT_TESTDATA}; "
              "run `make prepare-test-data` to populate")


# ---------------------------------------------------------------------------
# Synthetic seeds.
# ---------------------------------------------------------------------------

# Small, structurally distinct seeds for hex_string_to_bytes.
# The function reads 2-char substrings with strtol, so it tolerates odd
# lengths and non-hex chars — we want all of those paths covered.
HEX_SEEDS = {
    "empty.bin":        b"",
    "byte_pair.bin":    b"deadbeef",
    "sha256_zeros.bin": b"0" * 64,
    "odd_length.bin":   b"abc",
    "mixed_case.bin":   b"DeadBeef0123",
    "with_invalid.bin": b"de@dbeef",
}


def tlv(type_: int, payload: bytes) -> bytes:
    """Encode one legacy-format opaque-data field (no NVDAOD header):
    [2-byte LE type][2-byte LE length][payload]. Matches
    OpaqueDataParser::parse_tlv_entries(has_value_type=false)."""
    if not 0 <= type_ <= 0xFFFF:
        raise ValueError(f"type {type_} out of uint16 range")
    if len(payload) > 0xFFFF:
        raise ValueError(f"payload too large ({len(payload)} > 65535)")
    return struct.pack("<HH", type_, len(payload)) + payload


# Magic + per-field encoding for the NVDAOD header format. Must match
# OpaqueFieldSizes / OPAQUE_DATA_MAGIC in
# include/nv_attestation/spdm/spdm_opaque_data_parser.hpp.
NVDAOD_MAGIC = b"NVDAOD"
MIN_SVN_OPAQUE_VALUE_TYPE = 0x87  # see LocalGpuVerifier::compare_opaque_data (verify.cpp)


def nvdaod_tlv(type_: int, value_type: int, payload: bytes) -> bytes:
    """Encode one NVDAOD-format opaque-data field:
    [2-byte LE type][2-byte LE value_type][2-byte LE length][payload]."""
    if not 0 <= type_ <= 0xFFFF:
        raise ValueError(f"type {type_} out of uint16 range")
    if not 0 <= value_type <= 0xFFFF:
        raise ValueError(f"value_type {value_type} out of uint16 range")
    if len(payload) > 0xFFFF:
        raise ValueError(f"payload too large ({len(payload)} > 65535)")
    return struct.pack("<HHH", type_, value_type, len(payload)) + payload


def nvdaod_header(major: int, minor: int, profile: int = 0) -> bytes:
    return NVDAOD_MAGIC + struct.pack("<H", profile) + bytes((major, minor, 0, 0))


# Type IDs mirror GpuOpaqueDataType / SwitchOpaqueDataType in
# include/nv_attestation/{gpu,switch}/spdm/*_opaque_data_parser.hpp.
# Kept here just to name the seeds; authoritative values live in the SDK.
_GPU_T = {"CERT_ISSUER_NAME": 1, "DRIVER_VERSION": 3, "VBIOS_VERSION": 6,
          "MSRSCNT": 12, "FWID": 20, "SWITCH_PDI": 22,
          "OPAQUE_DATA_VERSION": 34}
_SW_T = {"CERT_ISSUER_NAME": 1, "DRIVER_VERSION": 3, "VBIOS_VERSION": 6,
         "MSRSCNT": 12, "FWID": 20, "DEVICE_PDI": 22,
         "SWITCH_GPU_PDIS": 26, "SWITCH_PORTS": 27}

GPU_OPAQUE_SEEDS = {
    "single_byte_field.bin": [(_GPU_T["CERT_ISSUER_NAME"], b"NVIDIA")],
    "msrscnt_uint32.bin":    [(_GPU_T["MSRSCNT"], struct.pack("<III", 1, 2, 3))],
    "switch_pdi.bin":        [(_GPU_T["SWITCH_PDI"], bytes(range(1, 9)))],
    "fwid.bin":              [(_GPU_T["FWID"], b"\xab" * 48)],
    "multi_field.bin":       [
        (_GPU_T["DRIVER_VERSION"], b"580.65.06"),
        (_GPU_T["VBIOS_VERSION"],  b"96.00.89.00.00"),
        (_GPU_T["OPAQUE_DATA_VERSION"], b"\x01\x00"),
    ],
    "unknown_type.bin":      [(0x1234, b"\xff\xee\xdd")],
}

# NVDAOD-header-format seeds — the typed-TLV path added for FSP firmware
# MIN_SVN rollback protection. Each entry is (type, value_type, payload).
GPU_OPAQUE_NVDAOD_SEEDS = {
    "nvdaod_min_svn.bin": [
        (0x1000, MIN_SVN_OPAQUE_VALUE_TYPE, struct.pack("<H", 5)),
    ],
    "nvdaod_multi_field.bin": [
        (_GPU_T["DRIVER_VERSION"], 0, b"580.65.06"),
        (0x1000, MIN_SVN_OPAQUE_VALUE_TYPE, struct.pack("<H", 5)),
        (_GPU_T["FWID"], 0, b"\xab" * 48),
    ],
    "nvdaod_wrong_value_type.bin": [
        (0x1000, 0x00, struct.pack("<H", 5)),
    ],
}

SWITCH_OPAQUE_SEEDS = {
    "single_byte_field.bin": [(_SW_T["CERT_ISSUER_NAME"], b"NVIDIA")],
    "msrscnt_uint32.bin":    [(_SW_T["MSRSCNT"], struct.pack("<III", 1, 2, 3))],
    "device_pdi.bin":        [(_SW_T["DEVICE_PDI"], bytes(range(1, 9)))],
    "switch_gpu_pdis.bin":   [(_SW_T["SWITCH_GPU_PDIS"], b"\x11" * 8 + b"\x22" * 8)],
    "switch_ports.bin":      [(_SW_T["SWITCH_PORTS"], b"\x01\x00\x02\x00\x03\x00")],
    "multi_field.bin":       [
        (_SW_T["DRIVER_VERSION"], b"580.65.06"),
        (_SW_T["VBIOS_VERSION"],  b"96.00.89.00.00"),
        (_SW_T["FWID"],           b"\xab" * 48),
    ],
    "unknown_type.bin":      [(0xABCD, b"\x00\x01\x02")],
}


def write_synthetic(dest: Path) -> None:
    for name, data in HEX_SEEDS.items():
        _write(dest / "hex_to_bytes" / name, data)

    for name, fields in GPU_OPAQUE_SEEDS.items():
        blob = b"".join(tlv(t, p) for t, p in fields)
        _write(dest / "gpu_opaque" / name, blob)

    for name, fields in GPU_OPAQUE_NVDAOD_SEEDS.items():
        blob = nvdaod_header(major=0, minor=2) + b"".join(nvdaod_tlv(t, vt, p) for t, vt, p in fields)
        _write(dest / "gpu_opaque" / name, blob)

    for name, fields in SWITCH_OPAQUE_SEEDS.items():
        blob = b"".join(tlv(t, p) for t, p in fields)
        _write(dest / "switch_opaque" / name, blob)

    # No seeds exist for these, but the Makefile's corpus-missing check
    # still requires the directories. libFuzzer handles empty corpora fine
    # and will accumulate discovered inputs on disk across runs.
    for empty in ("x509_pkcs11_sig", "opaque_data"):
        (dest / empty).mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Verify: re-parse opaque seeds to confirm they match the generator's intent.
# Non-opaque corpora are opaque blobs (XML / certs / raw bytes) — verification
# is "does the file exist" only.
# ---------------------------------------------------------------------------

def _parse_tlvs(raw: bytes) -> list[tuple[int, bytes]]:
    out: list[tuple[int, bytes]] = []
    off = 0
    while off < len(raw):
        if off + 4 > len(raw):
            raise ValueError(f"header truncated at offset {off}")
        type_, length = struct.unpack_from("<HH", raw, off)
        off += 4
        if off + length > len(raw):
            raise ValueError(f"payload truncated: type={type_} len={length}")
        out.append((type_, raw[off:off + length]))
        off += length
    if off != len(raw):
        raise ValueError(f"trailing bytes: consumed {off} of {len(raw)}")
    return out


def _parse_nvdaod_tlvs(raw: bytes) -> list[tuple[int, int, bytes]]:
    header_len = len(nvdaod_header(0, 0))
    if raw[:len(NVDAOD_MAGIC)] != NVDAOD_MAGIC:
        raise ValueError("missing NVDAOD magic")
    out: list[tuple[int, int, bytes]] = []
    off = header_len
    while off < len(raw):
        if off + 6 > len(raw):
            raise ValueError(f"header truncated at offset {off}")
        type_, value_type, length = struct.unpack_from("<HHH", raw, off)
        off += 6
        if off + length > len(raw):
            raise ValueError(f"payload truncated: type={type_} len={length}")
        out.append((type_, value_type, raw[off:off + length]))
        off += length
    if off != len(raw):
        raise ValueError(f"trailing bytes: consumed {off} of {len(raw)}")
    return out


def verify(dest: Path) -> int:
    failures = 0
    for name, fields in GPU_OPAQUE_NVDAOD_SEEDS.items():
        path = dest / "gpu_opaque" / name
        if not path.exists():
            print(f"MISSING {path}")
            failures += 1
            continue
        try:
            got = _parse_nvdaod_tlvs(path.read_bytes())
        except ValueError as e:
            print(f"MALFORMED {path}: {e}")
            failures += 1
            continue
        if got != fields:
            print(f"MISMATCH {path}\n  expected: {fields}\n  got: {got}")
            failures += 1
            continue
        print(f"OK {path} — {len(got)} field(s)")

    for subdir, expected in [("gpu_opaque", GPU_OPAQUE_SEEDS),
                             ("switch_opaque", SWITCH_OPAQUE_SEEDS)]:
        for name, fields in expected.items():
            path = dest / subdir / name
            if not path.exists():
                print(f"MISSING {path}")
                failures += 1
                continue
            try:
                got = _parse_tlvs(path.read_bytes())
            except ValueError as e:
                print(f"MALFORMED {path}: {e}")
                failures += 1
                continue
            if got != fields:
                print(f"MISMATCH {path}\n  expected: {fields}\n  got: {got}")
                failures += 1
                continue
            print(f"OK {path} — {len(got)} field(s)")

    for name in HEX_SEEDS:
        path = dest / "hex_to_bytes" / name
        print(("OK " if path.exists() else "MISSING ") + str(path))
        if not path.exists():
            failures += 1

    for name in RIM_FILES:
        path = dest / "rim_document" / name
        print(("OK " if path.exists() else "MISSING ") + str(path))
        if not path.exists():
            failures += 1

    for name in CORIM_FILES:
        path = dest / "corim_unsigned" / name
        print(("OK " if path.exists() else "MISSING ") + str(path))
        if not path.exists():
            failures += 1

    for name in COMID_FILES:
        path = dest / "corim_comid" / name
        print(("OK " if path.exists() else "MISSING ") + str(path))
        if not path.exists():
            failures += 1

    signed_dir = dest / "corim_signed"
    if not signed_dir.exists():
        print(f"MISSING {signed_dir}")
        failures += 1
    else:
        print(f"OK {signed_dir} ({len(list(signed_dir.glob('*.cbor')))} signed seed(s))")

    for subdir in ("eat", "eat_signed"):
        d = dest / subdir
        if not d.exists():
            print(f"MISSING {d}")
            failures += 1
        else:
            print(f"OK {d} ({len(list(d.glob('*.cbor')))} seed(s))")

    return failures


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _copy(src: Path, dst: Path) -> None:
    if not src.exists():
        raise FileNotFoundError(f"expected source seed {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def _write(dst: Path, data: bytes) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)


# ---------------------------------------------------------------------------

def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dest", type=Path, help="destination root for corpora")
    ap.add_argument("--verify", action="store_true",
                    help="parse on-disk seeds and report mismatches instead "
                         "of writing")
    args = ap.parse_args(argv[1:])

    if args.verify:
        return verify(args.dest.resolve())

    dest = args.dest.resolve()
    copy_real_captures(dest)
    write_synthetic(dest)
    print(f"corpora written under {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
