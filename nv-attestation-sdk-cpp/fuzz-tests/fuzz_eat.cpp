/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_eat.cpp
 * @brief Fuzz harness for parse_eat_claims (zcbor-generated EAT claims decoder).
 *
 * Exercises the RFC 9711 eat-claims-map CBOR decode + C++ wrapper construction,
 * including per-measurement concise-evidence parsing. This is the unsigned
 * claims-set entry point (no COSE / tag stack); see fuzz_eat_signed for the
 * signed-token path. Seed corpus is the claims-set fixtures under
 * unit-tests/testdata/sample_rims/eat/ (copied by generate_corpus.py).
 */

#include <cstdint>
#include <cstddef>
#include <vector>

#include "nv_attestation/corim_evidence/eat.h"
#include "fuzz_init.h"

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return fuzz::init_sdk_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::vector<uint8_t> bytes(data, data + size);
    nvattestation::Eat out;
    nvattestation::parse_eat_claims(bytes, out);
    return 0;
}
