/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_corim_unsigned.cpp
 * @brief Fuzz harness for parse_unsigned_corim (zcbor-generated CBOR decoder).
 *
 * Exercises the tagged unsigned CoRIM map (#6.501) decode + C++ wrapper
 * construction. Seed corpus is unit-tests/testdata/sample_rims/corim/{full,
 * alternate,extended}.cbor (copied by generate_corpus.py).
 */

#include <cstdint>
#include <cstddef>
#include <vector>

#include "nv_attestation/corim.h"
#include "fuzz_init.h"

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return fuzz::init_sdk_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::vector<uint8_t> bytes(data, data + size);
    nvattestation::CorimMap out;
    nvattestation::parse_unsigned_corim(bytes, out);
    return 0;
}
