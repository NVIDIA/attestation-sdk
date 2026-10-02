/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_opaque_data.cpp
 * @brief Fuzz harness for OpaqueDataParser::create (generic TLV stream).
 */

#include <cstdint>
#include <cstddef>
#include <vector>

#include "nv_attestation/spdm/spdm_opaque_data_parser.hpp"
#include "fuzz_init.h"

using namespace nvattestation;

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return fuzz::init_sdk_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::vector<uint8_t> raw(data, data + size);

    OpaqueDataParser parser;
    OpaqueDataParser::create(raw, parser);

    return 0;
}
