/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_switch_opaque.cpp
 * @brief Fuzz harness for SwitchOpaqueDataParser::create.
 */

#include <cstdint>
#include <cstddef>

#include "nv_attestation/switch/spdm/switch_opaque_data_parser.hpp"
#include "fuzz_init.h"

using namespace nvattestation;

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return fuzz::init_sdk_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<ParsedOpaqueFieldData> fields =
        fuzz::decode_opaque_fields(data, size);

    SwitchOpaqueDataParser parser;
    SwitchOpaqueDataParser::create(fields, parser);

    return 0;
}
