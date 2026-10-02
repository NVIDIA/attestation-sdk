/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_hex_to_bytes.cpp
 * @brief Fuzz harness for nvattestation::hex_string_to_bytes.
 */

#include <cstdint>
#include <cstddef>
#include <string>

#include "nv_attestation/utils.h"
#include "fuzz_init.h"

using namespace nvattestation;

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return fuzz::init_sdk_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string hex(reinterpret_cast<const char*>(data), size);
    hex_string_to_bytes(hex);
    return 0;
}
