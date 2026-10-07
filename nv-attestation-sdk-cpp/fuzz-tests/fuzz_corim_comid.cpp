/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_corim_comid.cpp
 * @brief Fuzz harness for parse_comid (standalone untagged concise-mid-tag map).
 *
 * Seed corpus starts empty; libFuzzer discovers the map structure quickly.
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
    nvattestation::ConciseMidTag out;
    nvattestation::parse_comid(bytes, out);
    return 0;
}
