/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_spdm_resp.cpp
 * @brief Fuzz harness for SpdmMeasurementResponseMessage11::create.
 *
 * First 2 bytes are consumed as a little-endian sig_len (0..65535);
 * the remainder is the SPDM response payload.
 */

#include <cstdint>
#include <cstddef>
#include <vector>

#include "nv_attestation/spdm/spdm_resp.hpp"
#include "fuzz_init.h"

using namespace nvattestation;

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return fuzz::init_sdk_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 2) {
        return 0;
    }

    const size_t sig_len = static_cast<size_t>(data[0]) | (static_cast<size_t>(data[1]) << 8);
    const std::vector<uint8_t> response_data(data + 2, data + size);

    SpdmMeasurementResponseMessage11 msg;
    SpdmMeasurementResponseMessage11::create(response_data, sig_len, msg);

    return 0;
}
