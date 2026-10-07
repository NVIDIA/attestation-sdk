/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_spdm_req.cpp
 * @brief Fuzz harness for SpdmMeasurementRequestMessage11::create.
 *
 * The request parser expects exactly 37 bytes; feeding arbitrary-length
 * input exercises both under- and over-length rejection paths in addition
 * to field parsing when the size matches.
 */

#include <cstdint>
#include <cstddef>
#include <vector>

#include "nv_attestation/spdm/spdm_req.hpp"
#include "fuzz_init.h"

using namespace nvattestation;

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return fuzz::init_sdk_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::vector<uint8_t> request_data(data, data + size);

    SpdmMeasurementRequestMessage11 msg;
    SpdmMeasurementRequestMessage11::create(request_data, msg);

    return 0;
}
