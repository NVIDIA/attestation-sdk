/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_init.h
 * @brief Shared SDK initialization for fuzz harnesses.
 *
 * Harnesses must call init_sdk_once() from LLVMFuzzerInitialize before
 * exercising SDK entry points. Log level is set to OFF so fuzzer output
 * isn't drowned.
 *
 * decode_opaque_fields is a TLV helper for the Switch opaque-data harness
 * (SwitchOpaqueDataParser has no NVDAOD-header variant): [2-byte LE type]
 * [2-byte LE length][length bytes].
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "nv_attestation/init.h"
#include "nv_attestation/log.h"
#include "nv_attestation/spdm/spdm_opaque_data_parser.hpp"

namespace fuzz {

inline int init_sdk_once() {
    std::shared_ptr<nvattestation::SdkOptions> opts = std::make_shared<nvattestation::SdkOptions>();
    opts->logger = std::make_shared<nvattestation::SpdLogLogger>(nvattestation::LogLevel::OFF);
    nvattestation::init(opts);
    return 0;
}

inline std::vector<nvattestation::ParsedOpaqueFieldData>
decode_opaque_fields(const uint8_t* data, size_t size) {
    std::vector<nvattestation::ParsedOpaqueFieldData> fields;

    size_t offset = 0;
    while (offset + 4 <= size) {
        const uint16_t type = static_cast<uint16_t>(data[offset] | (data[offset + 1] << 8));
        const uint16_t declared_len = static_cast<uint16_t>(data[offset + 2] | (data[offset + 3] << 8));
        offset += 4;

        const size_t actual_len = std::min<size_t>(declared_len, size - offset);
        const std::vector<uint8_t> field_bytes(data + offset, data + offset + actual_len);
        offset += actual_len;

        nvattestation::ParsedOpaqueFieldData field;
        if (nvattestation::ParsedOpaqueFieldData::create(field_bytes, type, field) ==
            nvattestation::Error::Ok) {
            fields.push_back(std::move(field));
        }
    }

    return fields;
}

}  // namespace fuzz
