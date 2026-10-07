/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_gpu_opaque.cpp
 * @brief Fuzz harness for GpuOpaqueDataParser::create.
 *
 * Fuzzer bytes are parsed by OpaqueDataParser::create exactly as
 * GpuEvidence::AttestationReport::create does (evidence.cpp), so both the
 * legacy TLV format and the NVDAOD header + typed-TLV format are reachable
 * from the same raw bytes, then dispatched to the GPU-specific sub-parsers.
 */

#include <cstdint>
#include <cstddef>

#include "nv_attestation/gpu/spdm/gpu_opaque_data_parser.hpp"
#include "nv_attestation/spdm/spdm_opaque_data_parser.hpp"
#include "fuzz_init.h"

using namespace nvattestation;

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return fuzz::init_sdk_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::vector<uint8_t> raw(data, data + size);

    OpaqueDataParser opaque_parser;
    if (OpaqueDataParser::create(raw, opaque_parser) != Error::Ok) {
        return 0;
    }

    const std::vector<ParsedOpaqueFieldData>* fields = nullptr;
    if (opaque_parser.get_all_fields(fields) != Error::Ok) {
        return 0;
    }

    GpuOpaqueDataParser gpu_parser;
    if (GpuOpaqueDataParser::create(*fields, opaque_parser.get_format_version(), gpu_parser) != Error::Ok) {
        return 0;
    }

    return 0;
}
