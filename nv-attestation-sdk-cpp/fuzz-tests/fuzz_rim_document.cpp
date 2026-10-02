/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_rim_document.cpp
 * @brief Fuzz harness for RimDocument::create_from_rim_data (libxml2 + xmlsec).
 *
 * RIM documents are TCG SWID XML files fetched from the NVIDIA RIM service.
 * create_from_rim_data parses the XML with XML_PARSE_PEDANTIC | XML_PARSE_NONET
 * and then exposes signature verification and measurement extraction paths.
 *
 * xmlsec and the OpenSSL crypto backend must be initialized once before any
 * parsing; fuzz::init_sdk_once() handles this via the SDK's init path.
 *
 * Note: XML parsing of large inputs can be slow.  libFuzzer's -max_len flag
 * can be used to bound input size (e.g. -max_len=65536) during long runs.
 */

#include <cstdint>
#include <cstddef>
#include <string>

#include "nv_attestation/rim.h"
#include "fuzz_init.h"

using namespace nvattestation;

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return fuzz::init_sdk_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string rim_data(reinterpret_cast<const char*>(data), size);

    RimDocument doc;
    RimDocument::create_from_rim_data(rim_data, doc);

    return 0;
}
