/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_x509_from_cert.cpp
 * @brief Fuzz harness for x509_from_cert_string (PEM -> X509 via OpenSSL).
 */

#include <cstdint>
#include <cstddef>
#include <string>

#include "nv_attestation/nv_x509.h"
#include "fuzz_init.h"

using namespace nvattestation;

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return fuzz::init_sdk_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::string cert_str(reinterpret_cast<const char*>(data), size);
    x509_from_cert_string(cert_str);
    return 0;
}
