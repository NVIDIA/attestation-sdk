/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_x509_cert_chain.cpp
 * @brief Fuzz harness for X509CertChain::create_from_cert_chain_str.
 *
 * Input is split 50/50 into (root, chain) to exercise the PEM-boundary
 * splitter plus downstream get_fwid / ASN.1 extension parsing.
 */

#include <cstdint>
#include <cstddef>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include "nv_attestation/nv_x509.h"
#include "fuzz_init.h"

using namespace nvattestation;

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return fuzz::init_sdk_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 3) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    const std::string root_cert = fdp.ConsumeBytesAsString(size / 2);
    const std::string cert_chain = fdp.ConsumeRemainingBytesAsString();

    X509CertChain chain;
    X509CertChain::create_from_cert_chain_str(
        CertificateChainType::GPU_DEVICE_IDENTITY,
        root_cert, cert_chain, chain);

    return 0;
}
