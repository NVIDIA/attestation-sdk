/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_x509_pkcs11_sig.cpp
 * @brief Fuzz harness for X509CertChain::verify_signature_pkcs11.
 *
 * Exercises the raw PKCS#11 R||S -> DER conversion path
 * (BN_bin2bn + i2d_ECDSA_SIG). Verification is expected to fail on
 * fuzzer-controlled inputs.
 */

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include <openssl/evp.h>

#include "nv_attestation/nv_x509.h"
#include "fuzz_init.h"

using namespace nvattestation;

// Self-signed P-384 cert generated solely for this harness. Regenerate with:
//   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
//     -keyout /dev/null -out /dev/stdout -days 3650 -nodes -subj "/CN=fuzz-test"
static const char kFuzzCert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBujCCAUCgAwIBAgIUWIz8jlvm3b6+rlynwoes28K3bXUwCgYIKoZIzj0EAwIw\n"
    "FDESMBAGA1UEAwwJZnV6ei10ZXN0MB4XDTI2MDQxNzIyNDM0OFoXDTM2MDQxNDIy\n"
    "NDM0OFowFDESMBAGA1UEAwwJZnV6ei10ZXN0MHYwEAYHKoZIzj0CAQYFK4EEACID\n"
    "YgAEbYZ/1/6KSGxqoC4IxCZ3dPYokNHE05VPpzm7Iuh4VmDOQ3S01JrDAG7Ngatx\n"
    "B5v2IbyzkYxCT4XhkFPCio+Q8d7F6ecg8ce7hyFedrwoN75koCElW3v7CgmjaeCX\n"
    "JrDoo1MwUTAdBgNVHQ4EFgQUS6qA9a9r18VIYkjiURN+cDoUGgkwHwYDVR0jBBgw\n"
    "FoAUS6qA9a9r18VIYkjiURN+cDoUGgkwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO\n"
    "PQQDAgNoADBlAjBf20e6oj7aJqWhum+IYAI/5o61N8YkbI86IWge8tQFbVkVThBL\n"
    "39GuvzpX3NcB16UCMQCpPDcnY7SyOxiHmMRrU8WQcRjgGwo76SG8YDcUTwZ+gGOj\n"
    "4O8A1FzceJIGNQmYGns=\n"
    "-----END CERTIFICATE-----\n";

static X509CertChain g_chain;

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    fuzz::init_sdk_once();

    const std::string cert_pem(kFuzzCert);
    // Abort hard if the embedded harness cert fails to parse. Silently
    // returning would leave every LLVMFuzzerTestOneInput call as a no-op,
    // producing a passing run that never exercised verify_signature_pkcs11.
    if (X509CertChain::create_from_cert_chain_str(
            CertificateChainType::GPU_DEVICE_IDENTITY,
            cert_pem, cert_pem, g_chain) != Error::Ok) {
        std::fprintf(stderr,
                     "fuzz_x509_pkcs11_sig: failed to parse embedded harness "
                     "cert; aborting so the harness is not a silent no-op.\n");
        std::abort();
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 3) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);

    const uint16_t data_len = fdp.ConsumeIntegral<uint16_t>();
    const std::vector<uint8_t> msg_data =
        fdp.ConsumeBytes<uint8_t>(data_len);
    const std::vector<uint8_t> pkcs11_sig =
        fdp.ConsumeRemainingBytes<uint8_t>();

    g_chain.verify_signature_pkcs11(msg_data, pkcs11_sig, EVP_sha384());

    return 0;
}
