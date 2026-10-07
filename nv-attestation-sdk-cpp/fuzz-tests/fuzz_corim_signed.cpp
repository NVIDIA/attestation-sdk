/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file fuzz_corim_signed.cpp
 * @brief Fuzz harness for parse_signed_corim (COSE_Sign1 + CoRIM payload).
 *
 * The harness runs parse_signed_corim with verify_ocsp=false and a no-op
 * IOcspHttpClient. The OCSP client is never invoked but is required by
 * reference. A real test root cert PEM is embedded so verify_cose_sign1's
 * non-empty-root_cert_pem precondition is satisfied; the cert is unrelated
 * to the fuzzer-generated input, so signature/chain verification will fail
 * for nearly every input. The valuable surface here is the COSE_Sign1 CBOR
 * decode and per-cert X.509 parsing that runs before crypto verification.
 *
 * Seed corpus is populated from unit-tests/testdata/sample_rims/corim_signed/
 * (produced by `make prepare-test-data`); empty if those generators haven't
 * been run yet, in which case libFuzzer starts from zero.
 */

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

#include "nv_attestation/corim.h"
#include "nv_attestation/cose.h"
#include "nv_attestation/error.h"
#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/nv_x509.h"
#include "fuzz_init.h"

namespace {

class NoopOcspHttpClient : public nvattestation::IOcspHttpClient {
public:
    nvattestation::Error get_ocsp_response(
        const nvattestation::nv_unique_ptr<X509>& /*subject_cert*/,
        const nvattestation::nv_unique_ptr<X509>& /*issuer_cert*/,
        const nvattestation::nv_unique_ptr<stack_st_X509>& /*intermediates*/,
        const nvattestation::nv_unique_ptr<X509_STORE>& /*trust_store*/,
        nvattestation::NvOcspResponse& /*out_ocsp_response*/) override {
        return nvattestation::Error::InternalError;
    }
};

// unit-tests/testdata/trusted_certs/rim_root.crt — used only to satisfy the
// non-empty root_cert_pem precondition; chain verification is expected to fail.
constexpr const char* kTestRootCertPem =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICKTCCAbCgAwIBAgIQRdrjoA5QN73fh1N17LXicDAKBggqhkjOPQQDAzBFMQsw\n"
    "CQYDVQQGEwJVUzEPMA0GA1UECgwGTlZJRElBMSUwIwYDVQQDDBxOVklESUEgQ29S\n"
    "SU0gc2lnbmluZyBSb290IENBMCAXDTIzMDMxNjE1MzczNFoYDzIwNTMwMzA4MTUz\n"
    "NzM0WjBFMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGTlZJRElBMSUwIwYDVQQDDBxO\n"
    "VklESUEgQ29SSU0gc2lnbmluZyBSb290IENBMHYwEAYHKoZIzj0CAQYFK4EEACID\n"
    "YgAEuECyi9vNM+Iw2lfUzyBldHAwaC1HF7TCgp12QcEyUTm3Tagxwr48d55+K2VI\n"
    "lWYIDk7NlAIQdcV/Ff7euGLI+Qauj93HsSI4WX298PpW54RTgz9tC+Q684caR/BX\n"
    "WEeZo2MwYTAdBgNVHQ4EFgQUpaXrOPK4ZDAk08DBskn594zeZjAwHwYDVR0jBBgw\n"
    "FoAUpaXrOPK4ZDAk08DBskn594zeZjAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B\n"
    "Af8EBAMCAQYwCgYIKoZIzj0EAwMDZwAwZAIwHGDyscDP6ihHqRvZlI3eqZ4YkvjE\n"
    "1duaN84tAHRVgxVMvNrp5Tnom3idHYGW/dskAjATvjIx6VzHm/4e2GiZAyZEIUBD\n"
    "OKPzp5ei/A0iUZpdvngenDwV8Qa/wGdiTmJ7Bp4=\n"
    "-----END CERTIFICATE-----\n";

}  // namespace

extern "C" int LLVMFuzzerInitialize(int* /*argc*/, char*** /*argv*/) {
    return fuzz::init_sdk_once();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const std::vector<uint8_t> bytes(data, data + size);

    nvattestation::CoseSign1VerifyOptions options;
    options.verify_ocsp = false;
    options.root_cert_pem = kTestRootCertPem;

    NoopOcspHttpClient ocsp_client;
    nvattestation::CorimMap out_corim;
    std::vector<nvattestation::PerCertStatus> out_claims;
    nvattestation::parse_signed_corim(bytes, options, ocsp_client, out_corim, out_claims);
    return 0;
}
