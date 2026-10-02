/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstdio>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>

#include "gtest/gtest.h"
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>
#include "jwt-cpp/traits/nlohmann-json/traits.h"

#include "nvat.h"
#include "nv_attestation/verify.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/gpu/claims.h"
#include "nv_attestation/switch/claims.h"
#include "nv_attestation/utils.h"
#include "environment.h"
#include "local_https_test_server.h"

using nvattestation::map_submod_payloads_to_claims;
using nvattestation::ClaimsCollection;
using nvattestation::Error;

// Loads the decoded GPU submod claim payload shipped as a test fixture and
// feeds it to the mapper as if it had come out of validate_and_decode_EAT.
TEST(MapSubmodPayloadsToClaims, GpuPayloadProducesGpuClaim) {
    std::string file_contents;
    Error err = nvattestation::readFileIntoString(
        "testdata/sample_attestation_data/hopperClaimsv3_decoded.json", file_contents);
    ASSERT_EQ(err, Error::Ok);
    nlohmann::json root = nlohmann::json::parse(file_contents);
    ASSERT_TRUE(root.contains("GPU-0"));

    std::unordered_map<std::string, std::string> device_claims_json;
    device_claims_json["GPU-0"] = root["GPU-0"].dump();

    ClaimsCollection claims;
    err = map_submod_payloads_to_claims(device_claims_json, claims);
    ASSERT_EQ(err, Error::Ok);
    ASSERT_EQ(claims.size(), 1u);

    std::string serialized;
    ASSERT_EQ(claims.serialize_json(serialized), Error::Ok);
    nlohmann::json out = nlohmann::json::parse(serialized);
    ASSERT_TRUE(out.is_array());
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].at("x-nvidia-device-type").get<std::string>(), "gpu");
}

// An unrecognized submod payload (no known device cert-chain key) must error,
// not silently drop the device.
TEST(MapSubmodPayloadsToClaims, UnknownDeviceTypeIsError) {
    std::unordered_map<std::string, std::string> device_claims_json;
    device_claims_json["BOGUS-0"] = R"({"iat":0,"exp":0,"jti":"x","iss":"y"})";

    ClaimsCollection claims;
    Error err = map_submod_payloads_to_claims(device_claims_json, claims);
    EXPECT_NE(err, Error::Ok);
    EXPECT_EQ(err, nvattestation::Error::NrasTokenInvalid);
}

// A two-entry map containing one valid entry and one bogus entry must
// return an error and leave out_claims completely empty (no partial population).
TEST(MapSubmodPayloadsToClaims, MultiDevicePartialFailureLeavesNoClaims) {
    std::string file_contents;
    Error err = nvattestation::readFileIntoString(
        "testdata/sample_attestation_data/hopperClaimsv3_decoded.json", file_contents);
    ASSERT_EQ(err, Error::Ok);
    nlohmann::json root = nlohmann::json::parse(file_contents);
    ASSERT_TRUE(root.contains("GPU-0"));

    std::unordered_map<std::string, std::string> device_claims_json;
    device_claims_json["GPU-0"] = root["GPU-0"].dump();
    device_claims_json["BOGUS-1"] = R"({"iat":0,"exp":0,"jti":"x","iss":"y"})";

    ClaimsCollection claims;
    err = map_submod_payloads_to_claims(device_claims_json, claims);
    EXPECT_NE(err, Error::Ok);
    EXPECT_EQ(claims.size(), 0u);
}

// === End-to-end test of the public nvat_verify_attestation_result C API ===
//
// Spins up the local Python HTTPS server (reused from nv_http_test.cpp) serving
// a JWKS that contains the EC P-384 cert used to sign a detached EAT in-test.
// The EAT issuer is set to the dynamic server base URL so issuer verification
// passes. Exercises the happy path, tamper rejection, null-arg rejection, and
// the overall-result-false path (which must still populate claims).

// Loads the GPU submod claim fixture into a fresh shared claim. The optional
// `force_mismatch` flips the measurement-result claim so the overall-result
// Rego policy evaluates to false.
static std::shared_ptr<nvattestation::SerializableGpuClaimsV4> load_gpu_claim(bool force_mismatch) {
    std::string decoded;
    if (nvattestation::readFileIntoString(
            "testdata/sample_attestation_data/hopperClaimsv3_decoded.json", decoded) != Error::Ok) {
        return nullptr;
    }
    nlohmann::json root = nlohmann::json::parse(decoded);
    auto gpu_claims = std::make_shared<nvattestation::SerializableGpuClaimsV4>();
    nvattestation::from_json(root.at("GPU-0"), *gpu_claims);
    if (force_mismatch) {
        gpu_claims->m_measurements_matching = nvattestation::SerializableMeasresClaim::Failure;
    }
    return gpu_claims;
}

// Strips the PEM armor and newlines from a certificate to produce the bare
// base64 DER form expected in a JWKS x5c entry.
static std::string pem_cert_to_x5c_b64(const std::string& pem) {
    static const std::string kBegin = "-----BEGIN CERTIFICATE-----";
    static const std::string kEnd = "-----END CERTIFICATE-----";
    auto start = pem.find(kBegin);
    auto end = pem.find(kEnd);
    if (start == std::string::npos || end == std::string::npos) {
        return "";
    }
    std::string body = pem.substr(start + kBegin.size(), end - (start + kBegin.size()));
    std::string out;
    for (char c : body) {
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
            out.push_back(c);
        }
    }
    return out;
}

class VerifyAttestationResultServerTest : public ::testing::Test {
  protected:
    static std::string m_base_url;       // e.g. https://localhost:<port>
    static std::string m_detached_eat;   // signed with eat_jwks_leaf key, overall==true
    static std::string m_detached_eat_overall_false;  // overall==false
    static std::string m_ca_cert_path;   // testdata/tls_test/tls_ca_cert.pem
    static std::string m_signing_key_pem;
    static bool m_setup_ok;
    static constexpr const char* KID = "nvat-test-kid";

    // Additional statics for x5c chain validation tests
    static std::string m_single_leaf_der_b64;         // DER b64 of eat_jwks_leaf (single-cert server)
    static std::string m_chain_leaf_der_b64;           // DER b64 of eat_jwks_chain_leaf
    static std::string m_chain_ca_der_b64;             // DER b64 of eat_jwks_ca
    static std::string m_valid_chain_base_url;
    static std::string m_mismatched_base_url;
    static std::string m_detached_eat_valid_chain;     // signed by chain_leaf key, issuer=valid_chain_base_url
    static std::string m_detached_eat_mismatched;      // signed by chain_leaf key, issuer=mismatched_base_url

    // Additional statics for intermediate-issuer partial-chain test
    static std::string m_int_leaf_der_b64;
    static std::string m_int_der_b64;
    static std::string m_int_base_url;
    static std::string m_detached_eat_int;

    // HTTPS test servers — one per distinct JWKS scenario
    static LocalHttpsTestServer m_server;
    static LocalHttpsTestServer m_valid_chain_server;
    static LocalHttpsTestServer m_mismatched_server;
    static LocalHttpsTestServer m_int_server;

    // Signs a detached EAT from the given GPU claim using the EC P-384 key,
    // with issuer == m_base_url and kid == KID. Returns Error::Ok or
    // Error::OverallResultFalse (both produce a usable token).
    static Error sign_eat(const std::shared_ptr<nvattestation::SerializableGpuClaimsV4>& gpu_claim,
                          const std::string& key_pem, std::string& out_eat) {
        return sign_eat_with_issuer(gpu_claim, key_pem, m_base_url, out_eat);
    }

    // Signs a detached EAT with an explicit issuer URL (used for multi-server tests).
    static Error sign_eat_with_issuer(const std::shared_ptr<nvattestation::SerializableGpuClaimsV4>& gpu_claim,
                                      const std::string& key_pem, const std::string& issuer,
                                      std::string& out_eat) {
        ClaimsCollection coll;
        coll.append(std::static_pointer_cast<nvattestation::Claims>(gpu_claim));
        nvattestation::DetachedEATOptions opts;
        opts.m_private_key_pem = key_pem;
        opts.m_issuer = issuer;
        opts.m_kid = KID;
        return coll.get_detached_eat(out_eat, opts);
    }

    static std::string sign_with_times(
        const nlohmann::json& payload, int64_t issued_at,
        int64_t not_before, int64_t expires_at) {
        auto token = jwt::create<jwt::traits::nlohmann_json>();
        for (auto it = payload.begin(); it != payload.end(); ++it) {
            token.set_payload_claim(
                it.key(), jwt::basic_claim<jwt::traits::nlohmann_json>(it.value()));
        }
        token.set_payload_claim(
            "iat", jwt::basic_claim<jwt::traits::nlohmann_json>(issued_at));
        token.set_payload_claim(
            "nbf", jwt::basic_claim<jwt::traits::nlohmann_json>(not_before));
        token.set_payload_claim(
            "exp", jwt::basic_claim<jwt::traits::nlohmann_json>(expires_at));
        token.set_header_claim(
            "kid", jwt::basic_claim<jwt::traits::nlohmann_json>(std::string(KID)));
        return token.sign(jwt::algorithm::es384("", m_signing_key_pem, "", ""));
    }

    static std::string make_time_skewed_eat(int64_t seconds_ahead) {
        nlohmann::json detached = nlohmann::json::parse(m_detached_eat);
        const std::string submod_label = detached.at(1).begin().key();
        const int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const int64_t issued_at = now + seconds_ahead;
        const int64_t expires_at = issued_at + 3600;

        nlohmann::json submod_payload = nlohmann::json::parse(
            jwt::decode<jwt::traits::nlohmann_json>(
                detached.at(1).at(submod_label).get<std::string>()).get_payload());
        const std::string submod_jwt = sign_with_times(
            submod_payload, issued_at, issued_at, expires_at);
        std::string submod_digest;
        if (nvattestation::compute_sha256_hex(submod_jwt, submod_digest) !=
            Error::Ok) {
            return "";
        }

        nlohmann::json overall_payload = nlohmann::json::parse(
            jwt::decode<jwt::traits::nlohmann_json>(
                detached.at(0).at(1).get<std::string>()).get_payload());
        overall_payload["submods"][submod_label][1][1] = submod_digest;
        detached[1][submod_label] = submod_jwt;
        detached[0][1] = sign_with_times(
            overall_payload, issued_at, issued_at, expires_at);
        return detached.dump();
    }

    static void SetUpTestSuite() {
        m_setup_ok = false;
        const std::string tls_dir = "testdata/tls_test";
        const std::string x509_dir = "testdata/x509_cert_chain";
        m_ca_cert_path = tls_dir + "/tls_ca_cert.pem";

        // 1. Generate the EAT signing certs (idempotent). TLS certs are generated
        //    inside LocalHttpsTestServer::start().
        if (std::system(("cd " + x509_dir + " && bash ./generate_test_certs.sh 2>&1").c_str()) != 0) {
            std::cerr << "x509 cert generation failed" << std::endl;
            return;
        }

        // 2. Read the EAT signing cert and build a JWKS containing its DER.
        std::string leaf_pem;
        if (nvattestation::readFileIntoString(x509_dir + "/eat_jwks_leaf", leaf_pem) != Error::Ok) {
            std::cerr << "Failed to read eat_jwks_leaf" << std::endl;
            return;
        }
        std::string der_b64 = pem_cert_to_x5c_b64(leaf_pem);
        if (der_b64.empty()) {
            std::cerr << "Failed to extract DER from eat_jwks_leaf" << std::endl;
            return;
        }
        nlohmann::json jwks;
        jwks["keys"] = nlohmann::json::array();
        jwks["keys"].push_back({{"kty", "EC"}, {"crv", "P-384"}, {"kid", KID},
                                {"x5c", nlohmann::json::array({der_b64})}});
        const std::string jwks_path = tls_dir + "/test_jwks.json";
        {
            std::ofstream out(jwks_path);
            out << jwks.dump();
        }

        // 3. Start the HTTPS server for the single-cert JWKS.
        if (!m_server.start(jwks_path)) {
            std::cerr << "HTTPS server did not become ready" << std::endl;
            return;
        }
        m_base_url = m_server.url();
        // Strip trailing slash so the issuer URL matches what sign_eat produces.
        if (!m_base_url.empty() && m_base_url.back() == '/') {
            m_base_url.pop_back();
        }

        // 4. Sign detached EATs (issuer must equal m_base_url). The overall
        //    result is derived by the embedded Rego policy from the claims, so
        //    flipping measres to a non-success value yields overall==false.
        std::string key_pem;
        if (nvattestation::readFileIntoString(x509_dir + "/eat_jwks_leaf_key.pem", key_pem) != Error::Ok) {
            std::cerr << "Failed to read eat_jwks_leaf_key.pem" << std::endl;
            return;
        }
        m_signing_key_pem = key_pem;
        auto gpu_ok = load_gpu_claim(/*force_mismatch=*/false);
        auto gpu_bad = load_gpu_claim(/*force_mismatch=*/true);
        if (gpu_ok == nullptr || gpu_bad == nullptr) {
            std::cerr << "Failed to load GPU claim fixture" << std::endl;
            return;
        }
        // gpu_ok still fails the cert-chain checks in the policy (the fixture's
        // OCSP/cert-status claims are not all "valid"/"good"), so its overall
        // result is also false. That is fine for the happy-path test, which
        // only asserts on rc and the claim's device-type after JWT verification.
        const Error sign_ok_rc = sign_eat(gpu_ok, key_pem, m_detached_eat);
        if (sign_ok_rc != Error::Ok && sign_ok_rc != Error::OverallResultFalse) {
            std::cerr << "Failed to sign valid EAT" << std::endl;
            return;
        }
        const Error sign_bad_rc = sign_eat(gpu_bad, key_pem, m_detached_eat_overall_false);
        if (sign_bad_rc != Error::Ok && sign_bad_rc != Error::OverallResultFalse) {
            std::cerr << "Failed to sign overall-false EAT" << std::endl;
            return;
        }
        m_single_leaf_der_b64 = der_b64;

        // 5. Read chain certs and build the two additional JWKS servers.
        std::string chain_leaf_pem;
        std::string chain_ca_pem;
        if (nvattestation::readFileIntoString(x509_dir + "/eat_jwks_chain_leaf", chain_leaf_pem) != Error::Ok) {
            std::cerr << "Failed to read eat_jwks_chain_leaf" << std::endl;
            return;
        }
        if (nvattestation::readFileIntoString(x509_dir + "/eat_jwks_ca", chain_ca_pem) != Error::Ok) {
            std::cerr << "Failed to read eat_jwks_ca" << std::endl;
            return;
        }
        m_chain_leaf_der_b64 = pem_cert_to_x5c_b64(chain_leaf_pem);
        m_chain_ca_der_b64   = pem_cert_to_x5c_b64(chain_ca_pem);
        if (m_chain_leaf_der_b64.empty() || m_chain_ca_der_b64.empty()) {
            std::cerr << "Failed to extract DER from chain certs" << std::endl;
            return;
        }

        // valid-chain server: x5c = [chain_leaf, chain_ca] (chain_leaf IS signed by chain_ca)
        const std::string valid_chain_jwks_path = tls_dir + "/test_jwks_valid_chain.json";
        {
            nlohmann::json vcj;
            vcj["keys"] = nlohmann::json::array();
            vcj["keys"].push_back({{"kty", "EC"}, {"crv", "P-384"}, {"kid", KID},
                                   {"x5c", nlohmann::json::array({m_chain_leaf_der_b64, m_chain_ca_der_b64})}});
            std::ofstream out(valid_chain_jwks_path);
            out << vcj.dump();
        }

        // mismatched server: x5c = [chain_leaf, single_leaf] (chain_leaf is NOT signed by single_leaf)
        const std::string mismatched_jwks_path = tls_dir + "/test_jwks_mismatched.json";
        {
            nlohmann::json mmj;
            mmj["keys"] = nlohmann::json::array();
            mmj["keys"].push_back({{"kty", "EC"}, {"crv", "P-384"}, {"kid", KID},
                                   {"x5c", nlohmann::json::array({m_chain_leaf_der_b64, m_single_leaf_der_b64})}});
            std::ofstream out(mismatched_jwks_path);
            out << mmj.dump();
        }

        if (!m_valid_chain_server.start(valid_chain_jwks_path)) {
            std::cerr << "Valid-chain HTTPS server did not become ready" << std::endl;
            return;
        }
        if (!m_mismatched_server.start(mismatched_jwks_path)) {
            std::cerr << "Mismatched HTTPS server did not become ready" << std::endl;
            return;
        }
        m_valid_chain_base_url = m_valid_chain_server.url();
        m_mismatched_base_url  = m_mismatched_server.url();
        if (!m_valid_chain_base_url.empty() && m_valid_chain_base_url.back() == '/') {
            m_valid_chain_base_url.pop_back();
        }
        if (!m_mismatched_base_url.empty() && m_mismatched_base_url.back() == '/') {
            m_mismatched_base_url.pop_back();
        }

        // 6. Sign EATs for the chain servers. The chain_leaf key signs both; the
        //    issuer URL must match the server the EAT will be verified against.
        std::string chain_leaf_key_pem;
        if (nvattestation::readFileIntoString(x509_dir + "/eat_jwks_chain_leaf_key.pem",
                                              chain_leaf_key_pem) != Error::Ok) {
            std::cerr << "Failed to read eat_jwks_chain_leaf_key.pem" << std::endl;
            return;
        }
        const Error sign_valid_rc = sign_eat_with_issuer(gpu_ok, chain_leaf_key_pem,
                                                           m_valid_chain_base_url,
                                                           m_detached_eat_valid_chain);
        if (sign_valid_rc != Error::Ok && sign_valid_rc != Error::OverallResultFalse) {
            std::cerr << "Failed to sign valid-chain EAT" << std::endl;
            return;
        }
        const Error sign_mismatch_rc = sign_eat_with_issuer(gpu_ok, chain_leaf_key_pem,
                                                             m_mismatched_base_url,
                                                             m_detached_eat_mismatched);
        if (sign_mismatch_rc != Error::Ok && sign_mismatch_rc != Error::OverallResultFalse) {
            std::cerr << "Failed to sign mismatched EAT" << std::endl;
            return;
        }

        // 7. Set up the intermediate-issuer (partial-chain) server.
        //    x5c = [int_leaf, int] — the intermediate is not self-signed.
        std::string int_leaf_pem;
        std::string int_pem;
        if (nvattestation::readFileIntoString(x509_dir + "/eat_jwks_int_leaf", int_leaf_pem) != Error::Ok) {
            std::cerr << "Failed to read eat_jwks_int_leaf" << std::endl;
            return;
        }
        if (nvattestation::readFileIntoString(x509_dir + "/eat_jwks_int", int_pem) != Error::Ok) {
            std::cerr << "Failed to read eat_jwks_int" << std::endl;
            return;
        }
        m_int_leaf_der_b64 = pem_cert_to_x5c_b64(int_leaf_pem);
        m_int_der_b64      = pem_cert_to_x5c_b64(int_pem);
        if (m_int_leaf_der_b64.empty() || m_int_der_b64.empty()) {
            std::cerr << "Failed to extract DER from int chain certs" << std::endl;
            return;
        }

        const std::string int_chain_jwks_path = tls_dir + "/test_jwks_int_chain.json";
        {
            nlohmann::json icj;
            icj["keys"] = nlohmann::json::array();
            icj["keys"].push_back({{"kty", "EC"}, {"crv", "P-384"}, {"kid", KID},
                                   {"x5c", nlohmann::json::array({m_int_leaf_der_b64, m_int_der_b64})}});
            std::ofstream out(int_chain_jwks_path);
            out << icj.dump();
        }

        if (!m_int_server.start(int_chain_jwks_path)) {
            std::cerr << "Int-chain HTTPS server did not become ready" << std::endl;
            return;
        }
        m_int_base_url = m_int_server.url();
        if (!m_int_base_url.empty() && m_int_base_url.back() == '/') {
            m_int_base_url.pop_back();
        }

        std::string int_leaf_key_pem;
        if (nvattestation::readFileIntoString(x509_dir + "/eat_jwks_int_leaf_key.pem",
                                              int_leaf_key_pem) != Error::Ok) {
            std::cerr << "Failed to read eat_jwks_int_leaf_key.pem" << std::endl;
            m_int_server.stop();
            return;
        }
        const Error sign_int_rc = sign_eat_with_issuer(gpu_ok, int_leaf_key_pem, m_int_base_url,
                                                       m_detached_eat_int);
        if (sign_int_rc != Error::Ok && sign_int_rc != Error::OverallResultFalse) {
            std::cerr << "Failed to sign int-chain EAT" << std::endl;
            m_int_server.stop();
            return;
        }

        m_setup_ok = true;
    }

    static void TearDownTestSuite() {
        m_server.stop();
        m_valid_chain_server.stop();
        m_mismatched_server.stop();
        m_int_server.stop();
    }

    static nvat_http_options_t make_http_options() {
        nvat_http_options_t http = nullptr;
        if (nvat_http_options_create_default(&http) != NVAT_RC_OK) {
            return nullptr;
        }
        nvat_http_options_set_tls_ca_cert(http, m_ca_cert_path.c_str());
        return http;
    }
};

std::string VerifyAttestationResultServerTest::m_base_url;
std::string VerifyAttestationResultServerTest::m_detached_eat;
std::string VerifyAttestationResultServerTest::m_detached_eat_overall_false;
std::string VerifyAttestationResultServerTest::m_ca_cert_path;
std::string VerifyAttestationResultServerTest::m_signing_key_pem;
bool VerifyAttestationResultServerTest::m_setup_ok = false;
constexpr const char* VerifyAttestationResultServerTest::KID;

std::string VerifyAttestationResultServerTest::m_single_leaf_der_b64;
std::string VerifyAttestationResultServerTest::m_chain_leaf_der_b64;
std::string VerifyAttestationResultServerTest::m_chain_ca_der_b64;
std::string VerifyAttestationResultServerTest::m_valid_chain_base_url;
std::string VerifyAttestationResultServerTest::m_mismatched_base_url;
std::string VerifyAttestationResultServerTest::m_detached_eat_valid_chain;
std::string VerifyAttestationResultServerTest::m_detached_eat_mismatched;

std::string VerifyAttestationResultServerTest::m_int_leaf_der_b64;
std::string VerifyAttestationResultServerTest::m_int_der_b64;
std::string VerifyAttestationResultServerTest::m_int_base_url;
std::string VerifyAttestationResultServerTest::m_detached_eat_int;

LocalHttpsTestServer VerifyAttestationResultServerTest::m_server;
LocalHttpsTestServer VerifyAttestationResultServerTest::m_valid_chain_server;
LocalHttpsTestServer VerifyAttestationResultServerTest::m_mismatched_server;
LocalHttpsTestServer VerifyAttestationResultServerTest::m_int_server;

TEST_F(VerifyAttestationResultServerTest, ValidTokenReturnsClaims) {
    if (!m_setup_ok) GTEST_SKIP() << "JWKS test server not available";

    nvat_http_options_t http = make_http_options();
    ASSERT_NE(http, nullptr) << "make_http_options() failed";
    nvat_claims_collection_t claims = nullptr;
    nvat_rc_t rc = nvat_verify_attestation_result(m_detached_eat.c_str(), m_base_url.c_str(), /*service_key=*/nullptr, /*nonce=*/nullptr, http, /*jwt_validation_options=*/nullptr, &claims);
    // The fixture's cert/OCSP claims don't all pass the overall-result policy,
    // so rc may be OK or OVERALL_RESULT_FALSE; either invariant proves the
    // JWT was verified (signature + issuer) and claims were mapped.
    ASSERT_NE(rc, NVAT_RC_NRAS_TOKEN_INVALID) << "JWT signature/issuer verification must pass";
    ASSERT_NE(rc, NVAT_RC_BAD_ARGUMENT);
    ASSERT_NE(claims, nullptr);

    nvat_str_t json = nullptr;
    ASSERT_EQ(nvat_claims_collection_serialize_json(claims, &json), NVAT_RC_OK);
    char* data = nullptr;
    ASSERT_EQ(nvat_str_get_data(json, &data), NVAT_RC_OK);
    nlohmann::json out = nlohmann::json::parse(data);
    ASSERT_TRUE(out.is_array());
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].at("x-nvidia-device-type").get<std::string>(), "gpu");

    nvat_str_free(&json);
    nvat_claims_collection_free(&claims);
    nvat_http_options_free(&http);
}

TEST_F(VerifyAttestationResultServerTest,
       ClockSkewLeewayAppliesToOverallAndSubmodTokens) {
    if (!m_setup_ok) GTEST_SKIP() << "JWKS test server not available";

    const std::string normally_skewed_eat =
        make_time_skewed_eat(/*seconds_ahead=*/10);
    ASSERT_FALSE(normally_skewed_eat.empty());
    const std::string skewed_eat = make_time_skewed_eat(/*seconds_ahead=*/120);
    ASSERT_FALSE(skewed_eat.empty());
    nvat_http_options_t http = make_http_options();
    ASSERT_NE(http, nullptr);

    // NULL options use the public API's default 60-second leeway.
    nvat_claims_collection_t default_claims = nullptr;
    const nvat_rc_t default_rc = nvat_verify_attestation_result(
        normally_skewed_eat.c_str(), m_base_url.c_str(),
        /*service_key=*/nullptr, /*expected_nonce=*/nullptr, http,
        /*jwt_validation_options=*/nullptr, &default_claims);
    EXPECT_TRUE(default_rc == NVAT_RC_OK ||
                default_rc == NVAT_RC_OVERALL_RESULT_FALSE);
    EXPECT_NE(default_claims, nullptr);

    nvat_jwt_validation_options_t leeway_options = nullptr;
    ASSERT_EQ(nvat_jwt_validation_options_create_default(&leeway_options),
              NVAT_RC_OK);
    nvat_jwt_validation_options_set_clock_skew_leeway_seconds(
        leeway_options, 5 * 60);
    nvat_claims_collection_t leeway_claims = nullptr;
    const nvat_rc_t leeway_rc = nvat_verify_attestation_result(
        skewed_eat.c_str(), m_base_url.c_str(), /*service_key=*/nullptr,
        /*expected_nonce=*/nullptr, http, leeway_options, &leeway_claims);
    EXPECT_NE(leeway_rc, NVAT_RC_NRAS_TOKEN_INVALID);
    EXPECT_NE(leeway_claims, nullptr);

    nvat_jwt_validation_options_t strict_options = nullptr;
    ASSERT_EQ(nvat_jwt_validation_options_create_default(&strict_options),
              NVAT_RC_OK);
    nvat_jwt_validation_options_set_clock_skew_leeway_seconds(
        strict_options, 0);
    nvat_claims_collection_t strict_claims = nullptr;
    EXPECT_EQ(nvat_verify_attestation_result(
                  skewed_eat.c_str(), m_base_url.c_str(),
                  /*service_key=*/nullptr, /*expected_nonce=*/nullptr, http,
                  strict_options, &strict_claims),
              NVAT_RC_NRAS_TOKEN_INVALID);
    EXPECT_EQ(strict_claims, nullptr);

    nvat_claims_collection_free(&default_claims);
    nvat_claims_collection_free(&leeway_claims);
    nvat_claims_collection_free(&strict_claims);
    nvat_jwt_validation_options_free(&leeway_options);
    nvat_jwt_validation_options_free(&strict_options);
    nvat_http_options_free(&http);
}

// The signing fixture (hopperClaimsv3_decoded.json) carries this eat_nonce,
// which becomes the overall token nonce that nvat_verify_attestation_result compares against
// the relying party's expected nonce.
static constexpr const char* kFixtureEatNonce =
    "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";

// A matching expected nonce must not change the outcome: the token still
// verifies (rc OK or OVERALL_RESULT_FALSE) and claims are populated.
TEST_F(VerifyAttestationResultServerTest, NonceMatchAccepted) {
    if (!m_setup_ok) GTEST_SKIP() << "JWKS test server not available";

    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_from_hex(&nonce, kFixtureEatNonce), NVAT_RC_OK);

    nvat_http_options_t http = make_http_options();
    ASSERT_NE(http, nullptr) << "make_http_options() failed";
    nvat_claims_collection_t claims = nullptr;
    nvat_rc_t rc = nvat_verify_attestation_result(m_detached_eat.c_str(), m_base_url.c_str(), /*service_key=*/nullptr, nonce, http, /*jwt_validation_options=*/nullptr, &claims);
    ASSERT_NE(rc, NVAT_RC_NONCE_MISMATCH) << "matching nonce must not be rejected; rc=" << rc;
    ASSERT_NE(rc, NVAT_RC_NRAS_TOKEN_INVALID);
    ASSERT_NE(rc, NVAT_RC_BAD_ARGUMENT);
    ASSERT_NE(claims, nullptr);

    nvat_claims_collection_free(&claims);
    nvat_nonce_free(&nonce);
    nvat_http_options_free(&http);
}

// A different expected nonce must be rejected with NVAT_RC_NONCE_MISMATCH even
// though the rest of the token (signature, issuer, structure) is valid.
TEST_F(VerifyAttestationResultServerTest, NonceMismatchRejected) {
    if (!m_setup_ok) GTEST_SKIP() << "JWKS test server not available";

    // Same length as the fixture nonce but a different value.
    const std::string different_nonce =
        "00000000000000000000000000000000000000000000000000000000deadbeef";
    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_from_hex(&nonce, different_nonce.c_str()), NVAT_RC_OK);

    nvat_http_options_t http = make_http_options();
    ASSERT_NE(http, nullptr) << "make_http_options() failed";
    nvat_claims_collection_t claims = nullptr;
    nvat_rc_t rc = nvat_verify_attestation_result(m_detached_eat.c_str(), m_base_url.c_str(), /*service_key=*/nullptr, nonce, http, /*jwt_validation_options=*/nullptr, &claims);
    EXPECT_EQ(rc, NVAT_RC_NONCE_MISMATCH) << "mismatched nonce must be rejected; rc=" << rc;

    nvat_claims_collection_free(&claims);
    nvat_nonce_free(&nonce);
    nvat_http_options_free(&http);
}

TEST_F(VerifyAttestationResultServerTest, OverallResultFalseReturnsClaims) {
    if (!m_setup_ok) GTEST_SKIP() << "JWKS test server not available";

    nvat_http_options_t http = make_http_options();
    ASSERT_NE(http, nullptr) << "make_http_options() failed";
    nvat_claims_collection_t claims = nullptr;
    nvat_rc_t rc =
        nvat_verify_attestation_result(m_detached_eat_overall_false.c_str(), m_base_url.c_str(), /*service_key=*/nullptr, /*nonce=*/nullptr, http, /*jwt_validation_options=*/nullptr, &claims);
    ASSERT_EQ(rc, NVAT_RC_OVERALL_RESULT_FALSE) << "rc=" << rc;
    ASSERT_NE(claims, nullptr);

    nvat_str_t json = nullptr;
    ASSERT_EQ(nvat_claims_collection_serialize_json(claims, &json), NVAT_RC_OK);
    char* data = nullptr;
    ASSERT_EQ(nvat_str_get_data(json, &data), NVAT_RC_OK);
    nlohmann::json out = nlohmann::json::parse(data);
    ASSERT_TRUE(out.is_array());
    EXPECT_FALSE(out.empty());

    nvat_str_free(&json);
    nvat_claims_collection_free(&claims);
    nvat_http_options_free(&http);
}

TEST_F(VerifyAttestationResultServerTest, TamperedSignatureRejected) {
    if (!m_setup_ok) GTEST_SKIP() << "JWKS test server not available";

    // Corrupt the SIGNATURE segment of the outer JWT (the part after the last
    // '.') so that JWT signature verification fails deterministically.
    // Corrupting a structural JSON character elsewhere could produce a
    // different error code; targeting the signature yields NRAS_TOKEN_INVALID.
    nlohmann::json detached = nlohmann::json::parse(m_detached_eat);
    std::string jwt_str = detached[0][1].get<std::string>();
    auto last_dot = jwt_str.rfind('.');
    ASSERT_NE(last_dot, std::string::npos) << "JWT must have three segments";
    ASSERT_GT(jwt_str.size(), last_dot + 1) << "JWT signature segment must not be empty";
    char& sig_last = jwt_str.back();
    sig_last = (sig_last == 'A') ? 'B' : 'A';
    detached[0][1] = jwt_str;
    std::string tampered = detached.dump();

    nvat_http_options_t http = make_http_options();
    ASSERT_NE(http, nullptr) << "make_http_options() failed";
    nvat_claims_collection_t claims = nullptr;
    nvat_rc_t rc = nvat_verify_attestation_result(tampered.c_str(), m_base_url.c_str(), /*service_key=*/nullptr, /*nonce=*/nullptr, http, /*jwt_validation_options=*/nullptr, &claims);
    EXPECT_EQ(rc, NVAT_RC_NRAS_TOKEN_INVALID);

    nvat_claims_collection_free(&claims);
    nvat_http_options_free(&http);
}

TEST_F(VerifyAttestationResultServerTest, MalformedJwksPreservesJsonSerializationError) {
    if (!m_setup_ok) GTEST_SKIP() << "JWKS test server not available";

    const std::string jwks_path = "testdata/tls_test/test_jwks.json";
    std::string valid_jwks;
    ASSERT_EQ(nvattestation::readFileIntoString(jwks_path, valid_jwks), Error::Ok);
    {
        std::ofstream malformed_jwks(jwks_path);
        ASSERT_TRUE(malformed_jwks);
        malformed_jwks << "MALFORMED_JWKS_RESPONSE_BODY::{not-json";
    }

    nvat_http_options_t http = make_http_options();
    ASSERT_NE(http, nullptr) << "make_http_options() failed";
    nvat_claims_collection_t claims = nullptr;
    const nvat_rc_t rc = nvat_verify_attestation_result(
        m_detached_eat.c_str(), m_base_url.c_str(), /*service_key=*/nullptr,
        /*nonce=*/nullptr, http, /*jwt_validation_options=*/nullptr, &claims);
    nvat_http_options_free(&http);

    {
        std::ofstream restored_jwks(jwks_path);
        ASSERT_TRUE(restored_jwks);
        restored_jwks << valid_jwks;
    }
    EXPECT_EQ(rc, NVAT_RC_JSON_SERIALIZATION_ERROR);
    EXPECT_EQ(claims, nullptr);
}

TEST_F(VerifyAttestationResultServerTest, NullArgsRejected) {
    if (!m_setup_ok) GTEST_SKIP() << "JWKS test server not available";

    nvat_claims_collection_t claims = nullptr;
    EXPECT_EQ(nvat_verify_attestation_result(nullptr, m_base_url.c_str(), nullptr, nullptr, nullptr, nullptr, &claims), NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_verify_attestation_result(m_detached_eat.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr, &claims), NVAT_RC_BAD_ARGUMENT);
    EXPECT_EQ(nvat_verify_attestation_result(m_detached_eat.c_str(), m_base_url.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr),
              NVAT_RC_BAD_ARGUMENT);
}

// A non-https nras_base_url must be rejected before any network call. Covers
// the require_https_and_normalize rejection path in verify_attestation_result.
TEST_F(VerifyAttestationResultServerTest, NonHttpsUrlRejected) {
    if (!m_setup_ok) GTEST_SKIP() << "JWKS test server not available";

    nvat_claims_collection_t claims = nullptr;
    EXPECT_EQ(nvat_verify_attestation_result(m_detached_eat.c_str(), "http://nras.example.com",
              /*service_key=*/nullptr, /*nonce=*/nullptr, /*http_options=*/nullptr, /*jwt_validation_options=*/nullptr, &claims),
              NVAT_RC_BAD_ARGUMENT);
    // A trailing-slash https URL is normalized and accepted past the scheme
    // check (it then fails later for lack of a matching JWKS, not BadArgument).
    nvat_claims_collection_t claims2 = nullptr;
    EXPECT_NE(nvat_verify_attestation_result(m_detached_eat.c_str(), (m_base_url + "/").c_str(),
              /*service_key=*/nullptr, /*nonce=*/nullptr, /*http_options=*/nullptr, /*jwt_validation_options=*/nullptr, &claims2),
              NVAT_RC_BAD_ARGUMENT);
    nvat_claims_collection_free(&claims2);
}

// A JWKS key whose x5c second cert did NOT sign the leaf (mismatched issuer)
// must be rejected (the key is skipped, so verification fails).
TEST_F(VerifyAttestationResultServerTest, MismatchedX5cIssuerRejected) {
    if (!m_setup_ok) GTEST_SKIP() << "JWKS test server not available";

    nvat_http_options_t http = make_http_options();
    ASSERT_NE(http, nullptr) << "make_http_options() failed";
    nvat_claims_collection_t claims = nullptr;
    // m_detached_eat_mismatched is signed by chain_leaf key with m_mismatched_base_url as issuer,
    // but the JWKS served at that URL has x5c=[chain_leaf, single_leaf] where single_leaf did NOT
    // sign chain_leaf.  The SDK must skip the key and return a non-OK error.
    nvat_rc_t rc = nvat_verify_attestation_result(m_detached_eat_mismatched.c_str(), m_mismatched_base_url.c_str(),
                                   /*service_key=*/nullptr, /*nonce=*/nullptr, http, /*jwt_validation_options=*/nullptr, &claims);
    EXPECT_NE(rc, NVAT_RC_OK);
    EXPECT_NE(rc, NVAT_RC_OVERALL_RESULT_FALSE);

    nvat_claims_collection_free(&claims);
    nvat_http_options_free(&http);
}

// A JWKS key whose x5c contains [chain_leaf, chain_ca] where chain_leaf was
// signed by chain_ca (a valid two-cert chain) must be accepted.
TEST_F(VerifyAttestationResultServerTest, ValidX5cChainAccepted) {
    if (!m_setup_ok) GTEST_SKIP() << "JWKS test server not available";

    nvat_http_options_t http = make_http_options();
    ASSERT_NE(http, nullptr) << "make_http_options() failed";
    nvat_claims_collection_t claims = nullptr;
    nvat_rc_t rc = nvat_verify_attestation_result(m_detached_eat_valid_chain.c_str(), m_valid_chain_base_url.c_str(),
                                   /*service_key=*/nullptr, /*nonce=*/nullptr, http, /*jwt_validation_options=*/nullptr, &claims);
    ASSERT_NE(rc, NVAT_RC_NRAS_TOKEN_INVALID)
        << "JWT with valid 2-cert x5c chain must be accepted; rc=" << rc;
    ASSERT_NE(rc, NVAT_RC_BAD_ARGUMENT);
    ASSERT_NE(claims, nullptr) << "claims must be populated when chain is valid";

    nvat_claims_collection_free(&claims);
    nvat_http_options_free(&http);
}

// A JWKS key whose x5c = [int_leaf, int] where int_leaf was signed by int (an
// intermediate, not a self-signed root) must be accepted when PARTIAL_CHAIN is
// enabled. Without X509_V_FLAG_PARTIAL_CHAIN this fails because OpenSSL cannot
// build a chain to a trusted self-signed anchor.
TEST_F(VerifyAttestationResultServerTest, IntermediateIssuerChainAccepted) {
    if (!m_setup_ok) GTEST_SKIP() << "JWKS test server not available";

    nvat_http_options_t http = make_http_options();
    ASSERT_NE(http, nullptr) << "make_http_options() failed";
    nvat_claims_collection_t claims = nullptr;
    nvat_rc_t rc = nvat_verify_attestation_result(m_detached_eat_int.c_str(), m_int_base_url.c_str(),
                                   /*service_key=*/nullptr, /*nonce=*/nullptr, http, /*jwt_validation_options=*/nullptr, &claims);
    // The leaf was signed by an intermediate (not a root), x5c[1] is not self-signed.
    // Without PARTIAL_CHAIN this would fail with NRAS_TOKEN_INVALID.
    ASSERT_NE(rc, NVAT_RC_NRAS_TOKEN_INVALID)
        << "JWT with intermediate-issued x5c chain must be accepted; rc=" << rc;
    ASSERT_NE(rc, NVAT_RC_BAD_ARGUMENT);
    ASSERT_NE(claims, nullptr) << "claims must be populated when intermediate chain is valid";

    nvat_claims_collection_free(&claims);
    nvat_http_options_free(&http);
}
