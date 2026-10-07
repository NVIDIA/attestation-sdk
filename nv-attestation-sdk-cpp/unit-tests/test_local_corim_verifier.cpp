/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
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

#include <climits>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <openssl/ocsp.h>

#include <jwt-cpp/jwt.h>
#include "jwt-cpp/traits/nlohmann-json/traits.h"

#include "gtest/gtest.h"

#include "local_https_test_server.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/cmw.h"
#include "nv_attestation/corim_evidence/corim_store.h"
#include "nv_attestation/corim_verify.h"
#include "nv_attestation/ear_mapper.h"
#include "nv_attestation/error.h"
#include "nv_attestation/nv_cache.h"
#include "nv_attestation/nv_ocsp.h"
#include "nv_attestation/utils.h"

namespace nvattestation {
namespace {

constexpr const char *kBlackwellCmwPath =
    "testdata/sample_attestation_data/blackwell_evidence.cmw.json";
constexpr const char *kRubinCmwPath =
    "testdata/sample_attestation_data/rubin_evidence.cmw.json";
constexpr const char *kBlackwellFspCmwPath =
    "testdata/sample_attestation_data/blackwell_fsp_evidence.cmw.json";
constexpr uint8_t kTamperMask = 0xFF;

// Records whether the verifier consulted it, so tests can assert the OCSP
// path was (or was not) taken.
class CallCountingOcspClient : public IOcspHttpClient {
  public:
    int calls = 0;
    Error get_ocsp_response(const nv_unique_ptr<X509> &,
                            const nv_unique_ptr<X509> &,
                            const nv_unique_ptr<stack_st_X509> &,
                            const nv_unique_ptr<X509_STORE> &,
                            NvOcspResponse &out_ocsp_response) override {
        ++calls;
        out_ocsp_response = NvOcspResponse{};
        return Error::Ok;
    }
};

// Reports every cert with a fixed OCSP status and a fixed produced-at/revoked-at,
// so tests can assert on both the OCSP timestamp mapping and revoked/unknown
// rejection.
class FixedStatusOcspClient : public IOcspHttpClient {
  public:
    explicit FixedStatusOcspClient(int status, bool nonce_matches = true,
                                   bool response_valid = true)
        : m_status(status), m_nonce_matches(nonce_matches), m_response_valid(response_valid) {}

    Error get_ocsp_response(const nv_unique_ptr<X509> &,
                            const nv_unique_ptr<X509> &,
                            const nv_unique_ptr<stack_st_X509> &,
                            const nv_unique_ptr<X509_STORE> &,
                            NvOcspResponse &out_ocsp_response) override {
        out_ocsp_response = NvOcspResponse{};
        out_ocsp_response.response_valid = m_response_valid;
        out_ocsp_response.nonce_matches = m_nonce_matches;
        out_ocsp_response.status = m_status;
        out_ocsp_response.reason = OCSP_REVOKED_STATUS_KEYCOMPROMISE;
        out_ocsp_response.thisupd = kThisUpdate;
        out_ocsp_response.nextupd = kThisUpdate + kNextUpdateTtlSeconds;
        out_ocsp_response.revtime = kRevokedAt;
        out_ocsp_response.producedat = kProducedAt;
        return Error::Ok;
    }

    static constexpr time_t kThisUpdate = 1699990000;
    static constexpr time_t kProducedAt = 1700000000;
    static constexpr time_t kRevokedAt = 1699996400;
    static constexpr time_t kNextUpdateTtlSeconds = 3600;

  private:
    int m_status;
    bool m_nonce_matches;
    bool m_response_valid;
};

// Fails every OCSP query, to drive the OCSP-error path.
class ErroringOcspClient : public IOcspHttpClient {
  public:
    Error get_ocsp_response(const nv_unique_ptr<X509> &,
                            const nv_unique_ptr<X509> &,
                            const nv_unique_ptr<stack_st_X509> &,
                            const nv_unique_ptr<X509_STORE> &,
                            NvOcspResponse &) override {
        return Error::OcspServerError;
    }
};

// Succeeds for the first succeed_count queries, then errors — drives the
// partial-failure path in generate_per_cert_status.
class FlakyOcspClient : public IOcspHttpClient {
  public:
    explicit FlakyOcspClient(int succeed_count) : m_succeed_count(succeed_count) {}

    Error get_ocsp_response(const nv_unique_ptr<X509> &,
                            const nv_unique_ptr<X509> &,
                            const nv_unique_ptr<stack_st_X509> &,
                            const nv_unique_ptr<X509_STORE> &,
                            NvOcspResponse &out_ocsp_response) override {
        if (m_calls++ < m_succeed_count) {
            out_ocsp_response = NvOcspResponse{};
            out_ocsp_response.response_valid = true;
            out_ocsp_response.nonce_matches = true;
            out_ocsp_response.status = V_OCSP_CERTSTATUS_GOOD;
            return Error::Ok;
        }
        return Error::OcspServerError;
    }

  private:
    int m_succeed_count;
    int m_calls = 0;
};

// Reports every cert as not applicable for OCSP (Error::Ok, skipped=true),
// matching NvHttpOcspClient's behavior for a cert with no AIA responder URL
// (e.g. the real Blackwell GPU device chain's leaf/AK cert).
class SkippedOcspClient : public IOcspHttpClient {
  public:
    Error get_ocsp_response(const nv_unique_ptr<X509> &,
                            const nv_unique_ptr<X509> &,
                            const nv_unique_ptr<stack_st_X509> &,
                            const nv_unique_ptr<X509_STORE> &,
                            NvOcspResponse &out_ocsp_response) override {
        out_ocsp_response = NvOcspResponse{};
        out_ocsp_response.skipped = true;
        return Error::Ok;
    }
};

TEST(LocalCorimVerifierTest, RejectsEmptyDeviceRootPem) {
    LocalCorimVerifier verifier(CorimStore{});
    EXPECT_EQ(verifier.add_device_identity_trust_root_pem(""),
              Error::BadArgument);
}

// set_verify_revocation(false) must gate an injected OCSP client too: the
// client is never consulted when revocation is disabled.
TEST(LocalCorimVerifierTest, RevocationDisabledSkipsInjectedOcspClient) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    auto spy = std::make_shared<CallCountingOcspClient>();
    LocalCorimVerifier verifier(CorimStore{}, spy);
    verifier.set_verify_revocation(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    EXPECT_EQ(spy->calls, 0);
}

// Positive control: with revocation enabled the injected client is consulted.
TEST(LocalCorimVerifierTest, RevocationEnabledUsesInjectedOcspClient) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    auto spy = std::make_shared<CallCountingOcspClient>();
    LocalCorimVerifier verifier(CorimStore{}, spy);
    verifier.set_verify_revocation(true);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    EXPECT_GT(spy->calls, 0);
}

// Positive control for all_certs_trusted: a fully good chain must still
// verify when revocation checking is enabled.
TEST(LocalCorimVerifierTest, GoodOcspStatusKeepsSignatureVerified) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    auto client = std::make_shared<FixedStatusOcspClient>(V_OCSP_CERTSTATUS_GOOD);
    LocalCorimVerifier verifier(CorimStore{}, client);
    verifier.set_verify_revocation(true);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    EXPECT_TRUE(result.items[0].evidence.signature_verified);
}

// Regression test: a cert with no AIA responder URL (SkippedOcspClient mimics
// NvHttpOcspClient's AIA-skip behavior, as on the real Blackwell GPU device
// chain's leaf/AK cert) must not fail an otherwise-trustworthy chain.
TEST(LocalCorimVerifierTest, SkippedOcspCheckKeepsSignatureVerified) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    auto client = std::make_shared<SkippedOcspClient>();
    LocalCorimVerifier verifier(CorimStore{}, client);
    verifier.set_verify_revocation(true);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    EXPECT_TRUE(result.items[0].evidence.signature_verified);
}

// The root (self-signed trust anchor) has no issuer in the chain to check
// it against, so collect_ocsp_responses now emits an explicit skipped
// response for it instead of silently never querying it. Confirms the root
// shows up as NOT_CHECKED, not simply absent.
TEST(LocalCorimVerifierTest, RootCertRecordedAsNotChecked) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    auto client = std::make_shared<FixedStatusOcspClient>(V_OCSP_CERTSTATUS_GOOD);
    LocalCorimVerifier verifier(CorimStore{}, client);
    verifier.set_verify_revocation(true);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    ASSERT_NE(result.items[0].evidence.cert_chain, nullptr);
    ASSERT_FALSE(result.items[0].evidence.cert_chain->empty());

    // cert_chain is root-first; index 0 is the self-signed trust anchor.
    const PerCertStatus &root = result.items[0].evidence.cert_chain->front();
    ASSERT_NE(root.ocsp, nullptr);
    EXPECT_EQ(root.ocsp->crl_status, OCSPStatus::NOT_CHECKED);
}

TEST(LocalCorimVerifierTest, RevokedOcspResponseCarriesTimestamps) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    auto client = std::make_shared<FixedStatusOcspClient>(V_OCSP_CERTSTATUS_REVOKED);
    LocalCorimVerifier verifier(CorimStore{}, client);
    verifier.set_verify_revocation(true);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    ASSERT_NE(result.items[0].evidence.cert_chain, nullptr);

    std::string expected_produced_at;
    ASSERT_EQ(format_time(FixedStatusOcspClient::kProducedAt, expected_produced_at), Error::Ok);
    std::string expected_revoked_at;
    ASSERT_EQ(format_time(FixedStatusOcspClient::kRevokedAt, expected_revoked_at), Error::Ok);

    bool found_revoked = false;
    for (const auto &cert : *result.items[0].evidence.cert_chain) {
        if (cert.ocsp && cert.ocsp->crl_status == OCSPStatus::REVOKED) {
            found_revoked = true;
            EXPECT_EQ(cert.ocsp->response_produced_at, expected_produced_at);
            EXPECT_EQ(cert.ocsp->response_revoked_at, expected_revoked_at);
        }
    }
    EXPECT_TRUE(found_revoked);
}

TEST(LocalCorimVerifierTest, RevokedDeviceChainFailsSignatureVerification) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    auto client = std::make_shared<FixedStatusOcspClient>(V_OCSP_CERTSTATUS_REVOKED);
    LocalCorimVerifier verifier(CorimStore{}, client);
    verifier.set_verify_revocation(true);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    EXPECT_FALSE(result.items[0].evidence.signature_verified);
}

// verify_evidence_signature only relaxes anchor/signature failures to a
// warning; it must not also suppress revocation enforcement.
TEST(LocalCorimVerifierTest, RevocationStillGatesWhenEvidenceSignatureCheckDisabled) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    auto client = std::make_shared<FixedStatusOcspClient>(V_OCSP_CERTSTATUS_REVOKED);
    LocalCorimVerifier verifier(CorimStore{}, client);
    verifier.set_verify_revocation(true);
    verifier.set_verify_evidence_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    EXPECT_FALSE(result.items[0].evidence.signature_verified);
}

// status/nonce_matches/response_valid passed straight through to FixedStatusOcspClient.
struct OcspFailureCase {
    std::string name;
    int status;
    bool nonce_matches;
    bool response_valid;
};

class OcspFailureMarksEarStatusContraindicated : public ::testing::TestWithParam<OcspFailureCase> {};

TEST_P(OcspFailureMarksEarStatusContraindicated, EarStatusIsContraindicated) {
    const auto &test_case = GetParam();
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    auto client = std::make_shared<FixedStatusOcspClient>(
        test_case.status, test_case.nonce_matches, test_case.response_valid);
    LocalCorimVerifier verifier(CorimStore{}, client);
    verifier.set_verify_revocation(true);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());

    nlohmann::json ear;
    ASSERT_EQ(map_to_ear_json(result, ear), Error::Ok);
    EXPECT_EQ(ear["ear_status"], "contraindicated");
    const std::string &label = result.items[0].label;
    ASSERT_TRUE(ear["submods"].contains(label));
    EXPECT_EQ(ear["submods"][label]["ear_status"], "contraindicated");
}

INSTANTIATE_TEST_SUITE_P(
    OcspStatuses, OcspFailureMarksEarStatusContraindicated,
    ::testing::Values(
        OcspFailureCase{"Revoked", V_OCSP_CERTSTATUS_REVOKED, /*nonce_matches=*/true, /*response_valid=*/true},
        OcspFailureCase{"Unknown", V_OCSP_CERTSTATUS_UNKNOWN, /*nonce_matches=*/true, /*response_valid=*/true},
        OcspFailureCase{"NonceMismatch", V_OCSP_CERTSTATUS_GOOD, /*nonce_matches=*/false, /*response_valid=*/true},
        OcspFailureCase{"InvalidResponse", V_OCSP_CERTSTATUS_GOOD, /*nonce_matches=*/true, /*response_valid=*/false}),
    [](const ::testing::TestParamInfo<OcspFailureCase> &info) {
        return info.param.name;
    });

TEST(LocalCorimVerifierTest, UnknownOcspStatusFailsSignatureVerification) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    auto client = std::make_shared<FixedStatusOcspClient>(V_OCSP_CERTSTATUS_UNKNOWN);
    LocalCorimVerifier verifier(CorimStore{}, client);
    verifier.set_verify_revocation(true);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    EXPECT_FALSE(result.items[0].evidence.signature_verified);
}

// A failed OCSP query leaves certs with no OCSP data — expiry is still collected.
TEST(LocalCorimVerifierTest, OcspQueryErrorRecordedAsErrorStatus) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    LocalCorimVerifier verifier(CorimStore{},
                                std::make_shared<ErroringOcspClient>());
    verifier.set_verify_revocation(true);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    ASSERT_NE(result.items[0].evidence.cert_chain, nullptr);
    ASSERT_FALSE(result.items[0].evidence.cert_chain->empty());

    // Root is NOT_CHECKED (never queried by design); every other cert gets ERROR.
    const auto& chain = *result.items[0].evidence.cert_chain;
    ASSERT_NE(chain.front().ocsp, nullptr);
    EXPECT_EQ(chain.front().ocsp->crl_status, OCSPStatus::NOT_CHECKED);
    for (size_t i = 1; i < chain.size(); ++i) {
        ASSERT_NE(chain[i].ocsp, nullptr) << "cert " << i << " should have an explicit ERROR status";
        EXPECT_EQ(chain[i].ocsp->crl_status, OCSPStatus::ERROR);
    }
    EXPECT_FALSE(result.items[0].evidence.signature_verified);
}

// Certs queried before the failure keep their real status; the rest get ERROR.
TEST(LocalCorimVerifierTest, PartialOcspFailureMarksRemainingCertsError) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    auto client = std::make_shared<FlakyOcspClient>(2);
    LocalCorimVerifier verifier(CorimStore{}, client);
    verifier.set_verify_revocation(true);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    ASSERT_NE(result.items[0].evidence.cert_chain, nullptr);

    int good_count = 0;
    int error_count = 0;
    for (const auto &cert : *result.items[0].evidence.cert_chain) {
        if (!cert.ocsp) {
            continue;
        }
        if (cert.ocsp->crl_status == OCSPStatus::GOOD) {
            ++good_count;
        }
        if (cert.ocsp->crl_status == OCSPStatus::ERROR) {
            ++error_count;
        }
    }
    EXPECT_EQ(good_count, 2);
    EXPECT_GT(error_count, 0);
    EXPECT_FALSE(result.items[0].evidence.signature_verified);
}

// Revocation disabled — no OCSP data present on any cert.
TEST(LocalCorimVerifierTest, RevocationDisabledRecordsOcspNotChecked) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    ASSERT_NE(result.items[0].evidence.cert_chain, nullptr);
    ASSERT_FALSE(result.items[0].evidence.cert_chain->empty());
    for (const auto& cert : *result.items[0].evidence.cert_chain) {
        EXPECT_EQ(cert.ocsp, nullptr) << "disabled revocation should leave ocsp field unset";
    }
}

TEST(LocalCorimVerifierTest, VerifyCmwRejectsNullData) {
    LocalCorimVerifier verifier(CorimStore{});
    CorimAttestationResult result;
    EXPECT_EQ(verifier.verify_cmw(nullptr, 10, CmwFormat::kJson, result),
              Error::BadArgument);
}

TEST(LocalCorimVerifierTest, VerifyCmwCborNotEnabled) {
    LocalCorimVerifier verifier(CorimStore{});
    std::vector<uint8_t> data = {0x00};
    CorimAttestationResult result;
    EXPECT_EQ(verifier.verify_cmw(data.data(), data.size(), CmwFormat::kCbor,
                                  result),
              Error::FeatureNotEnabled);
}

TEST(LocalCorimVerifierTest, VerifyCmwPropagatesParseFailure) {
    LocalCorimVerifier verifier(CorimStore{});
    std::string junk = "{not a cmw";
    CorimAttestationResult result;
    EXPECT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(junk.data()), junk.size(),
                  CmwFormat::kJson, result),
              Error::EvidenceMalformed);
}

// A structurally valid item with an unrecognized evidence media type is a
// per-item verifier error, not a bundle-fatal failure: verify_cmw returns Ok
// and the item carries an un-anchored appraisal with a stage_error.
TEST(LocalCorimVerifierTest, VerifyCmwUnknownEvidenceMediaTypeRecordsStageError) {
    std::string evidence_b64;
    encode_base64url(std::vector<uint8_t>(16, 0x5A), evidence_b64);
    std::string nonce_b64;
    encode_base64url(std::vector<uint8_t>(32, 0), nonce_b64);

    nlohmann::json evidence_item = nlohmann::json::object();
    evidence_item["__cmwc_t"] = kCmwEvidenceItemProfile;
    evidence_item["evidence"] = nlohmann::json::array(
        {"application/vnd.nvidia.not-real", evidence_b64});
    evidence_item["nonce"] =
        nlohmann::json::array({kCmwMediaOctetStream, nonce_b64});

    nlohmann::json root = nlohmann::json::object();
    root["__cmwc_t"] = kCmwInputProfile;
    root["nonce"] = nlohmann::json::array({kCmwMediaOctetStream, nonce_b64});
    root["gpu_0"] = evidence_item;
    std::string cmw_json = root.dump();

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);
    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_EQ(result.items.size(), 1U);
    EXPECT_EQ(result.items[0].evidence.cert_chain, nullptr);
    EXPECT_EQ(result.items[0].stage_error.message,
              "no evidence handler for media type: "
              "application/vnd.nvidia.not-real");
}

std::vector<uint8_t> load_binary_fixture(const std::string &path) {
    std::ifstream fixture_stream(path, std::ios::binary);
    if (!fixture_stream) {
        ADD_FAILURE() << "missing fixture: " << path;
        return {};
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(fixture_stream)),
                                std::istreambuf_iterator<char>());
}

std::string eat_cmw_json(const std::vector<uint8_t> &token) {
    std::string token_b64;
    EXPECT_EQ(encode_base64url(token, token_b64), Error::Ok);

    nlohmann::json evidence_item = nlohmann::json::object();
    evidence_item["__cmwc_t"] = kCmwEvidenceItemProfile;
    evidence_item["evidence"] =
        nlohmann::json::array({kCmwMediaEatCwt, token_b64});

    nlohmann::json root = nlohmann::json::object();
    root["__cmwc_t"] = kCmwInputProfile;
    root["device_0"] = evidence_item;
    return root.dump();
}

TEST(LocalCorimVerifierTest, VerifyCmwSignedEatAnchorsAndVerifiesSignature) {
    const std::string cmw_json =
        eat_cmw_json(load_binary_fixture("testdata/sample_rims/eat/full_signed.cbor"));
    std::string root_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/cose_signing_root.crt",
                                 root_pem),
              Error::Ok);

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);
    ASSERT_EQ(verifier.add_device_identity_trust_root_pem(root_pem), Error::Ok);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_EQ(result.items.size(), 1U);
    const auto &item = result.items[0];
    EXPECT_NE(item.evidence.cert_chain, nullptr);
    EXPECT_TRUE(item.evidence.signature_verified);
    EXPECT_TRUE(item.evidence.parsed);
    EXPECT_FALSE(item.eat_nonce.empty());
    EXPECT_FALSE(item.evidence.akpub.empty());
}

TEST(LocalCorimVerifierTest, VerifyCmwUnsignedEatSkipsDeviceIdentityChain) {
    const std::string cmw_json =
        eat_cmw_json(load_binary_fixture("testdata/sample_rims/eat/full.cbor"));

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);
    verifier.set_verify_evidence_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_EQ(result.items.size(), 1U);
    const auto &item = result.items[0];
    EXPECT_EQ(item.evidence.cert_chain, nullptr);
    EXPECT_TRUE(item.evidence.akpub.empty());
    EXPECT_FALSE(item.evidence.signature_verified);
    EXPECT_TRUE(item.evidence.parsed);
    EXPECT_EQ(item.stage_error.message, "no RIM reference values to appraise against");

    nlohmann::json serialized = result;
    ASSERT_TRUE(serialized.contains("evidence_items"));
    EXPECT_FALSE(serialized["evidence_items"][0].contains("cert_chain"));
}

TEST(LocalCorimVerifierTest, VerifyCmwToleratesTamperedEatSignatureWhenDisabled) {
    std::vector<uint8_t> tampered =
        load_binary_fixture("testdata/sample_rims/eat/full_signed.cbor");
    ASSERT_FALSE(tampered.empty());
    tampered.back() ^= kTamperMask;
    const std::string cmw_json = eat_cmw_json(tampered);
    std::string root_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/cose_signing_root.crt",
                                 root_pem),
              Error::Ok);

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);
    verifier.set_verify_evidence_signature(false);
    ASSERT_EQ(verifier.add_device_identity_trust_root_pem(root_pem), Error::Ok);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_EQ(result.items.size(), 1U);
    const auto &item = result.items[0];
    EXPECT_NE(item.evidence.cert_chain, nullptr);
    EXPECT_FALSE(item.evidence.signature_verified);
    EXPECT_TRUE(item.evidence.parsed);
    EXPECT_FALSE(item.evidence.akpub.empty());
    EXPECT_EQ(item.stage_error.message, "no RIM reference values to appraise against");
}

TEST(LocalCorimVerifierTest,
     UntrustedEatChainRemainsUnverifiedWhenVerificationIsDisabled) {
    const std::string cmw_json =
        eat_cmw_json(load_binary_fixture("testdata/sample_rims/eat/full_signed.cbor"));

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);
    verifier.set_verify_evidence_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_EQ(result.items.size(), 1U);
    const auto &item = result.items[0];
    ASSERT_NE(item.evidence.cert_chain, nullptr);
    EXPECT_FALSE(item.evidence.cert_chain->empty());
    EXPECT_FALSE(item.evidence.signature_verified);
    EXPECT_TRUE(item.evidence.parsed);
    EXPECT_FALSE(item.evidence.akpub.empty());
    nlohmann::json serialized = result;
    ASSERT_TRUE(serialized.contains("evidence_items"));
    EXPECT_TRUE(serialized["evidence_items"][0]["evidence"].contains("akpub"));
}

TEST(LocalCorimVerifierTest, VerifyCmwUnsignedEatRejectedWhenSignatureRequired) {
    const std::string cmw_json =
        eat_cmw_json(load_binary_fixture("testdata/sample_rims/eat/full.cbor"));

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_EQ(result.items.size(), 1U);
    EXPECT_EQ(result.items[0].stage_error.message, "cert chain extraction failed");
}

// No tagged-spdm-toc means no RIM locators, so appraisal stops after the
// signature verifies.
TEST(LocalCorimVerifierTest, VerifyCmwBlackwellAnchorsAndVerifiesSignature) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    for (const auto &item : result.items) {
        EXPECT_NE(item.evidence.cert_chain, nullptr) << item.label;
        EXPECT_TRUE(item.evidence.signature_verified) << item.label;
        EXPECT_TRUE(item.evidence.parsed) << item.label;
        EXPECT_TRUE(item.evidence.nonce_supplied) << item.label;
        EXPECT_TRUE(item.evidence.nonce_match) << item.label;
        EXPECT_FALSE(item.eat_nonce.empty()) << item.label;
        EXPECT_EQ(item.stage_error.message, "no RIM reference values to appraise against")
            << item.label;
        EXPECT_TRUE(item.corims.empty()) << item.label;
        EXPECT_TRUE(item.match.outcomes.empty()) << item.label;
        // Device identity cert (index 1), not the leaf firmware layer cert.
        EXPECT_EQ(item.evidence.device_cert_serial, "1215674193163864588919")
            << item.label;
        // akpub is the leaf key the payload signature verified against.
        EXPECT_EQ(item.evidence.akpub.rfind("-----BEGIN PUBLIC KEY-----", 0), 0U)
            << item.label;
        // Serial from the leaf's DMTF SubjectAltName otherName.
        EXPECT_EQ(item.evidence.spdm_end_entity_othername_serial,
                  "48B02DD4C0CB1539")
            << item.label;
    }

    // Result must serialize to JSON without throwing.
    nlohmann::json serialized = result;
    EXPECT_TRUE(serialized.contains("evidence_items"));
    EXPECT_EQ(serialized.dump().find("device_cert_serial"), std::string::npos)
        << "device_cert_serial must not reach the output";
    EXPECT_NE(serialized.dump().find("akpub"), std::string::npos)
        << "akpub must be emitted once the signature verified";
    EXPECT_EQ(serialized.dump().find("othername_serial"), std::string::npos)
        << "spdm_end_entity_othername_serial must not reach the output";
}

// Replay protection: a validly signed transcript whose embedded nonce does not
// match the CMW input nonce is rejected as a nonce mismatch, halting appraisal.
TEST(LocalCorimVerifierTest, VerifyCmwRejectsStaleNonce) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);
    nlohmann::json root = nlohmann::json::parse(cmw_json);
    std::string wrong_nonce;
    encode_base64url(std::vector<uint8_t>(32, 0xAB), wrong_nonce);
    for (auto &member : root.items()) {
        if (member.value().is_object() && member.value().contains("nonce")) {
            member.value()["nonce"][1] = wrong_nonce;
        }
    }
    std::string tampered = root.dump();

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);
    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(tampered.data()),
                  tampered.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_TRUE(item.evidence.signature_verified) << "signature is still valid";
    EXPECT_TRUE(item.evidence.nonce_supplied);
    EXPECT_FALSE(item.evidence.nonce_match);
    EXPECT_EQ(item.stage_error.message, "evidence nonce mismatch");
}

// No per-item nonce: no nonce_match, but eat_nonce is still extracted.
TEST(LocalCorimVerifierTest, VerifyCmwOptionalNonceOmittedYieldsEatNonce) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);
    nlohmann::json root = nlohmann::json::parse(cmw_json);
    for (auto &member : root.items()) {
        if (member.value().is_object()) {
            member.value().erase("nonce");
        }
    }
    std::string stripped = root.dump();

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);
    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(stripped.data()),
                  stripped.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_TRUE(item.evidence.signature_verified);
    EXPECT_FALSE(item.evidence.nonce_supplied);
    EXPECT_FALSE(item.eat_nonce.empty());
    // No RIM locators; the eat_nonce extraction under test is unaffected.
    EXPECT_EQ(item.stage_error.message, "no RIM reference values to appraise against");
}

TEST(LocalCorimVerifierTest, VerifyCmwMissingCompanionCertRecordsStageError) {
    std::string evidence_b64;
    encode_base64url(std::vector<uint8_t>(64, 0x5A), evidence_b64);
    std::string nonce_b64;
    encode_base64url(std::vector<uint8_t>(32, 0), nonce_b64);

    nlohmann::json evidence_item = nlohmann::json::object();
    evidence_item["__cmwc_t"] = kCmwEvidenceItemProfile;
    evidence_item["evidence"] =
        nlohmann::json::array({kCmwMediaSpdmTranscript, evidence_b64});
    evidence_item["nonce"] =
        nlohmann::json::array({kCmwMediaOctetStream, nonce_b64});

    nlohmann::json root = nlohmann::json::object();
    root["__cmwc_t"] = kCmwInputProfile;
    root["nonce"] = nlohmann::json::array({kCmwMediaOctetStream, nonce_b64});
    root["gpu_0"] = evidence_item;
    std::string cmw_json = root.dump();

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);
    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_EQ(result.items.size(), 1U);
    EXPECT_EQ(result.items[0].evidence.cert_chain, nullptr);
    EXPECT_EQ(result.items[0].stage_error.message, "cert chain extraction failed");
}

TEST(LocalCorimVerifierTest, VerifyCmwRejectsTamperedSignature) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);
    nlohmann::json root = nlohmann::json::parse(cmw_json);
    for (auto &member : root.items()) {
        if (!member.value().is_object() ||
            !member.value().contains("evidence")) {
            continue;
        }
        std::vector<uint8_t> evidence;
        ASSERT_EQ(decode_base64url(
                      member.value()["evidence"][1].get<std::string>(),
                      evidence),
                  Error::Ok);
        ASSERT_FALSE(evidence.empty());
        evidence.back() ^= kTamperMask;
        std::string reencoded;
        ASSERT_EQ(encode_base64url(evidence, reencoded), Error::Ok);
        member.value()["evidence"][1] = reencoded;
    }
    std::string tampered = root.dump();

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);
    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(tampered.data()),
                  tampered.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_FALSE(item.evidence.signature_verified);
    EXPECT_EQ(item.stage_error.message, "evidence signature verification failed");
    // akpub is only meaningful once the signature verifies.
    EXPECT_TRUE(item.evidence.akpub.empty());
    nlohmann::json serialized = result;
    EXPECT_EQ(serialized.dump().find("akpub"), std::string::npos);
}

TEST(LocalCorimVerifierTest, GspResponderDoesNotSynthesizeRimLocator) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_TRUE(item.evidence.signature_verified);
    // No locator anywhere -- neither from evidence nor synthesized.
    EXPECT_EQ(item.stage_error.message, "no RIM reference values to appraise against");
    EXPECT_TRUE(item.corims.empty());
}

TEST(LocalCorimVerifierTest, VerifyCmwToleratesTamperedSpdmSignatureWhenDisabled) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);
    nlohmann::json root = nlohmann::json::parse(cmw_json);
    for (auto &member : root.items()) {
        if (!member.value().is_object() ||
            !member.value().contains("evidence")) {
            continue;
        }
        std::vector<uint8_t> evidence;
        ASSERT_EQ(decode_base64url(
                      member.value()["evidence"][1].get<std::string>(),
                      evidence),
                  Error::Ok);
        ASSERT_FALSE(evidence.empty());
        evidence.back() ^= kTamperMask;
        std::string reencoded;
        ASSERT_EQ(encode_base64url(evidence, reencoded), Error::Ok);
        member.value()["evidence"][1] = reencoded;
    }
    std::string tampered = root.dump();

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);
    verifier.set_verify_evidence_signature(false);
    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(tampered.data()),
                  tampered.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_NE(item.evidence.cert_chain, nullptr);
    EXPECT_FALSE(item.evidence.signature_verified);
    EXPECT_FALSE(item.evidence.akpub.empty());
    EXPECT_EQ(item.stage_error.message, "no RIM reference values to appraise against");
}

TEST(LocalCorimVerifierTest,
     UnanchoredDtiChainEmitsDiagnosticClaimsWhenVerificationDisabled) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);
    nlohmann::json root = nlohmann::json::parse(cmw_json);
    auto &encoded_chain = root["gpu_0"]["certificate"][1];

    std::vector<uint8_t> chain_bytes;
    ASSERT_EQ(decode_base64url(encoded_chain.get<std::string>(), chain_bytes),
              Error::Ok);
    std::string chain_pem(chain_bytes.begin(), chain_bytes.end());
    const std::string end_marker = "-----END CERTIFICATE-----";
    const std::size_t first_cert_end = chain_pem.find(end_marker);
    ASSERT_NE(first_cert_end, std::string::npos);
    chain_pem.resize(first_cert_end + end_marker.size());
    chain_bytes.assign(chain_pem.begin(), chain_pem.end());
    std::string encoded_leaf;
    ASSERT_EQ(encode_base64url(chain_bytes, encoded_leaf), Error::Ok);
    encoded_chain = encoded_leaf;
    const std::string unanchored = root.dump();

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);
    verifier.set_verify_evidence_signature(false);
    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(unanchored.data()),
                  unanchored.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_EQ(result.items.size(), 1U);
    const auto &item = result.items[0];
    ASSERT_NE(item.evidence.cert_chain, nullptr);
    EXPECT_EQ(item.evidence.cert_chain->size(), 1U);
    EXPECT_FALSE(item.evidence.signature_verified);
    EXPECT_FALSE(item.evidence.akpub.empty());
    EXPECT_FALSE(item.chain_ect_environments.empty());

    nlohmann::json serialized = result;
    ASSERT_TRUE(serialized.contains("evidence_items"));
    EXPECT_TRUE(serialized["evidence_items"][0]["evidence"].contains("akpub"));
    EXPECT_TRUE(
        serialized["evidence_items"][0].contains("chain_ect_environments"));
}

TEST(LocalCorimVerifierTest, VerifyCmwRubinTocMatchesUnsignedFixtureRims) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw_json), Error::Ok);

    char vbios_path[PATH_MAX];
    char driver_path[PATH_MAX];
    ASSERT_NE(::realpath("testdata/sample_rims/corim/rubin_vbios_example.cbor",
                         vbios_path), nullptr);
    ASSERT_NE(::realpath("testdata/sample_rims/corim/rubin_driver_example.cbor",
                         driver_path), nullptr);

    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(
                  "https://rim.attestation.nvidia.com/v1/rim/"
                  "GR100_081D_9900230000",
                  "file://" + std::string(vbios_path)),
              Error::Ok);
    ASSERT_EQ(store.add_url_rewrite(
                  "https://rim.attestation.nvidia.com/v1/rim/"
                  "NV_GPU_DRIVER_GR100_620.54",
                  "file://" + std::string(driver_path)),
              Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_EQ(result.items.size(), 1u);
    const auto &item = result.items.front();
    EXPECT_EQ(item.label, "gpu_0");
    EXPECT_TRUE(item.evidence.signature_verified);
    EXPECT_TRUE(item.evidence.nonce_match);
    EXPECT_FALSE(item.stage_error.has_error()) << item.stage_error.message;
    EXPECT_TRUE(item.match.diagnostics.empty());
    ASSERT_NE(item.match.purpose, nullptr);
    EXPECT_EQ(*item.match.purpose, "CC MPT");
    ASSERT_NE(item.cert_chain_dti_match, nullptr);
    EXPECT_TRUE(*item.cert_chain_dti_match);
    ASSERT_EQ(item.corims.size(), 2u);
    EXPECT_TRUE(item.corims[0].parsed);
    EXPECT_TRUE(item.corims[1].parsed);
    EXPECT_EQ(item.corims[0].id, "example-rubin-vbios-GR100_081D_9900230000");
    EXPECT_EQ(item.corims[1].id, "example-rubin-driver-GR100_620.54");
    EXPECT_FALSE(item.corims[0].signature_verified);
    EXPECT_FALSE(item.corims[1].signature_verified);
}

// === RIM-fetch loop: fetched CoEV is converted into ECTs (appraise_item) ===
class LocalCorimVerifierCoevTest : public ::testing::Test {
  protected:
    static LocalHttpsTestServer m_server;
    static bool m_setup_ok;

    static void SetUpTestSuite() { m_setup_ok = m_server.start(); }
    static void TearDownTestSuite() { m_server.stop(); }

    void SetUp() override {
        ASSERT_TRUE(m_setup_ok) << "HTTPS test server not available";
    }

    CorimStore make_store() const {
        HttpOptions options;
        options.set_tls_ca_cert(m_server.cert_path("tls_ca_cert.pem"));
        options.set_max_retry_count(0);
        return CorimStore(options);
    }

    std::string server_url() const { return m_server.url(); }
};

LocalHttpsTestServer LocalCorimVerifierCoevTest::m_server;
bool LocalCorimVerifierCoevTest::m_setup_ok = false;

TEST_F(LocalCorimVerifierCoevTest, FetchedCoevIsConvertedAndFedIntoComparison) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw_json), Error::Ok);

    char nonroot[PATH_MAX];
    char empty[PATH_MAX];
    ASSERT_NE(::realpath("testdata/sample_rims/corim/nonroot_only.cbor", nonroot),
              nullptr);
    ASSERT_NE(::realpath("testdata/sample_rims/corim/empty.cbor", empty), nullptr);

    CorimStore store = make_store();
    ASSERT_EQ(store.add_url_rewrite(
                  "https://rim.attestation.nvidia.com/v1/rim/"
                  "GR100_081D_9900230000",
                  server_url() + "rim-service-with-real-coev"),
              Error::Ok);
    ASSERT_EQ(store.add_url_rewrite(
                  "https://rim.attestation.nvidia.com/v1/rim/"
                  "NV_GPU_DRIVER_GR100_620.54",
                  "file://" + std::string(empty)),
              Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);
    verifier.set_verify_coev_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_FALSE(item.stage_error.has_error()) << item.stage_error.message;
    ASSERT_EQ(item.corims.size(), 2u);
    EXPECT_TRUE(item.corims[0].fetched);
    EXPECT_TRUE(item.corims[1].fetched);
    EXPECT_TRUE(item.match.diagnostics.empty());

    bool found_coev_env = false;
    for (const auto &env : item.match.unmatched_environments) {
        const ClassMap *cls = env.getClass();
        if (cls != nullptr && cls->getVendor() != nullptr &&
            *cls->getVendor() == "TestVendor" && cls->getModel() != nullptr &&
            *cls->getModel() == "TestModel") {
            found_coev_env = true;
            break;
        }
    }
    EXPECT_TRUE(found_coev_env)
        << "expected the fetched CoEV's environment among unmatched_environments";
}

TEST_F(LocalCorimVerifierCoevTest, MissingCoevOnNonSynthesizedLocatorIsNotAnError) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw_json), Error::Ok);

    char empty[PATH_MAX];
    ASSERT_NE(::realpath("testdata/sample_rims/corim/empty.cbor", empty), nullptr);

    CorimStore store = make_store();
    ASSERT_EQ(store.add_url_rewrite(
                  "https://rim.attestation.nvidia.com/v1/rim/"
                  "GR100_081D_9900230000",
                  server_url() + "rim-service-real-rim-no-coev"),
              Error::Ok);
    ASSERT_EQ(store.add_url_rewrite(
                  "https://rim.attestation.nvidia.com/v1/rim/"
                  "NV_GPU_DRIVER_GR100_620.54",
                  "file://" + std::string(empty)),
              Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_FALSE(item.stage_error.has_error()) << item.stage_error.message;
    ASSERT_EQ(item.corims.size(), 2u);
    EXPECT_TRUE(item.corims[0].fetched);
    EXPECT_TRUE(item.corims[1].fetched);
}

TEST_F(LocalCorimVerifierCoevTest, FspResponderSynthesizesLocatorAndConvertsFetchedCoev) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellFspCmwPath, cmw_json), Error::Ok);

    CorimStore store = make_store();
    ASSERT_EQ(
        store.add_url_rewrite(
            "https://rim.attestation.nvidia.com/v1/rim/"
            "NV_GPU_VBIOS_GB100_065C_0100000001",
            server_url() + "rim-service-with-blackwell-fsp-coev"),
        Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);
    verifier.set_verify_coev_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_TRUE(item.evidence.signature_verified);
    EXPECT_FALSE(item.stage_error.has_error()) << item.stage_error.message;
    ASSERT_EQ(item.corims.size(), 1U);
    EXPECT_TRUE(item.corims[0].fetched);
    EXPECT_TRUE(item.match.diagnostics.empty());
    EXPECT_TRUE(item.match.unmatched_environments.empty());

    ASSERT_FALSE(item.match.outcomes.empty());
    std::size_t reachable_count = 0;
    for (const auto &outcome : item.match.outcomes) {
        if (outcome.reachable_from_root) {
            ++reachable_count;
            EXPECT_TRUE(outcome.matched())
                << "unexpected mismatch for a reachable environment";
        }
    }
    EXPECT_GT(reachable_count, 0U);
}

TEST_F(LocalCorimVerifierCoevTest, FetchedCoevProfilePopulatesEvidenceProfile) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellFspCmwPath, cmw_json), Error::Ok);

    CorimStore store = make_store();
    ASSERT_EQ(
        store.add_url_rewrite(
            "https://rim.attestation.nvidia.com/v1/rim/"
            "NV_GPU_VBIOS_GB100_065C_0100000001",
            server_url() + "rim-service-with-blackwell-fsp-coev-with-profile"),
        Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);
    verifier.set_verify_coev_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_FALSE(item.stage_error.has_error()) << item.stage_error.message;

    // The evidence itself carries no SPDM ToC (that's the whole point of the
    // FSP WAR): the only source of a profile here is the CoEV fetched from
    // the RIM service.
    ASSERT_TRUE(item.evidence_profile != nullptr)
        << "expected the fetched CoEV's profile to populate evidence_profile";
    EXPECT_EQ(item.evidence_profile->kind, ProfileKind::Uri);
    EXPECT_EQ(item.evidence_profile->value,
              "tag:nvidia.com,2026:evidence/profiles/spdm/gpu/blackwell-fsp/1.0.0");
}

TEST_F(LocalCorimVerifierCoevTest, VerifiesFetchedCoevSignatureEndToEnd) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellFspCmwPath, cmw_json), Error::Ok);

    std::string test_root_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/cose_signing_root.crt",
                                test_root_pem),
              Error::Ok);

    CorimStore store = make_store();
    ASSERT_EQ(
        store.add_url_rewrite(
            "https://rim.attestation.nvidia.com/v1/rim/"
            "NV_GPU_VBIOS_GB100_065C_0100000001",
            server_url() + "rim-service-with-blackwell-fsp-signed-coev"),
        Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);
    verifier.set_rim_signing_root_for_testing(test_root_pem);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_FALSE(item.stage_error.has_error()) << item.stage_error.message;
    ASSERT_EQ(item.corims.size(), 1U);
    EXPECT_TRUE(item.corims[0].fetched);
    EXPECT_TRUE(item.corims[0].coev_signature_verified);
    ASSERT_NE(item.corims[0].coev_cert_chain, nullptr);
    EXPECT_FALSE(item.corims[0].coev_cert_chain->empty());
    EXPECT_TRUE(item.match.diagnostics.empty());

    ASSERT_FALSE(item.match.outcomes.empty());
    std::size_t reachable_count = 0;
    for (const auto &outcome : item.match.outcomes) {
        if (outcome.reachable_from_root) {
            ++reachable_count;
            EXPECT_TRUE(outcome.matched())
                << "unexpected mismatch for a reachable environment";
        }
    }
    EXPECT_GT(reachable_count, 0U);
}

// Without a backup CoEV, a synthesized locator whose RIM has no CoEV is
// fatal -- there's no other way to interpret the evidence for it.
TEST_F(LocalCorimVerifierCoevTest, MissingCoevOnSynthesizedLocatorIsFatalWithoutBackup) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellFspCmwPath, cmw_json), Error::Ok);

    CorimStore store = make_store();
    ASSERT_EQ(
        store.add_url_rewrite(
            "https://rim.attestation.nvidia.com/v1/rim/"
            "NV_GPU_VBIOS_GB100_065C_0100000001",
            server_url() + "rim-service-blackwell-fsp-no-coev"),
        Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_EQ(item.stage_error.message, "one or more RIMs failed to fetch or parse");
    EXPECT_EQ(item.stage_error.code, Error::RimInvalidSchema);
    ASSERT_EQ(item.corims.size(), 1U);
    EXPECT_TRUE(item.corims[0].fetched);
}

TEST_F(LocalCorimVerifierCoevTest, RejectsTamperedCoevSignatureEndToEnd) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellFspCmwPath, cmw_json), Error::Ok);

    std::string test_root_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/cose_signing_root.crt",
                                test_root_pem),
              Error::Ok);

    CorimStore store = make_store();
    ASSERT_EQ(
        store.add_url_rewrite(
            "https://rim.attestation.nvidia.com/v1/rim/"
            "NV_GPU_VBIOS_GB100_065C_0100000001",
            server_url() + "rim-service-with-blackwell-fsp-signed-coev-bad-sig"),
        Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);
    verifier.set_rim_signing_root_for_testing(test_root_pem);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_EQ(item.stage_error.message, "one or more RIMs failed to fetch or parse");
    // A tampered signature must report as a signature failure, not as a schema
    // failure -- the payload parsed fine.
    EXPECT_EQ(item.stage_error.code, Error::CoseInvalidSignature);
    ASSERT_EQ(item.corims.size(), 1U);
    EXPECT_EQ(item.corims[0].error.code, Error::CoseInvalidSignature);
    EXPECT_TRUE(item.corims[0].fetched);
    EXPECT_FALSE(item.corims[0].coev_signature_verified);
    EXPECT_EQ(item.corims[0].coev_cert_chain, nullptr);
}

TEST_F(LocalCorimVerifierCoevTest, RejectsUnparseableCorim) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellFspCmwPath, cmw_json), Error::Ok);

    CorimStore store = make_store();
    ASSERT_EQ(
        store.add_url_rewrite(
            "https://rim.attestation.nvidia.com/v1/rim/"
            "NV_GPU_VBIOS_GB100_065C_0100000001",
            server_url() + "rim-service-blackwell-fsp-garbage-corim"),
        Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    EXPECT_EQ(result.items[0].stage_error.message, "one or more RIMs failed to fetch or parse");
    EXPECT_EQ(result.items[0].stage_error.code, Error::RimInvalidSchema);
}

TEST_F(LocalCorimVerifierCoevTest, RejectsUnparseableSpdmTocCoev) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellFspCmwPath, cmw_json), Error::Ok);

    CorimStore store = make_store();
    ASSERT_EQ(
        store.add_url_rewrite(
            "https://rim.attestation.nvidia.com/v1/rim/"
            "NV_GPU_VBIOS_GB100_065C_0100000001",
            server_url() + "rim-service-blackwell-fsp-garbage-spdmtoc-coev"),
        Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);
    verifier.set_verify_coev_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    EXPECT_EQ(result.items[0].stage_error.message, "one or more RIMs failed to fetch or parse");
    EXPECT_EQ(result.items[0].stage_error.code, Error::RimInvalidSchema);
}

TEST_F(LocalCorimVerifierCoevTest, RejectsUnparseableConciseEvidenceCoev) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellFspCmwPath, cmw_json), Error::Ok);

    CorimStore store = make_store();
    ASSERT_EQ(
        store.add_url_rewrite(
            "https://rim.attestation.nvidia.com/v1/rim/"
            "NV_GPU_VBIOS_GB100_065C_0100000001",
            server_url() + "rim-service-blackwell-fsp-garbage-concise-evidence-coev"),
        Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);
    verifier.set_verify_coev_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    EXPECT_EQ(result.items[0].stage_error.message, "one or more RIMs failed to fetch or parse");
    EXPECT_EQ(result.items[0].stage_error.code, Error::RimInvalidSchema);
}

// A caller-supplied backup CoEV should rescue the appraisal when the
// synthesized locator's RIM has no CoEV, not fail it.
TEST_F(LocalCorimVerifierCoevTest, BackupCoevRescuesSynthesizedLocatorMissingCoev) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kBlackwellFspCmwPath, cmw_json), Error::Ok);

    std::vector<uint8_t> backup_coev_bytes;
    ASSERT_EQ(readFileIntoBytes("testdata/sample_rims/coev/blackwell_fsp_real.cbor",
                                backup_coev_bytes),
              Error::Ok);

    CorimStore store = make_store();
    ASSERT_EQ(
        store.add_url_rewrite(
            "https://rim.attestation.nvidia.com/v1/rim/"
            "NV_GPU_VBIOS_GB100_065C_0100000001",
            server_url() + "rim-service-blackwell-fsp-no-coev"),
        Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);
    ASSERT_EQ(verifier.set_backup_spdm_coev(backup_coev_bytes.data(),
                                            backup_coev_bytes.size()),
              Error::Ok);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_TRUE(item.evidence.signature_verified);
    EXPECT_FALSE(item.stage_error.has_error()) << item.stage_error.message;
    ASSERT_EQ(item.corims.size(), 1U);
    EXPECT_TRUE(item.corims[0].fetched);
    EXPECT_TRUE(item.match.diagnostics.empty());
    EXPECT_TRUE(item.match.unmatched_environments.empty());

    ASSERT_FALSE(item.match.outcomes.empty());
    std::size_t reachable_count = 0;
    for (const auto &outcome : item.match.outcomes) {
        if (outcome.reachable_from_root) {
            ++reachable_count;
            EXPECT_TRUE(outcome.matched())
                << "unexpected mismatch for a reachable environment";
        }
    }
    EXPECT_GT(reachable_count, 0U);
}

// Rewrites the FSP CMW fixture's hints payload to a caller-supplied JSON
// value (as raw text, so callers can also produce non-JSON payloads).
std::string blackwell_fsp_cmw_with_hints_payload(const std::string &hints_json_text) {
    std::string cmw_json;
    if (readFileIntoString(kBlackwellFspCmwPath, cmw_json) != Error::Ok) {
        ADD_FAILURE() << "failed to read " << kBlackwellFspCmwPath;
        return {};
    }
    nlohmann::json root = nlohmann::json::parse(cmw_json);
    std::string encoded;
    encode_base64url(
        std::vector<uint8_t>(hints_json_text.begin(), hints_json_text.end()),
        encoded);
    root["gpu_0"]["hints"][1] = encoded;
    return root.dump();
}

TEST_F(LocalCorimVerifierCoevTest, MalformedHintsNotJsonIsFatal) {
    std::string cmw_json = blackwell_fsp_cmw_with_hints_payload("not json");

    LocalCorimVerifier verifier(make_store());
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    EXPECT_EQ(result.items[0].stage_error.message, "malformed hints record");
}

TEST_F(LocalCorimVerifierCoevTest, MalformedHintsNotObjectIsFatal) {
    std::string cmw_json = blackwell_fsp_cmw_with_hints_payload("[1, 2, 3]");

    LocalCorimVerifier verifier(make_store());
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    EXPECT_EQ(result.items[0].stage_error.message, "malformed hints record");
}

TEST_F(LocalCorimVerifierCoevTest, MalformedHintsFwversionNotStringIsFatal) {
    std::string cmw_json =
        blackwell_fsp_cmw_with_hints_payload(R"({"fwversion": 123})");

    LocalCorimVerifier verifier(make_store());
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    EXPECT_EQ(result.items[0].stage_error.message, "malformed hints record");
}

// No fwversion key means no locator to synthesize; the appraisal must name the
// input that was unusable rather than a generic "not found".
TEST_F(LocalCorimVerifierCoevTest, MissingFwVersionHintNamesTheUnusableInput) {
    std::string cmw_json = blackwell_fsp_cmw_with_hints_payload(R"({})");

    LocalCorimVerifier verifier(make_store());
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    EXPECT_EQ(item.stage_error.code, Error::EvidenceMalformed);
    EXPECT_EQ(item.stage_error.message,
              "could not build a RIM locator for FSP responder: "
              "firmware-version hint does not match expected format");
    ASSERT_EQ(item.corims.size(), 1u);
    EXPECT_EQ(item.corims[0].error.code, Error::EvidenceMalformed);
    EXPECT_TRUE(item.corims[0].locator.empty());
}

TEST(LocalCorimVerifierTest, RimFetchFailureRecordedPerCorimAttemptAll) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw_json), Error::Ok);

    char resolved[PATH_MAX];
    ASSERT_NE(::realpath("testdata/sample_rims/corim/empty.cbor", resolved),
              nullptr);
    const std::string rim_fixture(resolved);

    CorimStore store;
    // First locator (VBIOS) -> nonexistent file: fetch fails.
    ASSERT_EQ(store.add_url_rewrite(
                  "https://rim.attestation.nvidia.com/v1/rim/"
                  "GR100_081D_9900230000",
                  "file:///nonexistent/missing.cbor"),
              Error::Ok);
    // Second locator (DRIVER) -> real fixture: fetch ok.
    ASSERT_EQ(store.add_url_rewrite(
                  "https://rim.attestation.nvidia.com/v1/rim/"
                  "NV_GPU_DRIVER_GR100_620.54",
                  "file://" + rim_fixture),
              Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    ASSERT_EQ(item.corims.size(), 2u);
    EXPECT_FALSE(item.corims[0].fetched);
    EXPECT_TRUE(item.corims[1].fetched);
    // The fetch failed because the RIM is absent, so the store's own reason
    // must survive rather than a generic connection error -- and the later
    // successful fetch must not overwrite it.
    EXPECT_EQ(item.stage_error.code, Error::RimNotFound);
    EXPECT_EQ(item.corims[0].error.code, Error::RimNotFound);
}

TEST(LocalCorimVerifierTest, FailedCorimReportsWhichLocatorAndWhy) {
    // Two locators, one unparseable: the failure must name the one that broke.
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw_json), Error::Ok);

    char empty[PATH_MAX];
    char malformed[PATH_MAX];
    ASSERT_NE(::realpath("testdata/sample_rims/corim/empty.cbor", empty), nullptr);
    ASSERT_NE(::realpath("testdata/sample_rims/corim/reject_too_many_tags.cbor",
                        malformed),
              nullptr);

    CorimStore store;
    // First locator (VBIOS) -> valid, empty CoRIM: parses fine.
    ASSERT_EQ(store.add_url_rewrite(
                  "https://rim.attestation.nvidia.com/v1/rim/"
                  "GR100_081D_9900230000",
                  "file://" + std::string(empty)),
              Error::Ok);
    // Second locator (DRIVER) -> a CoRIM the wrapper layer rejects.
    ASSERT_EQ(store.add_url_rewrite(
                  "https://rim.attestation.nvidia.com/v1/rim/"
                  "NV_GPU_DRIVER_GR100_620.54",
                  "file://" + std::string(malformed)),
              Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    const auto &item = result.items[0];
    ASSERT_EQ(item.corims.size(), 2U);
    EXPECT_TRUE(item.corims[0].parsed);
    EXPECT_FALSE(item.corims[0].error.has_error());
    EXPECT_FALSE(item.corims[1].parsed);
    EXPECT_EQ(item.corims[1].error.code, Error::RimInvalidSchema);
}

TEST(LocalCorimVerifierTest, NoVerifyRimSignaturesParsesSignedCorim) {
    // When set_verify_rim_signature(false), a COSE_Sign1-wrapped CoRIM must be
    // unwrapped and parsed without attempting crypto verification.
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw_json), Error::Ok);

    char resolved[PATH_MAX];
    ASSERT_NE(::realpath("testdata/sample_rims/corim_signed/signed_full.cbor", resolved),
              nullptr)
        << "signed_full.cbor missing — run `make prepare-test-data`";
    const std::string signed_rim_fixture(resolved);

    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(
                  "https://rim.attestation.nvidia.com/v1/rim/"
                  "GR100_081D_9900230000",
                  "file://" + signed_rim_fixture),
              Error::Ok);
    ASSERT_EQ(store.add_url_rewrite(
                  "https://rim.attestation.nvidia.com/v1/rim/"
                  "NV_GPU_DRIVER_GR100_620.54",
                  "file://" + signed_rim_fixture),
              Error::Ok);

    LocalCorimVerifier verifier(std::move(store));
    verifier.set_verify_revocation(false);
    verifier.set_verify_rim_signature(false);

    CorimAttestationResult result;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result),
              Error::Ok);
    ASSERT_FALSE(result.items.empty());
    for (const auto &item : result.items) {
        EXPECT_FALSE(item.stage_error.has_error()) << item.label << ": " << item.stage_error.message;
        for (const auto &corim : item.corims) {
            EXPECT_TRUE(corim.fetched) << item.label;
            EXPECT_TRUE(corim.parsed) << item.label;
            EXPECT_FALSE(corim.signature_verified) << item.label;
        }
    }
}

// ars.digest-algos in the CMW appraisal-settings selects the digests the
// client wants; the verifier's configured set is only the fallback.
namespace {
std::string cmw_with_appraisal_settings(const std::string &cmw_json,
                                        const std::string &settings_json) {
    nlohmann::json root = nlohmann::json::parse(cmw_json);
    std::string encoded;
    EXPECT_EQ(encode_base64url(
                  std::vector<uint8_t>(settings_json.begin(), settings_json.end()),
                  encoded),
              Error::Ok);
    root["appraisal-settings"] = nlohmann::json::array({"application/json", encoded});
    return root.dump();
}

std::vector<std::string> digest_algs(const CorimAttestationResult &result) {
    std::vector<std::string> names;
    names.reserve(result.input_digests.size());
    for (const auto &digest : result.input_digests) {
        names.emplace_back(to_algorithm_name(digest.alg));
    }
    return names;
}

CorimAttestationResult verify_with_settings(const std::string &settings_json) {
    std::string cmw_json;
    EXPECT_EQ(readFileIntoString(kBlackwellCmwPath, cmw_json), Error::Ok);
    const std::string input =
        settings_json.empty() ? cmw_json
                              : cmw_with_appraisal_settings(cmw_json, settings_json);
    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);
    CorimAttestationResult result;
    EXPECT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(input.data()), input.size(),
                  CmwFormat::kJson, result),
              Error::Ok);
    return result;
}
} // namespace

TEST(LocalCorimVerifierTest, DigestAlgosFromAppraisalSettingsByNiId) {
    auto result = verify_with_settings(R"({"ars":{"digest-algos":[7,8]}})");
    EXPECT_EQ(digest_algs(result),
              (std::vector<std::string>{"sha-384", "sha-512"}));
}

TEST(LocalCorimVerifierTest, DigestAlgosFromAppraisalSettingsByName) {
    auto result = verify_with_settings(R"({"ars":{"digest-algos":["sha-512"]}})");
    EXPECT_EQ(digest_algs(result), (std::vector<std::string>{"sha-512"}));
}

// Unsupported entries are dropped, not fatal; duplicates collapse.
TEST(LocalCorimVerifierTest, DigestAlgosSkipsUnsupportedAndDuplicates) {
    auto result = verify_with_settings(
        R"({"ars":{"digest-algos":[9,"sha-1",7,7,"sha-384"]}})");
    EXPECT_EQ(digest_algs(result), (std::vector<std::string>{"sha-384"}));
}

// Out-of-range integers must not wrap onto a valid registry ID: 2^32 + 1
// narrows to 1 (sha-256) if the value is cast without a range check.
TEST(LocalCorimVerifierTest, DigestAlgosRejectsOutOfRangeIds) {
    auto result = verify_with_settings(
        R"({"ars":{"digest-algos":[4294967297]}})");
    EXPECT_TRUE(result.input_digests.empty());
}

// Absent settings, or settings without the key, fall back to the configured
// default (sha-256).
TEST(LocalCorimVerifierTest, DigestAlgosFallsBackWhenAbsent) {
    EXPECT_EQ(digest_algs(verify_with_settings("")),
              (std::vector<std::string>{"sha-256"}));
    EXPECT_EQ(digest_algs(verify_with_settings(R"({"ars":{}})")),
              (std::vector<std::string>{"sha-256"}));
}

// An explicit empty list means the client wants no input digests.
TEST(LocalCorimVerifierTest, DigestAlgosEmptyListEmitsNoDigests) {
    EXPECT_TRUE(verify_with_settings(R"({"ars":{"digest-algos":[]}})")
                    .input_digests.empty());
}

// --- CorimStore caching tests ---

// Tracks INvCache call counts and stores values by key for inspection.
class SpyCache : public INvCache {
  public:
    int get_calls = 0;
    int put_calls = 0;

    Error put(const std::string &key, std::shared_ptr<void> value,
              uint64_t /*size_bytes*/) override {
        put_calls++;
        m_data[key] = std::move(value);
        return Error::Ok;
    }

    Error get(const std::string &key,
              std::shared_ptr<void> &out_value) override {
        get_calls++;
        auto it = m_data.find(key);
        if (it == m_data.end()) {
            return Error::CacheObjectNotFound;
        }
        out_value = it->second;
        return Error::Ok;
    }

    void remove(const std::string &key) override { m_data.erase(key); }
    void clear() override { m_data.clear(); }

  private:
    std::unordered_map<std::string, std::shared_ptr<void>> m_data;
};

// Returns absolute file:// URL for a path relative to the test working dir.
std::string abs_file_url(const char *rel) {
    char resolved[PATH_MAX];
    if (::realpath(rel, resolved) == nullptr) {
        return "";
    }
    return "file://" + std::string(resolved);
}

// A small CBOR CoRIM fixture present in the test tree.
const char *kCacheTestFixturePath =
    "testdata/sample_rims/corim/empty.cbor";

// Raw URL that passes the default NVIDIA allowlist prefix check.
const char *kCacheTestRawUrl =
    "https://rim.attestation.nvidia.com/v1/rim/cache_test.corim";

// Cache is off by default: no caching, fetch always goes to source.
TEST(CorimStoreCacheTest, NoCachingByDefault) {
    std::string fixture_url = abs_file_url(kCacheTestFixturePath);
    ASSERT_FALSE(fixture_url.empty()) << "fixture not found";

    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(kCacheTestRawUrl, fixture_url), Error::Ok);

    std::vector<uint8_t> bytes1, bytes2;
    ASSERT_EQ(store.fetch(kCacheTestRawUrl, bytes1), Error::Ok);
    ASSERT_EQ(store.fetch(kCacheTestRawUrl, bytes2), Error::Ok);
    EXPECT_EQ(bytes1, bytes2);
}

// First fetch is a miss (put called); second is a hit (put not called again).
TEST(CorimStoreCacheTest, CacheMissThenHit) {
    std::string fixture_url = abs_file_url(kCacheTestFixturePath);
    ASSERT_FALSE(fixture_url.empty()) << "fixture not found";

    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(kCacheTestRawUrl, fixture_url), Error::Ok);

    auto spy = std::make_shared<SpyCache>();
    store.set_cache(spy);

    std::vector<uint8_t> bytes1;
    ASSERT_EQ(store.fetch(kCacheTestRawUrl, bytes1), Error::Ok);
    EXPECT_EQ(spy->get_calls, 1);
    EXPECT_EQ(spy->put_calls, 1);
    EXPECT_FALSE(bytes1.empty());

    std::vector<uint8_t> bytes2;
    ASSERT_EQ(store.fetch(kCacheTestRawUrl, bytes2), Error::Ok);
    EXPECT_EQ(spy->get_calls, 2);
    EXPECT_EQ(spy->put_calls, 1);
    EXPECT_EQ(bytes1, bytes2);
}

// Two raw URLs that rewrite to the same effective URL share one cache entry.
TEST(CorimStoreCacheTest, EffectiveUrlIsTheCacheKey) {
    std::string fixture_url = abs_file_url(kCacheTestFixturePath);
    ASSERT_FALSE(fixture_url.empty()) << "fixture not found";

    const char *raw_url_a =
        "https://rim.attestation.nvidia.com/v1/rim/cache_key_a.corim";
    const char *raw_url_b =
        "https://rim.attestation.nvidia.com/v1/rim/cache_key_b.corim";

    CorimStore store;
    ASSERT_EQ(store.add_url_rewrite(raw_url_a, fixture_url), Error::Ok);
    ASSERT_EQ(store.add_url_rewrite(raw_url_b, fixture_url), Error::Ok);

    auto spy = std::make_shared<SpyCache>();
    store.set_cache(spy);

    std::vector<uint8_t> bytes_a, bytes_b;
    ASSERT_EQ(store.fetch(raw_url_a, bytes_a), Error::Ok);
    ASSERT_EQ(store.fetch(raw_url_b, bytes_b), Error::Ok);

    EXPECT_EQ(spy->put_calls, 1);
    EXPECT_EQ(spy->get_calls, 2);
    EXPECT_EQ(bytes_a, bytes_b);
}

TEST(LocalCorimVerifierTest, VerifyCmwProducesUnsignedEarWhenOptionsNull) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw_json), Error::Ok);

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);

    CorimAttestationResult result;
    std::string ear_jwt;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result,
                  /*ear_signing_options=*/nullptr, &ear_jwt),
              Error::Ok);
    ASSERT_FALSE(ear_jwt.empty());
    auto decoded = jwt::decode<jwt::traits::nlohmann_json>(ear_jwt);
    EXPECT_EQ(decoded.get_algorithm(), "none");
}

TEST(LocalCorimVerifierTest, VerifyCmwSignsEarWithProvidedKey) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw_json), Error::Ok);
    std::string private_key_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/ec_p384_private.pem", private_key_pem), Error::Ok);

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);

    DetachedEATOptions options;
    options.m_private_key_pem = private_key_pem;
    options.m_issuer = "test-issuer";

    CorimAttestationResult result;
    std::string ear_jwt;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result, &options, &ear_jwt),
              Error::Ok);
    ASSERT_FALSE(ear_jwt.empty());
    auto decoded = jwt::decode<jwt::traits::nlohmann_json>(ear_jwt);
    EXPECT_EQ(decoded.get_algorithm(), "ES384");
    nlohmann::json payload = nlohmann::json::parse(decoded.get_payload());
    EXPECT_EQ(payload["iss"].get<std::string>(), "test-issuer");
}

TEST(LocalCorimVerifierTest, VerifyCmwOutEarJsonCarriesUnsignedEarWhenSigned) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw_json), Error::Ok);
    std::string private_key_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/ec_p384_private.pem", private_key_pem), Error::Ok);

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);

    DetachedEATOptions options;
    options.m_private_key_pem = private_key_pem;
    options.m_issuer = "test-issuer";

    CorimAttestationResult result;
    std::string ear_jwt;
    std::string ear_json;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result, &options,
                  &ear_jwt, &ear_json),
              Error::Ok);
    ASSERT_FALSE(ear_jwt.empty());
    ASSERT_FALSE(ear_json.empty());

    // out_ear_json is the same claims as plain JSON, no need to decode out_ear_jwt.
    nlohmann::json parsed = nlohmann::json::parse(ear_json, nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(parsed.is_discarded());
    EXPECT_EQ(parsed["iss"].get<std::string>(), "test-issuer");
    EXPECT_TRUE(parsed.contains("submods"));

    auto decoded = jwt::decode<jwt::traits::nlohmann_json>(ear_jwt);
    nlohmann::json jwt_payload = nlohmann::json::parse(decoded.get_payload());
    EXPECT_EQ(parsed, jwt_payload);
}

TEST(LocalCorimVerifierTest, VerifyCmwOmitsIssuerWhenOptionsIssuerNotOverridden) {
    std::string cmw_json;
    ASSERT_EQ(readFileIntoString(kRubinCmwPath, cmw_json), Error::Ok);
    std::string private_key_pem;
    ASSERT_EQ(readFileIntoString("testdata/x509_cert_chain/ec_p384_private.pem", private_key_pem), Error::Ok);

    LocalCorimVerifier verifier(CorimStore{});
    verifier.set_verify_revocation(false);

    DetachedEATOptions options;  // m_issuer left at its DetachedEATOptions default
    options.m_private_key_pem = private_key_pem;

    CorimAttestationResult result;
    std::string ear_jwt;
    ASSERT_EQ(verifier.verify_cmw(
                  reinterpret_cast<const uint8_t *>(cmw_json.data()),
                  cmw_json.size(), CmwFormat::kJson, result, &options, &ear_jwt),
              Error::Ok);
    auto decoded = jwt::decode<jwt::traits::nlohmann_json>(ear_jwt);
    nlohmann::json payload = nlohmann::json::parse(decoded.get_payload());
    EXPECT_FALSE(payload.contains("iss"));
}

} // namespace
} // namespace nvattestation
