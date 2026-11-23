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

// In-process handler tests use a fake nvat C API. The real Rego decision is
// covered separately by RelyingPartyPolicyV2 tests.

#include <cstdlib>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "gtest/gtest.h"

#include "nvat.h"
#include "attest_v2.h"
#include "nvattest_options.h"
#include "logging.h"
#include "fake_nvat_control.h"
#include "mock_cli_logger.h"

using namespace nvattest;

namespace {
const char* const kCmwPath = "/tmp/nvattest_attest_v2_mock.cmw.json";
const char* const kPolicyPath = "/tmp/nvattest_attest_v2_mock.rego";
const char* const kEatPath = "/tmp/nvattest_attest_v2_mock.eat.cbor";
const char* const kDeviceRoot1Path = "/tmp/nvattest_attest_v2_mock_device_root_1.pem";
const char* const kDeviceRoot2Path = "/tmp/nvattest_attest_v2_mock_device_root_2.pem";
const char* const kRimRoot1Path = "/tmp/nvattest_attest_v2_mock_rim_root_1.pem";
const char* const kRimRoot2Path = "/tmp/nvattest_attest_v2_mock_rim_root_2.pem";

class ScopedServiceUrlEnv {
  public:
    explicit ScopedServiceUrlEnv(const char* name) : name_(name) {
        if (const char* value = std::getenv(name)) {
            original_ = value;
            was_set_ = true;
        }
        unsetenv(name_);
    }

    ~ScopedServiceUrlEnv() {
        if (was_set_) {
            setenv(name_, original_.c_str(), 1);
        } else {
            unsetenv(name_);
        }
    }

  private:
    const char* name_;
    std::string original_;
    bool was_set_ = false;
};

using UrlRewrites = std::vector<std::pair<std::string, std::string>>;

} // namespace

class AttestV2Mock : public ::testing::Test {
  protected:
    AttestV2Options options;
    CommonOptions common;
    ScopedServiceUrlEnv rim_env{"NVAT_RIM_SERVICE_BASE_URL"};
    ScopedServiceUrlEnv ocsp_env{"NVAT_OCSP_BASE_URL"};
    std::streambuf* m_old_cout = nullptr;
    std::ostringstream m_captured_cout;

    void SetUp() override {
        fake_nvat_reset();
        // The file source keeps the fakes out of the collection path; the bytes
        // are never parsed, since verify_cmw is faked.
        std::ofstream(kCmwPath) << "{}";
        options.evidence_source = "file";
        options.evidence_file = kCmwPath;
        options.ocsp_cert_id_hash = "sha-256";
        options.relying_party_policy = "builtin:cc-bounce-buffer";
        g_fake_nvat.policy_apply_ear_rc = NVAT_RC_RP_POLICY_MISMATCH;
        common.format = "json";
        m_old_cout = std::cout.rdbuf(m_captured_cout.rdbuf());
    }

    void TearDown() override {
        std::cout.rdbuf(m_old_cout);
        std::remove(kCmwPath);
        std::remove(kPolicyPath);
        std::remove(kDeviceRoot1Path);
        std::remove(kDeviceRoot2Path);
        std::remove(kRimRoot1Path);
        std::remove(kRimRoot2Path);
    }

    void write_policy(const std::string& policy) {
        std::ofstream(kPolicyPath) << policy;
        options.relying_party_policy = kPolicyPath;
    }

    int run() {
        return handle_attest_v2_subcommand(shared_mock_logger(), options, common);
    }
};

TEST_F(AttestV2Mock, ServiceUrlEnvRoutesNvidiaHttpAia) {
    ASSERT_EQ(setenv("NVAT_RIM_SERVICE_BASE_URL",
                     "https://rim-internal.attestation.nvidia.com/internal/", 1), 0);
    ASSERT_EQ(setenv("NVAT_OCSP_BASE_URL",
                     "https://ocsp.ndis-stg.nvidia.com/", 1), 0);

    EXPECT_EQ(run(), 1);
    EXPECT_EQ(g_fake_nvat.corim_url_rewrites,
              (UrlRewrites{{"https://rim.attestation.nvidia.com/v1/rim/",
                            "https://rim-internal.attestation.nvidia.com/internal/v1/rim/"}}));
    EXPECT_EQ(g_fake_nvat.ocsp_aia_url_rewrites,
              (UrlRewrites{{"http://ocsp.ndis.nvidia.com",
                            "https://ocsp.ndis-stg.nvidia.com"}}));
}

TEST_F(AttestV2Mock, ServiceUrlExplicitRewriteWins) {
    ASSERT_EQ(setenv("NVAT_RIM_SERVICE_BASE_URL", "https://rim-env.example", 1), 0);
    ASSERT_EQ(setenv("NVAT_OCSP_BASE_URL", "https://ocsp-env.example", 1), 0);
    options.rim_url_rewrites = {
        "https://rim.attestation.nvidia.com/v1/rim/", "https://rim-cli.example/v1/rim/",
        "https://other.example/rim/", "file:///tmp/rims/"};
    options.ocsp_url_rewrites = {
        "http://ocsp.ndis.nvidia.com", "https://ocsp-cli.example",
        "http://other.example", "https://other-ocsp.example"};

    EXPECT_EQ(run(), 1);
    EXPECT_EQ(g_fake_nvat.corim_url_rewrites,
              (UrlRewrites{
                  {"https://rim.attestation.nvidia.com/v1/rim/",
                   "https://rim-cli.example/v1/rim/"},
                  {"https://other.example/rim/", "file:///tmp/rims/"},
                  {"https://rim.attestation.nvidia.com/v1/rim/",
                   "https://rim-env.example/v1/rim/"}}));
    EXPECT_EQ(g_fake_nvat.ocsp_aia_url_rewrites,
              (UrlRewrites{
                  {"http://ocsp.ndis.nvidia.com", "https://ocsp-cli.example"},
                  {"http://other.example", "https://other-ocsp.example"},
                  {"http://ocsp.ndis.nvidia.com", "https://ocsp-env.example"}}));
}

TEST_F(AttestV2Mock, ServiceUrlUnsetLeavesOriginal) {
    EXPECT_EQ(run(), 1);
    EXPECT_TRUE(g_fake_nvat.corim_url_rewrites.empty());
    EXPECT_TRUE(g_fake_nvat.ocsp_aia_url_rewrites.empty());

    ASSERT_EQ(setenv("NVAT_RIM_SERVICE_BASE_URL", "", 1), 0);
    ASSERT_EQ(setenv("NVAT_OCSP_BASE_URL", "", 1), 0);
    fake_nvat_reset();
    g_fake_nvat.policy_apply_ear_rc = NVAT_RC_RP_POLICY_MISMATCH;
    EXPECT_EQ(run(), 1);
    EXPECT_TRUE(g_fake_nvat.corim_url_rewrites.empty());
    EXPECT_TRUE(g_fake_nvat.ocsp_aia_url_rewrites.empty());
}

TEST_F(AttestV2Mock, PolicyCanAcceptContraindicatedEar) {
    write_policy("package policy\ndefault nv_match := true\n");
    g_fake_nvat.policy_apply_ear_rc = NVAT_RC_OK;

    EXPECT_EQ(run(), 0);
    EXPECT_EQ(g_fake_nvat.policy_apply_ear_input,
              g_fake_nvat.verify_cmw_result_json);
}

TEST_F(AttestV2Mock, PolicyCanRejectAffirmingEar) {
    g_fake_nvat.verify_cmw_result_json =
        R"({"submods":{"gpu_0":{"ear_status":"affirming"}}})";
    write_policy("package policy\ndefault nv_match := false\n");
    g_fake_nvat.policy_apply_ear_rc = NVAT_RC_RP_POLICY_MISMATCH;

    EXPECT_EQ(run(), 1);
    EXPECT_NE(m_captured_cout.str().find("\"submods\""), std::string::npos);
}

TEST_F(AttestV2Mock, PolicyCreationFailureIsVerifierError) {
    write_policy("not valid Rego");
    g_fake_nvat.policy_create_rc = NVAT_RC_POLICY_EVALUATION_ERROR;

    EXPECT_EQ(run(), 2);
    EXPECT_NE(m_captured_cout.str().find("\"submods\""), std::string::npos);
}

TEST_F(AttestV2Mock, PolicyEvaluationFailureIsVerifierError) {
    write_policy("package policy\ndefault nv_match := true\n");
    g_fake_nvat.policy_apply_ear_rc = NVAT_RC_POLICY_EVALUATION_ERROR;

    EXPECT_EQ(run(), 2);
    EXPECT_NE(m_captured_cout.str().find("\"submods\""), std::string::npos);
}


// Text-format summary should surface mismatched RIM/evidence environments.
// SPDLOG_CRITICAL writes straight to the console sink (bypasses std::cout's
// rdbuf), so this only asserts the exit code; run with --gtest_filter and
// look at the printed "Mismatched Environments" lines directly.
TEST_F(AttestV2Mock, TextFormatPrintsMismatchedEnvironments) {
    common.format = "text";
    g_fake_nvat.verify_cmw_result_json =
        R"({"eat_profile":"tag:nvidia.com,2026:ear/profiles/composite/generic/1.0.0",)"
        R"("eat_nonce":"deadbeef",)"
        R"("ear_status":"contraindicated",)"
        R"("submods":{"gpu_0":{)"
        R"("eat_profile":"tag:nvidia.com,2026-05:ear/profiles/gpu/1.0.0",)"
        R"("ear_status":"contraindicated",)"
        R"("ear_verifier_claims":{"ear_nvidia_evidence_rim_cmp":{)"
        R"("mismatched_env":[)"
        R"({"class":{"class_id":"1.2.3.4","vendor":"NVIDIA","model":"Driver"},"instance":"ueid:AAAA"},)"
        R"({"class":{"class_id":"1.2.3.5","vendor":"NVIDIA","model":"VBIOS"}})"
        R"(],)"
        R"("unmatched_env":[)"
        R"({"class":{"class_id":"1.2.3.6","vendor":"NVIDIA","model":"Unknown"}})"
        R"(])"
        R"(}}}}})";
    EXPECT_EQ(run(), 1);
}

TEST_F(AttestV2Mock, TextFormatPrintsEveryDiagnosticEnvironment) {
    common.format = "text";
    g_fake_nvat.verify_cmw_result_json =
        R"({"ear_status":"contraindicated","submods":{"gpu_0":{)"
        R"("ear_status":"contraindicated","ear_nvidia_error_details":[{)"
        R"("code":1003,"message":"multiple root environments",)"
        R"("related_envs":[{"class":{"model":"RootA","layer":1,"index":3}},)"
        R"({"class":{"model":"RootB","index":2}}]}]}}})";

    EXPECT_EQ(run(), 1);
    const auto text = m_captured_cout.str();
    EXPECT_NE(text.find("Related Environments:\n          - RootA, layer=1, index=3\n"),
              std::string::npos);
    EXPECT_NE(text.find("          - RootB, index=2\n"),
              std::string::npos);
}

// Text-format summary should surface evidence signature/cert-chain status
// and the RIM locators consulted (fetched/signature/cert-chain per locator).
TEST_F(AttestV2Mock, TextFormatPrintsEvidenceAndRimDetails) {
    common.format = "text";
    g_fake_nvat.policy_apply_ear_rc = NVAT_RC_OK;
    g_fake_nvat.verify_cmw_result_json =
        R"({"ear_status":"affirming","submods":{"gpu_0":{)"
        R"("ear_status":"affirming",)"
        R"("eat_nonce":"deadbeef",)"
        R"("ear_verifier_claims":{)"
        R"("ear_nvidia_evidence":{)"
        R"("signature_verified":true,"parsed":true,"nonce_match":true,)"
        R"("cert_chain":[)"
        R"({"cert_check_status":"valid","expiration_date":"2027-01-01T00:00:00Z",)"
        R"("ocsp_crl_status":"good"},)"
        R"({"cert_check_status":"revoked","expiration_date":"2030-01-01T00:00:00Z",)"
        R"("ocsp_crl_status":"revoked","revocation_reason":"keyCompromise"})"
        R"(])"
        R"(},)"
        R"("ear_nvidia_rims":[)"
        R"({"fetched":true,"locator":"https://rim.attestation.nvidia.com/v2/corim/abc123",)"
        R"("signature_verified":true,"cert_chain":[)"
        R"({"cert_check_status":"valid","expiration_date":"2028-06-01T00:00:00Z"})"
        R"(]},)"
        R"({"fetched":false,"locator":"https://rim.attestation.nvidia.com/v2/corim/unreachable"})"
        R"(])"
        R"(}}}})";
    EXPECT_EQ(run(), 0);
}

// Environment entries without a "class" object fall back to "[no class]";
// the optional "group" display string is a separate field from "instance".
TEST_F(AttestV2Mock, TextFormatHandlesEnvironmentHeaderAndGroupFields) {
    common.format = "text";
    g_fake_nvat.verify_cmw_result_json =
        R"({"submods":{"gpu_0":{)"
        R"("ear_status":"contraindicated",)"
        R"("ear_verifier_claims":{"ear_nvidia_evidence_rim_cmp":{)"
        R"("mismatched_env":[)"
        R"({"instance":"ueid:CCCC"},)"
        R"({"class":{"vendor":"NVIDIA"},"group":"grp1"})"
        R"(])"
        R"(}}}}})";
    EXPECT_EQ(run(), 1);
}

// A non-object "evidence" is skipped; empty cert_chain/rims arrays are
// skipped; individual non-object entries within them print as "[invalid]".
TEST_F(AttestV2Mock, TextFormatHandlesEvidenceAndCollectionEdgeCases) {
    common.format = "text";
    g_fake_nvat.policy_apply_ear_rc = NVAT_RC_OK;
    g_fake_nvat.verify_cmw_result_json =
        R"({"ear_status":"affirming","submods":{)"
        R"("gpu_0":{"ear_status":"affirming","ear_verifier_claims":{)"
        R"("ear_nvidia_evidence":"not-an-object")"
        R"(}},)"
        R"("gpu_1":{"ear_status":"affirming","ear_verifier_claims":{)"
        R"("ear_nvidia_evidence":{"cert_chain":[]},)"
        R"("ear_nvidia_rims":[])"
        R"(}},)"
        R"("gpu_2":{"ear_status":"affirming","ear_verifier_claims":{)"
        R"("ear_nvidia_evidence":{"cert_chain":[123]},)"
        R"("ear_nvidia_rims":[42])"
        R"(}})"
        R"(}})";
    EXPECT_EQ(run(), 0);
}

// No "submods" key at all renders "[none]" instead of a submod list.
TEST_F(AttestV2Mock, TextFormatHandlesMissingSubmods) {
    common.format = "text";
    g_fake_nvat.verify_cmw_result_json = R"({"eat_profile":"x"})";
    EXPECT_EQ(run(), 1);
}

// A non-object submod value prints "[invalid submod format]" and is skipped;
// "ear_nvidia_purpose" and non-string attester claims render too.
TEST_F(AttestV2Mock, TextFormatHandlesSubmodAndClaimEdgeCases) {
    common.format = "text";
    g_fake_nvat.verify_cmw_result_json =
        R"({"submods":{)"
        R"("gpu_0":"not-an-object",)"
        R"("gpu_1":{"ear_status":"affirming","ear_nvidia_purpose":"attestation",)"
        R"("ear_attester_claims":{"measurements":[1,2,3]})"
        R"(}}})";
    EXPECT_EQ(run(), 1);
}

// A verifier that reports success but yields nothing usable is undetermined,
// not a failed device.
TEST_F(AttestV2Mock, EmptyResultIsVerifierError) {
    g_fake_nvat.verify_cmw_result_json = "";
    EXPECT_EQ(run(), 2);
}

TEST_F(AttestV2Mock, UnparseableResultIsVerifierError) {
    g_fake_nvat.verify_cmw_result_json = "not json";
    EXPECT_EQ(run(), 2);
}

TEST_F(AttestV2Mock, VerifierFailureIsVerifierError) {
    g_fake_nvat.verify_cmw_rc = NVAT_RC_BAD_ARGUMENT;
    EXPECT_EQ(run(), 2);
}

TEST_F(AttestV2Mock, RegistersEachAdditionalRootInItsOwnStore) {
    std::ofstream(kDeviceRoot1Path) << "device root one";
    std::ofstream(kDeviceRoot2Path) << "device root two";
    std::ofstream(kRimRoot1Path) << "RIM root one";
    std::ofstream(kRimRoot2Path) << "RIM root two";
    options.device_identity_root_files = {kDeviceRoot1Path, kDeviceRoot2Path};
    options.rim_signing_root_files = {kRimRoot1Path, kRimRoot2Path};

    EXPECT_EQ(run(), 1);
    EXPECT_EQ(g_fake_nvat.device_identity_root_pems,
              (std::vector<std::string>{"device root one", "device root two"}));
    EXPECT_EQ(g_fake_nvat.rim_signing_root_pems,
              (std::vector<std::string>{"RIM root one", "RIM root two"}));
    EXPECT_EQ(g_fake_nvat.verify_cmw_calls, 1);
}

TEST_F(AttestV2Mock, ParsesRepeatedRootCaFileOptions) {
    std::ofstream(kDeviceRoot1Path) << "device root one";
    std::ofstream(kDeviceRoot2Path) << "device root two";
    std::ofstream(kRimRoot1Path) << "RIM root one";
    std::ofstream(kRimRoot2Path) << "RIM root two";
    CLI::App app;
    AttestV2Options parsed;
    create_attest_v2_subcommand(app, parsed);
    std::vector<std::string> tokens = {
        "nvattest", "attest-v2", "--rp", "builtin:cc-bounce-buffer",
        "--device-identity-root-ca-file", kDeviceRoot1Path,
        "--device-identity-root-ca-file", kDeviceRoot2Path,
        "--rim-root-ca-file", kRimRoot1Path,
        "--rim-root-ca-file", kRimRoot2Path};
    std::vector<char*> argv;
    for (auto& token : tokens) {
        argv.push_back(&token[0]);
    }

    ASSERT_NO_THROW(app.parse(static_cast<int>(argv.size()), argv.data()));
    EXPECT_EQ(parsed.device_identity_root_files,
              (std::vector<std::string>{kDeviceRoot1Path, kDeviceRoot2Path}));
    EXPECT_EQ(parsed.rim_signing_root_files,
              (std::vector<std::string>{kRimRoot1Path, kRimRoot2Path}));
}

TEST_F(AttestV2Mock, MissingRootFileStopsVerification) {
    options.device_identity_root_files = {kDeviceRoot1Path};

    EXPECT_EQ(run(), 2);
    EXPECT_TRUE(g_fake_nvat.device_identity_root_pems.empty());
    EXPECT_EQ(g_fake_nvat.verify_cmw_calls, 0);
}

TEST_F(AttestV2Mock, InvalidRootRejectedBySdkStopsVerification) {
    std::ofstream(kRimRoot1Path) << "invalid certificate";
    options.rim_signing_root_files = {kRimRoot1Path};
    g_fake_nvat.add_rim_signing_root_rc = NVAT_RC_BAD_ARGUMENT;

    EXPECT_EQ(run(), 2);
    EXPECT_EQ(g_fake_nvat.rim_signing_root_pems,
              (std::vector<std::string>{"invalid certificate"}));
    EXPECT_EQ(g_fake_nvat.verify_cmw_calls, 0);
}

TEST_F(AttestV2Mock, RootFileWithEmbeddedNulStopsVerification) {
    std::ofstream file(kDeviceRoot1Path, std::ios::binary);
    file.write("root\0trailer", 12);
    file.close();
    options.device_identity_root_files = {kDeviceRoot1Path};

    EXPECT_EQ(run(), 2);
    EXPECT_TRUE(g_fake_nvat.device_identity_root_pems.empty());
    EXPECT_EQ(g_fake_nvat.verify_cmw_calls, 0);
}

TEST_F(AttestV2Mock, CorimStoreCacheFailurePropagates) {
    g_fake_nvat.corim_store_enable_in_memory_cache_rc = NVAT_RC_BAD_ARGUMENT;
    EXPECT_EQ(run(), 2);
}

TEST_F(AttestV2Mock, OcspCachedClientCreateFailurePropagates) {
    g_fake_nvat.ocsp_create_cached_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), 2);
}

TEST_F(AttestV2Mock, OcspCertIdHashReachesAiaClientConstructor) {
    options.ocsp_cert_id_hash = "sha-384";

    EXPECT_EQ(run(), 1);
    EXPECT_EQ(g_fake_nvat.ocsp_aia_create_calls, 1);
    EXPECT_EQ(g_fake_nvat.last_ocsp_cert_id_hash,
              NVAT_OCSP_CERT_ID_HASH_SHA384);
}

TEST_F(AttestV2Mock, RevocationDisabledConstructsNoOcspOptionsOrClient) {
    options.verify_revocation = false;

    EXPECT_EQ(run(), 1);
    EXPECT_EQ(g_fake_nvat.ocsp_options_create_calls, 0);
    EXPECT_EQ(g_fake_nvat.ocsp_aia_create_calls, 0);
    EXPECT_EQ(g_fake_nvat.ocsp_cached_create_calls, 0);
}

TEST_F(AttestV2Mock, EatFileSourceWithoutNonceIsAccepted) {
    std::ofstream(kEatPath, std::ios::binary) << "not a real token";
    options.evidence_source = "eat-file";
    options.eat_file = kEatPath;
    g_fake_nvat.policy_apply_ear_rc = NVAT_RC_OK;
    g_fake_nvat.verify_cmw_result_json =
        R"({"ear_status":"affirming","submods":{"device_0":{"ear_status":"affirming"}}})";
    EXPECT_EQ(run(), 0);
    std::remove(kEatPath);
}

TEST_F(AttestV2Mock, EatFileSourceMissingFileIsVerifierError) {
    options.evidence_source = "eat-file";
    options.eat_file = "/nonexistent/does_not_exist.eat.cbor";
    EXPECT_EQ(run(), 2);
}

TEST_F(AttestV2Mock, EatFileSourceWithNonceIsAccepted) {
    std::ofstream(kEatPath, std::ios::binary) << "not a real token";
    options.evidence_source = "eat-file";
    options.eat_file = kEatPath;
    options.nonce = "deadbeef";

    g_fake_nvat.policy_apply_ear_rc = NVAT_RC_OK;
    g_fake_nvat.verify_cmw_result_json =
        R"({"ear_status":"affirming","submods":{"device_0":{"ear_status":"affirming"}}})";
    EXPECT_EQ(run(), 0);
    std::remove(kEatPath);
}

TEST_F(AttestV2Mock, EatFileSourceNonceParseFailureIsVerifierError) {
    std::ofstream(kEatPath, std::ios::binary) << "not a real token";
    options.evidence_source = "eat-file";
    options.eat_file = kEatPath;
    options.nonce = "deadbeef";
    g_fake_nvat.nonce_rc = NVAT_RC_BAD_ARGUMENT;

    EXPECT_EQ(run(), 2);
    std::remove(kEatPath);
}

TEST_F(AttestV2Mock, EatFileSourceCmwCreateFailureIsVerifierError) {
    std::ofstream(kEatPath, std::ios::binary) << "not a real token";
    options.evidence_source = "eat-file";
    options.eat_file = kEatPath;
    options.nonce = "deadbeef";
    g_fake_nvat.cmw_create_rc = NVAT_RC_INTERNAL_ERROR;

    EXPECT_EQ(run(), 2);
    std::remove(kEatPath);
}

TEST_F(AttestV2Mock, EatFileSourceCmwSerializeFailureIsVerifierError) {
    std::ofstream(kEatPath, std::ios::binary) << "not a real token";
    options.evidence_source = "eat-file";
    options.eat_file = kEatPath;
    options.nonce = "deadbeef";
    g_fake_nvat.cmw_serialize_rc = NVAT_RC_INTERNAL_ERROR;

    EXPECT_EQ(run(), 2);
    std::remove(kEatPath);
}

TEST_F(AttestV2Mock, EatFileSourceStrGetDataFailureIsVerifierError) {
    std::ofstream(kEatPath, std::ios::binary) << "not a real token";
    options.evidence_source = "eat-file";
    options.eat_file = kEatPath;
    options.nonce = "deadbeef";
    g_fake_nvat.str_get_data_rc = NVAT_RC_INTERNAL_ERROR;

    EXPECT_EQ(run(), 2);
    std::remove(kEatPath);
}

TEST_F(AttestV2Mock, EatFileSourceStrLengthFailureIsVerifierError) {
    std::ofstream(kEatPath, std::ios::binary) << "not a real token";
    options.evidence_source = "eat-file";
    options.eat_file = kEatPath;
    options.nonce = "deadbeef";
    g_fake_nvat.str_length_rc = NVAT_RC_INTERNAL_ERROR;

    EXPECT_EQ(run(), 2);
    std::remove(kEatPath);
}
