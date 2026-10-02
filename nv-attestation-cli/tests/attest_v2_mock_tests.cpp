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

// In-process white-box tests for handle_attest_v2_subcommand, driven against
// the fake nvat C API (fake_nvat.cpp). The verifier always emits a well-formed
// result, so the shapes exercised here cannot be produced through the real SDK;
// steering its response is the only way to reach the status mapping.

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

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
} // namespace

class AttestV2Mock : public ::testing::Test {
  protected:
    AttestV2Options options;
    CommonOptions common;
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
        common.format = "json";
        m_old_cout = std::cout.rdbuf(m_captured_cout.rdbuf());
    }

    void TearDown() override {
        std::cout.rdbuf(m_old_cout);
        std::remove(kCmwPath);
        std::remove(kPolicyPath);
    }

    void write_policy(const std::string& policy) {
        std::ofstream(kPolicyPath) << policy;
        options.relying_party_policy = kPolicyPath;
    }

    int run() {
        return handle_attest_v2_subcommand(shared_mock_logger(), options, common);
    }
};

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

TEST_F(AttestV2Mock, AffirmingWhenEverySubmodAffirms) {
    g_fake_nvat.verify_cmw_result_json =
        R"({"ear_status":"affirming","submods":{"gpu_0":{"ear_status":"affirming"}}})";
    EXPECT_EQ(run(), 0);
}

TEST_F(AttestV2Mock, TopLevelStatusMustAffirm) {
    g_fake_nvat.verify_cmw_result_json =
        R"({"ear_status":"contraindicated","submods":{"gpu_0":{"ear_status":"affirming"}}})";
    EXPECT_EQ(run(), 1);

    m_captured_cout.str("");
    m_captured_cout.clear();
    g_fake_nvat.verify_cmw_result_json =
        R"({"submods":{"gpu_0":{"ear_status":"affirming"}}})";
    EXPECT_EQ(run(), 1);
}

TEST_F(AttestV2Mock, ContraindicatedSubmodDoesNotAffirm) {
    g_fake_nvat.verify_cmw_result_json =
        R"({"submods":{"gpu_0":{"ear_status":"contraindicated"}}})";
    EXPECT_EQ(run(), 1);
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

// One bad submod is enough, whatever the others report.
TEST_F(AttestV2Mock, MixedSubmodStatusesDoNotAffirm) {
    g_fake_nvat.verify_cmw_result_json =
        R"({"submods":{"gpu_0":{"ear_status":"affirming"},)"
        R"("gpu_1":{"ear_status":"warning"}}})";
    EXPECT_EQ(run(), 1);
}

TEST_F(AttestV2Mock, SubmodWithoutEarStatusDoesNotAffirm) {
    g_fake_nvat.verify_cmw_result_json = R"({"submods":{"gpu_0":{}}})";
    EXPECT_EQ(run(), 1);
}

TEST_F(AttestV2Mock, MissingSubmodsDoesNotAffirm) {
    g_fake_nvat.verify_cmw_result_json = R"({"eat_profile":"x"})";
    EXPECT_EQ(run(), 1);
}

TEST_F(AttestV2Mock, EmptySubmodsDoesNotAffirm) {
    g_fake_nvat.verify_cmw_result_json = R"({"submods":{}})";
    EXPECT_EQ(run(), 1);
}

TEST_F(AttestV2Mock, NonObjectSubmodsDoesNotAffirm) {
    g_fake_nvat.verify_cmw_result_json = R"({"submods":"nope"})";
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
