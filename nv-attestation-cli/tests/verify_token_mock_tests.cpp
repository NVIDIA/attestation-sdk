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

// In-process white-box tests for handle_verify_token_subcommand, driven against
// the fake nvat C API (fake_nvat.cpp). Unlike the subprocess tests in
// verify_token_tests.cpp, these link verify_token.cpp directly into the test
// binary and steer the SDK return values, so paths that a real run only reaches
// with a live JWKS + signed EAT (the verification success/policy/serialize
// paths) can be exercised deterministically.

#include <array>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "gtest/gtest.h"

#include "nvat.h"
#include "verify_token.h"
#include "nvattest_options.h"
#include "logging.h"
#include "fake_nvat_control.h"
#include "mock_cli_logger.h"

using namespace nvattest;

namespace {

const char* const kTokenPath = "/tmp/nvattest_mock_eat.json";
const char* const kPolicyPath = "/tmp/nvattest_mock_policy.rego";
const char* const kSignedEar = "signed.ear.jwt";
const char* const kAffirmingEar =
    R"({"ear_status":"affirming","submods":{"gpu-0":{"ear_status":"affirming"}}})";
const char* const kContraindicatedEar =
    R"({"ear_status":"contraindicated","submods":{"gpu-0":{"ear_status":"contraindicated"}}})";

} // namespace

class VerifyTokenMock : public ::testing::Test {
  protected:
    VerifyTokenOptions options;
    EvidenceVerificationOptions verification_options;
    CommonOptions common_options;
    std::streambuf* m_old_cout = nullptr;
    std::ostringstream m_captured_cout;

    void SetUp() override {
        fake_nvat_reset();
        std::ofstream(kTokenPath) << "{}";           // content irrelevant to the fake
        options.token_file = kTokenPath;
        verification_options.nras_url = "https://nras.example.com";
        common_options.format = "json";
        // Keep the handler's stdout out of the test log.
        m_old_cout = std::cout.rdbuf(m_captured_cout.rdbuf());
    }

    void TearDown() override {
        std::cout.rdbuf(m_old_cout);
        std::remove(kTokenPath);
        std::remove(kPolicyPath);
    }

    int run() {
        return handle_verify_token_subcommand(shared_mock_logger(), options, verification_options, common_options);
    }

    void write_policy(const char* contents) {
        std::ofstream(kPolicyPath) << contents;
        verification_options.relying_party_policy = kPolicyPath;
    }

    void use_ear() {
        options.token_type = "ear";
        g_fake_nvat.verified_ear_json = kAffirmingEar;
        std::ofstream(kTokenPath) << kSignedEar;
    }

    nlohmann::json captured_json() const {
        return nlohmann::json::parse(m_captured_cout.str());
    }
};

class VerifyTokenEar : public VerifyTokenMock {};

// --- success paths ---

TEST_F(VerifyTokenMock, SuccessJsonReturnsZero) {
    EXPECT_EQ(run(), 0);
}

TEST_F(VerifyTokenMock, SuccessTextReturnsZero) {
    // Text mode exercises the claims-print + success-log output branch.
    common_options.format = "text";
    EXPECT_EQ(run(), 0);
}

TEST_F(VerifyTokenEar, UsesDefaultClockSkew) {
    use_ear();
    options.nonce = "00112233";
    verification_options.service_key = "service-key";
    verification_options.tls_ca_cert = "/tmp/fake-ca.pem";

    EXPECT_EQ(run(), 0);
    EXPECT_EQ(g_fake_nvat.legacy_verify_calls, 0);
    EXPECT_EQ(g_fake_nvat.ear_verify_calls, 1);
    EXPECT_EQ(g_fake_nvat.verify_ear_jwt, kSignedEar);
    EXPECT_EQ(g_fake_nvat.verify_ear_base_url, verification_options.nras_url);
    EXPECT_EQ(g_fake_nvat.verify_ear_service_key, "service-key");
    EXPECT_TRUE(g_fake_nvat.verify_ear_nonce_present);
    EXPECT_TRUE(g_fake_nvat.verify_ear_http_options_present);
    EXPECT_TRUE(g_fake_nvat.verify_ear_jwt_options_present);
    EXPECT_EQ(g_fake_nvat.verify_ear_clock_skew_leeway_seconds, 60U);
    EXPECT_EQ(g_fake_nvat.sdk_shutdown_calls, 1);
    EXPECT_FALSE(g_fake_nvat.sdk_shutdown_with_live_handles);
}

TEST_F(VerifyTokenEar, ForwardsClockSkewOverride) {
    use_ear();
    options.clock_skew_leeway_seconds = 17;

    EXPECT_EQ(run(), 0);
    EXPECT_TRUE(g_fake_nvat.verify_ear_jwt_options_present);
    EXPECT_EQ(g_fake_nvat.verify_ear_clock_skew_leeway_seconds, 17U);
}

TEST_F(VerifyTokenEar, TrimsSurroundingWhitespace) {
    use_ear();
    std::ofstream(kTokenPath) << " \t\r\n" << kSignedEar << "\n\t ";

    EXPECT_EQ(run(), 0);
    EXPECT_EQ(g_fake_nvat.verify_ear_jwt, kSignedEar);
}

TEST_F(VerifyTokenEar, PrintsPayloadOnlyAfterSuccess) {
    use_ear();
    g_fake_nvat.verify_ear_rc = NVAT_RC_NRAS_TOKEN_INVALID;

    EXPECT_EQ(run(), 1);
    const auto output = captured_json();
    EXPECT_EQ(output.at("ear"), nlohmann::json::object());
}

TEST_F(VerifyTokenEar, AppliesEarPolicyAndRetainsAuthenticatedPayload) {
    use_ear();
    write_policy("package policy\n");
    g_fake_nvat.policy_apply_ear_rc = NVAT_RC_RP_POLICY_MISMATCH;

    EXPECT_EQ(run(), 2);
    EXPECT_EQ(g_fake_nvat.policy_apply_ear_input, kAffirmingEar);
    EXPECT_EQ(captured_json().at("ear").at("ear_status"), "affirming");
}

TEST_F(VerifyTokenEar, NonAffirmingEarWithoutPolicyReturnsOverallFalse) {
    use_ear();
    const std::array<std::string, 3> authenticated_ears = {{
        kContraindicatedEar,
        R"({"ear_status":"contraindicated","submods":{"gpu-0":{"ear_status":"affirming"}}})",
        R"({"ear_status":"affirming","submods":{"gpu-0":{"ear_status":"contraindicated"}}})",
    }};

    for (const auto& ear : authenticated_ears) {
        SCOPED_TRACE(ear);
        m_captured_cout.str("");
        m_captured_cout.clear();
        g_fake_nvat.verified_ear_json = ear;
        EXPECT_EQ(run(), 3);
        EXPECT_EQ(captured_json().at("ear"), nlohmann::json::parse(ear));
    }
}

TEST_F(VerifyTokenEar, PolicySuccessDoesNotOverrideOverallFalse) {
    use_ear();
    g_fake_nvat.verified_ear_json = kContraindicatedEar;
    write_policy("package policy\n");

    EXPECT_EQ(run(), 3);
    EXPECT_EQ(captured_json().at("ear").at("ear_status"), "contraindicated");
}

TEST_F(VerifyTokenEar, PolicySetupFailuresRetainAuthenticatedPayload) {
    use_ear();
    verification_options.relying_party_policy = "/tmp/nvattest_missing_ear_policy.rego";

    EXPECT_EQ(run(), 1);
    EXPECT_EQ(captured_json().at("ear").at("ear_status"), "affirming");

    m_captured_cout.str("");
    m_captured_cout.clear();
    write_policy("package policy\n");
    g_fake_nvat.policy_create_rc = NVAT_RC_INTERNAL_ERROR;

    EXPECT_EQ(run(), 1);
    EXPECT_EQ(captured_json().at("ear").at("ear_status"), "affirming");
}

TEST_F(VerifyTokenEar, VerificationFailureReleasesAllHandlesBeforeShutdown) {
    use_ear();
    options.nonce = "00112233";
    verification_options.tls_ca_cert = "/tmp/fake-ca.pem";
    g_fake_nvat.verify_ear_rc = NVAT_RC_NRAS_TOKEN_INVALID;

    EXPECT_EQ(run(), 1);
    EXPECT_EQ(g_fake_nvat.tracked_sdk_handles, 0);
    EXPECT_FALSE(g_fake_nvat.sdk_shutdown_with_live_handles);
}

TEST(FakeNvatControl, AllocationsAndFreesBalance) {
    fake_nvat_reset();

    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_create(&nonce, 32), NVAT_RC_OK);
    nvat_nonce_free(&nonce);

    nvat_str_t detached_eat = nullptr;
    nvat_claims_collection_t claims = nullptr;
    ASSERT_EQ(nvat_attest_device(nullptr, nullptr, &detached_eat, &claims), NVAT_RC_OK);
    nvat_str_free(&detached_eat);
    nvat_claims_collection_free(&claims);

    EXPECT_EQ(g_fake_nvat.tracked_sdk_handles, 0);
}

TEST_F(VerifyTokenMock, OverallResultFalseReturnsThree) {
    g_fake_nvat.verify_rc = NVAT_RC_OVERALL_RESULT_FALSE;  // claims still populated
    EXPECT_EQ(run(), 3);
}

// --- verification / setup failures ---

TEST_F(VerifyTokenMock, VerifyFailureReturnsOne) {
    g_fake_nvat.verify_rc = NVAT_RC_NRAS_TOKEN_INVALID;
    EXPECT_EQ(run(), 1);
}

TEST_F(VerifyTokenMock, TextModeFailurePrintsErrorHelp) {
    // Text mode + a failure exercises the critical-log + error-help branch.
    common_options.format = "text";
    g_fake_nvat.verify_rc = NVAT_RC_NRAS_TOKEN_INVALID;
    EXPECT_EQ(run(), 1);
}

TEST_F(VerifyTokenMock, InitSdkFailureReturnsOne) {
    g_fake_nvat.sdk_init_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), 1);
}

TEST_F(VerifyTokenMock, HttpOptionsFailureReturnsOne) {
    // A TLS CA setting makes the handler build http options; steer that to fail.
    verification_options.tls_ca_cert = "/tmp/does-not-need-to-exist.pem";
    g_fake_nvat.http_options_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), 1);
}

TEST_F(VerifyTokenMock, SerializeFailureReturnsOne) {
    g_fake_nvat.serialize_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), 1);
}

TEST_F(VerifyTokenMock, StrGetDataFailureReturnsOne) {
    g_fake_nvat.str_get_data_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), 1);
}

// --- relying-party policy paths ---

TEST_F(VerifyTokenMock, PolicyPassReturnsZero) {
    write_policy("package policy\n");
    g_fake_nvat.policy_apply_rc = NVAT_RC_OK;
    EXPECT_EQ(run(), 0);
}

TEST_F(VerifyTokenMock, PolicyMismatchReturnsTwo) {
    write_policy("package policy\n");
    g_fake_nvat.policy_apply_rc = NVAT_RC_RP_POLICY_MISMATCH;
    EXPECT_EQ(run(), 2);
}

TEST_F(VerifyTokenMock, PolicyFileNotFoundReturnsOne) {
    verification_options.relying_party_policy = "/tmp/nvattest_mock_missing_policy_xyz.rego";
    EXPECT_EQ(run(), 1);
}

TEST_F(VerifyTokenMock, PolicyCreateFailureReturnsOne) {
    write_policy("not valid rego\n");
    g_fake_nvat.policy_create_rc = NVAT_RC_INTERNAL_ERROR;
    EXPECT_EQ(run(), 1);
}
