/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

//stdlibs
#include <fstream>
#include <thread>

//third party
#include "gtest/gtest.h"
#include "gmock/gmock.h"

//this sdk
#include "nv_attestation/claims.h"
#include "nv_attestation/claims_evaluator.h"
#include "nv_attestation/error.h"
#include <nlohmann/json.hpp>
#include "nvat.h"

using namespace nvattestation;
using ::testing::Return;
using ::testing::_;
using ::testing::DoAll;
using ::testing::SetArgReferee;


const char* VALID_POLICY = R"(
    package policy
    default nv_match := false
    nv_match := true {
        input[0].measres == "success"
    }
)";

const char* INVALID_POLICY = R"(
    package policy
    default unknown_rule := {"unknown_response": false}
)";

const char* MALFORMED_POLICY = R"(
    some malformed policy
)";

const char* VALID_CLAIMS = R"(
{
        "measres": "success",
        "x-nvidia-device-type": "gpu",
        "x-nvidia-gpu-arch-check": true,
        "x-nvidia-gpu-attestation-report-parsed": true,
        "x-nvidia-gpu-attestation-report-nonce-match": true,
        "x-nvidia-gpu-attestation-report-signature-verified": true,
        "x-nvidia-gpu-attestation-report-cert-chain":
        {
            "x-nvidia-cert-status": "valid",
            "x-nvidia-cert-ocsp-status": "good"
        },
        "x-nvidia-gpu-attestation-report-cert-chain-fwid-match": true,
        "x-nvidia-gpu-driver-rim-fetched": true,
        "x-nvidia-gpu-driver-rim-schema-validated": true,
        "x-nvidia-gpu-driver-rim-signature-verified": true,
        "x-nvidia-gpu-driver-rim-version-match": true,
        "x-nvidia-gpu-driver-rim-cert-chain":
        {
            "x-nvidia-cert-status": "valid",
            "x-nvidia-cert-ocsp-status": "good"
        },
        "x-nvidia-gpu-driver-rim-measurements-available": true,
        "x-nvidia-gpu-vbios-rim-fetched": true,
        "x-nvidia-gpu-vbios-rim-schema-validated": true,
        "x-nvidia-gpu-vbios-rim-signature-verified": true,
        "x-nvidia-gpu-vbios-rim-version-match": true,
        "x-nvidia-gpu-vbios-rim-cert-chain":
        {
            "x-nvidia-cert-status": "valid",
            "x-nvidia-cert-ocsp-status": "good"
        },
        "x-nvidia-gpu-vbios-rim-measurements-available": true,
        "x-nvidia-gpu-vbios-index-no-conflict": true
}
)";

const char* INVALID_CLAIMS = R"(
{
    "some_invalid_claims": "some_value"
})";

class ClaimsEvaluatorTest : public ::testing::Test {
    public:
};

// Mock Claims class for testing
class MockClaims : public Claims {
    public:
        MOCK_METHOD(Error, serialize_json, (std::string& out_json), (const, override));
        MOCK_METHOD(nlohmann::json, to_json_object, (), (const));
        void setup_json(const char* str) {
            ON_CALL(*this, serialize_json(_)).WillByDefault(DoAll(SetArgReferee<0>(std::string(str)), Return(Error::Ok)));
            ON_CALL(*this, to_json_object()).WillByDefault(Return(nlohmann::json::parse(str)));
        }
    };

TEST_F(ClaimsEvaluatorTest, CreateDefaultClaimsEvaluator) {
    auto evaluator = ClaimsEvaluatorFactory::create_default_claims_evaluator();

    auto claims = std::make_shared<MockClaims>();
    claims->setup_json(VALID_CLAIMS);
    ClaimsCollection claims_collection {};
    claims_collection.append(claims);
    
    bool result;
    Error error = evaluator->evaluate_claims(claims_collection, result);
    EXPECT_EQ(result, true);
}

TEST(ClaimsEvaluatorTestCApi, CreateDefaultClaimsEvaluator) {
    nvat_relying_party_policy_t rp_policy;
    nvat_rc_t rc = nvat_relying_party_policy_create_default(&rp_policy);
    EXPECT_EQ(rc, NVAT_RC_OK);
    EXPECT_NE(rp_policy, nullptr);
    nvat_relying_party_policy_free(&rp_policy);
}

TEST_F(ClaimsEvaluatorTest, EvaluateValidClaimsWithRegoEvaluator) {
    auto evaluator = ClaimsEvaluatorFactory::create_rego_claims_evaluator(VALID_POLICY);

    auto claims = std::make_shared<MockClaims>();;
    claims->setup_json(VALID_CLAIMS);
    ClaimsCollection claims_collection {};
    claims_collection.append(claims);
    
    bool result;
    Error error = evaluator->evaluate_claims(claims_collection, result);
    EXPECT_EQ(error, Error::Ok);
    EXPECT_EQ(result, true);
}

TEST_F(ClaimsEvaluatorTest, EvaluateInvalidClaimsWithRegoEvaluator) {
    auto evaluator = ClaimsEvaluatorFactory::create_rego_claims_evaluator(VALID_POLICY);

    auto claims = std::make_shared<MockClaims>();;
    claims->setup_json(INVALID_CLAIMS);
    ClaimsCollection claims_collection {};
    claims_collection.append(claims);
    
    bool result;
    Error error = evaluator->evaluate_claims(claims_collection, result);
    EXPECT_EQ(error, Error::Ok);
    EXPECT_EQ(result, false);
}

TEST_F(ClaimsEvaluatorTest, EvaluateClaimsWithInvalidRegoPolicy) {
    auto evaluator = ClaimsEvaluatorFactory::create_rego_claims_evaluator(INVALID_POLICY);

    auto claims = std::make_shared<MockClaims>();;
    claims->setup_json(VALID_CLAIMS);
    ClaimsCollection claims_collection {};
    claims_collection.append(claims);
    
    bool result;
    Error error = evaluator->evaluate_claims(claims_collection, result);
    EXPECT_EQ(error, Error::Ok);
    EXPECT_EQ(result, false);
}

TEST_F(ClaimsEvaluatorTest, EvaluateClaimsWithInvalidClaimsAndInvalidRegoPolicy) {
    auto evaluator = ClaimsEvaluatorFactory::create_rego_claims_evaluator(INVALID_POLICY);

    auto claims = std::make_shared<MockClaims>();;
    claims->setup_json(VALID_CLAIMS);
    ClaimsCollection claims_collection {};
    claims_collection.append(claims);
    
    bool result;
    Error error = evaluator->evaluate_claims(claims_collection, result);
    EXPECT_EQ(error, Error::Ok);
    EXPECT_EQ(result, false);
}

TEST_F(ClaimsEvaluatorTest, EvaluateClaimsWithMalformedPolicy) {
    auto evaluator = ClaimsEvaluatorFactory::create_rego_claims_evaluator(MALFORMED_POLICY);

    auto claims = std::make_shared<MockClaims>();;
    claims->setup_json(VALID_CLAIMS);
    ClaimsCollection claims_collection {};
    claims_collection.append(claims);
    
    bool result = false;
    Error error = evaluator->evaluate_claims(claims_collection, result);
    EXPECT_EQ(error, Error::PolicyEvaluationError);
    EXPECT_EQ(result, false);
}