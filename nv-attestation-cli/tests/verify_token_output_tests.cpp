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

// In-process unit tests for the pure verify-token output helpers. These do not
// invoke the nvattest binary or the network and do not link libnvat — they
// exercise verify_token_output.cpp directly (compiled into this test binary).

#include <string>

#include "gtest/gtest.h"
#include <nlohmann/json.hpp>

#include "nvat.h"
#include "verify_token_output.h"

using nvattest::verify_token_build_json;
using nvattest::verify_token_exit_code;
using nvattest::verify_token_result_has_claims;

TEST(VerifyTokenExitCode, ClaimBearingCodesMapToDocumentedExits) {
    EXPECT_EQ(verify_token_exit_code(NVAT_RC_OK), 0);
    EXPECT_EQ(verify_token_exit_code(NVAT_RC_RP_POLICY_MISMATCH), 2);
    EXPECT_EQ(verify_token_exit_code(NVAT_RC_OVERALL_RESULT_FALSE), 3);
}

TEST(VerifyTokenExitCode, FailureCodesMapToOne) {
    EXPECT_EQ(verify_token_exit_code(NVAT_RC_NRAS_TOKEN_INVALID), 1);
    EXPECT_EQ(verify_token_exit_code(NVAT_RC_BAD_ARGUMENT), 1);
    EXPECT_EQ(verify_token_exit_code(NVAT_RC_NONCE_MISMATCH), 1);
}

TEST(VerifyTokenResultHasClaims, TrueOnlyForClaimBearingCodes) {
    EXPECT_TRUE(verify_token_result_has_claims(NVAT_RC_OK));
    EXPECT_TRUE(verify_token_result_has_claims(NVAT_RC_RP_POLICY_MISMATCH));
    EXPECT_TRUE(verify_token_result_has_claims(NVAT_RC_OVERALL_RESULT_FALSE));

    EXPECT_FALSE(verify_token_result_has_claims(NVAT_RC_NRAS_TOKEN_INVALID));
    EXPECT_FALSE(verify_token_result_has_claims(NVAT_RC_BAD_ARGUMENT));
    EXPECT_FALSE(verify_token_result_has_claims(NVAT_RC_NONCE_MISMATCH));
}

TEST(VerifyTokenBuildJson, PopulatesClaimsForOkResult) {
    const std::string claims = R"([{"x-nvidia-device-type":"gpu"}])";
    nlohmann::json out = verify_token_build_json(NVAT_RC_OK, "Ok", claims);

    EXPECT_EQ(out.at("result_code").get<int>(), NVAT_RC_OK);
    EXPECT_EQ(out.at("result_message").get<std::string>(), "Ok");
    ASSERT_TRUE(out.at("claims").is_array());
    EXPECT_EQ(out.at("claims")[0].at("x-nvidia-device-type").get<std::string>(), "gpu");
}

TEST(VerifyTokenBuildJson, MalformedClaimsFallBackToEmptyObject) {
    nlohmann::json out = verify_token_build_json(NVAT_RC_OK, "Ok", "{not valid json}");

    EXPECT_EQ(out.at("result_code").get<int>(), NVAT_RC_OK);
    ASSERT_TRUE(out.at("claims").is_object());
    EXPECT_TRUE(out.at("claims").empty());
}

TEST(VerifyTokenBuildJson, NonClaimBearingCodeIgnoresClaimsPayload) {
    // Even with a non-empty (and valid) claims string, a code that does not
    // carry claims must yield an empty object.
    nlohmann::json out = verify_token_build_json(
        NVAT_RC_NRAS_TOKEN_INVALID, "NrasTokenInvalid", R"([{"a":1}])");

    ASSERT_TRUE(out.at("claims").is_object());
    EXPECT_TRUE(out.at("claims").empty());
    EXPECT_EQ(out.at("result_message").get<std::string>(), "NrasTokenInvalid");
}

TEST(VerifyTokenBuildJson, EmptyClaimsYieldEmptyObject) {
    nlohmann::json out = verify_token_build_json(NVAT_RC_OK, "Ok", "");
    ASSERT_TRUE(out.at("claims").is_object());
    EXPECT_TRUE(out.at("claims").empty());
}
