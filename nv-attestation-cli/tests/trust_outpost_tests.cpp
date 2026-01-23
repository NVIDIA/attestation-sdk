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

#include <string>
#include <thread>
#include <chrono>

//third party
#include "gtest/gtest.h"

//this sdk
#include "nvat.h"
#include "environment.h"
#include "test_utils.h"

TEST(CliTestRequiresTrustOutpost, GPUTrustOutpostWithoutRPP){
    
    if (g_cli_env->test_mode != "integration" || !g_cli_env->test_device_gpu || g_cli_env->test_label != "gpu-trust-outpost") {
        GTEST_SKIP();
    }

    RecordProperty("description", R"(
Verify GPU evidence using Trust Outpost without relying party policy.
Trust Outpost caches OCSP responses, so x-nvidia-cert-ocsp-nonce-matches will be false
on subsequent requests (cached response has different nonce than current request).
On the first request (cache miss), nonce may match. If so, wait 5 seconds and retry.
Local verifier.
Expected output: 
1. Attestation should fail with "Overall result is false"
2. Claims should indicate that OCSP nonce does not match (x-nvidia-cert-ocsp-nonce-matches = false)
)");

    std::string nvattest_bin = g_cli_env->nvattest_bin;
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    cmd += " --verifier local";
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);

    // First run may succeed if OCSP response is not cached (nonce will match).
    // In that case, wait 5 seconds for cache to be populated and retry.
    if (exit_code == 0) {
        std::cout << "First attestation passed (cache miss, nonce matched). Waiting 5 seconds for cache population..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
        output = exec_and_capture_output(cmd, exit_code);
    }

    ASSERT_EQ(exit_code, NVAT_RC_OVERALL_RESULT_FALSE) << "Expected exit code " << NVAT_RC_OVERALL_RESULT_FALSE << " but got " << exit_code << " (cached OCSP response has mismatched nonce). Command: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), NVAT_RC_OVERALL_RESULT_FALSE) << "Expected result_code to be NVAT_RC_OVERALL_RESULT_FALSE. JSON:\n" << response.dump(2);
    nlohmann::json claims;
    ASSERT_NO_THROW(claims = response["claims"].get<nlohmann::json>()) << "Failed to parse claims. Raw JSON:\n" << response["claims"].get<std::string>();
    ASSERT_FALSE(claims.empty()) << "Claims object is empty. JSON:\n" << claims.dump(2);
    auto first_device_claims = claims.begin().value();
    // Verify that OCSP nonce does not match (Trust Outpost returns cached response with old nonce)
    EXPECT_EQ(first_device_claims["x-nvidia-gpu-attestation-report-cert-chain"]["x-nvidia-cert-ocsp-nonce-matches"].get<bool>(), false) << "Expected OCSP nonce match to be false (cached response). JSON:\n" << first_device_claims.dump(2);
}

TEST(CliTestRequiresTrustOutpost, GPUTrustOutpostWithRPP){

    if (g_cli_env->test_mode != "integration" || !g_cli_env->test_device_gpu || g_cli_env->test_label != "gpu-trust-outpost") {
        GTEST_SKIP();
    }

    RecordProperty("description", R"(
Verify GPU evidence using Trust Outpost with relying party policy that skips 
the check for x-nvidia-cert-ocsp-nonce-matches claim
Local verifier.
Expected output: 
1. Attestation should pass
)");

    std::string rp_policy_file = g_cli_env->git_repo_root + "/relying_party_policy_examples/allow_trust_outpost_ocsp.rego";

    std::string nvattest_bin = g_cli_env->nvattest_bin;
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    cmd += " --verifier local";
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;
    cmd += " --relying-party-policy " + rp_policy_file;

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "Command should have passed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), NVAT_RC_OK) << "Expected result_code to be NVAT_OK. JSON:\n" << response.dump(2);
}
