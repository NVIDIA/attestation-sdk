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

//third party
#include "gtest/gtest.h"

//this sdk
#include "nvat.h"
#include "environment.h"
#include "test_utils.h"

TEST(CliTestRequiresFaultyDriver, GPUExpiredDriverRIMCert){
    
    if (g_cli_env->test_mode != "integration" || !g_cli_env->test_device_gpu || g_cli_env->test_label != "gpu-expired-driver-rim-cert") {
        GTEST_SKIP();
    }

    RecordProperty("description", R"(
Verify GPU evidence with expired driver RIM cert. 
Local verifier.
Expected output: 
1. Attestation should fail with "Overall result is false"
2. Claims should indicate that driver RIM cert has expired
)");

    std::string nvattest_bin = g_cli_env->nvattest_bin;
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    cmd += " --verifier local";
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;
    cmd += " --no-verify-rim-signatures";

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, NVAT_RC_OVERALL_RESULT_FALSE) << "Expected exit code " << NVAT_RC_OVERALL_RESULT_FALSE << " but got " << exit_code << ". Command: " << cmd << "\nOutput:\n" << output;

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
    EXPECT_EQ(first_device_claims["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-status"].get<std::string>(), "expired") << "Expected cert status to be expired. JSON:\n" << first_device_claims.dump(2);
}

TEST(CliTestRequiresFaultyDriver, GPURevokedDriverRIMCert){
    
    if (g_cli_env->test_mode != "integration" || !g_cli_env->test_device_gpu || g_cli_env->test_label != "gpu-revoked-driver-rim-cert") {
        GTEST_SKIP();
    }

    RecordProperty("description", R"(
Verify GPU evidence with revoked driver RIM cert. 
Local verifier.
Expected output: 
1. Attestation should fail with "Overall result is false"
2. Claims should indicate that driver RIM cert OCSP status is revoked
)");

    std::string nvattest_bin = g_cli_env->nvattest_bin;
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    cmd += " --verifier local";
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, NVAT_RC_OVERALL_RESULT_FALSE) << "Expected exit code " << NVAT_RC_OVERALL_RESULT_FALSE << " but got " << exit_code << ". Command: " << cmd << "\nOutput:\n" << output;

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
    EXPECT_EQ(first_device_claims["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-ocsp-status"].get<std::string>(), "revoked") << "Expected cert OCSP status to be revoked. JSON:\n" << first_device_claims.dump(2);
}

TEST(CliTestRequiresFaultyDriver, GPURevokedDriverRIMCertWithRPP){

    if (g_cli_env->test_mode != "integration" || !g_cli_env->test_device_gpu || g_cli_env->test_label != "gpu-revoked-driver-rim-cert") {
        GTEST_SKIP();
    }

    RecordProperty("description", R"(
Verify GPU evidence with revoked driver RIM cert with relying party policy
to allow revoked driver RIM cert. 
Local verifier.
Expected output: 
1. Attestation should pass
)");

    std::string rp_policy_file = g_cli_env->git_repo_root + "/relying_party_policy_examples/allow_gpu_driver_rim_cert_revoked.rego";

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

TEST(CliTestRequiresFaultyDriver, GPUUnknownDriverRIMCert){
    
    if (g_cli_env->test_mode != "integration" || !g_cli_env->test_device_gpu || g_cli_env->test_label != "gpu-unknown-driver-rim-cert") {
        GTEST_SKIP();
    }

    RecordProperty("description", R"(
Verify GPU evidence with unknown driver RIM cert OCSP status. 
Local verifier.
Expected output: 
1. Attestation should fail with "Overall result is false"
2. Claims should indicate that driver RIM cert OCSP status is unknown
)");

    std::string nvattest_bin = g_cli_env->nvattest_bin;
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    cmd += " --verifier local";
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, NVAT_RC_OVERALL_RESULT_FALSE) << "Expected exit code " << NVAT_RC_OVERALL_RESULT_FALSE << " but got " << exit_code << ". Command: " << cmd << "\nOutput:\n" << output;

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
    EXPECT_EQ(first_device_claims["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-ocsp-status"].get<std::string>(), "unknown") << "Expected cert OCSP status to be unknown. JSON:\n" << first_device_claims.dump(2);
}

TEST(CliTestRequiresFaultyDriver, GPUUnknownDriverRIMCertWithRPP){

    if (g_cli_env->test_mode != "integration" || !g_cli_env->test_device_gpu || g_cli_env->test_label != "gpu-unknown-driver-rim-cert") {
        GTEST_SKIP();
    }

    RecordProperty("description", R"(
Verify GPU evidence with unknown driver RIM cert OCSP status with relying party policy
to allow unknown driver RIM cert OCSP status. 
Local verifier.
Expected output: 
1. Attestation should pass
)");

    std::string rp_policy_file = g_cli_env->git_repo_root + "/relying_party_policy_examples/allow_gpu_driver_rim_cert_unknown.rego";

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

