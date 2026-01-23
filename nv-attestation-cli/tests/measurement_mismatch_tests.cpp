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

TEST(CliTestRequiresFaultyDriver, GPUMeasurementMismatchWithoutRPP){
    
    if (g_cli_env->test_mode != "integration" || !g_cli_env->test_device_gpu || g_cli_env->test_label != "gpu-measurement-mismatch") {
        GTEST_SKIP();
    }

    RecordProperty("description", R"(
Verify GPU evidence with tampered driver RIM (measurement mismatch at index 7). 
Local verifier.
Expected output: 
1. Attestation should fail with "Overall result is false"
2. Claims should indicate that measres is "failure"
3. x-nvidia-mismatch-measurement-records should contain mismatch details for index 7
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
    
    // Verify measres is "fail"
    ASSERT_TRUE(first_device_claims.contains("measres")) << "Claims missing measres. JSON:\n" << first_device_claims.dump(2);
    EXPECT_EQ(first_device_claims["measres"].get<std::string>(), "fail") << "Expected measres to be 'failure'. JSON:\n" << first_device_claims.dump(2);
    
    // Verify x-nvidia-mismatch-measurement-records exists and contains index 7
    ASSERT_TRUE(first_device_claims.contains("x-nvidia-mismatch-measurement-records")) << "Claims missing x-nvidia-mismatch-measurement-records. JSON:\n" << first_device_claims.dump(2);
    auto mismatch_records = first_device_claims["x-nvidia-mismatch-measurement-records"];
    ASSERT_TRUE(mismatch_records.is_array()) << "x-nvidia-mismatch-measurement-records should be an array. JSON:\n" << first_device_claims.dump(2);
    ASSERT_FALSE(mismatch_records.empty()) << "x-nvidia-mismatch-measurement-records should not be empty. JSON:\n" << first_device_claims.dump(2);
    
    // Find and verify index 7 mismatch record
    bool found_index_7 = false;
    for (const auto& record : mismatch_records) {
        if (record.contains("index") && record["index"].get<int>() == 7) {
            found_index_7 = true;
            
            // Verify all fields of the mismatch record
            EXPECT_EQ(record["index"].get<int>(), 7) << "Mismatch record index should be 7. Record:\n" << record.dump(2);
            EXPECT_EQ(record["goldenSize"].get<int>(), 48) << "Mismatch record goldenSize should be 48. Record:\n" << record.dump(2);
            EXPECT_EQ(record["goldenValue"].get<std::string>(), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef") << "Mismatch record goldenValue mismatch. Record:\n" << record.dump(2);
            EXPECT_EQ(record["runtimeSize"].get<int>(), 48) << "Mismatch record runtimeSize should be 48. Record:\n" << record.dump(2);
            EXPECT_EQ(record["runtimeValue"].get<std::string>(), "3292ac26b8e5ff38316082758489115e7f1de0b4b48a60ecabfb01b557a233ab019f9b9da1c9c891f4c672cc58cff3c9") << "Mismatch record runtimeValue mismatch. Record:\n" << record.dump(2);
            EXPECT_EQ(record["measurementSource"].get<std::string>(), "Driver") << "Mismatch record measurementSource should be 'Driver'. Record:\n" << record.dump(2);
            
            break;
        }
    }
    EXPECT_TRUE(found_index_7) << "Expected to find mismatch record for index 7. Records:\n" << mismatch_records.dump(2);
}

TEST(CliTestRequiresFaultyDriver, GPUMeasurementMismatchWithRPP){

    if (g_cli_env->test_mode != "integration" || !g_cli_env->test_device_gpu || g_cli_env->test_label != "gpu-measurement-mismatch") {
        GTEST_SKIP();
    }

    RecordProperty("description", R"(
Verify GPU evidence with tampered driver RIM (measurement mismatch at index 7) 
with relying party policy to allow measurement mismatch at index 7. 
Local verifier.
Expected output: 
1. Attestation should pass
)");

    std::string rp_policy_file = g_cli_env->git_repo_root + "/relying_party_policy_examples/allow_gpu_measurement_mismatch_index_7.rego";

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

