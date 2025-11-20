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
#include <vector>
#include <fstream>
#include <thread>
#include <memory>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <array>
#include <sys/wait.h>

//third party
#include "gtest/gtest.h"
#include <gmock/gmock.h>

//this sdk
#include "attest.h"
#include "nvat.h"
#include "environment.h"
#include "test_utils.h"
#include "nvattest_options.h"

TEST_F(CliTest, GPULocal) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string cmd = nvattest_bin + " attest --device gpu --verifier local";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0xe97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576";
        cmd += " --gpu-evidence " + gpu_evidence_path;
    }
    cmd += " --rim-url https://rim-internal.attestation.nvidia.com/internal";
    cmd += " --ocsp-url https://ocsp.ndis-stg.nvidia.com";

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "Command failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), 0) << "Non-zero result_code. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, GPULocalWithRelyingPartyPolicy) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest --device gpu --verifier local";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0xe97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576";
        cmd += " --gpu-evidence " + gpu_evidence_path;
    }
    cmd += " --rim-url https://rim-internal.attestation.nvidia.com/internal";
    cmd += " --ocsp-url https://ocsp.ndis-stg.nvidia.com";
    cmd += " --relying-party-policy " + relying_party_policy_file;

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "Command failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), 0) << "Non-zero result_code. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, GPULocalWithServiceKey) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest --device gpu --verifier local";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0xe97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576";
        cmd += " --gpu-evidence " + gpu_evidence_path;
    }
    cmd += " --rim-url https://rim-internal.attestation.nvidia.com/internal";
    cmd += " --ocsp-url https://ocsp.ndis-stg.nvidia.com";
    cmd += " --relying-party-policy " + relying_party_policy_file;
    cmd += " --service-key " + g_cli_env->service_key;

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "Command failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), 0) << "Non-zero result_code. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, GPURemote) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0xe97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576";
        cmd += " --gpu-evidence " + gpu_evidence_path;
    }
    cmd += " --verifier remote";
    cmd += " --nras-url https://nras.attestation-stg.nvidia.com";

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "Command failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), 0) << "Non-zero result_code. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, GPURemoteWithRelyingPartyPolicy) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0xe97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576";
        cmd += " --gpu-evidence " + gpu_evidence_path;
    }
    cmd += " --verifier remote";
    cmd += " --nras-url https://nras.attestation-stg.nvidia.com";
    cmd += " --relying-party-policy " + relying_party_policy_file;

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "Command failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), 0) << "Non-zero result_code. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, GPURemoteWithServiceKey) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0xe97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576";
        cmd += " --gpu-evidence " + gpu_evidence_path;
    }
    cmd += " --verifier remote";

    cmd += " --nras-url https://nras.attestation-stg.nvidia.com";
    cmd += " --relying-party-policy " + relying_party_policy_file;
    cmd += " --service-key " + g_cli_env->service_key;

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "Command failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), 0) << "Non-zero result_code. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, SwitchLocal) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        cmd += " --switch-evidence " + switch_evidence_path;
    }
    cmd += " --verifier local";
    cmd += " --rim-url https://rim-internal.attestation.nvidia.com/internal";
    cmd += " --ocsp-url https://ocsp.ndis-stg.nvidia.com";

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "Command failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), 0) << "Non-zero result_code. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, SwitchLocalWithRelyingPartyPolicy) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        cmd += " --switch-evidence " + switch_evidence_path;
    }
    cmd += " --verifier local";
    cmd += " --rim-url https://rim-internal.attestation.nvidia.com/internal";
    cmd += " --ocsp-url https://ocsp.ndis-stg.nvidia.com";
    cmd += " --relying-party-policy " + relying_party_policy_file;

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "Command failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), 0) << "Non-zero result_code. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, SwitchLocalWithServiceKey) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        cmd += " --switch-evidence " + switch_evidence_path;
    }
    cmd += " --verifier local";
    cmd += " --rim-url https://rim-internal.attestation.nvidia.com/internal";
    cmd += " --ocsp-url https://ocsp.ndis-stg.nvidia.com";
    cmd += " --relying-party-policy " + relying_party_policy_file;
    cmd += " --service-key " + g_cli_env->service_key;

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "Command failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), 0) << "Non-zero result_code. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, SwitchRemote) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        cmd += " --switch-evidence " + switch_evidence_path;
    }
    cmd += " --verifier remote";
    cmd += " --nras-url https://nras.attestation-stg.nvidia.com";

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "Command failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), 0) << "Non-zero result_code. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, SwitchRemoteWithRelyingPartyPolicy) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        cmd += " --switch-evidence " + switch_evidence_path;
    }
    cmd += " --verifier remote";
    cmd += " --nras-url https://nras.attestation-stg.nvidia.com";
    cmd += " --relying-party-policy " + relying_party_policy_file;

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "Command failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), 0) << "Non-zero result_code. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, SwitchRemoteWithServiceKey) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        cmd += " --switch-evidence " + switch_evidence_path;
    }
    cmd += " --verifier remote";
    cmd += " --nras-url https://nras.attestation-stg.nvidia.com";
    cmd += " --relying-party-policy " + relying_party_policy_file;
    cmd += " --service-key " + g_cli_env->service_key;

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "Command failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), 0) << "Non-zero result_code. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, GPULocalWithIncorrectServiceKey) {
    std::string nvattest_bin = "../nvattest";
    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
    cmd += " --verifier local";
    cmd += " --gpu-evidence " + gpu_evidence_path;
    cmd += " --rim-url https://rim-internal.attestation.nvidia.com/internal";
    cmd += " --ocsp-url https://ocsp.ndis-stg.nvidia.com";
    cmd += " --relying-party-policy " + relying_party_policy_file;
    cmd += " --service-key incorrect_service_key";

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_NE(exit_code, 0) << "Command should have failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_NE(response["result_code"].get<int>(), 0) << "Expected non-zero result_code with incorrect service key. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, GPURemoteWithIncorrectServiceKey) {
    std::string nvattest_bin = "../nvattest";
    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
    cmd += " --verifier remote";
    cmd += " --gpu-evidence " + gpu_evidence_path;
    cmd += " --nras-url https://nras.attestation-stg.nvidia.com";
    cmd += " --relying-party-policy " + relying_party_policy_file;
    cmd += " --service-key incorrect_service_key";

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_NE(exit_code, 0) << "Command should have failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_NE(response["result_code"].get<int>(), 0) << "Expected non-zero result_code with incorrect service key. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, SwitchLocalWithIncorrectServiceKey) {
    std::string nvattest_bin = "../nvattest";
    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
    cmd += " --verifier local";
    cmd += " --switch-evidence " + switch_evidence_path;
    cmd += " --rim-url https://rim-internal.attestation.nvidia.com/internal";
    cmd += " --ocsp-url https://ocsp.ndis-stg.nvidia.com";
    cmd += " --relying-party-policy " + relying_party_policy_file;
    cmd += " --service-key incorrect_service_key";

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_NE(exit_code, 0) << "Command should have failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_NE(response["result_code"].get<int>(), 0) << "Expected non-zero result_code with incorrect service key. JSON:\n" << response.dump(2);
}

TEST_F(CliTest, SwitchRemoteWithIncorrectServiceKey) {
    std::string nvattest_bin = "../nvattest";
    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
    cmd += " --verifier remote";
    cmd += " --switch-evidence " + switch_evidence_path;
    cmd += " --nras-url https://nras.attestation-stg.nvidia.com";
    cmd += " --relying-party-policy " + relying_party_policy_file;
    cmd += " --service-key incorrect_service_key";

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_NE(exit_code, 0) << "Command should have failed: " << cmd << "\nOutput:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "Did not find JSON in output. Raw output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str)) << "Failed to parse JSON. Raw JSON:\n" << json_str;
    ASSERT_TRUE(response.contains("result_code")) << "JSON missing result_code. JSON:\n" << response.dump(2);
    EXPECT_NE(response["result_code"].get<int>(), 0) << "Expected non-zero result_code with incorrect service key. JSON:\n" << response.dump(2);
}
