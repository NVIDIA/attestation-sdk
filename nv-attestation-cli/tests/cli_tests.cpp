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

//TODO: Fix ./nv-attestation-cli-tests in the build pipeline
//Note: Use ctest to run these test cases
class CliTest : public ::testing::Test {
};

static std::string exec_and_capture_output(const std::string& command, int& exit_code) {
    std::array<char, 4096> buffer{};
    std::string result;
    FILE* pipe = popen((command + " 2>&1").c_str(), "r");
    if (!pipe) {
        exit_code = -1;
        return result;
    }
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        result.append(buffer.data());
    }
    int status = pclose(pipe);
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else {
        exit_code = -1;
    }
    return result;
}

static bool extract_json_object(const std::string& input, std::string& json_out) {
    // Find the last balanced JSON object by scanning from the end and matching braces
    if (input.empty()) return false;
    std::size_t end_pos = std::string::npos;
    int depth = 0;
    for (std::size_t i = input.size(); i-- > 0;) {
        const char c = input[i];
        if (c == '}') {
            if (end_pos == std::string::npos) {
                end_pos = i;
            }
            depth++;
        } else if (c == '{') {
            if (depth > 0) {
                depth--;
                if (depth == 0 && end_pos != std::string::npos) {
                    json_out = input.substr(i, end_pos - i + 1);
                    return true;
                }
            }
        }
    }
    return false;
}

TEST_F(CliTest, GPULocalCommand) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest --device gpu --verifier local";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --gpu-evidence " + gpu_evidence_path;
    } else {
        cmd += " --rim-url https://rim.attestation-stg.nvidia.com";
        cmd += " --ocsp-url https://ocsp.ndis-stg.nvidia.com";
    }
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

TEST_F(CliTest, GPURemoteCommand) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest --device gpu --verifier remote";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --gpu-evidence " + gpu_evidence_path;
    } else {
        cmd += " --rim-url https://rim.attestation-stg.nvidia.com";
        cmd += " --ocsp-url https://ocsp.ndis-stg.nvidia.com";
        cmd += " --nras-url https://nras.attestation-stg.nvidia.com";
    }
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

TEST_F(CliTest, SwitchLocalCommand) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest --device nvswitch --verifier local";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --switch-evidence " + switch_evidence_path;
    }
    cmd += " --rim-url https://rim.attestation-stg.nvidia.com";
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

TEST_F(CliTest, SwitchRemoteCommand) { //integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = "../nvattest";

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest --device nvswitch --verifier remote";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --switch-evidence " + switch_evidence_path;
    }
    cmd += " --rim-url https://rim.attestation-stg.nvidia.com";
    cmd += " --ocsp-url https://ocsp.ndis-stg.nvidia.com";
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

TEST_F(CliTest, GPULocalWithPolicy) {
    std::vector<std::string> devices = {"gpu"};
    std::string verifier = "local";
    std::string gpu_evidence_file = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string switch_evidence_file = "";
    std::string relying_party_policy_file = "../../../common-test-data/relying_party_policy.rego";
    std::string rim_url = ""; 
    std::string ocsp_url = "";
    std::string nras_url = "";
    int result = nvattest::handle_attest_subcommand(devices, verifier, gpu_evidence_file, switch_evidence_file, relying_party_policy_file, rim_url, ocsp_url, nras_url);
    ASSERT_EQ(result, NVAT_RC_OK);
}

TEST_F(CliTest, GPULocalNoPolicy) {
    std::vector<std::string> devices = {"gpu"};
    std::string verifier = "local";
    std::string gpu_evidence_file = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string switch_evidence_file = "";
    std::string relying_party_policy_file = "";
    std::string rim_url = "";
    std::string ocsp_url = ""; 
    std::string nras_url = "";
    int result = nvattest::handle_attest_subcommand(devices, verifier, gpu_evidence_file, switch_evidence_file, relying_party_policy_file, rim_url, ocsp_url, nras_url);
    ASSERT_EQ(result, NVAT_RC_OK);
}

TEST_F(CliTest, GPURemoteWithPolicy) {
    std::vector<std::string> devices = {"gpu"};
    std::string verifier = "remote";
    std::string gpu_evidence_file = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string switch_evidence_file = "";
    std::string relying_party_policy_file = "../../../common-test-data/relying_party_policy.rego";
    std::string rim_url = "";
    std::string ocsp_url = ""; 
    std::string nras_url = "";
    int result = nvattest::handle_attest_subcommand(devices, verifier, gpu_evidence_file, switch_evidence_file, relying_party_policy_file, rim_url, ocsp_url, nras_url);
    ASSERT_EQ(result, NVAT_RC_OK);
}

TEST_F(CliTest, GPURemoteNoPolicy) {
    std::vector<std::string> devices = {"gpu"};
    std::string verifier = "remote";
    std::string gpu_evidence_file = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string switch_evidence_file = "";
    std::string relying_party_policy_file = "";
    std::string rim_url = ""; 
    std::string ocsp_url = "";
    std::string nras_url = "";
    int result = nvattest::handle_attest_subcommand(devices, verifier, gpu_evidence_file, switch_evidence_file, relying_party_policy_file, rim_url, ocsp_url, nras_url);
    ASSERT_EQ(result, NVAT_RC_OK);
}

TEST_F(CliTest, SwitchLocalWithPolicy) {
    std::vector<std::string> devices = {"nvswitch"};
    std::string verifier = "local";
    std::string gpu_evidence_file = "";
    std::string switch_evidence_file = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string rim_url = "https://rim.attestation-stg.nvidia.com";
    std::string ocsp_url = "https://ocsp.ndis-stg.nvidia.com";
    std::string nras_url = "https://nras.attestation-stg.nvidia.com";
    int result = nvattest::handle_attest_subcommand(devices, verifier, gpu_evidence_file, switch_evidence_file, relying_party_policy_file, rim_url, ocsp_url, nras_url);
    ASSERT_EQ(result, NVAT_RC_OK);
}

TEST_F(CliTest, SwitchLocalNoPolicy) {
    std::vector<std::string> devices = {"nvswitch"};
    std::string verifier = "local";
    std::string gpu_evidence_file = "";
    std::string switch_evidence_file = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "";
    std::string rim_url = "https://rim.attestation-stg.nvidia.com";
    std::string ocsp_url = "https://ocsp.ndis-stg.nvidia.com";
    std::string nras_url = "https://nras.attestation-stg.nvidia.com";
    int result = nvattest::handle_attest_subcommand(devices, verifier, gpu_evidence_file, switch_evidence_file, relying_party_policy_file, rim_url, ocsp_url, nras_url);
    ASSERT_EQ(result, NVAT_RC_OK);
}

TEST_F(CliTest, SwitchRemoteWithPolicy) {
    std::vector<std::string> devices = {"nvswitch"};
    std::string verifier = "remote";
    std::string gpu_evidence_file = "";
    std::string switch_evidence_file = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string rim_url = "https://rim.attestation-stg.nvidia.com";
    std::string ocsp_url = "https://ocsp.ndis-stg.nvidia.com";
    std::string nras_url = "https://nras.attestation-stg.nvidia.com";
    int result = nvattest::handle_attest_subcommand(devices, verifier, gpu_evidence_file, switch_evidence_file, relying_party_policy_file, rim_url, ocsp_url, nras_url);
    ASSERT_EQ(result, NVAT_RC_OK);
}

TEST_F(CliTest, SwitchRemoteNoPolicy) {
    std::vector<std::string> devices = {"nvswitch"};
    std::string verifier = "remote";
    std::string gpu_evidence_file = "";
    std::string switch_evidence_file = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "";
    std::string rim_url = "https://rim.attestation-stg.nvidia.com";
    std::string ocsp_url = "https://ocsp.ndis-stg.nvidia.com";
    std::string nras_url = "https://nras.attestation-stg.nvidia.com";
    int result = nvattest::handle_attest_subcommand(devices, verifier, gpu_evidence_file, switch_evidence_file, relying_party_policy_file, rim_url, ocsp_url, nras_url);
    ASSERT_EQ(result, NVAT_RC_OK);
}
