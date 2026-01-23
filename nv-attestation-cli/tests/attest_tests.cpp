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
#include <functional>
#include <map>
#include <sys/wait.h>

//third party
#include "gtest/gtest.h"
#include <gmock/gmock.h>

//this sdk
#include "attest.h"
#include "nlohmann/json_fwd.hpp"
#include "nvat.h"
#include "environment.h"
#include "test_utils.h"
#include "nvattest_options.h"

TEST_F(CliTest, GPULocal) { //integration + unit
    RecordProperty("description", "Verify GPU evidence locally");
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = g_cli_env->nvattest_bin;

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string cmd = nvattest_bin + " attest --device gpu --verifier local";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0xe97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576";
        cmd += " --gpu-evidence-source file --gpu-evidence-file " + gpu_evidence_path;
    }
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;

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
    RecordProperty("description", "Verify GPU evidence locally with relying party policy");
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = g_cli_env->nvattest_bin;

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/rp-policy-permissive.rego";
    std::string cmd = nvattest_bin + " attest --device gpu --verifier local";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0xe97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576";
        cmd += " --gpu-evidence-source file --gpu-evidence-file " + gpu_evidence_path;
    }
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;
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
    RecordProperty("description", "Verify GPU evidence locally with service key");
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = g_cli_env->nvattest_bin;

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/rp-policy-permissive.rego";
    std::string cmd = nvattest_bin + " attest --device gpu --verifier local";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0xe97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576";
        cmd += " --gpu-evidence-source file --gpu-evidence-file " + gpu_evidence_path;
    }
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;
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
    RecordProperty("description", "Verify GPU evidence using remote verifier");
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = g_cli_env->nvattest_bin;

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0xe97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576";
        cmd += " --gpu-evidence-source file --gpu-evidence-file " + gpu_evidence_path;
        cmd += " --nvswitch-evidence-source file --nvswitch-evidence-file invalid"; // should be ignored
    }
    cmd += " --verifier remote";
    cmd += " --nras-url " + g_cli_env->nras_url;

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
    RecordProperty("description", "Verify GPU evidence using remote verifier with relying party policy");
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = g_cli_env->nvattest_bin;

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/rp-policy-permissive.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0xe97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576";
        cmd += " --gpu-evidence-source file --gpu-evidence-file " + gpu_evidence_path;
    }
    cmd += " --verifier remote";
    cmd += " --nras-url " + g_cli_env->nras_url;
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
    RecordProperty("description", "Verify GPU evidence using remote verifier with service key");
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = g_cli_env->nvattest_bin;

    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/rp-policy-permissive.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0xe97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576";
        cmd += " --gpu-evidence-source file --gpu-evidence-file " + gpu_evidence_path;
    }
    cmd += " --verifier remote";

    cmd += " --nras-url " + g_cli_env->nras_url;
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
    RecordProperty("description", "Verify NVSwitch evidence locally");
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = g_cli_env->nvattest_bin;

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        cmd += " --nvswitch-evidence-source file --nvswitch-evidence-file " + switch_evidence_path;
    }
    cmd += " --verifier local";
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;

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
    RecordProperty("description", "Verify NVSwitch evidence locally with relying party policy");
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = g_cli_env->nvattest_bin;

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        cmd += " --nvswitch-evidence-source file --nvswitch-evidence-file " + switch_evidence_path;
    }
    cmd += " --verifier local";
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;
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
    RecordProperty("description", "Verify NVSwitch evidence locally with service key");
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = g_cli_env->nvattest_bin;

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        cmd += " --nvswitch-evidence-source file --nvswitch-evidence-file " + switch_evidence_path;
    }
    cmd += " --verifier local";
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;
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
    RecordProperty("description", "Verify NVSwitch evidence using remote verifier");
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = g_cli_env->nvattest_bin;

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        cmd += " --nvswitch-evidence-source file --nvswitch-evidence-file " + switch_evidence_path;
        cmd += " --gpu-evidence-source file --gpu-evidence-file invalid"; // should be ignored
    }
    cmd += " --verifier remote";
    cmd += " --nras-url " + g_cli_env->nras_url;

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
    RecordProperty("description", "Verify NVSwitch evidence using remote verifier with relying party policy");
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = g_cli_env->nvattest_bin;

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        cmd += " --nvswitch-evidence-source file --nvswitch-evidence-file " + switch_evidence_path;
    }
    cmd += " --verifier remote";
    cmd += " --nras-url " + g_cli_env->nras_url;
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
    RecordProperty("description", "Verify NVSwitch evidence using remote verifier with service key");
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = g_cli_env->nvattest_bin;

    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    if (g_cli_env->test_mode == "unit") {
        cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        cmd += " --nvswitch-evidence-source file --nvswitch-evidence-file " + switch_evidence_path;
    }
    cmd += " --verifier remote";
    cmd += " --nras-url " + g_cli_env->nras_url;
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
    std::string nvattest_bin = g_cli_env->nvattest_bin;
    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/rp-policy-permissive.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
    cmd += " --verifier local";
    cmd += " --gpu-evidence-source file --gpu-evidence-file " + gpu_evidence_path;
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;
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
    std::string nvattest_bin = g_cli_env->nvattest_bin;
    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string relying_party_policy_file = "../../../common-test-data/rp-policy-permissive.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device gpu";
    cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
    cmd += " --verifier remote";
    cmd += " --gpu-evidence-source file --gpu-evidence-file " + gpu_evidence_path;
    cmd += " --nras-url " + g_cli_env->nras_url;
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
    std::string nvattest_bin = g_cli_env->nvattest_bin;
    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
    cmd += " --verifier local";
    cmd += " --nvswitch-evidence-source file --nvswitch-evidence-file " + switch_evidence_path;
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;
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
    std::string nvattest_bin = g_cli_env->nvattest_bin;
    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string relying_party_policy_file = "../../../common-test-data/switch_relying_party_policy.rego";
    std::string cmd = nvattest_bin + " attest";
    cmd += " --device nvswitch";
    cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
    cmd += " --verifier remote";
    cmd += " --nvswitch-evidence-source file --nvswitch-evidence-file " + switch_evidence_path;
    cmd += " --nras-url " + g_cli_env->nras_url;
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

// Lambda type for label-specific claim handlers
// Takes full claims mappings (UEID -> claims) and return codes (mutable)
// Performs label-specific assertions, nullifies claims that differ by design,
// and can normalize return codes when expected to differ between local/remote
using LabelClaimHandler = std::function<void(
    std::map<std::string, nlohmann::json>& local_claims_by_ueid,
    std::map<std::string, nlohmann::json>& remote_claims_by_ueid,
    int& local_result_code,
    int& remote_result_code
)>;

// Map of test_label -> handler function
std::map<std::string, LabelClaimHandler> g_label_claim_handlers = {
    {"gpu-trust-outpost", [](
        std::map<std::string, nlohmann::json>& local_claims,
        std::map<std::string, nlohmann::json>& remote_claims,
        int& local_result_code,
        int& remote_result_code
    ) {
        // Assert expected return code difference for Trust Outpost:
        // Local verifier detects OCSP nonce mismatch → NVAT_RC_OVERALL_RESULT_FALSE
        // Remote verifier (NRAS) passes → NVAT_RC_OK
        EXPECT_EQ(local_result_code, NVAT_RC_OVERALL_RESULT_FALSE)
            << "Expected local result code to be NVAT_RC_OVERALL_RESULT_FALSE for Trust Outpost";
        EXPECT_EQ(remote_result_code, NVAT_RC_OK)
            << "Expected remote result code to be NVAT_RC_OK";
        
        // Normalize return codes so comparison passes
        local_result_code = NVAT_RC_OK;
        remote_result_code = NVAT_RC_OK;

        // Process all claims
        for (auto& entry : local_claims) {
            const std::string& ueid = entry.first;
            nlohmann::json& local_claim = entry.second;
            auto& remote_claim = remote_claims.at(ueid);
            
            std::vector<std::string> cert_chain_keys = {
                "x-nvidia-gpu-attestation-report-cert-chain",
                "x-nvidia-gpu-driver-rim-cert-chain",
                "x-nvidia-gpu-vbios-rim-cert-chain"
            };
            
            for (const auto& key : cert_chain_keys) {
                // Verify OCSP nonce mismatch in local claim (expected for Trust Outpost)
                EXPECT_FALSE(local_claim[key]["x-nvidia-cert-ocsp-nonce-matches"].get<bool>())
                    << "Expected OCSP nonce match to be false for " << key;
                
                // Null out only the OCSP nonce match field to exclude from final comparison
                local_claim[key]["x-nvidia-cert-ocsp-nonce-matches"] = nullptr;
                remote_claim[key]["x-nvidia-cert-ocsp-nonce-matches"] = nullptr;
            }
        }
    }},
    {"gpu-revoked-driver-rim-cert", [](
        std::map<std::string, nlohmann::json>& local_claims,
        std::map<std::string, nlohmann::json>& remote_claims,
        int& local_result_code,
        int& remote_result_code
    ) {
        // Process all claims
        for (auto& entry : local_claims) {
            const std::string& ueid = entry.first;
            nlohmann::json& local_claim = entry.second;
            auto& remote_claim = remote_claims.at(ueid);
            
            // Assert local OCSP status is "revoked" for driver RIM cert
            EXPECT_EQ(local_claim["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-ocsp-status"].get<std::string>(), "revoked")
                << "Expected driver RIM cert OCSP status to be revoked in local claim";
            
            // Null out driver RIM cert chain for comparison (local and remote may differ)
            local_claim["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-status"] = nullptr;
            remote_claim["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-status"] = nullptr;
        }
    }},
    {"gpu-unknown-driver-rim-cert", [](
        std::map<std::string, nlohmann::json>& local_claims,
        std::map<std::string, nlohmann::json>& remote_claims,
        int& local_result_code,
        int& remote_result_code
    ) {
        // Process all claims
        for (auto& entry : local_claims) {
            const std::string& ueid = entry.first;
            nlohmann::json& local_claim = entry.second;
            auto& remote_claim = remote_claims.at(ueid);
            
            // Assert local OCSP status is "unknown" for driver RIM cert
            EXPECT_EQ(local_claim["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-ocsp-status"].get<std::string>(), "unknown")
                << "Expected driver RIM cert OCSP status to be unknown in local claim";
            
            // Null out driver RIM cert chain for comparison (local and remote may differ)
            local_claim["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-status"] = nullptr;
            remote_claim["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-status"] = nullptr;
        }
    }}
};

TEST(ClaimsParity, GPULocalVsRemote) { // integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    if(g_cli_env->test_label=="gpu-expired-driver-rim-cert") {
        GTEST_SKIP() << "Skipping test to compare local and remote claims for expired driver rim cert";
        /*
            This is because the driver rim we are using to test for expired cert 
            has a lot of other issues other than the expired cert: mismatching 
            measurements, invaild rim signature

            Therefore, there is a separate which just tests the value of the 
            cert-status claim for rim driver and makes sure that its expired
        */
    }
    RecordProperty("description", "Verify local and remote GPU claims match for same evidence");

    std::string nvattest_bin = g_cli_env->nvattest_bin;
    std::string gpu_evidence_path = "../../../common-test-data/serialized_test_evidence/hopper_evidence.json";
    std::string nonce = "0xe97b23a1718095a0e9e35edca810768c70a6a5a389b705e753b197912bc11576";

    // Run local attestation
    std::string local_cmd = nvattest_bin + " attest --device gpu --verifier local";
    if (g_cli_env->test_mode == "unit") {
        local_cmd += " --nonce " + nonce;
        local_cmd += " --gpu-evidence-source file --gpu-evidence-file " + gpu_evidence_path;
    }
    local_cmd += " --rim-url " + g_cli_env->rim_url;
    local_cmd += " --ocsp-url " + g_cli_env->ocsp_url;

    int local_exit_code = 0;
    std::string local_output = exec_and_capture_output(local_cmd, local_exit_code);

    std::string local_json_str;
    ASSERT_TRUE(extract_json_object(local_output, local_json_str)) << "Did not find JSON in local output. Raw output:\n" << local_output;
    nlohmann::json local_response;
    ASSERT_NO_THROW(local_response = nlohmann::json::parse(local_json_str)) << "Failed to parse local JSON. Raw JSON:\n" << local_json_str;
    ASSERT_TRUE(local_response.contains("result_code")) << "Local response missing result_code. JSON:\n" << local_response.dump(2);
    int local_result_code = local_response["result_code"].get<int>();

    // Run remote attestation
    std::string remote_cmd = nvattest_bin + " attest --device gpu --verifier remote";
    if (g_cli_env->test_mode == "unit") {
        remote_cmd += " --nonce " + nonce;
        remote_cmd += " --gpu-evidence-source file --gpu-evidence-file " + gpu_evidence_path;
    }
    remote_cmd += " --nras-url " + g_cli_env->nras_url;

    int remote_exit_code = 0;
    std::string remote_output = exec_and_capture_output(remote_cmd, remote_exit_code);

    std::string remote_json_str;
    ASSERT_TRUE(extract_json_object(remote_output, remote_json_str)) << "Did not find JSON in remote output. Raw output:\n" << remote_output;
    nlohmann::json remote_response;
    ASSERT_NO_THROW(remote_response = nlohmann::json::parse(remote_json_str)) << "Failed to parse remote JSON. Raw JSON:\n" << remote_json_str;
    ASSERT_TRUE(remote_response.contains("result_code")) << "Remote response missing result_code. JSON:\n" << remote_response.dump(2);
    int remote_result_code = remote_response["result_code"].get<int>();

    // Assert exit codes match result codes
    ASSERT_EQ(local_exit_code, local_result_code) << "Local exit code doesn't match result_code";
    ASSERT_EQ(remote_exit_code, remote_result_code) << "Remote exit code doesn't match result_code";

    // Claims should be present for OK or OVERALL_RESULT_FALSE
    // For other error codes, claims won't be present
    bool local_has_claims = (local_result_code == NVAT_RC_OK || local_result_code == NVAT_RC_OVERALL_RESULT_FALSE);
    bool remote_has_claims = (remote_result_code == NVAT_RC_OK || remote_result_code == NVAT_RC_OVERALL_RESULT_FALSE);
    
    if (local_has_claims && remote_has_claims) {
        ASSERT_TRUE(local_response.contains("claims")) << "Local response missing claims. JSON:\n" << local_response.dump(2);
        ASSERT_TRUE(remote_response.contains("claims")) << "Remote response missing claims. JSON:\n" << remote_response.dump(2);

        // Index claims by ueid
        nlohmann::json local_claims_json = local_response["claims"];
        nlohmann::json remote_claims_json = remote_response["claims"];

        std::map<std::string, nlohmann::json> local_by_ueid = index_claims_by_ueid(local_claims_json);
        std::map<std::string, nlohmann::json> remote_by_ueid = index_claims_by_ueid(remote_claims_json);

        ASSERT_FALSE(local_by_ueid.empty()) << "No local claims with ueid found. Claims:\n" << local_claims_json.dump(2);
        ASSERT_FALSE(remote_by_ueid.empty()) << "No remote claims with ueid found. Claims:\n" << remote_claims_json.dump(2);
        ASSERT_EQ(local_by_ueid.size(), remote_by_ueid.size()) << "Mismatch in number of devices between local and remote";

        // Common field nullifications (hwmodel, eat_nonce)
        for (auto& entry : local_by_ueid) {
            // Null out hwmodel - local SDK returns full certificate CN
            // (e.g. "GH100 A01 GSP BROM") while remote NRAS returns shortened model name (e.g. "GH100")
            entry.second["hwmodel"] = nullptr;
            entry.second["eat_nonce"] = nullptr;
        }
        for (auto& entry : remote_by_ueid) {
            entry.second["hwmodel"] = nullptr;
            entry.second["eat_nonce"] = nullptr;
        }

        // Call label-specific handler with full context (can inspect cert chain data and modify return codes)
        auto handler_it = g_label_claim_handlers.find(g_cli_env->test_label);
        if (handler_it != g_label_claim_handlers.end()) {
            handler_it->second(
                local_by_ueid,
                remote_by_ueid,
                local_result_code,
                remote_result_code
            );
        }

        // Assert return codes are equal (after handler normalization)
        ASSERT_EQ(local_result_code, remote_result_code) 
            << "Local and remote result codes differ after handler normalization. Local: " << local_result_code 
            << ", Remote: " << remote_result_code
            << "\nLocal output:\n" << local_output
            << "\nRemote output:\n" << remote_output;

        // Compare claims for each ueid
        for (const auto& entry : local_by_ueid) {
            const std::string& ueid = entry.first;
            const nlohmann::json& local_claim = entry.second;
            ASSERT_TRUE(remote_by_ueid.count(ueid) > 0) << "UEID " << ueid << " found in local but not in remote claims";
            EXPECT_EQ(local_claim, remote_by_ueid.at(ueid)) 
                << "Claims mismatch for UEID: " << ueid 
                << "\nLocal:\n" << local_claim.dump(2) 
                << "\nRemote:\n" << remote_by_ueid.at(ueid).dump(2);
        }
    } else {
        // If claims are not present for both, just assert return codes match
        ASSERT_EQ(local_result_code, remote_result_code) 
            << "Local and remote result codes differ. Local: " << local_result_code 
            << ", Remote: " << remote_result_code
            << "\nLocal output:\n" << local_output
            << "\nRemote output:\n" << remote_output;
    }
}

TEST(ClaimsParity, SwitchLocalVsRemote) { // integration + unit
    if (g_cli_env->test_mode == "integration" && !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    RecordProperty("description", "Verify local and remote NVSwitch claims match for same evidence");

    std::string nvattest_bin = g_cli_env->nvattest_bin;
    std::string switch_evidence_path = "../../../common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    std::string nonce = "0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";

    // Run local attestation
    std::string local_cmd = nvattest_bin + " attest --device nvswitch --verifier local";
    if (g_cli_env->test_mode == "unit") {
        local_cmd += " --nonce " + nonce;
        local_cmd += " --nvswitch-evidence-source file --nvswitch-evidence-file " + switch_evidence_path;
    }
    local_cmd += " --rim-url " + g_cli_env->rim_url;
    local_cmd += " --ocsp-url " + g_cli_env->ocsp_url;

    int local_exit_code = 0;
    std::string local_output = exec_and_capture_output(local_cmd, local_exit_code);

    std::string local_json_str;
    ASSERT_TRUE(extract_json_object(local_output, local_json_str)) << "Did not find JSON in local output. Raw output:\n" << local_output;
    nlohmann::json local_response;
    ASSERT_NO_THROW(local_response = nlohmann::json::parse(local_json_str)) << "Failed to parse local JSON. Raw JSON:\n" << local_json_str;
    ASSERT_TRUE(local_response.contains("result_code")) << "Local response missing result_code. JSON:\n" << local_response.dump(2);
    int local_result_code = local_response["result_code"].get<int>();

    // Run remote attestation
    std::string remote_cmd = nvattest_bin + " attest --device nvswitch --verifier remote";
    if (g_cli_env->test_mode == "unit") {
        remote_cmd += " --nonce " + nonce;
        remote_cmd += " --nvswitch-evidence-source file --nvswitch-evidence-file " + switch_evidence_path;
    }
    remote_cmd += " --nras-url " + g_cli_env->nras_url;

    int remote_exit_code = 0;
    std::string remote_output = exec_and_capture_output(remote_cmd, remote_exit_code);

    std::string remote_json_str;
    ASSERT_TRUE(extract_json_object(remote_output, remote_json_str)) << "Did not find JSON in remote output. Raw output:\n" << remote_output;
    nlohmann::json remote_response;
    ASSERT_NO_THROW(remote_response = nlohmann::json::parse(remote_json_str)) << "Failed to parse remote JSON. Raw JSON:\n" << remote_json_str;
    ASSERT_TRUE(remote_response.contains("result_code")) << "Remote response missing result_code. JSON:\n" << remote_response.dump(2);
    int remote_result_code = remote_response["result_code"].get<int>();

    // Assert exit codes match result codes
    ASSERT_EQ(local_exit_code, local_result_code) << "Local exit code doesn't match result_code";
    ASSERT_EQ(remote_exit_code, remote_result_code) << "Remote exit code doesn't match result_code";

    // Assert local and remote have the same result code
    ASSERT_EQ(local_result_code, remote_result_code) 
        << "Local and remote result codes differ. Local: " << local_result_code 
        << ", Remote: " << remote_result_code
        << "\nLocal output:\n" << local_output
        << "\nRemote output:\n" << remote_output;

    // If attestation failed with NVAT_RC_OVERALL_RESULT_FALSE, claims will be present, so compare them
    // For other error codes, claims won't be present
    if (local_result_code == NVAT_RC_OK || local_result_code == NVAT_RC_OVERALL_RESULT_FALSE) {
        ASSERT_TRUE(local_response.contains("claims")) << "Local response missing claims. JSON:\n" << local_response.dump(2);
        ASSERT_TRUE(remote_response.contains("claims")) << "Remote response missing claims. JSON:\n" << remote_response.dump(2);

        // Index claims by ueid
        nlohmann::json local_claims = local_response["claims"];
        nlohmann::json remote_claims = remote_response["claims"];
        
        std::map<std::string, nlohmann::json> local_by_ueid = index_claims_by_ueid(local_claims);
        std::map<std::string, nlohmann::json> remote_by_ueid = index_claims_by_ueid(remote_claims);

        ASSERT_FALSE(local_by_ueid.empty()) << "No local claims with ueid found. Claims:\n" << local_claims.dump(2);
        ASSERT_FALSE(remote_by_ueid.empty()) << "No remote claims with ueid found. Claims:\n" << remote_claims.dump(2);
        ASSERT_EQ(local_by_ueid.size(), remote_by_ueid.size()) << "Mismatch in number of devices between local and remote";

        // Compare claims for each ueid
        for (const auto& entry : local_by_ueid) {
            const std::string& ueid = entry.first;
            ASSERT_TRUE(remote_by_ueid.count(ueid) > 0) << "UEID " << ueid << " found in local but not in remote claims";

            // Make copies to modify for comparison
            nlohmann::json local_claim = entry.second;
            nlohmann::json remote_claim = remote_by_ueid.at(ueid);

            // Null out hwmodel before comparison - local SDK returns full certificate CN
            // (e.g. "LS_10 A01 FSP BROM") while remote NRAS returns shortened model name (e.g. "LS_10")
            local_claim["hwmodel"] = nullptr;
            remote_claim["hwmodel"] = nullptr;

            local_claim["eat_nonce"] = nullptr;
            remote_claim["eat_nonce"] = nullptr;

            // Compare all fields
            EXPECT_EQ(local_claim, remote_claim) 
                << "Claims mismatch for UEID: " << ueid 
                << "\nLocal:\n" << local_claim.dump(2) 
                << "\nRemote:\n" << remote_claim.dump(2);
        }
    }
}
