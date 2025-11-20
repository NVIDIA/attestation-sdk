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
#include "collect_evidence.h"
#include "nvat.h"
#include "environment.h"
#include "test_utils.h"
#include "nvattest_options.h"

TEST_F(CliTest, CollectEvidenceGPU) { //integration
    if (g_cli_env->test_mode != "integration" || !g_cli_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    std::string nvattest_bin = "../nvattest";
    std::string cmd = nvattest_bin + " collect-evidence";
    cmd += " --device gpu";
    cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
    
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

TEST_F(CliTest, CollectEvidenceNVSwitch) { //integration
    if (g_cli_env->test_mode != "integration" || !g_cli_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }
    std::string nvattest_bin = "../nvattest";
    std::string cmd = nvattest_bin + " collect-evidence";
    cmd += " --device nvswitch";
    cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
    
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

