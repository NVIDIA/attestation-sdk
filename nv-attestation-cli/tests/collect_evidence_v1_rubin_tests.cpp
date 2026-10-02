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

// Integration tests for the v1 pipeline (collect-evidence / attest) on Rubin machines.
//
// collect-evidence has no architecture filter and succeeds on Rubin.
// attest (v1) runs evidence through LocalGpuVerifier, which explicitly rejects
// Rubin with NVAT_RC_GPU_ARCHITECTURE_NOT_SUPPORTED (gpu/verify.cpp:39-48).
//
// Required env: NVAT_CLI_TEST_LABEL=rubin-nvml  TEST_MODE=integration

#include <string>

#include "gtest/gtest.h"
#include <nlohmann/json.hpp>

#include "environment.h"
#include "nvat.h"
#include "test_utils.h"

class RubinNvmlV1Test : public ::testing::Test {
protected:
    void SetUp() override {
        if (g_cli_env->test_label != "rubin-nvml") {
            GTEST_SKIP() << "Skipping: requires NVAT_CLI_TEST_LABEL=rubin-nvml";
        }
        if (g_cli_env->test_mode != "integration") {
            GTEST_SKIP() << "Skipping: requires TEST_MODE=integration";
        }
    }
};

TEST_F(RubinNvmlV1Test, CollectEvidenceSucceeds) {
    std::string cmd = g_cli_env->nvattest_bin + " collect-evidence --device gpu --format json";
    cmd += " --nonce 0x931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0) << "collect-evidence unexpectedly failed on Rubin:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "No JSON in output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str));
    ASSERT_TRUE(response.contains("result_code")) << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(), 0) << response.dump(2);
}

TEST_F(RubinNvmlV1Test, AttestFailsWithArchitectureNotSupported) {
    // LocalGpuVerifier rejects Rubin — this must not pass.
    std::string cmd = g_cli_env->nvattest_bin + " attest --device gpu --verifier local --format json";
    cmd += " --rim-url " + g_cli_env->rim_url;
    cmd += " --ocsp-url " + g_cli_env->ocsp_url;

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_NE(exit_code, 0) << "attest unexpectedly succeeded on Rubin:\n" << output;

    // Assert the specific rejection, so an unrelated failure cannot pass as one.
    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "No JSON in output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str));
    ASSERT_TRUE(response.contains("result_code")) << response.dump(2);
    EXPECT_EQ(response["result_code"].get<int>(),
              NVAT_RC_GPU_ARCHITECTURE_NOT_SUPPORTED)
        << response.dump(2);
}
