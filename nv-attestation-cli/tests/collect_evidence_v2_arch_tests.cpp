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

// Integration tests for collect-evidence-v2 --evidence-source nvml on live GPU machines.
//
// collect-evidence-v2 with the NVML source has no architecture filter and should
// succeed on Rubin, Hopper, and Blackwell. The output is a CMW JSON collection.
//
// Required env (TEST_MODE=integration throughout; the label selects the arch):
//   NVAT_CLI_TEST_LABEL=rubin-nvml
//   NVAT_CLI_TEST_LABEL=hopper-nvml
//   NVAT_CLI_TEST_LABEL=blackwell-nvml

#include <string>

#include "gtest/gtest.h"
#include <nlohmann/json.hpp>

#include "environment.h"
#include "test_utils.h"

namespace {

// Runs collect-evidence-v2 --evidence-source nvml --format json and validates
// that the output is a valid CMW collection JSON.
void assert_nvml_collection_succeeds(const std::string& arch_label) {
    const std::string cmd =
        g_cli_env->nvattest_bin +
        " collect-evidence-v2 --evidence-source nvml --format json";

    int exit_code = 0;
    std::string output = exec_and_capture_output(cmd, exit_code);
    ASSERT_EQ(exit_code, 0)
        << "collect-evidence-v2 failed on " << arch_label << ":\n" << output;

    // Success path outputs the raw CMW JSON (no result_code wrapper).
    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str))
        << "No JSON in output:\n" << output;
    nlohmann::json cmw = nlohmann::json::parse(json_str, nullptr, /*allow_exceptions=*/false);
    ASSERT_FALSE(cmw.is_discarded()) << "Output is not valid JSON:\n" << output;
    ASSERT_TRUE(cmw.contains("__cmwc_t"))
        << "CMW output missing __cmwc_t tag:\n" << cmw.dump(2);
    ASSERT_TRUE(cmw.contains("gpu_0"))
        << "CMW output missing gpu_0 entry:\n" << cmw.dump(2);
}

class RubinCollectV2Test : public ::testing::Test {
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

class HopperCollectV2Test : public ::testing::Test {
protected:
    void SetUp() override {
        if (g_cli_env->test_label != "hopper-nvml") {
            GTEST_SKIP() << "Skipping: requires NVAT_CLI_TEST_LABEL=hopper-nvml";
        }
        if (g_cli_env->test_mode != "integration") {
            GTEST_SKIP() << "Skipping: requires TEST_MODE=integration";
        }
    }
};

class BlackwellCollectV2Test : public ::testing::Test {
protected:
    void SetUp() override {
        if (g_cli_env->test_label != "blackwell-nvml") {
            GTEST_SKIP() << "Skipping: requires NVAT_CLI_TEST_LABEL=blackwell-nvml";
        }
        if (g_cli_env->test_mode != "integration") {
            GTEST_SKIP() << "Skipping: requires TEST_MODE=integration";
        }
    }
};

} // namespace

TEST_F(RubinCollectV2Test, NvmlSucceeds) {
    assert_nvml_collection_succeeds("rubin");
}

TEST_F(HopperCollectV2Test, NvmlSucceeds) {
    assert_nvml_collection_succeeds("hopper");
}

TEST_F(BlackwellCollectV2Test, NvmlSucceeds) {
    assert_nvml_collection_succeeds("blackwell");
}
