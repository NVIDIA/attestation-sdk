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

// Integration tests for attest-v2 --evidence-source nvml on live GPU machines.
//
// attest-v2 is intended for Rubin machines only:
//   - Rubin: must pass.
//   - Hopper/Blackwell: must fail, their evidence carries no CoEV.
//
// Required env per label:
//   rubin-nvml    → TEST_MODE=integration
//   hopper-nvml   → TEST_MODE=integration
//   blackwell-nvml→ TEST_MODE=integration

#include <string>

#include "gtest/gtest.h"
#include <nlohmann/json.hpp>

#include "environment.h"
#include "test_utils.h"

namespace {

std::string base_attest_v2_cmd() {
    return g_cli_env->nvattest_bin +
           " attest-v2 --evidence-source nvml --format json --no-verify-revocation";
}

class RubinAttestV2Test : public ::testing::Test {
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

class HopperAttestV2Test : public ::testing::Test {
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

class BlackwellAttestV2Test : public ::testing::Test {
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

// Hopper and Blackwell evidence carries no CoEV, so nothing is appraised.
// Exit 1 is "ran, did not affirm"; exit 2 would be "could not collect or parse".
void assert_no_reference_values(const std::string& arch_label) {
    int exit_code = 0;
    std::string output = exec_and_capture_output(base_attest_v2_cmd(), exit_code);
    ASSERT_EQ(exit_code, 1)
        << "attest-v2 did not report a failed appraisal on " << arch_label
        << ":\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "No JSON in output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str));
    ASSERT_TRUE(response.contains("evidence_items")) << response.dump(2);

    const auto& items = response["evidence_items"];
    ASSERT_TRUE(items.is_array()) << response.dump(2);
    ASSERT_FALSE(items.empty()) << "No evidence items in result";

    for (const auto& item : items) {
        EXPECT_FALSE(item.contains("corims")) << item.dump(2);
        ASSERT_TRUE(item.contains("match")) << item.dump(2);
        EXPECT_TRUE(item["match"].value("outcomes", nlohmann::json::array()).empty())
            << item["match"].dump(2);
    }
}

} // namespace

TEST_F(RubinAttestV2Test, Passes) {
    int exit_code = 0;
    std::string output = exec_and_capture_output(base_attest_v2_cmd(), exit_code);
    ASSERT_EQ(exit_code, 0) << "attest-v2 failed on Rubin:\n" << output;

    std::string json_str;
    ASSERT_TRUE(extract_json_object(output, json_str)) << "No JSON in output:\n" << output;
    nlohmann::json response;
    ASSERT_NO_THROW(response = nlohmann::json::parse(json_str));
    ASSERT_TRUE(response.contains("evidence_items")) << response.dump(2);

    const auto& items = response["evidence_items"];
    ASSERT_TRUE(items.is_array());
    ASSERT_FALSE(items.empty()) << "No evidence items in result";

    for (const auto& item : items) {
        ASSERT_TRUE(item.contains("evidence")) << item.dump(2);
        EXPECT_TRUE(item["evidence"].value("signature_verified", false)) << item.dump(2);

        ASSERT_TRUE(item.contains("corims")) << "No RIMs located:\n" << item.dump(2);
        for (const auto& corim : item["corims"]) {
            EXPECT_TRUE(corim.value("fetched", false)) << corim.dump(2);
        }
    }
}

TEST_F(HopperAttestV2Test, Fails) {
    assert_no_reference_values("Hopper");
}

TEST_F(BlackwellAttestV2Test, Fails) {
    assert_no_reference_values("Blackwell");
}
