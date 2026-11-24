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
//   - Rubin: policy affirmation depends on the independently confirmed CC mode.
//   - Hopper/Blackwell: must fail, their evidence carries no CoEV.
//
// Rubin runs use TEST_EXPECTED_MODE=spt|mpt|tdisp under either label.

#include <string>

#include "gtest/gtest.h"
#include <nlohmann/json.hpp>

#include "environment.h"
#include "test_utils.h"

namespace {

std::string base_attest_v2_cmd(const std::string& policy) {
    return g_cli_env->nvattest_bin +
           " attest-v2 --evidence-source nvml --format json"
           " --relying-party-policy " + policy +
           " --verify-revocation"
           " --service-key " + g_cli_env->service_key;
}

class RubinAttestV2Test : public ::testing::Test {
protected:
    std::string expected_purpose_;
    std::string matching_policy_;
    std::string opposite_policy_;

    void SetUp() override {
        if (!g_cli_env->expects_gpu_v2_attestation()) {
            GTEST_SKIP() << "Skipping: v2 GPU tests not selected for this run";
        }
        const std::string& mode = g_cli_env->expected_mode;
        const bool tdisp = mode == "tdisp";
        expected_purpose_ = tdisp ? "TDISP" : (mode == "spt" ? "CC SPT" : "CC MPT");
        matching_policy_ = tdisp ? "builtin:cc-tdisp" : "builtin:cc-bounce-buffer";
        opposite_policy_ = tdisp ? "builtin:cc-bounce-buffer" : "builtin:cc-tdisp";
    }

    void assert_rubin_appraisal(const std::string& policy, int expected_exit,
                                const std::string& expected_purpose) {
        int exit_code = 0;
        std::string output = exec_and_capture_output(base_attest_v2_cmd(policy), exit_code);
        ASSERT_EQ(exit_code, expected_exit) << "attest-v2 on Rubin:\n" << output;

        std::string json_str;
        ASSERT_TRUE(extract_json_object(output, json_str)) << "No JSON in output:\n" << output;
        nlohmann::json response;
        ASSERT_NO_THROW(response = nlohmann::json::parse(json_str));
        ASSERT_TRUE(response.is_object()) << response.dump(2);

        ASSERT_TRUE(response.contains("ear_status")) << response.dump(2);
        EXPECT_EQ(response["ear_status"], "affirming") << response.dump(2);
        ASSERT_TRUE(response.contains("submods")) << response.dump(2);
        const auto& submods = response["submods"];
        ASSERT_TRUE(submods.is_object()) << response.dump(2);
        ASSERT_FALSE(submods.empty()) << "No GPU submods in EAR";
        for (const auto& submod_entry : submods.items()) {
            EXPECT_EQ(submod_entry.key().rfind("gpu_", 0), 0U) << submod_entry.key();
            const auto& submod = submod_entry.value();
            ASSERT_TRUE(submod.is_object()) << submod.dump(2);
            ASSERT_TRUE(submod.contains("ear_status")) << submod.dump(2);
            EXPECT_EQ(submod["ear_status"], "affirming") << submod.dump(2);
            ASSERT_TRUE(submod.contains("ear_nvidia_purpose")) << submod.dump(2);
            EXPECT_EQ(submod["ear_nvidia_purpose"], expected_purpose) << submod.dump(2);
            ASSERT_TRUE(submod.contains("ear_verifier_claims")) << submod.dump(2);
            const auto& claims = submod["ear_verifier_claims"];
            ASSERT_TRUE(claims.is_object()) << submod.dump(2);
            ASSERT_TRUE(claims.contains("ear_nvidia_evidence")) << submod.dump(2);
            const auto& evidence = claims["ear_nvidia_evidence"];
            ASSERT_TRUE(evidence.is_object()) << submod.dump(2);
            EXPECT_TRUE(evidence.value("signature_verified", false)) << submod.dump(2);
            ASSERT_TRUE(evidence.contains("nonce_match")) << submod.dump(2);
            EXPECT_EQ(evidence["nonce_match"], true) << submod.dump(2);
            ASSERT_TRUE(claims.contains("ear_nvidia_rims")) << "No RIMs located:\n" << submod.dump(2);
            const auto& rims = claims["ear_nvidia_rims"];
            ASSERT_TRUE(rims.is_array()) << submod.dump(2);
            ASSERT_FALSE(rims.empty()) << "No RIMs located:\n" << submod.dump(2);
            for (const auto& rim : rims) {
                EXPECT_TRUE(rim.value("fetched", false)) << rim.dump(2);
            }
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
    std::string output = exec_and_capture_output(
        base_attest_v2_cmd("builtin:cc-bounce-buffer"), exit_code);
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
    assert_rubin_appraisal(matching_policy_, 0, expected_purpose_);
}

TEST_F(RubinAttestV2Test, RejectsOppositeModePolicy) {
    assert_rubin_appraisal(opposite_policy_, 1, expected_purpose_);
}

TEST_F(HopperAttestV2Test, Fails) {
    assert_no_reference_values("Hopper");
}

TEST_F(BlackwellAttestV2Test, Fails) {
    assert_no_reference_values("Blackwell");
}
