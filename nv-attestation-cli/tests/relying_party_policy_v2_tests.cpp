/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "relying_party_policy_v2.h"
#include "nvat.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

namespace {

using nlohmann::json;
constexpr const char* kEarProfile = "tag:nvidia.com,2026:ear/profiles/composite/generic/pre-1.0.0";
constexpr const char* kGpuProfile = "tag:nvidia.com,2026-05:ear/profiles/gpu/1.0.0";

json submod(const char* profile, const char* purpose) {
    return {{"eat_profile", profile},
            {"ear_nvidia_purpose", purpose},
            {"ear_status", "affirming"},
            {"ear_verifier_claims", {{"ear_nvidia_evidence", {{"nonce_match", true}}}}}};
}

json valid_ear() {
    return {{"eat_profile", kEarProfile},
            {"ear_status", "affirming"},
            {"submods", {{"gpu_0", submod(kGpuProfile, "CC MPT")},
                         {"gpu_1", submod(kGpuProfile, "CC MPT")}}}};
}

class RelyingPartyPolicyV2 : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        ASSERT_EQ(nvat_sdk_init(nullptr), NVAT_RC_OK);
    }
    static void TearDownTestSuite() {
        nvat_sdk_shutdown();
    }
    void SetUp() override {
        ASSERT_EQ(nvat_relying_party_policy_create_rego_from_str(
                      &bounce_policy_, nvattest::builtin_relying_party_policy_v2("cc-bounce-buffer")),
                  NVAT_RC_OK);
        ASSERT_EQ(nvat_relying_party_policy_create_rego_from_str(
                      &tdisp_policy_, nvattest::builtin_relying_party_policy_v2("cc-tdisp")),
                  NVAT_RC_OK);
    }
    void TearDown() override {
        if (bounce_policy_ != nullptr) nvat_relying_party_policy_free(&bounce_policy_);
        if (tdisp_policy_ != nullptr) nvat_relying_party_policy_free(&tdisp_policy_);
    }
    nvat_rc_t evaluate(const json& ear, nvat_relying_party_policy_t policy = nullptr) {
        const std::string encoded = ear.dump();
        return nvat_apply_relying_party_policy_to_ear(
            policy == nullptr ? bounce_policy_ : policy, encoded.c_str());
    }
    nvat_relying_party_policy_t bounce_policy_ = nullptr;
    nvat_relying_party_policy_t tdisp_policy_ = nullptr;
};

TEST_F(RelyingPartyPolicyV2, SeparatesGpuPurposeModes) {
    auto ear = valid_ear();
    ear["submods"]["gpu_0"]["eat_profile"] =
        "tag:nvidia.com,2026-05:ear/profiles/gpu/1.7.3";
    for (const char* purpose : {"CC SPT", "CC MPT"}) {
        ear["submods"]["gpu_0"]["ear_nvidia_purpose"] = purpose;
        EXPECT_EQ(evaluate(ear), NVAT_RC_OK) << purpose;
        EXPECT_EQ(evaluate(ear, tdisp_policy_), NVAT_RC_RP_POLICY_MISMATCH) << purpose;
    }
    ear["submods"]["gpu_0"]["ear_nvidia_purpose"] = "TDISP";
    ear["submods"]["gpu_1"]["ear_nvidia_purpose"] = "TDISP";
    EXPECT_EQ(evaluate(ear), NVAT_RC_RP_POLICY_MISMATCH);
    EXPECT_EQ(evaluate(ear, tdisp_policy_), NVAT_RC_OK);

    ear["submods"]["gpu_1"]["ear_nvidia_purpose"] = "CC MPT";
    EXPECT_EQ(evaluate(ear), NVAT_RC_RP_POLICY_MISMATCH);
    EXPECT_EQ(evaluate(ear, tdisp_policy_), NVAT_RC_RP_POLICY_MISMATCH);

    for (const char* purpose : {"CC_SPT", "CC_MPT"}) {
        ear["submods"]["gpu_0"]["ear_nvidia_purpose"] = purpose;
        EXPECT_EQ(evaluate(ear), NVAT_RC_RP_POLICY_MISMATCH) << purpose;
    }
}

TEST_F(RelyingPartyPolicyV2, RejectsMissingGpuAndInvalidSubmoduleClaims) {
    auto ear = valid_ear();
    ear["submods"]["gpu_1"]["ear_verifier_claims"]["ear_nvidia_evidence"]["nonce_match"] = false;
    EXPECT_EQ(evaluate(ear), NVAT_RC_RP_POLICY_MISMATCH);
    ear = valid_ear();
    ear["submods"]["gpu_1"]["ear_status"] = "contraindicated";
    EXPECT_EQ(evaluate(ear), NVAT_RC_RP_POLICY_MISMATCH);
    ear = valid_ear();
    ear["ear_status"] = "contraindicated";
    EXPECT_EQ(evaluate(ear), NVAT_RC_RP_POLICY_MISMATCH);
    ear = valid_ear();
    ear["eat_profile"] = "tag:nvidia.com,2026:ear/profiles/composite/generic/pre-2.0.0";
    EXPECT_EQ(evaluate(ear), NVAT_RC_RP_POLICY_MISMATCH);
    ear = valid_ear();
    ear["submods"]["gpu_1"]["ear_nvidia_purpose"] = "DEFAULT";
    EXPECT_EQ(evaluate(ear), NVAT_RC_RP_POLICY_MISMATCH);
    ear = valid_ear();
    ear["submods"]["gpu_1"].erase("ear_nvidia_purpose");
    EXPECT_EQ(evaluate(ear), NVAT_RC_RP_POLICY_MISMATCH);
    ear = valid_ear();
    ear["submods"]["gpu_1"]["ear_verifier_claims"]["ear_nvidia_evidence"].erase("nonce_match");
    EXPECT_EQ(evaluate(ear), NVAT_RC_RP_POLICY_MISMATCH);
    ear = valid_ear();
    ear["submods"] = {{"cx9", submod("cx9-profile", "INFRA")}};
    EXPECT_EQ(evaluate(ear), NVAT_RC_RP_POLICY_MISMATCH);
    ear = valid_ear();
    ear["submods"]["gpu_0"]["eat_profile"] =
        "tag:nvidia.com,2026-05:ear/profiles/gpu/2.0.0";
    ear["submods"]["gpu_1"]["eat_profile"] =
        "tag:nvidia.com,2026-05:ear/profiles/gpu/10.0.0";
    EXPECT_EQ(evaluate(ear), NVAT_RC_RP_POLICY_MISMATCH);
    ear = valid_ear();
    ear["submods"]["cx9"] = submod(
        "tag:nvidia.com,2026-05:ear/profiles/cx9/1.0.0", "INFRA");
    EXPECT_EQ(evaluate(ear), NVAT_RC_RP_POLICY_MISMATCH);
    ear["submods"]["gpu_0"]["ear_nvidia_purpose"] = "TDISP";
    ear["submods"]["gpu_1"]["ear_nvidia_purpose"] = "TDISP";
    EXPECT_EQ(evaluate(ear, tdisp_policy_), NVAT_RC_RP_POLICY_MISMATCH);
}
} // namespace
