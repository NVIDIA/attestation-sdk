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

//stdlibs
#include <fstream>
#include <thread>
#include <memory>

//third party
#include "gtest/gtest.h"
#include "gmock/gmock.h"

//this sdk
#include "nv_attestation/attestation.h"
#include "nv_attestation/gpu/evidence.h"
#include "nv_attestation/rim.h"
#include "nv_attestation/switch/evidence.h"
#include "nv_attestation/gpu/verify.h"
#include "nv_attestation/switch/verify.h"
#include "nv_attestation/claims.h"
#include "nv_attestation/claims_evaluator.h"
#include "nv_attestation/verify.h"
#include "test_utils.h"
#include "switch_test_utils.h"
#include "environment.h"
#include "nvat.h"

using namespace nvattestation;
using ::testing::Return;
using ::testing::_;
using ::testing::DoAll;
using ::testing::SetArgReferee;
using ::testing::Invoke;

class AttestationTest : public ::testing::Test {
    
};

TEST_F(AttestationTest, MockSuccessGpuAttestationDefaultContext) {
    Error err;
    auto mock_evidence_source = std::make_shared<MockGpuEvidenceSource>();
    mock_evidence_source->setup_success_behavior();

    AttestationContext ctx;
    ctx.set_verifier_type(VerifierType::Local);
    ctx.set_gpu_evidence_source(mock_evidence_source);
    ctx.set_service_key(g_env->service_key);
    ctx.set_default_ocsp_url("https://ocsp.ndis-stg.nvidia.com");
    ctx.set_default_rim_store_url("https://rim-internal.attestation.nvidia.com/internal");
    ctx.set_default_nras_url("https://nras.attestation-stg.nvidia.com");

    ClaimsCollection claims {};
    std::string detached_eat;
    err = ctx.attest_device({}, &detached_eat, claims);
    ASSERT_EQ(err, Error::Ok) << "attestation process did not fail";
}

TEST_F(AttestationTest, MockFailedEvidenceCollectionGpuAttestation) {
    Error err;
    auto mock_evidence_source = std::make_shared<MockGpuEvidenceSource>();

    // Set up mock to return failure directly
    EXPECT_CALL(*mock_evidence_source, get_evidence(_, _))
        .WillRepeatedly(Return(Error::Unknown));

    auto local_gpu_verifier = std::make_shared<LocalGpuVerifier>();

    AttestationContext ctx;
    ctx.set_gpu_evidence_source(mock_evidence_source);
    ctx.set_gpu_verifier(local_gpu_verifier);
    ctx.set_service_key(g_env->service_key);

    ClaimsCollection claims {};
    std::string detached_eat;
    err = ctx.attest_device({}, &detached_eat, claims);
    ASSERT_EQ(err, Error::Unknown) << "attest_gpu should have failed";
}

TEST(AttestationTestCApi, GpuHighLevelApiLocalVerify) { // integration + unit 
    RecordProperty("description", "Verify GPU evidence using high-level API. Local verifier.");
    if (g_env->test_mode == "integration" && !g_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }

    nvat_attestation_ctx_t ctx = nullptr;
    ASSERT_EQ(nvat_attestation_ctx_create(&ctx), NVAT_RC_OK);
    ASSERT_NE(ctx, nullptr);

    nvat_attestation_ctx_set_verifier_type(ctx, NVAT_VERIFY_LOCAL);
    if (g_env->test_mode == "unit") {
        std::string gpu_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/hopper_evidence.json";
        ASSERT_EQ(nvat_attestation_ctx_set_gpu_evidence_source_json_file(ctx, gpu_evidence_path.c_str()), NVAT_RC_OK);
    }

    ASSERT_EQ(nvat_attestation_ctx_set_default_ocsp_url(ctx, "https://ocsp.ndis-stg.nvidia.com"), NVAT_RC_OK);
    ASSERT_EQ(nvat_attestation_ctx_set_default_rim_store_url(ctx, "https://rim-internal.attestation.nvidia.com/internal"), NVAT_RC_OK);
    ASSERT_EQ(nvat_attestation_ctx_set_default_nras_url(ctx, "https://nras.attestation-stg.nvidia.com"), NVAT_RC_OK);

    nvat_claims_collection_t claims = nullptr;
    nvat_nonce_t nonce = nullptr;
    nvat_str_t detached_eat = nullptr;
    std::string nonce_str = evidence_to_nonce_map.find("hopper_latest")->second;
    ASSERT_EQ(nvat_nonce_from_hex(&nonce, nonce_str.c_str()), NVAT_RC_OK);
    nvat_rc_t err = nvat_attest_device(ctx, nonce, &detached_eat, &claims);

    if (err != NVAT_RC_OK) {
        if (claims) {
            nvat_claims_collection_free(&claims);
        }
        nvat_attestation_ctx_free(&ctx);
        GTEST_FAIL() << "Attestation failed with error: " << nvat_rc_to_string(err);
        return;
    }

    ASSERT_EQ(err, NVAT_RC_OK);
    ASSERT_NE(claims, nullptr);
    ASSERT_NE(detached_eat, nullptr);

    char * detached_eat_data = nullptr;
    ASSERT_EQ(nvat_str_get_data(detached_eat, &detached_eat_data), NVAT_RC_OK);
    ASSERT_NE(detached_eat_data, nullptr);
    LOG_DEBUG("Detached EAT: " << detached_eat_data);
    nvat_str_free(&detached_eat);

    nvat_claims_collection_free(&claims);
    nvat_nonce_free(&nonce);
    nvat_attestation_ctx_free(&ctx);
}

TEST(AttestationTestCApi, GpuHighLevelApiRemoteVerify) { // integration + unit 
    RecordProperty("description", "Verify GPU evidence using high-level API. Remote verifier.");
    if (g_env->test_mode == "integration" && !g_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }

    nvat_attestation_ctx_t ctx = nullptr;
    ASSERT_EQ(nvat_attestation_ctx_create(&ctx), NVAT_RC_OK);
    ASSERT_NE(ctx, nullptr);

    nvat_attestation_ctx_set_verifier_type(ctx, NVAT_VERIFY_REMOTE);
    nvat_attestation_ctx_set_service_key(ctx, g_env->service_key.c_str());
    if (g_env->test_mode == "unit") {
        std::string gpu_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/hopper_evidence.json";
        ASSERT_EQ(nvat_attestation_ctx_set_gpu_evidence_source_json_file(ctx, gpu_evidence_path.c_str()), NVAT_RC_OK);
    }

    ASSERT_EQ(nvat_attestation_ctx_set_default_ocsp_url(ctx, "https://ocsp.ndis-stg.nvidia.com"), NVAT_RC_OK);
    ASSERT_EQ(nvat_attestation_ctx_set_default_rim_store_url(ctx, "https://rim-internal.attestation.nvidia.com/internal"), NVAT_RC_OK);
    ASSERT_EQ(nvat_attestation_ctx_set_default_nras_url(ctx, "https://nras.attestation-stg.nvidia.com"), NVAT_RC_OK);

    nvat_claims_collection_t claims = nullptr;
    nvat_nonce_t nonce = nullptr;
    nvat_str_t detached_eat = nullptr;
    std::string nonce_str = evidence_to_nonce_map.find("hopper_latest")->second;
    ASSERT_EQ(nvat_nonce_from_hex(&nonce, nonce_str.c_str()), NVAT_RC_OK);
    nvat_rc_t err = nvat_attest_device(ctx, nonce, &detached_eat, &claims);
    
    if (err != NVAT_RC_OK) {
        if (claims) {
            nvat_claims_collection_free(&claims);
        }
        nvat_attestation_ctx_free(&ctx);
        GTEST_FAIL() << "Attestation failed with error: " << nvat_rc_to_string(err);
        return;
    }

    ASSERT_NE(claims, nullptr);

    nvat_claims_collection_free(&claims);
    nvat_str_free(&detached_eat);
    nvat_nonce_free(&nonce);
    nvat_attestation_ctx_free(&ctx);
}

TEST(AttestationTestCApi, SwitchHighLevelApiLocalVerify) { // integration + unit 
    RecordProperty("description", "Verify switch evidence using high-level API. Local verifier.");
    if (g_env->test_mode == "integration" && !g_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }

    nvat_attestation_ctx_t ctx = nullptr;
    ASSERT_EQ(nvat_attestation_ctx_create(&ctx), NVAT_RC_OK);
    ASSERT_NE(ctx, nullptr);
    ASSERT_EQ(nvat_attestation_ctx_set_device_type(ctx, NVAT_DEVICE_NVSWITCH), NVAT_RC_OK);

    nvat_attestation_ctx_set_verifier_type(ctx, NVAT_VERIFY_LOCAL);
    nvat_attestation_ctx_set_service_key(ctx, g_env->service_key.c_str());
    if (g_env->test_mode == "unit") {
        std::string switch_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/switch_evidence_ls10.json";
        ASSERT_EQ(nvat_attestation_ctx_set_switch_evidence_source_json_file(ctx, switch_evidence_path.c_str()), NVAT_RC_OK);
    }

    ASSERT_EQ(nvat_attestation_ctx_set_default_ocsp_url(ctx, "https://ocsp.ndis-stg.nvidia.com"), NVAT_RC_OK);
    ASSERT_EQ(nvat_attestation_ctx_set_default_rim_store_url(ctx, "https://rim-internal.attestation.nvidia.com/internal"), NVAT_RC_OK);
    ASSERT_EQ(nvat_attestation_ctx_set_default_nras_url(ctx, "https://nras.attestation-stg.nvidia.com"), NVAT_RC_OK);

    nvat_claims_collection_t claims = nullptr;
    nvat_nonce_t nonce = nullptr;
    nvat_str_t detached_eat = nullptr;
    ASSERT_EQ(nvat_nonce_from_hex(&nonce, "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"), NVAT_RC_OK);
    nvat_rc_t err = nvat_attest_device(ctx, nonce, &detached_eat, &claims);
    ASSERT_EQ(err, NVAT_RC_OK) << "Attestation failed with error: " << nvat_rc_to_string(err);
    ASSERT_NE(claims, nullptr);
    ASSERT_NE(detached_eat, nullptr);

    char * detached_eat_data = nullptr;
    ASSERT_EQ(nvat_str_get_data(detached_eat, &detached_eat_data), NVAT_RC_OK);
    ASSERT_NE(detached_eat_data, nullptr);
    LOG_DEBUG("Detached EAT: " << detached_eat_data);
    nvat_str_free(&detached_eat);

    nvat_claims_collection_free(&claims);
    nvat_str_free(&detached_eat);
    nvat_nonce_free(&nonce);
    nvat_attestation_ctx_free(&ctx);
} 

TEST(AttestationTestCApi, SwitchHighLevelApiRemoteVerify) { // integration + unit 
    RecordProperty("description", "Verify switch evidence using high-level API. Remote verifier.");
    if (g_env->test_mode == "integration" && !g_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }

    nvat_attestation_ctx_t ctx = nullptr;
    ASSERT_EQ(nvat_attestation_ctx_create(&ctx), NVAT_RC_OK);
    ASSERT_EQ(nvat_attestation_ctx_set_device_type(ctx, NVAT_DEVICE_NVSWITCH), NVAT_RC_OK);
    ASSERT_NE(ctx, nullptr);


    nvat_attestation_ctx_set_verifier_type(ctx, NVAT_VERIFY_REMOTE);
    nvat_attestation_ctx_set_service_key(ctx, g_env->service_key.c_str());
    if (g_env->test_mode == "unit") {
        std::string switch_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/switch_evidence_ls10.json";
        ASSERT_EQ(nvat_attestation_ctx_set_switch_evidence_source_json_file(ctx, switch_evidence_path.c_str()), NVAT_RC_OK);
    }

    ASSERT_EQ(nvat_attestation_ctx_set_default_ocsp_url(ctx, "https://ocsp.ndis-stg.nvidia.com"), NVAT_RC_OK);
    ASSERT_EQ(nvat_attestation_ctx_set_default_rim_store_url(ctx, "https://rim-internal.attestation.nvidia.com/internal"), NVAT_RC_OK);
    ASSERT_EQ(nvat_attestation_ctx_set_default_nras_url(ctx, "https://nras.attestation-stg.nvidia.com"), NVAT_RC_OK);

    nvat_claims_collection_t claims = nullptr;
    nvat_nonce_t nonce = nullptr;
    nvat_str_t detached_eat = nullptr;
    ASSERT_EQ(nvat_nonce_from_hex(&nonce, "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"), NVAT_RC_OK);
    nvat_rc_t err = nvat_attest_device(ctx, nonce, &detached_eat, &claims);
    ASSERT_EQ(err, NVAT_RC_OK) << "Attestation failed with error: " << nvat_rc_to_string(err);
    ASSERT_NE(claims, nullptr);

    nvat_claims_collection_free(&claims);
    nvat_str_free(&detached_eat);
    nvat_nonce_free(&nonce);
    nvat_attestation_ctx_free(&ctx);
}
