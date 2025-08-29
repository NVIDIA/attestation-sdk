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

TEST_F(AttestationTest, MockSuccessGpuAttestation) {
    Error err;
    auto mock_evidence_source = std::make_shared<MockGpuEvidenceSource>();
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_default();
    mock_evidence_source->setup_success_behavior(mock_data);

    auto rim_store = std::make_shared<NvRemoteRimStoreImpl>();
    err = NvRemoteRimStoreImpl::init_from_env(*rim_store, "https://rim.attestation.nvidia.com", HttpOptions());
    ASSERT_EQ(err, Error::Ok);
    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "https://ocsp.ndis.nvidia.com", HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    auto local_gpu_verifier = std::make_shared<LocalGpuVerifier>();
    err = LocalGpuVerifier::create(*local_gpu_verifier, rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(err, Error::Ok);

    AttestationContext ctx;
    ctx.set_gpu_evidence_source(mock_evidence_source);
    ctx.set_gpu_verifier(local_gpu_verifier);

    ClaimsCollection claims {};
    std::string detached_eat;
    err = ctx.attest_device({}, &detached_eat, claims);
    ASSERT_EQ(err, Error::Ok) << "attestation process did not fail";
    ASSERT_FALSE(claims.empty()) << "attestation should have produced claims";
}

TEST_F(AttestationTest, MockSuccessGpuAttestationDefaultContext) {
    Error err;
    auto mock_evidence_source = std::make_shared<MockGpuEvidenceSource>();
    mock_evidence_source->setup_success_behavior();

    AttestationContext ctx;
    ctx.set_verifier_type(VerifierType::Local);
    ctx.set_gpu_evidence_source(mock_evidence_source);

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

    ClaimsCollection claims {};
    std::string detached_eat;
    err = ctx.attest_device({}, &detached_eat, claims);
    ASSERT_EQ(err, Error::Unknown) << "attest_gpu should have failed";
}

TEST_F(AttestationTest, MockSuccessSwitchAttestation) {
    auto mock_evidence_source = std::make_shared<MockSwitchEvidenceSource>();

    // Set up mock to return successful evidence collection with real data
    MockSwitchEvidenceData mock_data = MockSwitchEvidenceData::create_default();
    mock_evidence_source->setup_success_behavior(mock_data);


    auto mock_rim_store = std::make_shared<MockNvRemoteRimStore>();
    // the sample evidence for switch we are using here is from stg env and is an internal RIM
    // therefore that schema is different from public RIM. the existing nvremote rim store does not
    // support this. so we need to mock the get_rim function to create the RIM document manually
    // from manually downloaded and saved RIM file.

    EXPECT_CALL(*mock_rim_store, get_rim(_, _))
        .WillOnce(Invoke([](const std::string& rim_id, RimDocument& out_rim_document) -> Error {
            if (rim_id != "NV_SWITCH_BIOS_5612_0002_890_9610550001") {
                LOG_ERROR("RIM ID mismatch: " << rim_id);
                return Error::RimNotFound;
            }
            std::ifstream file("testdata/switchVBIOSRim_NV_SWITCH_BIOS_5612_0002_890_9610550001.xml");
            std::string xml_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            Error error = RimDocument::create_from_rim_data(xml_data, out_rim_document);
            return error;
        }));
    std::shared_ptr<NvHttpOcspClient> ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis-stg.nvidia.com", HttpOptions());
    ASSERT_EQ(error, Error::Ok);

    auto local_switch_verifier = std::make_shared<LocalSwitchVerifier>();
    Error err = LocalSwitchVerifier::create(*local_switch_verifier, mock_rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(err, Error::Ok);

    AttestationContext ctx;
    ctx.set_device_type(NVAT_DEVICE_NVSWITCH);
    ctx.set_switch_evidence_source(mock_evidence_source);
    ctx.set_switch_verifier(local_switch_verifier);

    ClaimsCollection claims {};
    std::string detached_eat;
    err = ctx.attest_device({}, &detached_eat, claims);
    ASSERT_EQ(err, Error::Ok);
    ASSERT_FALSE(claims.empty()) << "attestation should have produced claims";
}

TEST(AttestationTestCApi, GpuHighLevelApiLocalVerify) { // integration + unit 
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

    nvat_claims_collection_t claims = nullptr;
    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_from_hex(&nonce, "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"), NVAT_RC_OK);
    nvat_rc_t err = nvat_attest_device(ctx, nonce, NULL, &claims);

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
    nvat_nonce_free(&nonce);
    nvat_attestation_ctx_free(&ctx);
}

TEST(AttestationTestCApi, GpuHighLevelApiRemoteVerify) { // integration + unit 
    if (g_env->test_mode == "integration" && !g_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }

    nvat_attestation_ctx_t ctx = nullptr;
    ASSERT_EQ(nvat_attestation_ctx_create(&ctx), NVAT_RC_OK);
    ASSERT_NE(ctx, nullptr);

    nvat_attestation_ctx_set_verifier_type(ctx, NVAT_VERIFY_REMOTE);
    if (g_env->test_mode == "unit") {
        std::string gpu_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/hopper_evidence.json";
        ASSERT_EQ(nvat_attestation_ctx_set_gpu_evidence_source_json_file(ctx, gpu_evidence_path.c_str()), NVAT_RC_OK);
    }

    nvat_claims_collection_t claims = nullptr;
    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_from_hex(&nonce, "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"), NVAT_RC_OK);
    nvat_rc_t err = nvat_attest_device(ctx, nonce, NULL, &claims);
    
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
    nvat_nonce_free(&nonce);
    nvat_attestation_ctx_free(&ctx);
}

TEST(AttestationTestCApi, SwitchHighLevelApiLocalVerify) { // integration + unit 
    if (g_env->test_mode == "integration" && !g_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }

    nvat_attestation_ctx_t ctx = nullptr;
    ASSERT_EQ(nvat_attestation_ctx_create(&ctx), NVAT_RC_OK);
    ASSERT_NE(ctx, nullptr);
    ASSERT_EQ(nvat_attestation_ctx_set_device_type(ctx, NVAT_DEVICE_NVSWITCH), NVAT_RC_OK);

    nvat_attestation_ctx_set_verifier_type(ctx, NVAT_VERIFY_LOCAL);
    if (g_env->test_mode == "unit") {
        std::string switch_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/switch_evidence_ls10.json";
        ASSERT_EQ(nvat_attestation_ctx_set_switch_evidence_source_json_file(ctx, switch_evidence_path.c_str()), NVAT_RC_OK);
        ASSERT_EQ(nvat_attestation_ctx_set_default_ocsp_url(ctx, "https://ocsp.ndis-stg.nvidia.com"), NVAT_RC_OK);
        ASSERT_EQ(nvat_attestation_ctx_set_default_rim_store_url(ctx, "https://rim.attestation-stg.nvidia.com"), NVAT_RC_OK);
        ASSERT_EQ(nvat_attestation_ctx_set_default_nras_url(ctx, "https://nras.attestation-stg.nvidia.com"), NVAT_RC_OK);
    }

    nvat_claims_collection_t claims = nullptr;
    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_from_hex(&nonce, "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"), NVAT_RC_OK);
    nvat_rc_t err = nvat_attest_device(ctx, nonce, NULL, &claims);
    ASSERT_EQ(err, NVAT_RC_OK) << "Attestation failed with error: " << nvat_rc_to_string(err);
    ASSERT_NE(claims, nullptr);

    nvat_claims_collection_free(&claims);
    nvat_nonce_free(&nonce);
    nvat_attestation_ctx_free(&ctx);
} 

TEST(AttestationTestCApi, SwitchHighLevelApiRemoteVerify) { // integration + unit 
    if (g_env->test_mode == "integration" && !g_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }

    nvat_attestation_ctx_t ctx = nullptr;
    ASSERT_EQ(nvat_attestation_ctx_create(&ctx), NVAT_RC_OK);
    ASSERT_EQ(nvat_attestation_ctx_set_device_type(ctx, NVAT_DEVICE_NVSWITCH), NVAT_RC_OK);
    ASSERT_NE(ctx, nullptr);


    nvat_attestation_ctx_set_verifier_type(ctx, NVAT_VERIFY_REMOTE);
    if (g_env->test_mode == "unit") {
        std::string switch_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/switch_evidence_ls10.json";
        ASSERT_EQ(nvat_attestation_ctx_set_switch_evidence_source_json_file(ctx, switch_evidence_path.c_str()), NVAT_RC_OK);
        ASSERT_EQ(nvat_attestation_ctx_set_default_ocsp_url(ctx, "https://ocsp.ndis-stg.nvidia.com"), NVAT_RC_OK);
        ASSERT_EQ(nvat_attestation_ctx_set_default_rim_store_url(ctx, "https://rim.attestation-stg.nvidia.com"), NVAT_RC_OK);
        ASSERT_EQ(nvat_attestation_ctx_set_default_nras_url(ctx, "https://nras.attestation-stg.nvidia.com"), NVAT_RC_OK);
    }

    nvat_claims_collection_t claims = nullptr;
    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_from_hex(&nonce, "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"), NVAT_RC_OK);
    nvat_rc_t err = nvat_attest_device(ctx, nonce, NULL, &claims);
    ASSERT_EQ(err, NVAT_RC_OK) << "Attestation failed with error: " << nvat_rc_to_string(err);
    ASSERT_NE(claims, nullptr);

    nvat_claims_collection_free(&claims);
    nvat_nonce_free(&nonce);
    nvat_attestation_ctx_free(&ctx);
}

TEST(AttestationTestCApi, GpuLowLevelApi) { // integration + unit
    if (g_env->test_mode == "integration" && !g_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }

    nvat_gpu_evidence_source_t evidence_source = nullptr;
    if (g_env->test_mode == "integration") {
        ASSERT_EQ(nvat_gpu_evidence_source_nvml_create(&evidence_source), NVAT_RC_OK);
        ASSERT_NE(evidence_source, nullptr);
    }

    if (g_env->test_mode == "unit") {
        std::string gpu_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/hopper_evidence.json";
        ASSERT_EQ(nvat_gpu_evidence_source_from_json_file(&evidence_source, gpu_evidence_path.c_str()), NVAT_RC_OK);
        ASSERT_NE(evidence_source, nullptr);
    }
    ASSERT_NE(evidence_source, nullptr);

    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_from_hex(&nonce, "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"), NVAT_RC_OK);
    ASSERT_NE(nonce, nullptr);

    nvat_gpu_evidence_t* evidences = nullptr;
    size_t num_evidences = 0;
    ASSERT_EQ(nvat_gpu_evidence_collect(evidence_source, nonce, &evidences, &num_evidences), NVAT_RC_OK);
    nvat_nonce_free(&nonce);
    nvat_gpu_evidence_source_free(&evidence_source);
    ASSERT_NE(evidences, nullptr);
    ASSERT_NE(num_evidences, 0);

    nvat_rim_store_t rim_store = nullptr;
    ASSERT_EQ(nvat_rim_store_create_remote(&rim_store, "", nullptr), NVAT_RC_OK);
    ASSERT_NE(rim_store, nullptr);

    nvat_ocsp_client_t ocsp_client = nullptr;
    ASSERT_EQ(nvat_ocsp_client_create_default(&ocsp_client, "", nullptr), NVAT_RC_OK);
    ASSERT_NE(ocsp_client, nullptr);

    nvat_gpu_local_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_gpu_local_verifier_create(&verifier, rim_store, ocsp_client, nullptr), NVAT_RC_OK);
    ASSERT_NE(verifier, nullptr);
    nvat_ocsp_client_free(&ocsp_client);
    nvat_rim_store_free(&rim_store);

    nvat_gpu_verifier_t verifier_upcast = nullptr;
    verifier_upcast = nvat_gpu_local_verifier_upcast(verifier);
    ASSERT_NE(verifier_upcast, nullptr);

    nvat_evidence_policy_t evidence_policy = nullptr;
    ASSERT_EQ(nvat_evidence_policy_create_default(&evidence_policy), NVAT_RC_OK);
    ASSERT_NE(evidence_policy, nullptr);

    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    ASSERT_EQ(nvat_verify_gpu_evidence(verifier_upcast, evidences, num_evidences, evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
    nvat_gpu_verifier_free(&verifier_upcast);
    nvat_evidence_policy_free(&evidence_policy);
    nvat_gpu_evidence_array_free(&evidences, num_evidences);
    ASSERT_NE(claims, nullptr);

    ASSERT_NE(detached_eat, nullptr);
    nvat_str_free(&detached_eat);
    nvat_claims_collection_free(&claims);
} 

TEST(AttestationTestCApi, SwitchLowLevelApi) {
    if (g_env->test_mode == "integration" && !g_env->test_device_switch) {
        GTEST_SKIP() << "Skipping Switch Integration tests";
    }

    nvat_rim_store_t rim_store = nullptr;
    nvat_ocsp_client_t ocsp_client = nullptr;
    nvat_switch_evidence_source_t evidence_source = nullptr;
    if (g_env->test_mode == "integration") {
        ASSERT_EQ(nvat_switch_evidence_source_nscq_create(&evidence_source), NVAT_RC_OK);
        ASSERT_EQ(nvat_rim_store_create_remote(&rim_store, "", nullptr), NVAT_RC_OK);
        ASSERT_NE(rim_store, nullptr);
        ASSERT_EQ(nvat_ocsp_client_create_default(&ocsp_client, "", nullptr), NVAT_RC_OK);
        ASSERT_NE(ocsp_client, nullptr);
    }

    if (g_env->test_mode == "unit") {
        std::string switch_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/switch_evidence_ls10.json";
        ASSERT_EQ(nvat_switch_evidence_source_from_json_file(&evidence_source, switch_evidence_path.c_str()), NVAT_RC_OK);
        ASSERT_EQ(nvat_rim_store_create_remote(&rim_store, "https://rim.attestation-stg.nvidia.com", nullptr), NVAT_RC_OK);
        ASSERT_NE(rim_store, nullptr);
        ASSERT_EQ(nvat_ocsp_client_create_default(&ocsp_client, "https://ocsp.ndis-stg.nvidia.com", nullptr), NVAT_RC_OK);
        ASSERT_NE(ocsp_client, nullptr);
    }
    ASSERT_NE(evidence_source, nullptr);

    nvat_nonce_t nonce = nullptr;
    ASSERT_EQ(nvat_nonce_from_hex(&nonce, "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"), NVAT_RC_OK);
    ASSERT_NE(nonce, nullptr);

    nvat_switch_evidence_t* switch_evidence_array = nullptr;
    size_t num_evidences = 0;
    ASSERT_EQ(nvat_switch_evidence_collect(evidence_source, nonce, &switch_evidence_array, &num_evidences), NVAT_RC_OK);
    nvat_nonce_free(&nonce);
    nvat_switch_evidence_source_free(&evidence_source);
    nvat_nonce_free(&nonce);
    ASSERT_NE(switch_evidence_array, nullptr);
    ASSERT_NE(num_evidences, 0);


    nvat_switch_local_verifier_t verifier = nullptr;
    ASSERT_EQ(nvat_switch_local_verifier_create(&verifier, rim_store, ocsp_client, nullptr), NVAT_RC_OK);
    ASSERT_NE(verifier, nullptr);
    nvat_ocsp_client_free(&ocsp_client);
    nvat_rim_store_free(&rim_store);

    nvat_switch_verifier_t verifier_upcast = nullptr; 
    verifier_upcast = nvat_switch_local_verifier_upcast(verifier);
    ASSERT_NE(verifier_upcast, nullptr);

    nvat_evidence_policy_t evidence_policy = nullptr;
    ASSERT_EQ(nvat_evidence_policy_create_default(&evidence_policy), NVAT_RC_OK);
    ASSERT_NE(evidence_policy, nullptr);

    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    ASSERT_EQ(nvat_verify_switch_evidence(verifier_upcast, switch_evidence_array, num_evidences, evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
    nvat_switch_verifier_free(&verifier_upcast);
    nvat_evidence_policy_free(&evidence_policy);
    nvat_switch_evidence_array_free(&switch_evidence_array, num_evidences);
    ASSERT_NE(claims, nullptr);

    ASSERT_NE(detached_eat, nullptr);
    nvat_str_free(&detached_eat);

    nvat_claims_collection_free(&claims);
}