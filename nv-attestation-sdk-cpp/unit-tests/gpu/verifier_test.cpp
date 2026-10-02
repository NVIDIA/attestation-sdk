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

#include <algorithm>
#include <fstream>
#include <thread>
#include <future>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "nv_attestation/claims.h"
#include "nv_attestation/gpu/claims.h"
#include "nv_attestation/gpu/verify.h"
#include "nv_attestation/gpu/spdm/gpu_opaque_data_parser.hpp"
#include "nv_attestation/spdm/spdm_opaque_data_parser.hpp"
#include "nv_attestation/utils.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/rim.h"
#include "nv_attestation/claims_evaluator.h"
#include "environment.h"

#include "test_utils.h"

using namespace nvattestation;
using ::testing::Return;
using ::testing::_;
using ::testing::Invoke;

class GpuVerifierTest : public ::testing::Test {
    protected:
        // Setup method for common test initialization
        void SetUp() override {
            // Any common setup can go here
        }
};

TEST_F(GpuVerifierTest, SuccessfullyVerifyGpuEvidence) {
    auto rim_store = std::make_shared<NvRemoteRimStoreImpl>();
    Error error = NvRemoteRimStoreImpl::init_from_env(*rim_store, "https://rim-internal.attestation.nvidia.com/internal", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    error = NvHttpOcspClient::create(*ocsp_client, "https://ocsp.ndis-stg.nvidia.com", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    LocalGpuVerifier verifier;
    error = LocalGpuVerifier::create(verifier, rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence using test utilities
    std::vector<std::shared_ptr<GpuEvidence>> evidence_list;
    
    // Use default mock data
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_default();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy{};
    ClaimsCollection claims;
    std::string detached_eat;
    error = verifier.verify_evidence(evidence_list, evidence_policy, &detached_eat, claims);
    ASSERT_EQ(error, Error::Ok) << "Could not verify evidence: " << to_string(error);
    EXPECT_EQ(claims.size(), 1);

    const SerializableGpuClaimsV4* claims_v3 = dynamic_cast<SerializableGpuClaimsV4*>(claims[0].get());
    ASSERT_NE(claims_v3, nullptr) << "Expected SerializableGpuClaimsV4 claims";
    ASSERT_EQ(claims_v3->m_measurements_matching, SerializableMeasresClaim::Success);
    ASSERT_EQ(claims_v3->m_driver_version, mock_data.driver_version);
    ASSERT_EQ(claims_v3->m_vbios_version, mock_data.vbios_version);
    ASSERT_EQ(claims_v3->m_hwmodel, "GH100 A01 GSP BROM");
    ASSERT_EQ(claims_v3->m_ueid, "509096176156678437554566035365892618958504054724");
    ASSERT_EQ(claims_v3->m_oem_id, "5703");

}

TEST_F(GpuVerifierTest, SuccessfullyVerifyGpuEvidenceRemoteVerifier) {
    NvRemoteGpuVerifier verifier;
    Error error = NvRemoteGpuVerifier::init_from_env(verifier, "https://nras.attestation-stg.nvidia.com", g_env->service_key.c_str(), HttpOptions());
    ASSERT_EQ(error, Error::Ok);

    std::vector<std::shared_ptr<GpuEvidence>> evidence_list;
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_default();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());

    EvidencePolicy evidence_policy{};
    ClaimsCollection claims;
    std::string detached_eat;
    error = verifier.verify_evidence(evidence_list, evidence_policy, &detached_eat, claims);
    ASSERT_EQ(error, Error::Ok) << "Could not verify evidence: " << to_string(error);
    ASSERT_EQ(claims.size(), 1);

    SerializableGpuClaimsV4* claims_v3 = dynamic_cast<SerializableGpuClaimsV4*>(claims[0].get());
    ASSERT_NE(claims_v3, nullptr) << "Expected SerializableGpuClaimsV4 claims";
    EXPECT_EQ(claims_v3->m_measurements_matching, SerializableMeasresClaim::Success);
    EXPECT_EQ(claims_v3->m_driver_version, mock_data.driver_version);
    EXPECT_EQ(claims_v3->m_vbios_version, mock_data.vbios_version);
    EXPECT_EQ(claims_v3->m_hwmodel, "GH100");
    EXPECT_EQ(claims_v3->m_ueid, "509096176156678437554566035365892618958504054724");
    EXPECT_EQ(claims_v3->m_oem_id, "5703");
    EXPECT_EQ(claims_v3->m_nonce, mock_data.nonce);
}
TEST_F(GpuVerifierTest, VerifyGpuEvidenceWithBadNonce) {
    auto rim_store = std::make_shared<NvRemoteRimStoreImpl>();
    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "https://ocsp.ndis-stg.nvidia.com", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    LocalGpuVerifier verifier;
    error = LocalGpuVerifier::create(verifier, rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence with bad nonce
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::shared_ptr<GpuEvidence>> evidence_list;
    
    // Use mock data for nonce mismatch scenario
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_bad_nonce_scenario();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy{};
    ClaimsCollection claims;
    error = verifier.verify_evidence(evidence_list, evidence_policy, nullptr, claims);
    // Nonce mismatch should be treated as a fatal error in current implementation
    ASSERT_EQ(error, Error::GpuEvidenceNonceMismatch) << "Expected nonce mismatch error, got: " << to_string(error);
    // No claims should be generated when verification fails
    EXPECT_TRUE(claims.empty());
}

TEST_F(GpuVerifierTest, VerifyGpuEvidenceWithInvalidSignature) {
    auto rim_store = std::make_shared<NvRemoteRimStoreImpl>();
    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "https://ocsp.ndis-stg.nvidia.com", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    LocalGpuVerifier verifier;
    error = LocalGpuVerifier::create(verifier, rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence with invalid signature
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04}; // Sample nonce
    std::vector<std::shared_ptr<GpuEvidence>> evidence_list;
    
    // Use invalid signature mock data
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_invalid_signature_scenario();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy{};
    ClaimsCollection claims;
    error = verifier.verify_evidence(evidence_list, evidence_policy, nullptr, claims);

    ASSERT_EQ(error, Error::GpuEvidenceInvalidSignature) << "Could not verify evidence: " << to_string(error);
    // No claims should be generated when verification fails due to invalid signature
    EXPECT_TRUE(claims.empty());
}

TEST_F(GpuVerifierTest, RemoteVerifyGpuEvidenceWithBadNonce) {
    auto rim_store = std::make_shared<NvRemoteRimStoreImpl>();
    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "https://ocsp.ndis-stg.nvidia.com", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    NvRemoteGpuVerifier verifier;
    error = NvRemoteGpuVerifier::init_from_env(verifier, "https://nras.attestation-stg.nvidia.com", g_env->service_key.c_str(), HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence with invalid signature
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04}; // Sample nonce
    std::vector<std::shared_ptr<GpuEvidence>> evidence_list;
    
    // Use invalid signature mock data
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_bad_nonce_scenario();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy{};
    ClaimsCollection claims;
    error = verifier.verify_evidence(evidence_list, evidence_policy, nullptr, claims);

    ASSERT_EQ(error, Error::GpuEvidenceNonceMismatch) << "Could not verify evidence: " << to_string(error);
    // No claims should be generated when verification fails due to invalid signature
    EXPECT_TRUE(claims.empty());
}

TEST_F(GpuVerifierTest, VerifyGpuEvidenceWithDriverMeasurementsMismatch) {
    auto verifier = std::make_shared<LocalGpuVerifier>();
    std::shared_ptr<MockNvRemoteRimStore> mock_rim_store = std::make_shared<MockNvRemoteRimStore>();
    EXPECT_CALL(*mock_rim_store, get_rim(_, _))
        .WillOnce(Invoke([](const std::string& rim_id, RimDocument& out_rim_document) -> Error {
            if (rim_id != "NV_GPU_DRIVER_GH100_535.86.09") {
                LOG_ERROR("RIM ID mismatch: " << rim_id);
                return Error::RimNotFound;
            }
            std::ifstream file("testdata/sample_rims/NV_GPU_DRIVER_GH100_535.86.09_measurement_mismatch.xml");
            std::string xml_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            Error error = RimDocument::create_from_rim_data(xml_data, out_rim_document);
            return error;
        }))
        .WillOnce(Invoke([](const std::string& rim_id, RimDocument& out_rim_document) -> Error {
            if (rim_id != "NV_GPU_VBIOS_1010_0200_882_96005E0001") {
                LOG_ERROR("VBIOS RIM ID mismatch: " << rim_id);
                return Error::RimNotFound;
            }
            std::ifstream file("testdata/sample_rims/NV_GPU_VBIOS_1010_0200_882_96005E0001_measurement_mismatch.xml");
            std::string xml_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            Error error = RimDocument::create_from_rim_data(xml_data, out_rim_document);
            return error;
        }));
    std::shared_ptr<NvHttpOcspClient> ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis-stg.nvidia.com", g_env->service_key, HttpOptions());
    error = LocalGpuVerifier::create(*verifier, mock_rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence with driver measurements mismatch scenario
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04}; // Sample nonce
    std::vector<std::shared_ptr<GpuEvidence>> evidence_list;
    
    // Use driver measurements mismatch mock data
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_measurements_mismatch_scenario();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy{};
    // disable rim signature verification because the rim version in the mock rim file
    // was changed to match the expected rim version. this is because, to make the 
    // measurements mismatch, a random rim file is used. the version change is required
    // because rim version match check happens before measurements are checked.
    evidence_policy.verify_rim_signature = false;
    ClaimsCollection claims;
    error = verifier->verify_evidence(evidence_list, evidence_policy, nullptr, claims);
    ASSERT_EQ(error, Error::Ok) << "Verification should succeed but mark measurements as mismatched, got: " << to_string(error);
    EXPECT_EQ(claims.size(), 1);

    const SerializableGpuClaimsV4* claims_v3 = dynamic_cast<SerializableGpuClaimsV4*>(claims[0].get());
    ASSERT_NE(claims_v3, nullptr) << "Expected SerializableGpuClaimsV4 claims";

    // Verify that measurements are marked as not matching
    EXPECT_EQ(claims_v3->m_measurements_matching, SerializableMeasresClaim::Failure);
    
    // When measurements don't match, secure_boot and debug_status should be null
    EXPECT_EQ(claims_v3->m_secure_boot, nullptr);
    EXPECT_EQ(claims_v3->m_debug_status, nullptr);
    
    // Mismatched measurements should be populated
    EXPECT_NE(claims_v3->m_mismatched_measurements, nullptr);
    EXPECT_GT(claims_v3->m_mismatched_measurements->size(), 0);
}

TEST_F(GpuVerifierTest, VerifyGpuEvidenceWithExpiredDriverRim) {
    RecordProperty("description", "Verify GPU evidence with expired driver rim. Local verifier.");
    auto verifier = std::make_shared<LocalGpuVerifier>();
    std::shared_ptr<NvRemoteRimStoreImpl> rim_store = std::make_shared<NvRemoteRimStoreImpl>();
    Error error = NvRemoteRimStoreImpl::init_from_env(*rim_store, "https://rim-internal.attestation.nvidia.com/internal", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    std::shared_ptr<NvHttpOcspClient> ocsp_client = std::make_shared<NvHttpOcspClient>();
    error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis-stg.nvidia.com", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    error = LocalGpuVerifier::create(*verifier, rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence with expired driver rim scenario
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04}; // Sample nonce
    std::vector<std::shared_ptr<GpuEvidence>> evidence_list;
    
    // Use expired driver rim mock data
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_expired_driver_rim_scenario();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy{};
    evidence_policy.verify_rim_signature = false;
    ClaimsCollection claims;
    error = verifier->verify_evidence(evidence_list, evidence_policy, nullptr, claims);
    ASSERT_EQ(error, Error::Ok);

    std::string claims_json;
    error = claims.serialize_json(claims_json);
    ASSERT_EQ(error, Error::Ok);
    nlohmann::json claims_json_object = nlohmann::json::parse(claims_json);
    EXPECT_EQ(claims_json_object[0]["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-status"], "expired");

}

TEST_F(GpuVerifierTest, VerifyGpuEvidenceWithBlackwell) {
    auto rim_store = std::make_shared<NvRemoteRimStoreImpl>();
    const char* base_url = "https://rim-internal.attestation.nvidia.com/internal";
    Error error = NvRemoteRimStoreImpl::init_from_env(*rim_store, base_url, g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    error = NvHttpOcspClient::create(*ocsp_client, "https://ocsp.ndis-stg.nvidia.com", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    LocalGpuVerifier local_verifier;
    error = LocalGpuVerifier::create(local_verifier, rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence using test utilities
    std::vector<std::shared_ptr<GpuEvidence>> evidence_list;
    
    // Use default mock data
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_blackwell_scenario();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy{};


    ClaimsCollection claims;
    error = local_verifier.verify_evidence(evidence_list, evidence_policy, nullptr, claims);
    ASSERT_EQ(error, Error::Ok) << "Could not verify evidence: " << to_string(error);
    EXPECT_EQ(claims.size(), 1);

    const SerializableGpuClaimsV4* claims_v3 = dynamic_cast<SerializableGpuClaimsV4*>(claims[0].get());
    ASSERT_NE(claims_v3, nullptr) << "Expected SerializableGpuClaimsV4 claims";
    EXPECT_EQ(claims_v3->m_hwmodel, "GB100 A01 GSP BROM");
    EXPECT_EQ(claims_v3->m_ueid, "474146966256510137525212816567191319424869109849");
    EXPECT_EQ(claims_v3->m_oem_id, "5703");
    EXPECT_EQ(claims_v3->m_driver_version, mock_data.driver_version);
    EXPECT_EQ(claims_v3->m_vbios_version, mock_data.vbios_version);
    EXPECT_EQ(claims_v3->m_measurements_matching, SerializableMeasresClaim::Success);
}

TEST_F(GpuVerifierTest, RejectsRubinEvidence) {
    auto mock_rim_store = std::make_shared<MockNvRemoteRimStore>();
    EXPECT_CALL(*mock_rim_store, get_rim(_, _)).Times(0);

    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis-stg.nvidia.com", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);

    LocalGpuVerifier verifier;
    error = LocalGpuVerifier::create(verifier, mock_rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(error, Error::Ok);

    auto rubin_evidence = std::make_shared<GpuEvidence>();
    rubin_evidence->set_gpu_architecture(GpuArchitecture::Rubin);
    std::vector<std::shared_ptr<GpuEvidence>> evidence_list{rubin_evidence};

    EvidencePolicy evidence_policy{};
    ClaimsCollection claims;
    error = verifier.verify_evidence(evidence_list, evidence_policy, nullptr, claims);
    EXPECT_EQ(error, Error::GpuArchitectureNotSupported);
    EXPECT_TRUE(claims.empty());
}

class GpuLocalVerifierTestCApi : public ::testing::Test {
    protected:
        nvat_gpu_evidence_t* m_mock_single_gpu_evidence = nullptr;
        size_t m_num_mock_single_gpu_evidence = 1;
        nvat_gpu_evidence_t* m_mock_multi_gpu_evidence = nullptr;
        size_t m_num_mock_multi_gpu_evidence = 4;
        nvat_gpu_evidence_t* m_actual_gpu_evidence = nullptr;
        size_t m_num_actual_gpu_evidence = 0;
        nvat_gpu_verifier_t m_verifier = nullptr;
        nvat_gpu_verifier_t m_caching_verifier = nullptr;
        nvat_evidence_policy_t m_evidence_policy = nullptr;

        void SetUp() override {
            
            nvat_gpu_evidence_source_t evidence_source = nullptr;

            nvat_rim_store_t rim_store = nullptr;
            nvat_ocsp_client_t ocsp_client = nullptr;
            ASSERT_EQ(nvat_rim_store_create_remote(&rim_store, "https://rim-internal.attestation.nvidia.com/internal", g_env->service_key.c_str(), nullptr), NVAT_RC_OK);
            ASSERT_NE(rim_store, nullptr);
            ASSERT_EQ(nvat_ocsp_client_create_default(&ocsp_client, "https://ocsp.ndis-stg.nvidia.com", g_env->service_key.c_str(), nullptr), NVAT_RC_OK);
            ASSERT_NE(ocsp_client, nullptr);


            nvat_rim_store_t cached_rim_store = nullptr;
            ASSERT_EQ(nvat_rim_store_create_cached(&cached_rim_store, rim_store, 1024*1024, 60*60), NVAT_RC_OK);
            ASSERT_NE(cached_rim_store, nullptr);
            nvat_ocsp_client_t cached_ocsp_client = nullptr;
            ASSERT_EQ(nvat_ocsp_client_create_cached(&cached_ocsp_client, ocsp_client, 1024*1024, 60*60), NVAT_RC_OK);
            ASSERT_NE(cached_ocsp_client, nullptr);


            nvat_gpu_local_verifier_t local_verifier = nullptr;
            ASSERT_EQ(nvat_gpu_local_verifier_create(&local_verifier, rim_store, ocsp_client, nullptr), NVAT_RC_OK);
            ASSERT_NE(local_verifier, nullptr);
            m_verifier = nvat_gpu_local_verifier_upcast(local_verifier);
            ASSERT_NE(m_verifier, nullptr);

            nvat_gpu_local_verifier_t caching_local_verifier = nullptr;
            ASSERT_EQ(nvat_gpu_local_verifier_create(&caching_local_verifier, cached_rim_store, cached_ocsp_client, nullptr), NVAT_RC_OK);
            ASSERT_NE(caching_local_verifier, nullptr);
            m_caching_verifier = nvat_gpu_local_verifier_upcast(caching_local_verifier);
            ASSERT_NE(m_caching_verifier, nullptr);

            if (g_env->test_mode == "integration" && g_env->test_device_gpu) {
                time_t start_time = time(nullptr);
                ASSERT_EQ(nvat_gpu_evidence_source_nvml_create(&evidence_source), NVAT_RC_OK);
                ASSERT_EQ(nvat_gpu_evidence_collect(evidence_source, nullptr, &m_actual_gpu_evidence, &m_num_actual_gpu_evidence), NVAT_RC_OK);
                time_t end_time = time(nullptr);
                std::cout << "Actual GPU evidence collection took " << end_time - start_time << " seconds" << std::endl;
                nvat_gpu_evidence_source_free(&evidence_source);
            }
            std::string gpu_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/hopper_evidence.json";
            ASSERT_EQ(nvat_gpu_evidence_source_from_json_file(&evidence_source, gpu_evidence_path.c_str()), NVAT_RC_OK);
            nvat_nonce_t nonce = nullptr;
            std::string nonce_str = evidence_to_nonce_map.find("hopper_latest")->second;
            ASSERT_EQ(nvat_nonce_from_hex(&nonce, nonce_str.c_str()), NVAT_RC_OK);
            ASSERT_NE(nonce, nullptr);
            ASSERT_EQ(nvat_gpu_evidence_collect(evidence_source, nonce, &m_mock_single_gpu_evidence, &m_num_mock_single_gpu_evidence), NVAT_RC_OK);
            nvat_gpu_evidence_source_free(&evidence_source);

            gpu_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/multi_gpu_hopper.json";
            ASSERT_EQ(nvat_gpu_evidence_source_from_json_file(&evidence_source, gpu_evidence_path.c_str()), NVAT_RC_OK);
            ASSERT_EQ(nvat_gpu_evidence_collect(evidence_source, nonce, &m_mock_multi_gpu_evidence, &m_num_mock_multi_gpu_evidence), NVAT_RC_OK);
            nvat_gpu_evidence_source_free(&evidence_source);
            nvat_nonce_free(&nonce);

            nvat_ocsp_client_free(&cached_ocsp_client);
            nvat_ocsp_client_free(&ocsp_client);
            nvat_rim_store_free(&rim_store);
            nvat_rim_store_free(&cached_rim_store);
            
            ASSERT_EQ(nvat_evidence_policy_create_default(&m_evidence_policy), NVAT_RC_OK);
            ASSERT_NE(m_evidence_policy, nullptr);
        }

        void TearDown() override {
            nvat_evidence_policy_free(&m_evidence_policy);
            nvat_gpu_verifier_free(&m_verifier);
            nvat_gpu_verifier_free(&m_caching_verifier);
            if (g_env->test_mode == "integration" && g_env->test_device_gpu) {
                nvat_gpu_evidence_array_free(&m_actual_gpu_evidence, m_num_actual_gpu_evidence);
            }
            nvat_gpu_evidence_array_free(&m_mock_single_gpu_evidence, m_num_mock_single_gpu_evidence);
            nvat_gpu_evidence_array_free(&m_mock_multi_gpu_evidence, m_num_mock_multi_gpu_evidence);
        }
};

TEST_F(GpuLocalVerifierTestCApi, SerialVerify) {
    RecordProperty("description", "Serial verify 4 GPU evidences with service key. Local verifier.");
    if (g_env->test_mode == "integration" && !g_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    time_t start_time = time(nullptr);
    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    if (g_env->test_mode == "unit"){
        ASSERT_EQ(nvat_verify_gpu_evidence(m_verifier, m_mock_multi_gpu_evidence, m_num_mock_multi_gpu_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
    } else if (g_env->test_mode == "integration"){
        ASSERT_EQ(nvat_verify_gpu_evidence(m_verifier, m_actual_gpu_evidence, m_num_actual_gpu_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
    }
    ASSERT_NE(claims, nullptr);
    ASSERT_NE(detached_eat, nullptr);
    time_t end_time = time(nullptr);
    std::cout << "Time taken for serial verify: " << end_time - start_time << " seconds" << std::endl;
    char* detached_eat_str = nullptr;
    ASSERT_EQ(nvat_str_get_data(detached_eat, &detached_eat_str), NVAT_RC_OK);
    ASSERT_NE(detached_eat_str, nullptr);
    LOG_DEBUG("Detached EAT: " << detached_eat_str);
    nvat_str_free(&detached_eat);
    nvat_claims_collection_free(&claims);
} 

TEST_F(GpuLocalVerifierTestCApi, SerialVerifyWithCache) { 
    RecordProperty("description", "Serial verify 4 GPU evidences with cache and service key. Local verifier.");
    if (g_env->test_mode == "integration" && !g_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    time_t start_time = time(nullptr);
    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    if (g_env->test_mode == "unit"){
        ASSERT_EQ(nvat_verify_gpu_evidence(m_caching_verifier, m_mock_multi_gpu_evidence, m_num_mock_multi_gpu_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
    } else if (g_env->test_mode == "integration"){
        ASSERT_EQ(nvat_verify_gpu_evidence(m_caching_verifier, m_actual_gpu_evidence, m_num_actual_gpu_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
    }
    ASSERT_NE(claims, nullptr);
    ASSERT_NE(detached_eat, nullptr);
    time_t end_time = time(nullptr);
    std::cout << "Time taken for serial verify with cache: " << end_time - start_time << " seconds" << std::endl;
    nvat_str_free(&detached_eat);
    nvat_claims_collection_free(&claims);
}

TEST_F(GpuLocalVerifierTestCApi, ParallelVerify) { 
    RecordProperty("description", "Parallel verify 4 GPU evidences with service key. Local verifier.");
    if (g_env->test_mode == "integration" && !g_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    nvat_gpu_evidence_t* evidences = nullptr;
    size_t num_evidences = 0;
    if (g_env->test_mode == "unit"){
        evidences = m_mock_multi_gpu_evidence;
        num_evidences = m_num_mock_multi_gpu_evidence;
    } else if (g_env->test_mode == "integration"){
        evidences = m_actual_gpu_evidence;
        num_evidences = m_num_actual_gpu_evidence;
    }

    std::vector<std::future<nvat_rc_t>> futures;
    // Limit threads to the number of evidences to avoid threads with 0 work
    const int num_threads = std::min(static_cast<size_t>(4), num_evidences);
    if (num_threads == 0) {
        GTEST_SKIP() << "No evidences to verify";
    }
    int num_evidences_per_thread = num_evidences / num_threads;
    time_t start_time = time(nullptr);
    for (int i = 0; i < num_threads; i++) {
        futures.emplace_back(std::async(std::launch::async, [this, evidences, num_evidences, num_evidences_per_thread, num_threads, i]() -> nvat_rc_t {
            nvat_claims_collection_t claims = nullptr;
            nvat_str_t detached_eat = nullptr;
            int this_thread_evidences = num_evidences_per_thread;
            if (i == num_threads - 1) {
                this_thread_evidences = num_evidences - i*num_evidences_per_thread;
            }
            nvat_rc_t result = nvat_verify_gpu_evidence(m_verifier, evidences+i*num_evidences_per_thread, this_thread_evidences, m_evidence_policy, &detached_eat, &claims);
            nvat_str_free(&detached_eat);
            nvat_claims_collection_free(&claims);
            return result;
        }));
    }
    for (auto& future : futures) {
        ASSERT_EQ(future.get(), NVAT_RC_OK);
    }
    time_t end_time = time(nullptr);
    std::cout << "Time taken for parallel verify: " << end_time - start_time << " seconds" << std::endl;
}

TEST_F(GpuLocalVerifierTestCApi, ParallelVerifyWithWarmCache) { 
    RecordProperty("description", "Parallel verify 4 GPU evidences with cache and service key. Local verifier.");
    if (g_env->test_mode == "integration" && !g_env->test_device_gpu) {
        GTEST_SKIP() << "Skipping GPU Integration tests";
    }
    nvat_gpu_evidence_t* evidences = nullptr;
    size_t num_evidences = 0;
    if (g_env->test_mode == "unit"){
        evidences = m_mock_multi_gpu_evidence;
        num_evidences = m_num_mock_multi_gpu_evidence;
    } else if (g_env->test_mode == "integration"){
        evidences = m_actual_gpu_evidence;
        num_evidences = m_num_actual_gpu_evidence;
    }

    // warm up the cache
    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    ASSERT_EQ(nvat_verify_gpu_evidence(m_caching_verifier, evidences, num_evidences, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
    ASSERT_NE(claims, nullptr);
    ASSERT_NE(detached_eat, nullptr);
    nvat_str_free(&detached_eat);
    nvat_claims_collection_free(&claims);

    std::vector<std::future<nvat_rc_t>> futures;
    // Limit threads to the number of evidences to avoid threads with 0 work
    const int num_threads = std::min(static_cast<size_t>(4), num_evidences);
    if (num_threads == 0) {
        GTEST_SKIP() << "No evidences to verify";
    }
    int num_evidences_per_thread = num_evidences / num_threads;
    time_t start_time = time(nullptr);
    for (int i = 0; i < num_threads; i++) {
        futures.emplace_back(std::async(std::launch::async, [this, evidences, num_evidences, num_evidences_per_thread, num_threads, i]() -> nvat_rc_t {
            nvat_claims_collection_t claims = nullptr;
            nvat_str_t detached_eat = nullptr;
            int this_thread_evidences = num_evidences_per_thread;
            if (i == num_threads - 1) {
                this_thread_evidences = num_evidences - i*num_evidences_per_thread;
            }
            nvat_rc_t result = nvat_verify_gpu_evidence(m_caching_verifier, evidences+i*num_evidences_per_thread, this_thread_evidences, m_evidence_policy, &detached_eat, &claims);
            nvat_str_free(&detached_eat);
            nvat_claims_collection_free(&claims);
            return result;
        }));
    }
    for (auto& future : futures) {
        ASSERT_EQ(future.get(), NVAT_RC_OK);
    }
    time_t end_time = time(nullptr);
    std::cout << "Time taken for parallel verify with cache: " << end_time - start_time << " seconds" << std::endl;
}

TEST_F(GpuLocalVerifierTestCApi, VerifyWithInvalidServiceKey) {
    RecordProperty("description", 
        "Verify GPU evidence with invalid service key. "
        "Local verifier. Invalid service key will be "
        "applied to OCSP and RIM store");
    std::string service_key = "invalid_service_key";
    nvat_rim_store_t rim_store = nullptr;
    nvat_ocsp_client_t ocsp_client = nullptr;
    ASSERT_EQ(nvat_rim_store_create_remote(&rim_store, "https://rim-internal.attestation.nvidia.com/internal", service_key.c_str(), nullptr), NVAT_RC_OK);
    ASSERT_NE(rim_store, nullptr);
    ASSERT_EQ(nvat_ocsp_client_create_default(&ocsp_client, "https://ocsp.ndis-stg.nvidia.com", service_key.c_str(), nullptr), NVAT_RC_OK);
    ASSERT_NE(ocsp_client, nullptr);
    nvat_gpu_local_verifier_t local_verifier = nullptr;
    ASSERT_EQ(nvat_gpu_local_verifier_create(&local_verifier, rim_store, ocsp_client, nullptr), NVAT_RC_OK);
    ASSERT_NE(local_verifier, nullptr);
    nvat_gpu_verifier_t verifier = nvat_gpu_local_verifier_upcast(local_verifier);
    ASSERT_NE(verifier, nullptr);
    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    ASSERT_EQ(nvat_verify_gpu_evidence(verifier, m_mock_single_gpu_evidence, m_num_mock_single_gpu_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OCSP_FORBIDDEN);
    ASSERT_EQ(claims, nullptr);
    nvat_gpu_verifier_free(&verifier);
    nvat_ocsp_client_free(&ocsp_client);
    nvat_rim_store_free(&rim_store);
}

TEST_F(GpuLocalVerifierTestCApi, Certhold) {
    RecordProperty("description", "Verify GPU evidence with cert hold. Local verifier.");
    std::string evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/hopper_evidence_cert_hold.json";
    nvat_gpu_evidence_source_t evidence_source = nullptr;
    ASSERT_EQ(nvat_gpu_evidence_source_from_json_file(&evidence_source, evidence_path.c_str()), NVAT_RC_OK);
    nvat_nonce_t nonce = nullptr;
    std::string nonce_str = evidence_to_nonce_map.find("hopper_570_86_cert_hold")->second;
    ASSERT_EQ(nvat_nonce_from_hex(&nonce, nonce_str.c_str()), NVAT_RC_OK);
    ASSERT_NE(nonce, nullptr);
    nvat_gpu_evidence_t* evidence = nullptr;
    size_t num_evidence = 0;
    ASSERT_EQ(nvat_gpu_evidence_collect(evidence_source, nonce, &evidence, &num_evidence), NVAT_RC_OK);
    ASSERT_NE(evidence, nullptr);
    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    ASSERT_EQ(nvat_verify_gpu_evidence(m_caching_verifier, evidence, num_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OVERALL_RESULT_FALSE);
    ASSERT_NE(detached_eat, nullptr);
    ASSERT_NE(claims, nullptr);
    // get serialized claims
    nvat_str_t serialized_claims = nullptr;
    ASSERT_EQ(nvat_claims_collection_serialize_json(claims, &serialized_claims), NVAT_RC_OK);
    ASSERT_NE(serialized_claims, nullptr);
    char* serialized_claims_str = nullptr;
    ASSERT_EQ(nvat_str_get_data(serialized_claims, &serialized_claims_str), NVAT_RC_OK);
    ASSERT_NE(serialized_claims_str, nullptr);
    LOG_DEBUG("Serialized claims: " << serialized_claims_str);
    nlohmann::json json_claims = nlohmann::json::parse(serialized_claims_str);
    EXPECT_EQ(json_claims[0]["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-ocsp-status"], "revoked");
    EXPECT_EQ(json_claims[0]["x-nvidia-gpu-driver-rim-cert-chain"]["x-nvidia-cert-revocation-reason"], "certificateHold");
    nvat_str_free(&serialized_claims);
    nvat_str_free(&detached_eat);
    nvat_claims_collection_free(&claims);
    nvat_gpu_evidence_array_free(&evidence, num_evidence);
    nvat_gpu_evidence_source_free(&evidence_source);
    nvat_nonce_free(&nonce);
}

class GpuRemoteVerifierTestCApi : public ::testing::Test {
    protected:
        nvat_gpu_verifier_t m_verifier = nullptr;
        nvat_gpu_evidence_t* m_mock_single_gpu_evidence = nullptr;
        size_t m_num_mock_single_gpu_evidence = 1;
        nvat_evidence_policy_t m_evidence_policy = nullptr;


        void SetUp() override {
            nvat_gpu_nras_verifier_t nras_verifier = nullptr;
            ASSERT_EQ(nvat_gpu_nras_verifier_create(&nras_verifier, "https://nras.attestation-stg.nvidia.com", g_env->service_key.c_str(), nullptr), NVAT_RC_OK);
            ASSERT_NE(nras_verifier, nullptr);
            m_verifier = nvat_gpu_nras_verifier_upcast(nras_verifier);
            ASSERT_NE(m_verifier, nullptr);

            std::string gpu_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/hopper_evidence.json";
            nvat_gpu_evidence_source_t evidence_source = nullptr;
            ASSERT_EQ(nvat_gpu_evidence_source_from_json_file(&evidence_source, gpu_evidence_path.c_str()), NVAT_RC_OK);
            
            nvat_nonce_t nonce = nullptr;
            std::string nonce_str = evidence_to_nonce_map.find("hopper_latest")->second;
            ASSERT_EQ(nvat_nonce_from_hex(&nonce, nonce_str.c_str()), NVAT_RC_OK);
            ASSERT_NE(nonce, nullptr);

            ASSERT_EQ(nvat_gpu_evidence_collect(evidence_source, nonce, &m_mock_single_gpu_evidence, &m_num_mock_single_gpu_evidence), NVAT_RC_OK);
            nvat_gpu_evidence_source_free(&evidence_source);
            nvat_nonce_free(&nonce);

            ASSERT_EQ(nvat_evidence_policy_create_default(&m_evidence_policy), NVAT_RC_OK);
            ASSERT_NE(m_evidence_policy, nullptr);
        }

        void TearDown() override {
            nvat_gpu_evidence_array_free(&m_mock_single_gpu_evidence, m_num_mock_single_gpu_evidence);
            nvat_gpu_verifier_free(&m_verifier);
            nvat_evidence_policy_free(&m_evidence_policy);
        }
};

TEST_F(GpuRemoteVerifierTestCApi, VerifySingleGpuEvidence) {
    RecordProperty("description", "Verify single GPU evidence with service key. Remote verifier.");
    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    ASSERT_EQ(nvat_verify_gpu_evidence(m_verifier, m_mock_single_gpu_evidence, m_num_mock_single_gpu_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
    ASSERT_NE(claims, nullptr);
    ASSERT_NE(detached_eat, nullptr);
    nvat_str_free(&detached_eat);
    nvat_claims_collection_free(&claims);
}

TEST_F(GpuRemoteVerifierTestCApi, InvalidServiceKey) {
    RecordProperty("description", "Verify single GPU evidence with invalid service key. "
        "Remote verifier. Invalid service key will be "
        "applied to NRAS");
    std::string service_key = "invalid_service_key";
    nvat_gpu_nras_verifier_t nras_verifier = nullptr;
    ASSERT_EQ(nvat_gpu_nras_verifier_create(&nras_verifier, "https://nras.attestation-stg.nvidia.com", service_key.c_str(), nullptr), NVAT_RC_OK);
    ASSERT_NE(nras_verifier, nullptr);
    nvat_gpu_verifier_t verifier = nvat_gpu_nras_verifier_upcast(nras_verifier);
    ASSERT_NE(verifier, nullptr);
    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    ASSERT_EQ(nvat_verify_gpu_evidence(verifier, m_mock_single_gpu_evidence, m_num_mock_single_gpu_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_NRAS_FORBIDDEN);
    ASSERT_EQ(claims, nullptr);
    ASSERT_EQ(detached_eat, nullptr);
    nvat_gpu_verifier_free(&verifier);
}
TEST_F(GpuLocalVerifierTestCApi, DISABLED_VerifyGpuModeClaimRPPolicy) {
    std::string rp_plicy = R"(
        package policy
        import future.keywords.every
        default nv_match := false
        nv_match := true {
            # Ensure input is not empty
            count(input) > 0
            
            # Check all claims have the mode field
            every result in input {
                result["x-nvidia-gpu-mode"]
                result["x-nvidia-device-type"] == "gpu"
            }
            
            # Get all unique mode values
            modes := {result["x-nvidia-gpu-mode"] | result := input[_]}
            
            # Ensure all modes are the same (only 1 unique value)
            count(modes) == 1
        }
    )";

    nvat_relying_party_policy_t policy = nullptr;
    ASSERT_EQ(nvat_relying_party_policy_create_rego_from_str(&policy, rp_plicy.c_str()), NVAT_RC_OK);
    ASSERT_NE(policy, nullptr);

    nvat_claims_collection_t claims = nullptr;
    ASSERT_EQ(nvat_verify_gpu_evidence(m_caching_verifier, m_mock_multi_gpu_evidence, m_num_mock_multi_gpu_evidence, m_evidence_policy, nullptr, &claims), NVAT_RC_OK);
    ASSERT_NE(claims, nullptr);
    ASSERT_EQ(nvat_apply_relying_party_policy(policy, claims), NVAT_RC_OK);
    nvat_relying_party_policy_free(&policy);
    nvat_claims_collection_free(&claims);
}

TEST_F(GpuVerifierTest, EmptyEvidenceReturnsBadArgument) {
    auto rim_store = std::make_shared<MockNvRemoteRimStore>();
    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "https://ocsp.example.com", "", HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    LocalGpuVerifier verifier;
    error = LocalGpuVerifier::create(verifier, rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(error, Error::Ok);

    std::vector<std::shared_ptr<GpuEvidence>> empty_evidence;
    EvidencePolicy evidence_policy{};
    ClaimsCollection claims;
    error = verifier.verify_evidence(empty_evidence, evidence_policy, nullptr, claims);
    EXPECT_EQ(error, Error::BadArgument);
}

// ---------------------------------------------------------------------------
// OpaqueDataComparison unit tests
// ---------------------------------------------------------------------------

static std::vector<ParsedOpaqueFieldData> make_fields_with_min_svn(uint16_t svn) {
    std::vector<uint8_t> svn_bytes = {
        static_cast<uint8_t>(svn & 0xFFU),
        static_cast<uint8_t>(svn >> 8U)
    };
    ParsedOpaqueFieldData field;
    ParsedOpaqueFieldData::create(svn_bytes, 37U, 0x87U, field);
    return {field};
}

static OpaqueRimRecords make_min_svn_rim_records(uint64_t floor, bool include_in_result) {
    OpaqueRimRecord rec;
    rec.type_id           = 37U;
    rec.name              = "FSP_UCODE_MIN_SVN";
    rec.min_svn           = floor;
    rec.include_in_result = include_in_result;
    OpaqueRimRecords records;
    records.add_record(rec);
    return records;
}

TEST(OpaqueComparisonTest, MinSvnMatchEmitsAttesterClaim) {
    auto fields = make_fields_with_min_svn(5U);
    OpaqueDataFormatVersion ver{0, 2, true};
    GpuOpaqueDataParser opaque;
    ASSERT_EQ(GpuOpaqueDataParser::create(fields, ver, opaque), Error::Ok);

    auto rim_records = make_min_svn_rim_records(5U, true);
    SerializableGpuClaimsV4 claims;
    LocalGpuVerifier::compare_opaque_data(opaque, rim_records, claims);

    EXPECT_TRUE(claims.m_mismatched_opaque_records == nullptr ||
                claims.m_mismatched_opaque_records->empty());
    ASSERT_EQ(claims.m_attester_claims.count("FSP_UCODE_MIN_SVN"), 1U);
    EXPECT_EQ(claims.m_attester_claims.at("FSP_UCODE_MIN_SVN"), 5U);
}

TEST(OpaqueComparisonTest, UnregisteredTypeIdWithMinSvnValueTypeStillCompares) {
    // A new firmware field with no GpuOpaqueDataType enum entry yet must still compare
    // correctly as long as it carries the MIN_SVN value_type tag (0x87); see
    // GpuOpaqueDataParser::create, which retains fields by raw id rather than dropping them.
    std::vector<uint8_t> svn_bytes = {0x05, 0x00};  // 5
    ParsedOpaqueFieldData field;
    ASSERT_EQ(ParsedOpaqueFieldData::create(svn_bytes, 40U, 0x87U, field), Error::Ok);

    OpaqueDataFormatVersion ver{0, 2, true};
    GpuOpaqueDataParser opaque;
    ASSERT_EQ(GpuOpaqueDataParser::create({field}, ver, opaque), Error::Ok);

    OpaqueRimRecord rec;
    rec.type_id           = 40U;
    rec.name              = "FUTURE_MIN_SVN_FIELD";
    rec.min_svn           = 5U;
    rec.include_in_result = true;
    OpaqueRimRecords rim_records;
    rim_records.add_record(rec);

    SerializableGpuClaimsV4 claims;
    LocalGpuVerifier::compare_opaque_data(opaque, rim_records, claims);

    EXPECT_TRUE(claims.m_mismatched_opaque_records == nullptr ||
                claims.m_mismatched_opaque_records->empty());
    ASSERT_EQ(claims.m_attester_claims.count("FUTURE_MIN_SVN_FIELD"), 1U);
    EXPECT_EQ(claims.m_attester_claims.at("FUTURE_MIN_SVN_FIELD"), 5U);
}

TEST(OpaqueComparisonTest, TypeIdZeroCompares) {
    // type_id 0 (RIM index == OPAQUE_DATA_RIM_INDEX_BASE exactly) is not reserved/excluded --
    // confirm it's treated as an ordinary, comparable field, not specially dropped anywhere.
    std::vector<uint8_t> svn_bytes = {0x05, 0x00};  // 5
    ParsedOpaqueFieldData field;
    ASSERT_EQ(ParsedOpaqueFieldData::create(svn_bytes, 0U, 0x87U, field), Error::Ok);

    OpaqueDataFormatVersion ver{0, 2, true};
    GpuOpaqueDataParser opaque;
    ASSERT_EQ(GpuOpaqueDataParser::create({field}, ver, opaque), Error::Ok);

    OpaqueRimRecord rec;
    rec.type_id           = 0U;
    rec.name              = "TYPE_ID_ZERO_MIN_SVN";
    rec.min_svn           = 5U;
    rec.include_in_result = true;
    OpaqueRimRecords rim_records;
    rim_records.add_record(rec);

    SerializableGpuClaimsV4 claims;
    LocalGpuVerifier::compare_opaque_data(opaque, rim_records, claims);

    EXPECT_TRUE(claims.m_mismatched_opaque_records == nullptr ||
                claims.m_mismatched_opaque_records->empty());
    ASSERT_EQ(claims.m_attester_claims.count("TYPE_ID_ZERO_MIN_SVN"), 1U);
    EXPECT_EQ(claims.m_attester_claims.at("TYPE_ID_ZERO_MIN_SVN"), 5U);
}

TEST(OpaqueComparisonTest, MinSvnBelowFloorCreatesMismatch) {
    auto fields = make_fields_with_min_svn(3U);
    OpaqueDataFormatVersion ver{0, 2, true};
    GpuOpaqueDataParser opaque;
    ASSERT_EQ(GpuOpaqueDataParser::create(fields, ver, opaque), Error::Ok);

    auto rim_records = make_min_svn_rim_records(5U, true);
    SerializableGpuClaimsV4 claims;
    LocalGpuVerifier::compare_opaque_data(opaque, rim_records, claims);

    ASSERT_NE(claims.m_mismatched_opaque_records, nullptr);
    ASSERT_EQ(claims.m_mismatched_opaque_records->size(), 1U);
    const auto& mm = (*claims.m_mismatched_opaque_records)[0];
    EXPECT_EQ(mm.opaque_data_id,  37U);
    EXPECT_EQ(mm.name,            "FSP_UCODE_MIN_SVN");
    EXPECT_EQ(mm.golden_value,    5U);
    ASSERT_NE(mm.runtime_value, nullptr);
    EXPECT_EQ(*mm.runtime_value,  3U);

    EXPECT_EQ(claims.m_attester_claims.count("FSP_UCODE_MIN_SVN"), 1U);
}

TEST(OpaqueComparisonTest, MinSvnEqualToFloorIsNotMismatch) {
    auto fields = make_fields_with_min_svn(5U);
    OpaqueDataFormatVersion ver{0, 2, true};
    GpuOpaqueDataParser opaque;
    ASSERT_EQ(GpuOpaqueDataParser::create(fields, ver, opaque), Error::Ok);

    auto rim_records = make_min_svn_rim_records(5U, false);
    SerializableGpuClaimsV4 claims;
    LocalGpuVerifier::compare_opaque_data(opaque, rim_records, claims);

    EXPECT_TRUE(claims.m_mismatched_opaque_records == nullptr ||
                claims.m_mismatched_opaque_records->empty());
}

TEST(OpaqueComparisonTest, MismatchFlipsMeasresToFailureEvenWhenSpdmMeasurementsMatched) {
    auto fields = make_fields_with_min_svn(3U);
    OpaqueDataFormatVersion ver{0, 2, true};
    GpuOpaqueDataParser opaque;
    ASSERT_EQ(GpuOpaqueDataParser::create(fields, ver, opaque), Error::Ok);

    auto rim_records = make_min_svn_rim_records(5U, true);
    SerializableGpuClaimsV4 claims;
    claims.m_measurements_matching = SerializableMeasresClaim::Success;
    LocalGpuVerifier::compare_opaque_data(opaque, rim_records, claims);

    EXPECT_EQ(claims.m_measurements_matching, SerializableMeasresClaim::Failure);
}

TEST(OpaqueComparisonTest, MatchLeavesMeasresUntouched) {
    auto fields = make_fields_with_min_svn(5U);
    OpaqueDataFormatVersion ver{0, 2, true};
    GpuOpaqueDataParser opaque;
    ASSERT_EQ(GpuOpaqueDataParser::create(fields, ver, opaque), Error::Ok);

    auto rim_records = make_min_svn_rim_records(5U, true);
    SerializableGpuClaimsV4 claims;
    claims.m_measurements_matching = SerializableMeasresClaim::Success;
    LocalGpuVerifier::compare_opaque_data(opaque, rim_records, claims);

    EXPECT_EQ(claims.m_measurements_matching, SerializableMeasresClaim::Success);
}

TEST(OpaqueComparisonTest, WrongValueTypeCreatesMismatchEvenWhenValueWouldPass) {
    std::vector<uint8_t> svn_bytes = {0x05, 0x00};  // 5, would satisfy a floor of 5
    ParsedOpaqueFieldData field;
    ParsedOpaqueFieldData::create(svn_bytes, 37U, 0x86U, field);  // wrong rmDataValueType (not minSvn's 0x87)
    OpaqueDataFormatVersion ver{0, 2, true};
    GpuOpaqueDataParser opaque;
    ASSERT_EQ(GpuOpaqueDataParser::create({field}, ver, opaque), Error::Ok);

    auto rim_records = make_min_svn_rim_records(5U, true);
    SerializableGpuClaimsV4 claims;
    LocalGpuVerifier::compare_opaque_data(opaque, rim_records, claims);

    ASSERT_NE(claims.m_mismatched_opaque_records, nullptr);
    ASSERT_EQ(claims.m_mismatched_opaque_records->size(), 1U);
    EXPECT_EQ((*claims.m_mismatched_opaque_records)[0].runtime_value, nullptr);
    EXPECT_EQ(claims.m_attester_claims.count("FSP_UCODE_MIN_SVN"), 0U);
}

TEST(OpaqueComparisonTest, MissingMinSvnInEvidenceCreatesMismatch) {
    GpuOpaqueDataParser opaque;
    OpaqueDataFormatVersion ver{};
    ASSERT_EQ(GpuOpaqueDataParser::create({}, ver, opaque), Error::Ok);

    auto rim_records = make_min_svn_rim_records(5U, false);
    SerializableGpuClaimsV4 claims;
    LocalGpuVerifier::compare_opaque_data(opaque, rim_records, claims);

    ASSERT_NE(claims.m_mismatched_opaque_records, nullptr);
    ASSERT_EQ(claims.m_mismatched_opaque_records->size(), 1U);
    EXPECT_EQ((*claims.m_mismatched_opaque_records)[0].runtime_value, nullptr);

    EXPECT_EQ(claims.m_attester_claims.count("FSP_UCODE_MIN_SVN"), 0U);
}

TEST(OpaqueComparisonTest, NoRimRecordsIsNoop) {
    GpuOpaqueDataParser opaque;
    OpaqueDataFormatVersion ver{};
    ASSERT_EQ(GpuOpaqueDataParser::create({}, ver, opaque), Error::Ok);

    OpaqueRimRecords empty_records;
    SerializableGpuClaimsV4 claims;
    LocalGpuVerifier::compare_opaque_data(opaque, empty_records, claims);

    EXPECT_TRUE(claims.m_mismatched_opaque_records == nullptr ||
                claims.m_mismatched_opaque_records->empty());
    EXPECT_TRUE(claims.m_attester_claims.empty());
}

TEST(OpaqueRecordsConflictTest, DistinctTypeIdAndNameIsOk) {
    OpaqueRimRecord driver_rec;
    driver_rec.type_id = 37U;
    driver_rec.name    = "FSP_UCODE_MIN_SVN";
    OpaqueRimRecords driver_records;
    driver_records.add_record(driver_rec);

    OpaqueRimRecord vbios_rec;
    vbios_rec.type_id = 40U;
    vbios_rec.name    = "OTHER_MIN_SVN";
    OpaqueRimRecords vbios_records;
    vbios_records.add_record(vbios_rec);

    EXPECT_EQ(LocalGpuVerifier::check_opaque_records_conflict(driver_records, vbios_records), Error::Ok);
}

TEST(OpaqueRecordsConflictTest, SameTypeIdConflicts) {
    OpaqueRimRecord driver_rec;
    driver_rec.type_id = 37U;
    driver_rec.name    = "FSP_UCODE_MIN_SVN";
    OpaqueRimRecords driver_records;
    driver_records.add_record(driver_rec);

    OpaqueRimRecord vbios_rec;
    vbios_rec.type_id = 37U;
    vbios_rec.name    = "OTHER_MIN_SVN";
    OpaqueRimRecords vbios_records;
    vbios_records.add_record(vbios_rec);

    EXPECT_EQ(LocalGpuVerifier::check_opaque_records_conflict(driver_records, vbios_records), Error::RimMeasurementConflict);
}

TEST(OpaqueRecordsConflictTest, SameNameDifferentTypeIdConflicts) {
    // distinct type_id alone isn't sufficient: m_attester_claims is keyed by name, so a name
    // collision would silently overwrite one record's claim with the other's
    OpaqueRimRecord driver_rec;
    driver_rec.type_id = 37U;
    driver_rec.name    = "FSP_UCODE_MIN_SVN";
    OpaqueRimRecords driver_records;
    driver_records.add_record(driver_rec);

    OpaqueRimRecord vbios_rec;
    vbios_rec.type_id = 40U;
    vbios_rec.name    = "FSP_UCODE_MIN_SVN";
    OpaqueRimRecords vbios_records;
    vbios_records.add_record(vbios_rec);

    EXPECT_EQ(LocalGpuVerifier::check_opaque_records_conflict(driver_records, vbios_records), Error::RimMeasurementConflict);
}

TEST(OpaqueComparisonTest, ClaimsVersionIs4_0) {
    SerializableGpuClaimsV4 claims;
    std::string ver;
    ASSERT_EQ(claims.get_version(ver), Error::Ok);
    EXPECT_EQ(ver, "4.0");
}

TEST(OpaqueComparisonTest, JsonRoundTripPreservesAttesterClaimsAndMismatchedOpaqueRecords) {
    SerializableGpuClaimsV4 original;
    original.m_attester_claims["FSP_UCODE_MIN_SVN"] = 7U;

    SerializableOpaqueDataMismatch mm;
    mm.opaque_data_id = 37U;
    mm.name           = "FSP_UCODE_MIN_SVN";
    mm.golden_value   = 10U;
    mm.runtime_type   = std::make_shared<std::string>("MIN_SVN");
    mm.runtime_value  = std::make_shared<uint64_t>(7U);
    original.m_mismatched_opaque_records =
        std::make_shared<std::vector<SerializableOpaqueDataMismatch>>(
            std::vector<SerializableOpaqueDataMismatch>{mm});

    std::string json_str;
    ASSERT_EQ(original.serialize_json(json_str), Error::Ok);

    nlohmann::json parsed = nlohmann::json::parse(json_str);
    SerializableGpuClaimsV4 roundtripped;
    from_json(parsed, roundtripped);

    EXPECT_EQ(original, roundtripped);
}