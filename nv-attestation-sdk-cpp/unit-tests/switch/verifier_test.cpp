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

#include <fstream>
#include <thread>
#include <future>
#include <iostream>

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "nv_attestation/claims.h"
#include "nv_attestation/switch/verify.h"
#include "nv_attestation/switch/evidence.h"
#include "nv_attestation/rim.h"
#include "nv_attestation/claims_evaluator.h"
#include "nv_attestation/verify.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/nv_x509.h"
#include "environment.h"

#include "test_utils.h"
#include "switch_test_utils.h"

using ::testing::Return;
using ::testing::_;
using ::testing::DoAll;
using ::testing::SetArgReferee;
using ::testing::Invoke;

using namespace nvattestation;

class SwitchVerifierTest : public ::testing::Test {
    protected:
        void SetUp() override {
            // Any common setup can go here
        }
};

TEST_F(SwitchVerifierTest, SuccessfullyVerifySwitchEvidence) {
    auto mock_evidence_source = std::make_shared<MockSwitchEvidenceSource>();
    auto evidence_source = std::dynamic_pointer_cast<ISwitchEvidenceSource>(mock_evidence_source);

    // Set up mock to return successful evidence collection with real data
    MockSwitchEvidenceData mock_data = MockSwitchEvidenceData::create_default();
    std::vector<std::shared_ptr<SwitchEvidence>> evidence_list;
    Error error = get_mock_switch_evidence(mock_data, evidence_list);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());

    auto verifier = std::make_shared<LocalSwitchVerifier>();
    std::shared_ptr<MockNvRemoteRimStore> mock_rim_store = std::make_shared<MockNvRemoteRimStore>();
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
    error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis-stg.nvidia.com", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    error = LocalSwitchVerifier::create(*verifier, mock_rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(error, Error::Ok);

    EvidencePolicy evidence_policy {};
    ClaimsCollection claims;
    std::string detached_eat;
    error = verifier->verify_evidence(evidence_list, evidence_policy, &detached_eat, claims);
    ASSERT_EQ(error, Error::Ok) << "Could not verify evidence: " << to_string(error);
    EXPECT_EQ(claims.size(), 1);

    const SerializableSwitchClaimsV3* claims_v3 = dynamic_cast<SerializableSwitchClaimsV3*>(claims[0].get());
    ASSERT_NE(claims_v3, nullptr) << "Expected SerializableSwitchClaimsV3 claims";

    EXPECT_EQ(claims_v3->m_switch_bios_version, mock_data.bios_version);
    EXPECT_EQ(claims_v3->m_hwmodel, "LS_10 A01 FSP BROM");
    EXPECT_EQ(claims_v3->m_ueid, "694931143880983876767046803400974855445978836716");
    EXPECT_EQ(claims_v3->m_measurements_matching, SerializableMeasresClaim::Success);

}

TEST_F(SwitchVerifierTest, SuccessSwitchEvidenceRemoteVerifier) {

    auto mock_evidence_source = std::make_shared<MockSwitchEvidenceSource>();
    auto evidence_source = std::dynamic_pointer_cast<ISwitchEvidenceSource>(mock_evidence_source);

    // Set up mock to return successful evidence collection with real data
    MockSwitchEvidenceData mock_data = MockSwitchEvidenceData::create_default();
    mock_evidence_source->setup_success_behavior(mock_data);

    std::vector<std::shared_ptr<SwitchEvidence>> evidence_list;
    Error error = get_mock_switch_evidence(mock_data, evidence_list);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());

    NvRemoteSwitchVerifier verifier;
    NvRemoteSwitchVerifier::init_from_env(verifier, "https://nras.attestation-stg.nvidia.com", g_env->service_key, HttpOptions());

    EvidencePolicy evidence_policy {};
    ClaimsCollection claims;
    std::string detached_eat;
    error = verifier.verify_evidence(evidence_list, evidence_policy, &detached_eat, claims);
    ASSERT_EQ(error, Error::Ok) << "Could not verify evidence: " << to_string(error);
    EXPECT_EQ(claims.size(), 1);

    const SerializableSwitchClaimsV3* claims_v3 = dynamic_cast<SerializableSwitchClaimsV3*>(claims[0].get());
    ASSERT_NE(claims_v3, nullptr) << "Expected SerializableSwitchClaimsV3 claims";

    EXPECT_EQ(claims_v3->m_switch_bios_version, mock_data.bios_version);
    EXPECT_EQ(claims_v3->m_hwmodel, "LS_10 A01 FSP BROM");
    EXPECT_EQ(claims_v3->m_ueid, "694931143880983876767046803400974855445978836716");
    EXPECT_EQ(claims_v3->m_measurements_matching, SerializableMeasresClaim::Success);

}

TEST_F(SwitchVerifierTest, VerifySwitchEvidenceWithBadNonce) {
    auto rim_store = std::make_shared<NvRemoteRimStoreImpl>();
    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis-stg.nvidia.com", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    LocalSwitchVerifier verifier;
    error = LocalSwitchVerifier::create(verifier, rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock switch evidence with bad nonce
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04};
    std::vector<std::shared_ptr<SwitchEvidence>> evidence_list;
    
    // Use mock data for nonce mismatch scenario
    MockSwitchEvidenceData mock_data = MockSwitchEvidenceData::create_bad_nonce_scenario();
    error = get_mock_switch_evidence(mock_data, evidence_list);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy {};
    ClaimsCollection claims;
    error = verifier.verify_evidence(evidence_list, evidence_policy, nullptr, claims);
    // Nonce mismatch should be treated as a fatal error in current implementation
    ASSERT_EQ(error, Error::SwitchEvidenceNonceMismatch) << "Expected InternalError for nonce mismatch, got: " << to_string(error);
    // No claims should be generated when verification fails
    EXPECT_TRUE(claims.empty());
}

TEST_F(SwitchVerifierTest, VerifySwitchEvidenceWithBadRimSignature) {
    auto verifier = std::make_shared<LocalSwitchVerifier>();
    std::shared_ptr<MockNvRemoteRimStore> mock_rim_store = std::make_shared<MockNvRemoteRimStore>();
    EXPECT_CALL(*mock_rim_store, get_rim(_, _))
        .WillOnce(Invoke([](const std::string& rim_id, RimDocument& out_rim_document) -> Error {
            if (rim_id != "NV_SWITCH_BIOS_5612_0002_890_9610550001") {
                LOG_ERROR("RIM ID mismatch: " << rim_id);
                return Error::RimNotFound;
            }
            std::ifstream file("testdata/sample_rims/NV_SWITCH_BIOS_5612_0002_890_9610550001_invalid_signature.xml");
            std::string xml_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            Error error = RimDocument::create_from_rim_data(xml_data, out_rim_document);
            return error;
        }));
    std::shared_ptr<NvHttpOcspClient> ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis-stg.nvidia.com", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    error = LocalSwitchVerifier::create(*verifier, mock_rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock switch evidence with invalid signature
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04}; // Sample nonce
    std::vector<std::shared_ptr<SwitchEvidence>> evidence_list;
    
    // Use invalid signature mock data
    MockSwitchEvidenceData mock_data = MockSwitchEvidenceData::create_bad_rim_signature_scenario();
    Error result = get_mock_switch_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy {};
    ClaimsCollection claims;
    error = verifier->verify_evidence(evidence_list, evidence_policy, nullptr, claims);
    ASSERT_EQ(error, Error::RimInvalidSignature) << "Could not verify evidence: " << to_string(error);
    // No claims should be generated when verification fails due to OCSP validation failure
    EXPECT_TRUE(claims.empty());
}

TEST_F(SwitchVerifierTest, VerifySwitchEvidenceWithDriverMeasurementsMismatch) {
    auto verifier = std::make_shared<LocalSwitchVerifier>();
    std::shared_ptr<MockNvRemoteRimStore> mock_rim_store = std::make_shared<MockNvRemoteRimStore>();
    EXPECT_CALL(*mock_rim_store, get_rim(_, _))
        .WillOnce(Invoke([](const std::string& rim_id, RimDocument& out_rim_document) -> Error {
            if (rim_id != "NV_SWITCH_BIOS_5612_0002_890_9610550001") {
                LOG_ERROR("RIM ID mismatch: " << rim_id);
                return Error::RimNotFound;
            }
            std::ifstream file("testdata/sample_rims/NV_SWITCH_BIOS_5612_0002_890_9610550001_measurement_mismatch.xml");
            std::string xml_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            Error error = RimDocument::create_from_rim_data(xml_data, out_rim_document);
            return error;
        }));    
    std::shared_ptr<NvHttpOcspClient> ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis-stg.nvidia.com", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    error = LocalSwitchVerifier::create(*verifier, mock_rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock switch evidence with driver measurements mismatch scenario
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04}; // Sample nonce
    std::vector<std::shared_ptr<SwitchEvidence>> evidence_list;
    
    // Use driver measurements mismatch mock data
    MockSwitchEvidenceData mock_data = MockSwitchEvidenceData::create_measurements_mismatch_scenario();
    Error result = get_mock_switch_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy {};
    // disable rim signature verification because the rim version in the mock rim file
    // was changed to match the expected rim version. this is because, to make the 
    // measurements mismatch, a random rim file is used. the version change is required
    // because rim version match check happens before measurements are checked.
    evidence_policy.verify_rim_signature = false;
    ClaimsCollection claims;
    error = verifier->verify_evidence(evidence_list, evidence_policy, nullptr, claims);
    ASSERT_EQ(error, Error::Ok) << "Verification should succeed but mark measurements as mismatched, got: " << to_string(error);
    EXPECT_EQ(claims.size(), 1);

    const SerializableSwitchClaimsV3* claims_v3 = dynamic_cast<SerializableSwitchClaimsV3*>(claims[0].get());
    ASSERT_NE(claims_v3, nullptr) << "Expected SerializableSwitchClaimsV3 claims";

    // Verify that measurements are marked as not matching
    EXPECT_EQ(claims_v3->m_measurements_matching, SerializableMeasresClaim::Failure);
    
    // When measurements don't match, secure_boot and debug_status should be null
    EXPECT_EQ(claims_v3->m_secure_boot, nullptr);
    EXPECT_EQ(claims_v3->m_debug_status, nullptr);
    
    // Mismatched measurements should be populated
    EXPECT_NE(claims_v3->m_mismatched_measurements, nullptr);
    EXPECT_GT(claims_v3->m_mismatched_measurements->size(), 0);
}

TEST_F(SwitchVerifierTest, VerifySwitchEvidenceWithInvalidSignature) {
    auto rim_store = std::make_shared<NvRemoteRimStoreImpl>();
    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis-stg.nvidia.com", g_env->service_key, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    LocalSwitchVerifier verifier;
    error = LocalSwitchVerifier::create(verifier, rim_store, ocsp_client, DetachedEATOptions());
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence with invalid signature
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04}; // Sample nonce
    std::vector<std::shared_ptr<SwitchEvidence>> evidence_list;
    
    // Use invalid signature mock data
    MockSwitchEvidenceData mock_data = MockSwitchEvidenceData::create_invalid_signature_scenario();
    Error result = get_mock_switch_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy {};
    ClaimsCollection claims;
    error = verifier.verify_evidence(evidence_list, evidence_policy, nullptr, claims);
    ASSERT_EQ(error, Error::SwitchEvidenceInvalidSignature) << "Could not verify evidence: " << to_string(error);
    // No claims should be generated when verification fails due to invalid signature
    EXPECT_TRUE(claims.empty());
}

class SwitchLocalVerifierTestCApi : public ::testing::Test {
    protected:
        nvat_switch_evidence_t* m_mock_single_switch_evidence = nullptr;
        size_t m_num_mock_single_switch_evidence = 1;
        nvat_switch_evidence_t* m_mock_multi_switch_evidence = nullptr;
        size_t m_num_mock_multi_switch_evidence = 4;
        nvat_switch_evidence_t* m_actual_switch_evidence = nullptr;
        size_t m_num_actual_switch_evidence = 0;
        nvat_switch_verifier_t m_verifier = nullptr;
        nvat_switch_verifier_t m_caching_verifier = nullptr;
        nvat_evidence_policy_t m_evidence_policy = nullptr;

        void SetUp() override {
            
            nvat_switch_evidence_source_t evidence_source = nullptr;
            if (g_env->test_mode == "integration" && g_env->test_device_switch) {
                time_t start_time = time(nullptr);
                ASSERT_EQ(nvat_switch_evidence_source_nscq_create(&evidence_source), NVAT_RC_OK);
                ASSERT_EQ(nvat_switch_evidence_collect(evidence_source, nullptr, &m_actual_switch_evidence, &m_num_actual_switch_evidence), NVAT_RC_OK);
                time_t end_time = time(nullptr);
                std::cout << "Actual switch evidence collection took " << end_time - start_time << " seconds" << std::endl;
                nvat_switch_evidence_source_free(&evidence_source);

                nvat_rim_store_t rim_store = nullptr;
                nvat_ocsp_client_t ocsp_client = nullptr;
                ASSERT_EQ(nvat_rim_store_create_remote(&rim_store, "https://rim-internal.attestation.nvidia.com/internal", g_env->service_key.c_str(), nullptr), NVAT_RC_OK);
                ASSERT_NE(rim_store, nullptr);
                ASSERT_EQ(nvat_ocsp_client_create_default(&ocsp_client, "https://ocsp.ndis-stg.nvidia.com", g_env->service_key.c_str(), nullptr), NVAT_RC_OK);
                ASSERT_NE(ocsp_client, nullptr);

                nvat_switch_local_verifier_t local_verifier = nullptr;
                ASSERT_EQ(nvat_switch_local_verifier_create(&local_verifier, rim_store, ocsp_client, nullptr), NVAT_RC_OK);
                ASSERT_NE(local_verifier, nullptr);
                m_verifier = nvat_switch_local_verifier_upcast(local_verifier);
                ASSERT_NE(m_verifier, nullptr);

                nvat_rim_store_t cached_rim_store = nullptr;
                nvat_ocsp_client_t cached_ocsp_client = nullptr;
                ASSERT_EQ(nvat_rim_store_create_cached(&cached_rim_store, rim_store, 1024*1024, 60*60), NVAT_RC_OK);
                ASSERT_NE(cached_rim_store, nullptr);
                ASSERT_EQ(nvat_ocsp_client_create_cached(&cached_ocsp_client, ocsp_client, 1024*1024, 60*60), NVAT_RC_OK);
                ASSERT_NE(cached_ocsp_client, nullptr);
                nvat_switch_local_verifier_t caching_local_verifier = nullptr;
                ASSERT_EQ(nvat_switch_local_verifier_create(&caching_local_verifier, cached_rim_store, cached_ocsp_client, nullptr), NVAT_RC_OK);
                ASSERT_NE(caching_local_verifier, nullptr);
                m_caching_verifier = nvat_switch_local_verifier_upcast(caching_local_verifier);
                ASSERT_NE(m_caching_verifier, nullptr);

                nvat_ocsp_client_free(&cached_ocsp_client);
                nvat_ocsp_client_free(&ocsp_client);
                nvat_rim_store_free(&rim_store);
                nvat_rim_store_free(&cached_rim_store);
            } else {
                std::string switch_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/switch_evidence_ls10.json";
                ASSERT_EQ(nvat_switch_evidence_source_from_json_file(&evidence_source, switch_evidence_path.c_str()), NVAT_RC_OK);
                nvat_nonce_t nonce = nullptr;
                ASSERT_EQ(nvat_nonce_from_hex(&nonce, "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"), NVAT_RC_OK);
                ASSERT_NE(nonce, nullptr);
                ASSERT_EQ(nvat_switch_evidence_collect(evidence_source, nonce, &m_mock_single_switch_evidence, &m_num_mock_single_switch_evidence), NVAT_RC_OK);
                nvat_switch_evidence_source_free(&evidence_source);

                switch_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/multi_switch_ls10.json";
                ASSERT_EQ(nvat_switch_evidence_source_from_json_file(&evidence_source, switch_evidence_path.c_str()), NVAT_RC_OK);
                ASSERT_EQ(nvat_switch_evidence_collect(evidence_source, nonce, &m_mock_multi_switch_evidence, &m_num_mock_multi_switch_evidence), NVAT_RC_OK);
                nvat_switch_evidence_source_free(&evidence_source);
                nvat_nonce_free(&nonce);

                nvat_rim_store_t rim_store = nullptr;
                ASSERT_EQ(nvat_rim_store_create_remote(&rim_store, "https://rim-internal.attestation.nvidia.com/internal", g_env->service_key.c_str(), nullptr), NVAT_RC_OK);
                ASSERT_NE(rim_store, nullptr);

                nvat_ocsp_client_t ocsp_client = nullptr;
                ASSERT_EQ(nvat_ocsp_client_create_default(&ocsp_client, "https://ocsp.ndis-stg.nvidia.com", g_env->service_key.c_str(), nullptr), NVAT_RC_OK);
                ASSERT_NE(ocsp_client, nullptr);

                nvat_switch_local_verifier_t local_verifier = nullptr;
                ASSERT_EQ(nvat_switch_local_verifier_create(&local_verifier, rim_store, ocsp_client, nullptr), NVAT_RC_OK);
                ASSERT_NE(local_verifier, nullptr);
                m_verifier = nvat_switch_local_verifier_upcast(local_verifier);
                ASSERT_NE(m_verifier, nullptr);

                nvat_rim_store_t cached_rim_store = nullptr;
                ASSERT_EQ(nvat_rim_store_create_cached(&cached_rim_store, rim_store, 1024*1024, 60*60), NVAT_RC_OK);
                ASSERT_NE(cached_rim_store, nullptr);
                nvat_ocsp_client_t cached_ocsp_client = nullptr;
                ASSERT_EQ(nvat_ocsp_client_create_cached(&cached_ocsp_client, ocsp_client, 1024*1024, 60*60), NVAT_RC_OK);
                ASSERT_NE(cached_ocsp_client, nullptr);
                nvat_switch_local_verifier_t caching_local_verifier = nullptr;
                ASSERT_EQ(nvat_switch_local_verifier_create(&caching_local_verifier, cached_rim_store, cached_ocsp_client, nullptr), NVAT_RC_OK);
                ASSERT_NE(caching_local_verifier, nullptr);
                m_caching_verifier = nvat_switch_local_verifier_upcast(caching_local_verifier);
                ASSERT_NE(m_caching_verifier, nullptr);

                nvat_ocsp_client_free(&ocsp_client);
                nvat_ocsp_client_free(&cached_ocsp_client);
                nvat_rim_store_free(&rim_store);
                nvat_rim_store_free(&cached_rim_store);
            }
            
        ASSERT_EQ(nvat_evidence_policy_create_default(&m_evidence_policy), NVAT_RC_OK);
        ASSERT_NE(m_evidence_policy, nullptr);
        }

        void TearDown() override {
            nvat_evidence_policy_free(&m_evidence_policy);
            nvat_switch_verifier_free(&m_verifier);
            nvat_switch_verifier_free(&m_caching_verifier);
            if (g_env->test_mode == "integration" && g_env->test_device_switch) {
                nvat_switch_evidence_array_free(&m_actual_switch_evidence, m_num_actual_switch_evidence);
            } else {
                nvat_switch_evidence_array_free(&m_mock_single_switch_evidence, m_num_mock_single_switch_evidence);
                nvat_switch_evidence_array_free(&m_mock_multi_switch_evidence, m_num_mock_multi_switch_evidence);
            }
        }
};

TEST_F(SwitchLocalVerifierTestCApi, SerialVerify) { 
    if (g_env->test_mode == "integration" && !g_env->test_device_switch) {
        GTEST_SKIP() << "Skipping switch Integration tests";
    }
    time_t start_time = time(nullptr);
    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    if (g_env->test_mode == "unit"){
        ASSERT_EQ(nvat_verify_switch_evidence(m_verifier, m_mock_multi_switch_evidence, m_num_mock_multi_switch_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
    } else if (g_env->test_mode == "integration"){
        ASSERT_EQ(nvat_verify_switch_evidence(m_verifier, m_actual_switch_evidence, m_num_actual_switch_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
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

TEST_F(SwitchLocalVerifierTestCApi, SerialVerifyWithCache) { 
    if (g_env->test_mode == "integration" && !g_env->test_device_switch) {
        GTEST_SKIP() << "Skipping switch Integration tests";
    }
    time_t start_time = time(nullptr);
    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    if (g_env->test_mode == "unit"){
        ASSERT_EQ(nvat_verify_switch_evidence(m_caching_verifier, m_mock_multi_switch_evidence, m_num_mock_multi_switch_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
    } else if (g_env->test_mode == "integration"){
        ASSERT_EQ(nvat_verify_switch_evidence(m_caching_verifier, m_actual_switch_evidence, m_num_actual_switch_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
    }
    ASSERT_NE(claims, nullptr);
    ASSERT_NE(detached_eat, nullptr);
    time_t end_time = time(nullptr);
    std::cout << "Time taken for serial verify with cache: " << end_time - start_time << " seconds" << std::endl;
    nvat_str_free(&detached_eat);
    nvat_claims_collection_free(&claims);
}

TEST_F(SwitchLocalVerifierTestCApi, ParallelVerify) { 
    if (g_env->test_mode == "integration" && !g_env->test_device_switch) {
        GTEST_SKIP() << "Skipping switch Integration tests";
    }
    nvat_switch_evidence_t* evidences = nullptr;
    size_t num_evidences = 0;
    if (g_env->test_mode == "unit"){
        evidences = m_mock_multi_switch_evidence;
        num_evidences = m_num_mock_multi_switch_evidence;
    } else if (g_env->test_mode == "integration"){
        evidences = m_actual_switch_evidence;
        num_evidences = m_num_actual_switch_evidence;
    }

    std::vector<std::future<nvat_rc_t>> futures;
    const int num_threads = 4;
    int num_evidences_per_thread = num_evidences / num_threads;
    time_t start_time = time(nullptr);
    for (size_t i = 0; i < num_threads; i++) {
        futures.emplace_back(std::async(std::launch::async, [this, evidences, num_evidences, num_evidences_per_thread, i]() -> nvat_rc_t {
            nvat_claims_collection_t claims = nullptr;
            nvat_str_t detached_eat = nullptr;
            int this_thread_evidences = num_evidences_per_thread;
            if (i == num_threads - 1) {
                this_thread_evidences = num_evidences - i*num_evidences_per_thread;
            }
            nvat_rc_t result = nvat_verify_switch_evidence(m_verifier, evidences+i*num_evidences_per_thread, this_thread_evidences, m_evidence_policy, &detached_eat, &claims);
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

TEST_F(SwitchLocalVerifierTestCApi, ParallelVerifyWithWarmCache) { 
    if (g_env->test_mode == "integration" && !g_env->test_device_switch) {
        GTEST_SKIP() << "Skipping switch Integration tests";
    }
    nvat_switch_evidence_t* evidences = nullptr;
    size_t num_evidences = 0;
    if (g_env->test_mode == "unit"){
        evidences = m_mock_multi_switch_evidence;
        num_evidences = m_num_mock_multi_switch_evidence;
    } else if (g_env->test_mode == "integration"){
        evidences = m_actual_switch_evidence;
        num_evidences = m_num_actual_switch_evidence;
    }

    // warm up the cache
    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    ASSERT_EQ(nvat_verify_switch_evidence(m_caching_verifier, evidences, num_evidences, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
    ASSERT_NE(claims, nullptr);
    ASSERT_NE(detached_eat, nullptr);
    nvat_str_free(&detached_eat);
    nvat_claims_collection_free(&claims);

    std::vector<std::future<nvat_rc_t>> futures;
    const int num_threads = 4;
    int num_evidences_per_thread = num_evidences / num_threads;
    time_t start_time = time(nullptr);
    for (size_t i = 0; i < num_threads; i++) {
        futures.emplace_back(std::async(std::launch::async, [this, evidences, num_evidences, num_evidences_per_thread, i]() -> nvat_rc_t {
            nvat_claims_collection_t claims = nullptr;
            nvat_str_t detached_eat = nullptr;
            int this_thread_evidences = num_evidences_per_thread;
            if (i == num_threads - 1) {
                this_thread_evidences = num_evidences - i*num_evidences_per_thread;
            }
            nvat_rc_t result = nvat_verify_switch_evidence(m_caching_verifier, evidences+i*num_evidences_per_thread, this_thread_evidences, m_evidence_policy, &detached_eat, &claims);
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

class SwitchRemoteVerifierTestCApi : public ::testing::Test {
    protected:
        nvat_switch_verifier_t m_verifier = nullptr;
        nvat_switch_evidence_t* m_mock_single_switch_evidence = nullptr;
        size_t m_num_mock_single_switch_evidence = 1;
        nvat_evidence_policy_t m_evidence_policy = nullptr;


        void SetUp() override {
            nvat_switch_nras_verifier_t nras_verifier = nullptr;
            ASSERT_EQ(nvat_switch_nras_verifier_create(&nras_verifier, "https://nras.attestation-stg.nvidia.com", g_env->service_key.c_str(), nullptr), NVAT_RC_OK);
            ASSERT_NE(nras_verifier, nullptr);
            m_verifier = nvat_switch_nras_verifier_upcast(nras_verifier);
            ASSERT_NE(m_verifier, nullptr);

            std::string switch_evidence_path = g_env->common_test_data_dir + "/serialized_test_evidence/switch_evidence_ls10.json";
            nvat_switch_evidence_source_t evidence_source = nullptr;
            ASSERT_EQ(nvat_switch_evidence_source_from_json_file(&evidence_source, switch_evidence_path.c_str()), NVAT_RC_OK);
            nvat_nonce_t nonce = nullptr;
            ASSERT_EQ(nvat_nonce_from_hex(&nonce, "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb"), NVAT_RC_OK);
            ASSERT_NE(nonce, nullptr);
            ASSERT_EQ(nvat_switch_evidence_collect(evidence_source, nonce, &m_mock_single_switch_evidence, &m_num_mock_single_switch_evidence), NVAT_RC_OK);
            nvat_switch_evidence_source_free(&evidence_source);
            nvat_nonce_free(&nonce);

            ASSERT_EQ(nvat_evidence_policy_create_default(&m_evidence_policy), NVAT_RC_OK);
            ASSERT_NE(m_evidence_policy, nullptr);
        }

        void TearDown() override {
            nvat_switch_evidence_array_free(&m_mock_single_switch_evidence, m_num_mock_single_switch_evidence);
            nvat_switch_verifier_free(&m_verifier);
            nvat_evidence_policy_free(&m_evidence_policy);
        }
};

TEST_F(SwitchRemoteVerifierTestCApi, VerifySingleSwitchEvidence) {
    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    ASSERT_EQ(nvat_verify_switch_evidence(m_verifier, m_mock_single_switch_evidence, m_num_mock_single_switch_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_OK);
    ASSERT_NE(claims, nullptr);
    ASSERT_NE(detached_eat, nullptr);
    nvat_str_free(&detached_eat);
    nvat_claims_collection_free(&claims);
}

TEST_F(SwitchRemoteVerifierTestCApi, InvalidServiceKey) {
    std::string service_key = "invalid_service_key";
    nvat_switch_nras_verifier_t nras_verifier = nullptr;
    ASSERT_EQ(nvat_switch_nras_verifier_create(&nras_verifier, "https://nras.attestation-stg.nvidia.com", service_key.c_str(), nullptr), NVAT_RC_OK);
    ASSERT_NE(nras_verifier, nullptr);
    nvat_switch_verifier_t verifier = nvat_switch_nras_verifier_upcast(nras_verifier);
    ASSERT_NE(verifier, nullptr);
    nvat_claims_collection_t claims = nullptr;
    nvat_str_t detached_eat = nullptr;
    ASSERT_EQ(nvat_verify_switch_evidence(verifier, m_mock_single_switch_evidence, m_num_mock_single_switch_evidence, m_evidence_policy, &detached_eat, &claims), NVAT_RC_NRAS_FORBIDDEN);
    ASSERT_EQ(claims, nullptr);
    ASSERT_EQ(detached_eat, nullptr);
    nvat_switch_verifier_free(&verifier);
}
