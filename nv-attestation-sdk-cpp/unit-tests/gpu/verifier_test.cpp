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

//third party
#include "gtest/gtest.h"
#include "gmock/gmock.h"

//this sdk
#include "nv_attestation/claims.h"
#include "nv_attestation/gpu/verify.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/nv_x509.h"
#include "nv_attestation/rim.h"
#include "nv_attestation/claims_evaluator.h"

//test utils
#include "test_utils.h"

using namespace nvattestation;
using ::testing::Return;
using ::testing::_;

class GpuVerifierTest : public ::testing::Test {
    protected:
        // Setup method for common test initialization
        void SetUp() override {
            // Any common setup can go here
        }
};

TEST_F(GpuVerifierTest, SuccessfullyVerifyGpuEvidence) {
    auto rim_store = std::make_shared<NvRemoteRimStoreImpl>();
    Error error = NvRemoteRimStoreImpl::init_from_env(*rim_store, "https://rim.attestation.nvidia.com", HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    error = NvHttpOcspClient::create(*ocsp_client, "https://ocsp.ndis.nvidia.com", HttpOptions());
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

    const SerializableGpuClaimsV3* claims_v3 = dynamic_cast<SerializableGpuClaimsV3*>(claims[0].get());
    ASSERT_NE(claims_v3, nullptr) << "Expected SerializableGpuClaimsV3 claims";
    ASSERT_EQ(claims_v3->m_measurements_matching, SerializableMeasresClaim::Success);
    ASSERT_EQ(claims_v3->m_driver_version, mock_data.driver_version);
    ASSERT_EQ(claims_v3->m_vbios_version, mock_data.vbios_version);
    ASSERT_EQ(claims_v3->m_hwmodel, "GH100 A01 GSP BROM");
    ASSERT_EQ(claims_v3->m_ueid, "478176379286082186618948445787393647364802107249");
    ASSERT_EQ(claims_v3->m_oem_id, "5703");

}

TEST_F(GpuVerifierTest, SuccessfullyVerifyGpuEvidenceRemoteVerifier) {
    NvRemoteGpuVerifier verifier;
    Error error = NvRemoteGpuVerifier::init_from_env(verifier);
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

    SerializableGpuClaimsV3* claims_v3 = dynamic_cast<SerializableGpuClaimsV3*>(claims[0].get());
    EXPECT_EQ(claims_v3->m_measurements_matching, SerializableMeasresClaim::Success);
    EXPECT_EQ(claims_v3->m_driver_version, mock_data.driver_version);
    EXPECT_EQ(claims_v3->m_vbios_version, mock_data.vbios_version);
    EXPECT_EQ(claims_v3->m_hwmodel, "GH100 A01 GSP BROM");
    EXPECT_EQ(claims_v3->m_ueid, "478176379286082186618948445787393647364802107249");
    EXPECT_EQ(claims_v3->m_oem_id, "5703");
    EXPECT_EQ(claims_v3->m_nonce, mock_data.nonce);
}
TEST_F(GpuVerifierTest, VerifyGpuEvidenceWithBadNonce) {
    auto rim_store = std::make_shared<NvRemoteRimStoreImpl>();
    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "https://ocsp.ndis.nvidia.com", HttpOptions());
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
    Error error = NvHttpOcspClient::create(*ocsp_client, "https://ocsp.ndis.nvidia.com", HttpOptions());
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
    Error error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis.nvidia.com", HttpOptions());
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

    const SerializableGpuClaimsV3* claims_v3 = dynamic_cast<SerializableGpuClaimsV3*>(claims[0].get());
    ASSERT_NE(claims_v3, nullptr) << "Expected SerializableGpuClaimsV3 claims";

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
    auto verifier = std::make_shared<LocalGpuVerifier>();
    std::shared_ptr<MockNvRemoteRimStore> mock_rim_store = std::make_shared<MockNvRemoteRimStore>();
    EXPECT_CALL(*mock_rim_store, get_rim(_, _))
        .WillOnce(Invoke([](const std::string& rim_id, RimDocument& out_rim_document) -> Error {
            if (rim_id != "NV_GPU_DRIVER_GH100_570.124.03") {
                LOG_ERROR("RIM ID mismatch: " << rim_id);
                return Error::RimNotFound;
            }
            std::ifstream file("testdata/sample_rims/NV_GPU_DRIVER_GH100_570.124.03_expired.xml");
            std::string xml_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            Error error = RimDocument::create_from_rim_data(xml_data, out_rim_document);
            return error;
        }));
    std::shared_ptr<NvHttpOcspClient> ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis.nvidia.com", HttpOptions());
    error = LocalGpuVerifier::create(*verifier, mock_rim_store, ocsp_client, DetachedEATOptions());
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
    ClaimsCollection claims;
    error = verifier->verify_evidence(evidence_list, evidence_policy, nullptr, claims);
    // Nonce mismatch should be treated as a fatal error in current implementation
    ASSERT_EQ(error, Error::CertChainVerificationFailure) << "Could not verify evidence: " << to_string(error);
    // No claims should be generated when verification fails
    EXPECT_TRUE(claims.empty());
}

TEST_F(GpuVerifierTest, VerifyGpuEvidenceWithBlackwell) {
    auto rim_store = std::make_shared<NvRemoteRimStoreImpl>();
    const char* base_url = "https://rim.attestation-stg.nvidia.com";
    Error error = NvRemoteRimStoreImpl::init_from_env(*rim_store, base_url, HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    error = NvHttpOcspClient::create(*ocsp_client, "https://ocsp.ndis-stg.nvidia.com", HttpOptions());
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

    const SerializableGpuClaimsV3* claims_v3 = dynamic_cast<SerializableGpuClaimsV3*>(claims[0].get());
    ASSERT_NE(claims_v3, nullptr) << "Expected SerializableGpuClaimsV3 claims";
    EXPECT_EQ(claims_v3->m_hwmodel, "GB100 A01 GSP BROM");
    EXPECT_EQ(claims_v3->m_ueid, "474146966256510137525212816567191319424869109849");
    EXPECT_EQ(claims_v3->m_oem_id, "5703");
    EXPECT_EQ(claims_v3->m_driver_version, mock_data.driver_version);
    EXPECT_EQ(claims_v3->m_vbios_version, mock_data.vbios_version);
    EXPECT_EQ(claims_v3->m_measurements_matching, SerializableMeasresClaim::Success);
}