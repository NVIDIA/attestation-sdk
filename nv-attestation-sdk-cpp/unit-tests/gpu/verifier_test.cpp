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
    error = LocalGpuVerifier::create(verifier, rim_store, ocsp_client);
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence using test utilities
    std::vector<GpuEvidence> evidence_list;
    
    // Use default mock data
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_default();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy{};
    ClaimsCollection claims;
    error = verifier.verify_evidence(evidence_list, evidence_policy, claims);
    ASSERT_EQ(error, Error::Ok) << "Could not verify evidence: " << to_string(error);
    EXPECT_EQ(claims.size(), 1);

    const SerializableGpuClaimsV3* claims_v3 = dynamic_cast<SerializableGpuClaimsV3*>(claims[0].get());
    ASSERT_NE(claims_v3, nullptr) << "Expected SerializableGpuClaimsV3 claims";

    std::string expected_claims_v3;
    readFileIntoString("testdata/sample_attestation_data/hopperClaimsv3_decoded.json", expected_claims_v3);

    SerializableGpuClaimsV3 expected_claims_v3_obj;
    try {
        nlohmann::json j = nlohmann::json::parse(expected_claims_v3);
        nlohmann::json gpu0_claims = j.at("GPU-0");
        expected_claims_v3_obj = gpu0_claims.get<SerializableGpuClaimsV3>();
    } catch (const nlohmann::json::exception& e) {
        LOG_ERROR("JSON parse error in when getting expected claims v3: " << e.what());
        GTEST_FAIL() << "could not parse expected claims v3";
        return;
    }

    EXPECT_EQ(claims_v3->m_measurements_matching, expected_claims_v3_obj.m_measurements_matching);
    EXPECT_EQ(claims_v3->m_gpu_arch_match, expected_claims_v3_obj.m_gpu_arch_match);
    ASSERT_NE(claims_v3->m_secure_boot, nullptr);
    ASSERT_NE(claims_v3->m_debug_status, nullptr);
    EXPECT_EQ(*claims_v3->m_secure_boot, *expected_claims_v3_obj.m_secure_boot);
    EXPECT_EQ(*claims_v3->m_debug_status, *expected_claims_v3_obj.m_debug_status);
    EXPECT_EQ(claims_v3->m_mismatched_measurements, nullptr);
    EXPECT_EQ(claims_v3->m_driver_version, expected_claims_v3_obj.m_driver_version);
    EXPECT_EQ(claims_v3->m_vbios_version, expected_claims_v3_obj.m_vbios_version);

    // ar cert chain claims
    EXPECT_EQ(claims_v3->m_ar_cert_chain.m_cert_expiration_date, expected_claims_v3_obj.m_ar_cert_chain.m_cert_expiration_date);
    EXPECT_EQ(claims_v3->m_ar_cert_chain.m_cert_status, expected_claims_v3_obj.m_ar_cert_chain.m_cert_status);
    EXPECT_EQ(claims_v3->m_ar_cert_chain.m_cert_ocsp_status, expected_claims_v3_obj.m_ar_cert_chain.m_cert_ocsp_status);
    EXPECT_EQ(claims_v3->m_ar_cert_chain.m_cert_revocation_reason, expected_claims_v3_obj.m_ar_cert_chain.m_cert_revocation_reason);
    EXPECT_EQ(claims_v3->m_ar_cert_chain_fwid_match, expected_claims_v3_obj.m_ar_cert_chain_fwid_match);
    EXPECT_EQ(claims_v3->m_ar_parsed, expected_claims_v3_obj.m_ar_parsed);
    EXPECT_EQ(claims_v3->m_gpu_ar_nonce_match, expected_claims_v3_obj.m_gpu_ar_nonce_match);
    EXPECT_EQ(claims_v3->m_ar_signature_verified, expected_claims_v3_obj.m_ar_signature_verified);
    

    // driver rim claims
    EXPECT_EQ(claims_v3->m_driver_rim_fetched, expected_claims_v3_obj.m_driver_rim_fetched);
    EXPECT_EQ(claims_v3->m_driver_rim_cert_chain.m_cert_expiration_date, expected_claims_v3_obj.m_driver_rim_cert_chain.m_cert_expiration_date);
    EXPECT_EQ(claims_v3->m_driver_rim_cert_chain.m_cert_status, expected_claims_v3_obj.m_driver_rim_cert_chain.m_cert_status);
    EXPECT_EQ(claims_v3->m_driver_rim_cert_chain.m_cert_ocsp_status, expected_claims_v3_obj.m_driver_rim_cert_chain.m_cert_ocsp_status);
    EXPECT_EQ(claims_v3->m_driver_rim_cert_chain.m_cert_revocation_reason, expected_claims_v3_obj.m_driver_rim_cert_chain.m_cert_revocation_reason);
    EXPECT_EQ(claims_v3->m_driver_rim_signature_verified, expected_claims_v3_obj.m_driver_rim_signature_verified);
    EXPECT_EQ(claims_v3->m_gpu_driver_rim_version_match, expected_claims_v3_obj.m_gpu_driver_rim_version_match);
    EXPECT_EQ(claims_v3->m_driver_rim_measurements_available, expected_claims_v3_obj.m_driver_rim_measurements_available);

    // vbios rim claims
    EXPECT_EQ(claims_v3->m_vbios_rim_fetched, expected_claims_v3_obj.m_vbios_rim_fetched);
    EXPECT_EQ(claims_v3->m_vbios_rim_cert_chain.m_cert_expiration_date, expected_claims_v3_obj.m_vbios_rim_cert_chain.m_cert_expiration_date);
    EXPECT_EQ(claims_v3->m_vbios_rim_cert_chain.m_cert_status, expected_claims_v3_obj.m_vbios_rim_cert_chain.m_cert_status);
    EXPECT_EQ(claims_v3->m_vbios_rim_cert_chain.m_cert_ocsp_status, expected_claims_v3_obj.m_vbios_rim_cert_chain.m_cert_ocsp_status);
    EXPECT_EQ(claims_v3->m_vbios_rim_cert_chain.m_cert_revocation_reason, expected_claims_v3_obj.m_vbios_rim_cert_chain.m_cert_revocation_reason);
    EXPECT_EQ(claims_v3->m_gpu_vbios_rim_version_match, expected_claims_v3_obj.m_gpu_vbios_rim_version_match);
    EXPECT_EQ(claims_v3->m_vbios_rim_signature_verified, expected_claims_v3_obj.m_vbios_rim_signature_verified);
    EXPECT_EQ(claims_v3->m_vbios_rim_measurements_available, expected_claims_v3_obj.m_vbios_rim_measurements_available);
    EXPECT_EQ(claims_v3->m_vbios_index_no_conflict, expected_claims_v3_obj.m_vbios_index_no_conflict);
    ASSERT_EQ(error, Error::Ok);

    std::shared_ptr<IClaimsEvaluator> claims_evaluator = ClaimsEvaluatorFactory::create_default_claims_evaluator();
    bool out_match;
    error = claims_evaluator->evaluate_claims(claims, out_match);
    ASSERT_EQ(error, Error::Ok) << "Could not evaluate claims: " << to_string(error);
    EXPECT_EQ(out_match, true);
}

TEST_F(GpuVerifierTest, SuccessfullyVerifyGpuEvidenceRemoteVerifier) {
    NvRemoteGpuVerifier verifier;
    Error error = NvRemoteGpuVerifier::init_from_env(verifier);
    ASSERT_EQ(error, Error::Ok);

    std::vector<GpuEvidence> evidence_list;
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_default();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());

    EvidencePolicy evidence_policy{};
    ClaimsCollection claims;
    error = verifier.verify_evidence(evidence_list, evidence_policy, claims);
    ASSERT_EQ(error, Error::Ok) << "Could not verify evidence: " << to_string(error);
    ASSERT_EQ(claims.size(), 1);
    std::string expected_claims_v3;
    readFileIntoString("testdata/sample_attestation_data/hopperClaimsv3_decoded.json", expected_claims_v3);
    nlohmann::json expected_claims_v3_json = nlohmann::json::parse(expected_claims_v3);
    nlohmann::json gpu0_claims = expected_claims_v3_json.at("GPU-0");
    SerializableGpuClaimsV3 expected_claims_v3_obj = gpu0_claims.get<SerializableGpuClaimsV3>();

    EXPECT_TRUE(*dynamic_cast<SerializableGpuClaimsV3*>(claims[0].get()) == expected_claims_v3_obj) << "Claims v3 mismatch";
}
TEST_F(GpuVerifierTest, VerifyGpuEvidenceWithBadNonce) {
    auto rim_store = std::make_shared<NvRemoteRimStoreImpl>();
    auto ocsp_client = std::make_shared<NvHttpOcspClient>();
    Error error = NvHttpOcspClient::create(*ocsp_client, "https://ocsp.ndis.nvidia.com", HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    LocalGpuVerifier verifier;
    error = LocalGpuVerifier::create(verifier, rim_store, ocsp_client);
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence with bad nonce
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04};
    std::vector<GpuEvidence> evidence_list;
    
    // Use mock data for nonce mismatch scenario
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_bad_nonce_scenario();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy{};
    ClaimsCollection claims;
    error = verifier.verify_evidence(evidence_list, evidence_policy, claims);
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
    error = LocalGpuVerifier::create(verifier, rim_store, ocsp_client);
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence with invalid signature
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04}; // Sample nonce
    std::vector<GpuEvidence> evidence_list;
    
    // Use invalid signature mock data
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_invalid_signature_scenario();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy{};
    ClaimsCollection claims;
    error = verifier.verify_evidence(evidence_list, evidence_policy, claims);

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
    error = LocalGpuVerifier::create(*verifier, mock_rim_store, ocsp_client);
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence with driver measurements mismatch scenario
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04}; // Sample nonce
    std::vector<GpuEvidence> evidence_list;
    
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
    error = verifier->verify_evidence(evidence_list, evidence_policy, claims);
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
    error = LocalGpuVerifier::create(*verifier, mock_rim_store, ocsp_client);
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence with expired driver rim scenario
    std::vector<uint8_t> nonce = {0x01, 0x02, 0x03, 0x04}; // Sample nonce
    std::vector<GpuEvidence> evidence_list;
    
    // Use expired driver rim mock data
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_expired_driver_rim_scenario();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy{};
    ClaimsCollection claims;
    error = verifier->verify_evidence(evidence_list, evidence_policy, claims);
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
    error = LocalGpuVerifier::create(local_verifier, rim_store, ocsp_client);
    ASSERT_EQ(error, Error::Ok);
    
    // Create mock GPU evidence using test utilities
    std::vector<GpuEvidence> evidence_list;
    
    // Use default mock data
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_blackwell_scenario();
    Error result = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(result, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    
    EvidencePolicy evidence_policy{};

    NvRemoteGpuVerifier remote_verifier;
    error = NvRemoteGpuVerifier::init_from_env(remote_verifier, "https://nras.attestation-stg.nvidia.com");
    ASSERT_EQ(error, Error::Ok);
    ClaimsCollection remote_claims;
    error = remote_verifier.verify_evidence(evidence_list, evidence_policy, remote_claims);
    ASSERT_EQ(error, Error::Ok) << "Could not verify evidence from nras: " << to_string(error);
    EXPECT_EQ(remote_claims.size(), 1);
    const SerializableGpuClaimsV3* remote_claims_v3 = dynamic_cast<SerializableGpuClaimsV3*>(remote_claims[0].get());
    ASSERT_NE(remote_claims_v3, nullptr) << "Expected SerializableGpuClaimsV3 claims";

    ClaimsCollection claims;
    error = local_verifier.verify_evidence(evidence_list, evidence_policy, claims);
    ASSERT_EQ(error, Error::Ok) << "Could not verify evidence: " << to_string(error);
    EXPECT_EQ(claims.size(), 1);

    const SerializableGpuClaimsV3* claims_v3 = dynamic_cast<SerializableGpuClaimsV3*>(claims[0].get());
    ASSERT_NE(claims_v3, nullptr) << "Expected SerializableGpuClaimsV3 claims";


    EXPECT_EQ(*claims_v3, *remote_claims_v3);
}