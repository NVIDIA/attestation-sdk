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

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "nv_attestation/claims.h"
#include "nv_attestation/switch/verify.h"
#include "nv_attestation/rim.h"
#include "nv_attestation/claims_evaluator.h"
#include "nv_attestation/verify.h"
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
    error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis-stg.nvidia.com", HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    error = LocalSwitchVerifier::create(*verifier, mock_rim_store, ocsp_client);
    ASSERT_EQ(error, Error::Ok);

    EvidencePolicy evidence_policy {};
    ClaimsCollection claims;
    error = verifier->verify_evidence(evidence_list, evidence_policy, claims);
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
    NvRemoteSwitchVerifier::init_from_env(verifier, "https://nras.attestation-stg.nvidia.com", HttpOptions());

    EvidencePolicy evidence_policy {};
    ClaimsCollection claims;
    error = verifier.verify_evidence(evidence_list, evidence_policy, claims);
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
    LocalSwitchVerifier verifier;
    Error error = LocalSwitchVerifier::create(verifier, rim_store, ocsp_client);
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
    error = verifier.verify_evidence(evidence_list, evidence_policy, claims);
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
    Error error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis-stg.nvidia.com", HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    error = LocalSwitchVerifier::create(*verifier, mock_rim_store, ocsp_client);
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
    error = verifier->verify_evidence(evidence_list, evidence_policy, claims);
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
    Error error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis-stg.nvidia.com", HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    error = LocalSwitchVerifier::create(*verifier, mock_rim_store, ocsp_client);
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
    error = verifier->verify_evidence(evidence_list, evidence_policy, claims);
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
    Error error = NvHttpOcspClient::create(*ocsp_client, "http://ocsp.ndis-stg.nvidia.com", HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    LocalSwitchVerifier verifier;
    error = LocalSwitchVerifier::create(verifier, rim_store, ocsp_client);
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
    error = verifier.verify_evidence(evidence_list, evidence_policy, claims);
    ASSERT_EQ(error, Error::SwitchEvidenceInvalidSignature) << "Could not verify evidence: " << to_string(error);
    // No claims should be generated when verification fails due to invalid signature
    EXPECT_TRUE(claims.empty());
}
