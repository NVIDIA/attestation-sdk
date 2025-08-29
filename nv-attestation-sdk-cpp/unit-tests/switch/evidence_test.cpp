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
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <iostream>
#include <ctime>

#include "gtest/gtest.h"

#include "nv_attestation/utils.h" // For hex_string_to_bytes
#include "nv_attestation/switch/evidence.h"
#include "switch_test_utils.h"
#include "nv_attestation/switch/claims.h"
#include "nvat.h"
#include "nv_attestation/nvat_private.hpp"
#include "test_utils.h"

void assert_switch_evidence_claims(const SwitchEvidenceClaims& claims, const MockSwitchEvidenceData& mock_data) {
    EXPECT_EQ(claims.m_switch_arch_match, true);
    EXPECT_EQ(claims.m_switch_bios_version, mock_data.bios_version);
    EXPECT_EQ(claims.m_switch_ar_nonce_match, true);
    EXPECT_EQ(claims.m_attestation_report_claims.m_cert_chain_claims.status, CertChainStatus::VALID);
    EXPECT_FALSE(claims.m_attestation_report_claims.m_cert_chain_claims.expiration_date.empty());
    EXPECT_EQ(claims.m_attestation_report_claims.m_cert_chain_claims.ocsp_claims.status, OCSPStatus::GOOD);
    EXPECT_EQ(claims.m_attestation_report_claims.m_cert_chain_claims.ocsp_claims.nonce_matches, true);
    EXPECT_LT(time(nullptr), claims.m_attestation_report_claims.m_cert_chain_claims.ocsp_claims.ocsp_resp_expiration_time);
    EXPECT_EQ(claims.m_attestation_report_claims.m_fwid_match, true);
    EXPECT_EQ(claims.m_attestation_report_claims.m_parsed, true);
    EXPECT_EQ(claims.m_attestation_report_claims.m_signature_verified, true);
}

// Define a test fixture for SwitchEvidence tests
class SwitchEvidenceTest : public ::testing::Test {
protected:
    SwitchEvidence m_evidence;
    MockSwitchEvidenceData m_mock_data;
    
    void SetUp() override {
        // Create mock data instance
        m_mock_data = MockSwitchEvidenceData::create_default();
        
        // Use the common get_mock_switch_evidence function with mock data
        std::vector<SwitchEvidence> evidence_list;
        
        Error error = get_mock_switch_evidence(m_mock_data, evidence_list);
        ASSERT_EQ(error, Error::Ok);
        ASSERT_FALSE(evidence_list.empty());
        
        // Get the first (and only) evidence from the list
        m_evidence = evidence_list[0];
    }
};

// Test case using the fixture
TEST_F(SwitchEvidenceTest, CanCreateEvidence) {
    EXPECT_EQ(m_evidence.get_switch_architecture(), m_mock_data.architecture);
    EXPECT_EQ(m_evidence.get_uuid(), m_mock_data.uuid);
    EXPECT_EQ(m_evidence.get_tnvl_mode(), m_mock_data.tnvl_mode);
    EXPECT_EQ(m_evidence.get_lock_mode(), m_mock_data.lock_mode);
    
    EXPECT_FALSE(m_evidence.get_attestation_report().empty());
    EXPECT_FALSE(m_evidence.get_attestation_cert_chain().empty());
}

TEST_F(SwitchEvidenceTest, CorrectSwitchEvidenceClaimsV3) {
    SwitchEvidenceClaims claims;
    OcspVerifyOptions ocsp_verify_options;
    NvHttpOcspClient ocsp_client;
    Error error = NvHttpOcspClient::create(ocsp_client, "http://ocsp.ndis-stg.nvidia.com", HttpOptions());
    ASSERT_EQ(error, Error::Ok);    
    SwitchEvidence::AttestationReport attestation_report;
    error = m_evidence.get_parsed_attestation_report(attestation_report);
    ASSERT_EQ(error, Error::Ok) << "Failed to parse attestation report";
    error = m_evidence.generate_switch_evidence_claims(attestation_report, ocsp_verify_options, ocsp_client, claims);
    ASSERT_EQ(error, Error::Ok) << "Failed to generate switch evidence claims";

    EXPECT_EQ(claims.m_switch_arch_match, true);
    EXPECT_EQ(claims.m_switch_bios_version, m_mock_data.bios_version);
    EXPECT_EQ(claims.m_switch_ar_nonce_match, true);
    EXPECT_EQ(claims.m_attestation_report_claims.m_fwid_match, true);
    EXPECT_EQ(claims.m_attestation_report_claims.m_cert_chain_claims.status, CertChainStatus::VALID);
    EXPECT_FALSE(claims.m_attestation_report_claims.m_cert_chain_claims.expiration_date.empty());
    EXPECT_EQ(claims.m_attestation_report_claims.m_cert_chain_claims.ocsp_claims.status, OCSPStatus::GOOD);
    EXPECT_EQ(claims.m_attestation_report_claims.m_cert_chain_claims.ocsp_claims.nonce_matches, true);
    EXPECT_LT(time(nullptr), claims.m_attestation_report_claims.m_cert_chain_claims.ocsp_claims.ocsp_resp_expiration_time);

    EXPECT_EQ(claims.m_attestation_report_claims.m_parsed, true);
    EXPECT_EQ(claims.m_attestation_report_claims.m_signature_verified, true);
}

TEST_F(SwitchEvidenceTest, CanSerializeAndDeserialize) {
    
    MockSwitchEvidenceData mock_data = MockSwitchEvidenceData::create_default();
    std::vector<SwitchEvidence> evidence_list;
    Error error = get_mock_switch_evidence(mock_data, evidence_list);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());

    std::string json_string;
    error = SwitchEvidence::collection_to_json(evidence_list, json_string);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_FALSE(json_string.empty());

    // save to a temp file
    std::string temp_file_path = "/tmp/switch_evidence_ls10.json";
    std::ofstream temp_file(temp_file_path);
    temp_file << json_string;

    SwitchEvidenceSourceFromJsonFile source;
    error = SwitchEvidenceSourceFromJsonFile::create(temp_file_path, source);
    ASSERT_EQ(error, Error::Ok);

    std::vector<SwitchEvidence> deserialized_evidence_list;
    error = source.get_evidence({}, deserialized_evidence_list);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_FALSE(deserialized_evidence_list.empty());
    SwitchEvidence deserialized_evidence = deserialized_evidence_list[0];

    EXPECT_EQ(deserialized_evidence.get_attestation_report(), evidence_list[0].get_attestation_report());
    EXPECT_EQ(deserialized_evidence.get_attestation_cert_chain(), evidence_list[0].get_attestation_cert_chain());
    EXPECT_EQ(deserialized_evidence.get_nonce(), evidence_list[0].get_nonce());
    EXPECT_EQ(deserialized_evidence.get_switch_architecture(), evidence_list[0].get_switch_architecture());

    SwitchEvidenceClaims claims;
    OcspVerifyOptions ocsp_verify_options;
    NvHttpOcspClient ocsp_client;
    error = NvHttpOcspClient::create(ocsp_client, "http://ocsp.ndis-stg.nvidia.com", HttpOptions());
    ASSERT_EQ(error, Error::Ok);
    SwitchEvidence::AttestationReport attestation_report;
    error = deserialized_evidence.get_parsed_attestation_report(attestation_report);
    error = deserialized_evidence.generate_switch_evidence_claims(attestation_report, ocsp_verify_options, ocsp_client, claims);
    ASSERT_EQ(error, Error::Ok);
    assert_switch_evidence_claims(claims, mock_data);
}

TEST(SwitchEvidenceTestCApi, CanCreateEvidenceSourceFromJsonFile) {

    std::string json_file_path;
    Error error = get_git_repo_root(json_file_path);
    ASSERT_EQ(error, Error::Ok);
    json_file_path += "/common-test-data/serialized_test_evidence/switch_evidence_ls10.json";
    nvat_switch_evidence_source_t switch_evidence_source;
    nvat_rc_t err = nvat_switch_evidence_source_from_json_file(&switch_evidence_source, json_file_path.c_str());
    ASSERT_EQ(err, NVAT_RC_OK);

    nvat_nonce_t nonce;
    err = nvat_nonce_create(&nonce, 32);
    ASSERT_EQ(err, NVAT_RC_OK);

    nvat_switch_evidence_collection_t collection;
    err = nvat_switch_evidence_collect(switch_evidence_source, nonce, &collection);
    ASSERT_EQ(err, NVAT_RC_OK);

    nvat_str_t serialized_evidence;
    err = nvat_switch_evidence_serialize_json(collection, &serialized_evidence);
    ASSERT_EQ(err, NVAT_RC_OK);
    char * serialized_evidence_str = nullptr;
    err = nvat_str_get_data(serialized_evidence, &serialized_evidence_str);
    ASSERT_EQ(err, NVAT_RC_OK);

    nlohmann::json actual_json_obj = nlohmann::json::parse(serialized_evidence_str);
    string expected_json_str; 
    error = readFileIntoString(json_file_path, expected_json_str);
    ASSERT_EQ(error, Error::Ok);
    nlohmann::json expected_json_obj = nlohmann::json::parse(expected_json_str);
    EXPECT_EQ(actual_json_obj, expected_json_obj);

    nvat_nonce_free(&nonce);
    nvat_switch_evidence_collection_free(&collection);
    nvat_switch_evidence_source_free(&switch_evidence_source);
    nvat_str_free(&serialized_evidence);
}