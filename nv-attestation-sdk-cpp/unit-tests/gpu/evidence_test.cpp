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
#include "nv_attestation/gpu/evidence.h"
#include "nvat.h"
#include "nv_attestation/nvat_private.hpp"
#include "test_utils.h" // Added for MockEvidenceCollector and MockGpuEvidenceData


// Define a test fixture for GpuEvidence tests
class GpuEvidenceTest : public ::testing::Test {
protected:
    std::shared_ptr<GpuEvidence> m_evidence;
    MockGpuEvidenceData m_mock_data;
    
    void SetUp() override {
        m_mock_data = MockGpuEvidenceData::create_default();
        
        std::vector<std::shared_ptr<GpuEvidence>> evidence_list;
        
        Error error = get_mock_gpu_evidence(m_mock_data, evidence_list);
        ASSERT_EQ(error, Error::Ok);
        ASSERT_FALSE(evidence_list.empty());
        
        // Get the first (and only) evidence from the list
        m_evidence = evidence_list[0];
    }
};

// Test case using the fixture
TEST_F(GpuEvidenceTest, CanCreateEvidence) {
    EXPECT_EQ(m_evidence->get_gpu_architecture(), m_mock_data.architecture);
    EXPECT_EQ(m_evidence->get_board_id(), m_mock_data.board_id);
    EXPECT_EQ(m_evidence->get_uuid(), m_mock_data.uuid);
    EXPECT_EQ(m_evidence->get_vbios_version(), m_mock_data.vbios_version);
    EXPECT_EQ(m_evidence->get_driver_version(), m_mock_data.driver_version);
    
    EXPECT_FALSE(m_evidence->get_attestation_report().empty());
}

TEST_F(GpuEvidenceTest, CorrectGpuEvidenceClaims) {
    GpuEvidenceClaims claims;
    OcspVerifyOptions ocsp_verify_options;
    NvHttpOcspClient ocsp_client;
    Error error = NvHttpOcspClient::create(ocsp_client, "https://ocsp.ndis.nvidia.com", HttpOptions());
    ASSERT_EQ(error, Error::Ok);    
    GpuEvidence::AttestationReport attestation_report;
    error = m_evidence->get_parsed_attestation_report(attestation_report);
    ASSERT_EQ(error, Error::Ok) << "Failed to parse attestation report";
    error = m_evidence->generate_gpu_evidence_claims(attestation_report, ocsp_verify_options, ocsp_client, claims);
    ASSERT_EQ(error, Error::Ok) << "Failed to generate GPU evidence claims";

    LOG_DEBUG("Claims: " << claims);
    
    // Print all fields of the claims using the << operator
    LOG_DEBUG(claims);
    // need to check only these claims because if the any of the other claims 
    // are not as expected, we would get an error
    ASSERT_EQ(claims.m_driver_version, m_mock_data.driver_version);
    ASSERT_EQ(claims.m_vbios_version, m_mock_data.vbios_version);
    ASSERT_EQ(claims.m_attestation_report_claims.m_ueid, "478176379286082186618948445787393647364802107249");
    ASSERT_EQ(claims.m_attestation_report_claims.m_hwmodel, "GH100 A01 GSP BROM");
}

TEST_F(GpuEvidenceTest, BlackwellCorrectGpuEvidenceClaims) {
    GpuEvidenceClaims claims;
    OcspVerifyOptions ocsp_verify_options;
    NvHttpOcspClient ocsp_client;
    Error error = NvHttpOcspClient::create(ocsp_client, "https://ocsp.ndis-stg.nvidia.com", HttpOptions());
    ASSERT_EQ(error, Error::Ok);    

    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_blackwell_scenario();
    std::vector<std::shared_ptr<GpuEvidence>> evidence_list;
    error = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());

    std::shared_ptr<GpuEvidence> gpu_evidence = evidence_list[0];
    GpuEvidence::AttestationReport attestation_report;
    error = gpu_evidence->get_parsed_attestation_report(attestation_report);
    ASSERT_EQ(error, Error::Ok) << "Failed to parse attestation report";
    error = gpu_evidence->generate_gpu_evidence_claims(attestation_report, ocsp_verify_options, ocsp_client, claims);
    ASSERT_EQ(error, Error::Ok) << "Failed to generate GPU evidence claims";
    
    // Print all fields of the claims using the << operator
    LOG_DEBUG(claims);
    ASSERT_EQ(claims.m_driver_version, mock_data.driver_version);
    ASSERT_EQ(claims.m_vbios_version, mock_data.vbios_version);
    ASSERT_EQ(claims.m_attestation_report_claims.m_ueid, "474146966256510137525212816567191319424869109849");
    ASSERT_EQ(claims.m_attestation_report_claims.m_hwmodel, "GB100 A01 GSP BROM");
}

TEST_F(GpuEvidenceTest, CanSerializeAndDeserialize) {
    MockGpuEvidenceData mock_data = MockGpuEvidenceData::create_default();
    std::vector<std::shared_ptr<GpuEvidence>> evidence_list;
    Error error = get_mock_gpu_evidence(mock_data, evidence_list);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_FALSE(evidence_list.empty());
    // LOG_DEBUG("Evidence: " << evidence_list[0]);

    std::string json_string;
    error = GpuEvidence::collection_to_json(evidence_list, json_string);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_FALSE(json_string.empty());

    // LOG_DEBUG("Serialized evidence: " << json_string);
    // save to a temp file
    std::string temp_file_path = "/tmp/gpu_evidence.json";
    std::ofstream temp_file(temp_file_path);
    temp_file << json_string;
    temp_file.close();

    GpuEvidenceSourceFromJsonFile source;
    error = GpuEvidenceSourceFromJsonFile::create(temp_file_path, source);
    ASSERT_EQ(error, Error::Ok);

    std::vector<std::shared_ptr<GpuEvidence>> deserialized_evidence_list;
    error = source.get_evidence(evidence_list[0]->get_nonce(), deserialized_evidence_list);
    ASSERT_EQ(error, Error::Ok);
    ASSERT_FALSE(deserialized_evidence_list.empty());
    std::shared_ptr<GpuEvidence> deserialized_evidence = deserialized_evidence_list[0];
    // LOG_DEBUG("Deserialized evidence: " << deserialized_evidence);

    EXPECT_EQ(deserialized_evidence->get_attestation_report(), evidence_list[0]->get_attestation_report());
    EXPECT_EQ(deserialized_evidence->get_attestation_cert_chain(), evidence_list[0]->get_attestation_cert_chain());

    GpuEvidenceClaims claims;
    OcspVerifyOptions ocsp_verify_options;
    NvHttpOcspClient ocsp_client;
    error = NvHttpOcspClient::create(ocsp_client, "https://ocsp.ndis-stg.nvidia.com", HttpOptions());
    ASSERT_EQ(error, Error::Ok);    
    GpuEvidence::AttestationReport attestation_report; 
    error = deserialized_evidence->get_parsed_attestation_report(attestation_report);
    ASSERT_EQ(error, Error::Ok);
    error = deserialized_evidence->generate_gpu_evidence_claims(attestation_report, ocsp_verify_options, ocsp_client, claims);
    ASSERT_EQ(error, Error::Ok);
    // LOG_DEBUG("Claims: " << claims);

    ASSERT_EQ(claims.m_driver_version, mock_data.driver_version);
    ASSERT_EQ(claims.m_vbios_version, mock_data.vbios_version);
    ASSERT_EQ(claims.m_attestation_report_claims.m_ueid, "478176379286082186618948445787393647364802107249");
    ASSERT_EQ(claims.m_attestation_report_claims.m_hwmodel, "GH100 A01 GSP BROM");
}

TEST(GpuEvidenceTestCApi, CanCreateEvidenceSourceFromJsonFile) {
    nvat_gpu_evidence_source_t gpu_evidence_source;
    std::string json_file_path;
    Error error = get_git_repo_root(json_file_path);
    ASSERT_EQ(error, Error::Ok);
    json_file_path += "/common-test-data/serialized_test_evidence/hopper_evidence.json";
    nvat_rc_t err = nvat_gpu_evidence_source_from_json_file(&gpu_evidence_source, json_file_path.c_str());
    ASSERT_EQ(err, NVAT_RC_OK);

    nvat_nonce_t nonce;
    err = nvat_nonce_from_hex(&nonce, "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb");
    ASSERT_EQ(err, NVAT_RC_OK);

    nvat_gpu_evidence_t* gpu_evidences = nullptr;
    size_t length = 0;
    err = nvat_gpu_evidence_collect(gpu_evidence_source, nonce, &gpu_evidences, &length);
    ASSERT_EQ(err, NVAT_RC_OK);

    nvat_str_t serialized_evidence;
    err = nvat_gpu_evidence_serialize_json(gpu_evidences, length, &serialized_evidence);
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
    nvat_gpu_evidence_array_free(&gpu_evidences, length);
    nvat_gpu_evidence_source_free(&gpu_evidence_source);
    nvat_str_free(&serialized_evidence);
}