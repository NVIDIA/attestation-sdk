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

#pragma once

#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

//third party
#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "nv_attestation/utils.h"
#include "nv_attestation/gpu/evidence.h"
#include "nv_attestation/log.h"
#include "nv_attestation/rim.h"
#include "nv_attestation/gpu/claims.h"
#include "nv_attestation/claims.h"

using namespace nvattestation;
using ::testing::Return;
using ::testing::_;
using ::testing::DoAll;
using ::testing::SetArgReferee;
using ::testing::Invoke;

// Mock evidence data class containing test constants
class MockGpuEvidenceData {
public:
    GpuArchitecture architecture;
    unsigned int board_id;
    std::string uuid;
    std::string vbios_version;
    std::string driver_version;
    std::string nonce;
    std::string attestation_report_path;
    std::string attestation_cert_chain_path;
    
    // Default constructor with Hopper GPU data
    MockGpuEvidenceData();

    // Parameterized constructor for custom scenarios
    MockGpuEvidenceData(GpuArchitecture arch, unsigned int bid, const std::string& gpu_uuid, 
                        const std::string& vbios_ver, const std::string& driver_ver, 
                        const std::string& nonce_str, const std::string& report_path, 
                        const std::string& cert_chain_path)
        : architecture(arch), board_id(bid), uuid(gpu_uuid), vbios_version(vbios_ver),
          driver_version(driver_ver), nonce(nonce_str), attestation_report_path(report_path),
          attestation_cert_chain_path(cert_chain_path) {}
    
    // Factory method declarations
    static MockGpuEvidenceData create_default();
    static MockGpuEvidenceData create_bad_nonce_scenario();
    static MockGpuEvidenceData create_invalid_signature_scenario();
    static MockGpuEvidenceData create_expired_driver_rim_scenario();
    static MockGpuEvidenceData create_measurements_mismatch_scenario();
    static MockGpuEvidenceData create_blackwell_scenario();
};

/**
 * @brief Common function to get mock GPU evidence for testing purposes.
 */
inline Error get_mock_gpu_evidence(const MockGpuEvidenceData& mock_data, std::vector<std::shared_ptr<GpuEvidence>>& out_evidence) {
    // Read attestation report data
    std::vector<uint8_t> attestation_report_data;
    std::ifstream report_file(mock_data.attestation_report_path);
    if (report_file) {
        std::string report_hex_str((std::istreambuf_iterator<char>(report_file)),
                                   std::istreambuf_iterator<char>());
        report_file.close();
        attestation_report_data = hex_string_to_bytes(report_hex_str);
    } else {
        LOG_ERROR("Failed to open attestation report file: " + mock_data.attestation_report_path);
        return Error::InternalError;
    }

    // Read attestation cert chain
    std::string attestation_cert_chain_str;
    std::ifstream cert_chain_file(mock_data.attestation_cert_chain_path);
    if (cert_chain_file) {
        std::stringstream buffer;
        buffer << cert_chain_file.rdbuf();
        cert_chain_file.close();
        attestation_cert_chain_str = buffer.str();
    } else {
        LOG_ERROR("Failed to open attestation cert chain file: " + mock_data.attestation_cert_chain_path);
        return Error::InternalError;
    }

    // Convert mock nonce to bytes
    std::vector<uint8_t> nonce_bytes = hex_string_to_bytes(mock_data.nonce);
    
    // Create GpuEvidence with mock data
    std::shared_ptr<GpuEvidence> gpu_evidence = std::make_shared<GpuEvidence>(
        mock_data.architecture,
        mock_data.board_id,
        mock_data.uuid,
        mock_data.vbios_version,
        mock_data.driver_version,
        attestation_report_data,
        attestation_cert_chain_str,
        nonce_bytes
    );
    
    out_evidence.push_back(gpu_evidence);
    return Error::Ok;
}


// Google Mock for IGpuEvidenceSource with helper methods
class MockGpuEvidenceSource : public IGpuEvidenceSource {
public:
    MOCK_METHOD(Error, get_evidence, (const std::vector<uint8_t>& nonce_input, std::vector<std::shared_ptr<GpuEvidence>>& out_evidence), (const, override));

    // Helper method to set up successful evidence collection with real mock data
    void setup_success_behavior(const MockGpuEvidenceData& mock_data = MockGpuEvidenceData::create_default()) {
        EXPECT_CALL(*this, get_evidence(_, _))
            .WillRepeatedly(Invoke([mock_data](const std::vector<uint8_t>& nonce_input, std::vector<std::shared_ptr<GpuEvidence>>& out_evidence) -> Error {
                return get_mock_gpu_evidence(mock_data, out_evidence);
            }));
    }
};

class MockNvRemoteRimStore : public NvRemoteRimStoreImpl {
public:
    MOCK_METHOD(Error, get_rim, (const std::string& rim_id, RimDocument& out_rim_document), (override));
};

Error get_git_repo_root(std::string& out_git_repo_root);