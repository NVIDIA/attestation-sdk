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
#include "nv_attestation/switch/evidence.h"
#include "nv_attestation/log.h"

using namespace nvattestation;
using ::testing::Return;
using ::testing::_;
using ::testing::DoAll;
using ::testing::SetArgReferee;
using ::testing::Invoke;

// Mock evidence data class containing all test constants
class MockSwitchEvidenceData {
public:
    SwitchArchitecture architecture;
    std::string uuid;
    std::string bios_version;
    std::string nonce;
    std::string attestation_report_path;
    std::string attestation_cert_chain_path;
    bool tnvl_mode;
    bool lock_mode;
    
    // Default constructor
    MockSwitchEvidenceData();

    // Parameterized constructor for custom scenarios
    MockSwitchEvidenceData(SwitchArchitecture arch, const std::string& switch_uuid, 
                           const std::string& bios_ver, const std::string& nonce_str,
                           const std::string& report_path, const std::string& cert_chain_path,
                           bool tnvl, bool lock)
        : architecture(arch), uuid(switch_uuid), bios_version(bios_ver), 
          nonce(nonce_str), attestation_report_path(report_path), 
          attestation_cert_chain_path(cert_chain_path), tnvl_mode(tnvl), lock_mode(lock) {}
    
    // Factory method declarations
    static MockSwitchEvidenceData create_default();
    static MockSwitchEvidenceData create_bad_nonce_scenario();
    static MockSwitchEvidenceData create_bad_rim_signature_scenario();
    static MockSwitchEvidenceData create_measurements_mismatch_scenario();
    static MockSwitchEvidenceData create_invalid_signature_scenario();
};

/**
 * @brief Common function to get mock SWITCH evidence for testing purposes.
 */
inline Error get_mock_switch_evidence(const MockSwitchEvidenceData& mock_data, std::vector<std::shared_ptr<SwitchEvidence>>& out_evidence) {
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
    
    // Create SwitchEvidence with mock data
    std::shared_ptr<SwitchEvidence> switch_evidence = std::make_shared<SwitchEvidence>(
        mock_data.architecture,
        mock_data.uuid,
        attestation_report_data,
        attestation_cert_chain_str,
        mock_data.tnvl_mode,
        mock_data.lock_mode,
        nonce_bytes
    );
    
    out_evidence.push_back(switch_evidence);
    return Error::Ok;
}


// Google Mock for ISwitchEvidenceSource with helper methods
class MockSwitchEvidenceSource : public ISwitchEvidenceSource {
public:
    MOCK_METHOD(Error, get_evidence, (const std::vector<uint8_t>& nonce_input, std::vector<std::shared_ptr<SwitchEvidence>>& out_evidence), (const, override));

    // Helper method to set up successful evidence collection with real mock data
    void setup_success_behavior(const MockSwitchEvidenceData& mock_data = MockSwitchEvidenceData::create_default()) {
        EXPECT_CALL(*this, get_evidence(_, _))
            .WillRepeatedly(Invoke([mock_data](const std::vector<uint8_t>& nonce_input, std::vector<std::shared_ptr<SwitchEvidence>>& out_evidence) -> Error {
                return get_mock_switch_evidence(mock_data, out_evidence);
            }));
    }
};

