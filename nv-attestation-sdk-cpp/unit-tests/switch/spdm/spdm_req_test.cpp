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
#include <string>
#include <vector>
#include <array>
#include <memory>

#include "gtest/gtest.h"
#include "nlohmann/json.hpp"

#include "nv_attestation/spdm/spdm_req.hpp"
#include "nv_attestation/spdm/utils.h"
#include "nv_attestation/utils.h"

using namespace nvattestation;
using json = nlohmann::json;

/**
 * @brief Test fixture for SpdmMeasurementRequestMessage11 tests.
 *
 * Provides a common setup and teardown environment for tests related to
 * SPDM request message parsing and handling.
 */
class SwitchSpdmReqTest : public ::testing::Test {
protected:
    /**
     * @brief Sets up the test environment before each test case.
     * 
     * Reads the SPDM report, extracts the request, parses it, and loads expected values from JSON.
     */
    void SetUp() override {
        std::string full_report_hex;
        std::ifstream report_file("testdata/switchAttestationReport.txt");

        if (!report_file.is_open()) {
            GTEST_FAIL() << "Failed to open unit-tests/testdata/switchAttestationReport.txt";
        }
        
        std::getline(report_file, full_report_hex);
        report_file.close();

        if (full_report_hex.empty()) {
            GTEST_FAIL() << "Failed to read data from switchAttestationReport.txt or file is empty.";
        }

        const size_t request_hex_length = 37 * 2; // SPDM request is 37 bytes
        if (full_report_hex.length() < request_hex_length) {
            GTEST_FAIL() << "Report data too short to contain a request.";
        }

        std::string request_hex_data = full_report_hex.substr(0, request_hex_length);
        m_request_bytes = hex_string_to_bytes(request_hex_data);

        Error error = SpdmMeasurementRequestMessage11::create(m_request_bytes, m_msg);
        if (error != Error::Ok) {
            GTEST_FAIL() << "Failed to create SpdmMeasurementRequestMessage11 in SetUp. Check logs for errors.";
        }

        std::ifstream json_file("testdata/switch_spdm_req_parsed_output.json");
        if (!json_file.is_open()) {
            GTEST_FAIL() << "Failed to open unit-tests/testdata/switch_spdm_req_parsed_output.json in SetUp";
        }
        json_file >> m_expected_values_json;
        json_file.close();
    }

    /**
     * @brief Cleans up the test environment after each test case.
     */
    void TearDown() override {
        // Common teardown for tests if needed
        // msg_ unique_ptr will automatically clean up.
        // Other members are value types or standard containers that manage their own memory.
    }

    // Member variables to hold common test data
    std::vector<uint8_t> m_request_bytes;
    SpdmMeasurementRequestMessage11 m_msg;
    json m_expected_values_json;
};

/**
 * @brief Tests parsing of a valid SPDM GET_MEASUREMENTS request and verifies its fields.
 *
 * The expected values are loaded from `switch_spdm_req_parsed_output.json` which contains
 * the expected parsed fields of an SPDM GET_MEASUREMENTS request.
 */
TEST_F(SwitchSpdmReqTest, ParseAndVerifySpdmRequest) {
    ASSERT_FALSE(m_expected_values_json.is_null()) << "Expected values JSON (switch_spdm_req_parsed_output.json) is null. SetUp might have failed.";

    EXPECT_EQ(m_msg.get_spdm_version(), static_cast<uint8_t>(std::stoul(m_expected_values_json["SPDMVersion"].get<std::string>(), nullptr, 16)));
    EXPECT_EQ(m_msg.get_request_response_code(), static_cast<uint8_t>(std::stoul(m_expected_values_json["RequestResponseCode"].get<std::string>(), nullptr, 16)));
    EXPECT_EQ(m_msg.get_param1(), static_cast<uint8_t>(std::stoul(m_expected_values_json["Param1"].get<std::string>(), nullptr, 16)));
    EXPECT_EQ(m_msg.get_param2(), static_cast<uint8_t>(std::stoul(m_expected_values_json["Param2"].get<std::string>(), nullptr, 16)));
    
    // Nonce
    const std::string expected_nonce_hex = m_expected_values_json["Nonce"].get<std::string>();
    std::vector<uint8_t> expected_nonce_bytes = hex_string_to_bytes(expected_nonce_hex.rfind("0x", 0) == 0 ? expected_nonce_hex.substr(2) : expected_nonce_hex);
    std::array<uint8_t, 32> actual_nonce_array = m_msg.get_nonce(); 
    std::vector<uint8_t> actual_nonce_vec(actual_nonce_array.begin(), actual_nonce_array.end());
    EXPECT_EQ(actual_nonce_vec, expected_nonce_bytes);

    EXPECT_EQ(m_msg.get_slot_id_param(), static_cast<uint8_t>(std::stoul(m_expected_values_json["SlotIDParam"].get<std::string>(), nullptr, 16)));
}