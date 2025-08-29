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

/**
 * @file spdm_resp_test.cpp
 * @brief Unit tests for the SpdmMeasurementResponseMessage11 class.
 */
#include <vector>
#include <string>
#include <iomanip> // For std::setw, std::setfill, std::hex
#include <sstream> // For std::stringstream
#include <algorithm> // For std::copy
#include <fstream>   // For file input
#include <string>    // For std::stoul
#include <memory>    // For std::unique_ptr, std::shared_ptr

#include "gtest/gtest.h"

#include "nv_attestation/spdm/spdm_resp.hpp"
#include "nv_attestation/spdm/spdm_req.hpp"
#include "nv_attestation/spdm/spdm_opaque_data_parser.hpp" // For OpaqueDataType, ParsedOpaqueFieldData
#include "nv_attestation/spdm/spdm_measurement_records.hpp" // For SpdmMeasurementRecordParser
#include "nv_attestation/switch/spdm/switch_opaque_data_parser.hpp" // For SwitchOpaqueDataType, SwitchParsedOpaqueFieldData, SwitchOpaqueDataParser
#include "nv_attestation/log.h" // For LOG_DEBUG
#include "nv_attestation/error.h" // For nvattestation::Error
#include "nlohmann/json.hpp" // For JSON parsing
#include "nv_attestation/utils.h"
#include "spdm_test_utils.h"

using namespace nvattestation;
using json = nlohmann::json;


/**
 * @brief Test fixture for SpdmMeasurementResponseMessage11 tests.
 *
 * Provides a common setup and teardown environment for tests related to
 * SPDM response message parsing and handling.
 */
class SwitchSpdmRespTest : public ::testing::Test {
protected:
    /**
     * @brief Sets up the test environment before each test case.
     * 
     * Reads the SPDM report, parses the response, and loads expected values from JSON.
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

        size_t request_hex_length = SpdmMeasurementRequestMessage11::get_request_length() * 2;
        if (full_report_hex.length() < request_hex_length) {
            GTEST_FAIL() << "Report data too short.";
        }

        std::string response_hex_data = full_report_hex.substr(request_hex_length);
        m_response_bytes = hex_string_to_bytes(response_hex_data);

        // Default signature length, adjust if necessary based on actual SPDM settings.
        m_signature_length = 96; 

        Error error = SpdmMeasurementResponseMessage11::create(m_response_bytes, m_signature_length, m_msg);
        if (error != Error::Ok) {
            GTEST_FAIL() << "Failed to create SpdmMeasurementResponseMessage11 in SetUp. Check logs for errors.";
        }

        std::ifstream json_file("testdata/switch_spdm_parsed_output.json");
        if (!json_file.is_open()) {
            GTEST_FAIL() << "Failed to open unit-tests/testdata/switch_spdm_parsed_output.json in SetUp";
        }
        json_file >> m_expected_values_json;
        json_file.close();
    }

    /**
     * @brief Cleans up the test environment after each test case.
     */
    void TearDown() override {
        // Common teardown for tests if needed
        // Other members are value types or standard containers that manage their own memory.
    }

    // Member variables to hold common test data
    std::vector<uint8_t> m_response_bytes;
    size_t m_signature_length;
    SpdmMeasurementResponseMessage11 m_msg;
    json m_expected_values_json;
};

/**
 * @brief Tests parsing of a valid SPDM GET_MEASUREMENTS response and verifies its fields.
 *
 * the expected values were hardcoded from `spdm_parsed_output.json` which is a dump of parsed
 * spdm response for the sample spdm response switchAttestationReport.txt from
 * the old python sdk. essentially, we are making sure that the parsed spdm response 
 * gives the same values as that of the old python sdk.
 */
TEST_F(SwitchSpdmRespTest, ParseAndVerifySpdmResponse) {
    parse_and_verify_spdm_response(m_msg, m_expected_values_json);
    EXPECT_EQ(m_msg.get_signature().size(), m_signature_length);
}

TEST_F(SwitchSpdmRespTest, ParseAndVerifyOpaqueData) {
    ASSERT_FALSE(m_expected_values_json.is_null()) << "Expected values JSON is null. SetUp might have failed.";

    const OpaqueDataParser& opaque_parser = m_msg.get_parsed_opaque_struct();

    LOG_DEBUG(opaque_parser);

    // Get all fields from the base parser
    const std::vector<ParsedOpaqueFieldData>* base_fields_ptr = nullptr;
    Error error = opaque_parser.get_all_fields(base_fields_ptr);
    ASSERT_EQ(error, Error::Ok) << "Failed to get all fields from base parser";

    // Create SWITCH-specific parser
    SwitchOpaqueDataParser switch_parser;
    error = SwitchOpaqueDataParser::create(*base_fields_ptr, switch_parser);
    ASSERT_EQ(error, Error::Ok) << "Failed to create SWITCH opaque data parser";

    LOG_DEBUG(switch_parser);

    const json& expected_opaque_fields = m_expected_values_json["OpaqueData"]["OpaqueDataField"];

    // Helper lambda to get and check a byte_vector field
    auto check_byte_vector_field = [&](SwitchOpaqueDataType type, const std::string& json_key) {
        const SwitchParsedOpaqueFieldData* actual_field_data = nullptr;
        Error error = switch_parser.get_field(type, actual_field_data);
        ASSERT_EQ(error, Error::Ok) << "Failed to get field: " << json_key;
        ASSERT_NE(actual_field_data, nullptr);
        ASSERT_EQ(actual_field_data->get_type(), SwitchParsedFieldType::BYTE_VECTOR) << "Field " << json_key << " is not a byte vector.";
        
        const std::string expected_hex = expected_opaque_fields[json_key].get<std::string>();
        // Ensure "0x" prefix is handled if present, hex_string_to_bytes expects it to be absent
        std::vector<uint8_t> expected_bytes = hex_string_to_bytes(expected_hex.rfind("0x", 0) == 0 ? expected_hex.substr(2) : expected_hex);
        const std::vector<uint8_t>* actual_bytes = nullptr;
        ASSERT_EQ(actual_field_data->get_byte_vector(actual_bytes), Error::Ok) << "Failed to get byte vector for field: " << json_key;
        ASSERT_NE(actual_bytes, nullptr);
        EXPECT_EQ(*actual_bytes, expected_bytes) << "Mismatch for opaque field: " << json_key;
    };

    // Helper lambda to get and check a pdi_vector field
    auto check_pdi_vector_field = [&](SwitchOpaqueDataType type, const std::string& json_key) {
        const SwitchParsedOpaqueFieldData* actual_field_data = nullptr;
        Error error = switch_parser.get_field(type, actual_field_data);
        ASSERT_EQ(error, Error::Ok) << "Failed to get field: " << json_key;
        ASSERT_NE(actual_field_data, nullptr);
        ASSERT_EQ(actual_field_data->get_type(), SwitchParsedFieldType::PDI_VECTOR) << "Field " << json_key << " is not a pdi vector.";
        
        const auto& expected_hex_list = expected_opaque_fields[json_key].get<std::vector<std::string>>();
        std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE>> expected_pdis;
        for (const auto& hex_str : expected_hex_list) {
            std::vector<uint8_t> pdi_bytes = hex_string_to_bytes(hex_str.rfind("0x", 0) == 0 ? hex_str.substr(2) : hex_str);
            std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE> pdi_array;
            std::copy_n(pdi_bytes.begin(), SwitchOpaqueFieldSizes::PDI_DATA_SIZE, pdi_array.begin());
            expected_pdis.push_back(pdi_array);
        }
        
        const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE>>* actual_pdis = nullptr;
        ASSERT_EQ(actual_field_data->get_pdi_vector(actual_pdis), Error::Ok) << "Failed to get pdi vector for field: " << json_key;
        ASSERT_NE(actual_pdis, nullptr);
        EXPECT_EQ(*actual_pdis, expected_pdis) << "Mismatch for opaque field: " << json_key;
    };

    // Helper lambda to get and check a port_vector field
    auto check_port_vector_field = [&](SwitchOpaqueDataType type, const std::string& json_key) {
        const SwitchParsedOpaqueFieldData* actual_field_data = nullptr;
        Error error = switch_parser.get_field(type, actual_field_data);
        ASSERT_EQ(error, Error::Ok) << "Failed to get field: " << json_key;
        ASSERT_NE(actual_field_data, nullptr);
        ASSERT_EQ(actual_field_data->get_type(), SwitchParsedFieldType::PORT_VECTOR) << "Field " << json_key << " is not a port vector.";
        
        const auto& expected_hex_list = expected_opaque_fields[json_key].get<std::vector<std::string>>();
        std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE>> expected_ports;
        for (const auto& hex_str : expected_hex_list) {
            std::vector<uint8_t> port_bytes = hex_string_to_bytes(hex_str.rfind("0x", 0) == 0 ? hex_str.substr(2) : hex_str);
            std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE> port_array;
            std::copy_n(port_bytes.begin(), SwitchOpaqueFieldSizes::PORT_ID_SIZE, port_array.begin());
            expected_ports.push_back(port_array);
        }
        
        const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE>>* actual_ports = nullptr;
        ASSERT_EQ(actual_field_data->get_port_vector(actual_ports), Error::Ok) << "Failed to get port vector for field: " << json_key;
        ASSERT_NE(actual_ports, nullptr);
        EXPECT_EQ(*actual_ports, expected_ports) << "Mismatch for opaque field: " << json_key;
    };


    // Assertions for Opaque Data Fields
    check_byte_vector_field(SwitchOpaqueDataType::SWITCH_LOCK_STATUS, "OPAQUE_FIELD_ID_SWITCH_LOCK_STATUS");
    check_byte_vector_field(SwitchOpaqueDataType::SWITCH_POSITION_ID, "OPAQUE_FIELD_ID_SWITCH_POSITION_ID");
    check_byte_vector_field(SwitchOpaqueDataType::VBIOS_VERSION, "OPAQUE_FIELD_ID_VBIOS_VERSION");
    check_byte_vector_field(SwitchOpaqueDataType::DEVICE_PDI, "OPAQUE_FIELD_ID_DEVICE_PDI");

    // Special handling for DISABLED_PORTS (byte_vector of uint8_t)
    const SwitchParsedOpaqueFieldData* disabled_ports_field_data = nullptr;
    error = switch_parser.get_field(SwitchOpaqueDataType::DISABLED_PORTS, disabled_ports_field_data);
    ASSERT_EQ(error, Error::Ok) << "Failed to get field: DISABLED_PORTS";
    ASSERT_NE(disabled_ports_field_data, nullptr);
    ASSERT_EQ(disabled_ports_field_data->get_type(), SwitchParsedFieldType::BYTE_VECTOR) << "Field DISABLED_PORTS is not a byte vector.";
    std::vector<uint8_t> expected_disabled_ports = expected_opaque_fields["OPAQUE_FIELD_ID_DISABLED_PORTS"].get<std::vector<uint8_t>>();
    const std::vector<uint8_t>* actual_disabled_ports = nullptr;
    ASSERT_EQ(disabled_ports_field_data->get_byte_vector(actual_disabled_ports), Error::Ok) << "Failed to get byte vector for field: DISABLED_PORTS";
    ASSERT_NE(actual_disabled_ports, nullptr);
    EXPECT_EQ(*actual_disabled_ports, expected_disabled_ports) << "Mismatch for opaque field: DISABLED_PORTS";
    
    // Special handling for MSRSCNT (uint32_vector)
    const SwitchParsedOpaqueFieldData* msrscnt_field_data = nullptr;
    error = switch_parser.get_field(SwitchOpaqueDataType::MSRSCNT, msrscnt_field_data);
    ASSERT_EQ(error, Error::Ok) << "Failed to get field: MSRSCNT";
    ASSERT_NE(msrscnt_field_data, nullptr);
    ASSERT_EQ(msrscnt_field_data->get_type(), SwitchParsedFieldType::UINT32_VECTOR) << "Field MSRSCNT is not a uint32 vector.";
    std::vector<uint32_t> expected_msrscnt = expected_opaque_fields["OPAQUE_FIELD_ID_MSRSCNT"].get<std::vector<uint32_t>>();
    const std::vector<uint32_t>* actual_msrscnt = nullptr;
    ASSERT_EQ(msrscnt_field_data->get_uint32_vector(actual_msrscnt), Error::Ok) << "Failed to get uint32 vector for field: MSRSCNT";
    ASSERT_NE(actual_msrscnt, nullptr);
    EXPECT_EQ(*actual_msrscnt, expected_msrscnt) << "Mismatch for opaque field: MSRSCNT";

    // Special handling for SWITCH_GPU_PDIS (pdi_vector)
    check_pdi_vector_field(SwitchOpaqueDataType::SWITCH_GPU_PDIS, "OPAQUE_FIELD_ID_SWITCH_GPU_PDIS");

    // Special handling for SWITCH_PORTS (port_vector)
    check_port_vector_field(SwitchOpaqueDataType::SWITCH_PORTS, "OPAQUE_FIELD_ID_SWITCH_PORT");
}

TEST_F(SwitchSpdmRespTest, ParseAndVerifyMeasurementRecords) {
    parse_and_verify_measurement_records(m_msg, m_expected_values_json);
}
