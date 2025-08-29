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
#include "nv_attestation/spdm/spdm_opaque_data_parser.hpp" // For OpaqueDataParser, ParsedOpaqueFieldData
#include "nv_attestation/gpu/spdm/gpu_opaque_data_parser.hpp" // For GpuOpaqueDataType, GpuParsedOpaqueFieldData, GpuOpaqueDataParser
#include "nv_attestation/spdm/spdm_measurement_records.hpp" // For SpdmMeasurementRecordParser
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
class GpuSpdmRespTest : public ::testing::Test {
protected:
    /**
     * @brief Sets up the test environment before each test case.
     * 
     * Reads the SPDM report, parses the response, and loads expected values from JSON.
     */
    void SetUp() override {
        std::string full_report_hex;
        std::ifstream report_file("testdata/hopperAttestationReport.txt");

        if (!report_file.is_open()) {
            GTEST_FAIL() << "Failed to open unit-tests/testdata/hopperAttestationReport.txt";
        }
        
        std::getline(report_file, full_report_hex);
        report_file.close();

        if (full_report_hex.empty()) {
            GTEST_FAIL() << "Failed to read data from hopperAttestationReport.txt or file is empty.";
        }

        const size_t request_hex_length = SpdmMeasurementRequestMessage11::get_request_length()*2;
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

        std::ifstream json_file("testdata/spdm_parsed_output.json");
        if (!json_file.is_open()) {
            GTEST_FAIL() << "Failed to open unit-tests/testdata/spdm_parsed_output.json in SetUp";
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
 * spdm response for the sample spdm response hopperAttestationReport.txt from
 * the old python sdk. essentially, we are making sure that the parsed spdm response 
 * gives the same values as that of the old python sdk.
 */
TEST_F(GpuSpdmRespTest, ParseAndVerifySpdmResponse) {
    parse_and_verify_spdm_response(m_msg, m_expected_values_json);
    EXPECT_EQ(m_msg.get_signature().size(), m_signature_length);
}

TEST_F(GpuSpdmRespTest, ParseAndVerifyOpaqueData) {
    ASSERT_FALSE(m_expected_values_json.is_null()) << "Expected values JSON is null. SetUp might have failed.";

    const OpaqueDataParser& opaque_parser = m_msg.get_parsed_opaque_struct();

    LOG_DEBUG(opaque_parser);

    // Get all fields from the base parser
    const std::vector<ParsedOpaqueFieldData>* base_fields_ptr = nullptr;
    Error error = opaque_parser.get_all_fields(base_fields_ptr);
    ASSERT_EQ(error, Error::Ok) << "Failed to get all fields from base parser";

    // Create GPU-specific parser
    GpuOpaqueDataParser gpu_parser;
    error = GpuOpaqueDataParser::create(*base_fields_ptr, gpu_parser);
    ASSERT_EQ(error, Error::Ok) << "Failed to create GPU opaque data parser";

    LOG_DEBUG(gpu_parser);

    const json& expected_opaque_fields = m_expected_values_json["OpaqueData"]["OpaqueDataField"];

    // Helper lambda to get and check a byte_vector field
    auto check_byte_vector_field = [&](GpuOpaqueDataType type, const std::string& json_key) {
        const GpuParsedOpaqueFieldData* actual_field_data = nullptr;
        Error error = gpu_parser.get_field(type, actual_field_data);
        ASSERT_EQ(error, Error::Ok) << "Failed to get field: " << json_key;
        ASSERT_EQ(actual_field_data->get_type(), GpuParsedFieldType::BYTE_VECTOR) << "Field " << json_key << " is not a byte vector.";
        
        const std::string expected_hex = expected_opaque_fields[json_key].get<std::string>();
        // Ensure "0x" prefix is handled if present, hex_string_to_bytes expects it to be absent
        std::vector<uint8_t> expected_bytes = hex_string_to_bytes(expected_hex.rfind("0x", 0) == 0 ? expected_hex.substr(2) : expected_hex);
        const std::vector<uint8_t>* actual_bytes = nullptr;
        ASSERT_EQ(actual_field_data->get_byte_vector(actual_bytes), Error::Ok) << "Failed to get byte vector for field: " << json_key;
        EXPECT_EQ(*actual_bytes, expected_bytes) << "Mismatch for opaque field: " << json_key;
    };

    // Assertions for Opaque Data Fields
    check_byte_vector_field(GpuOpaqueDataType::BOARD_ID, "OPAQUE_FIELD_ID_BOARD_ID");
    check_byte_vector_field(GpuOpaqueDataType::CHIP_SKU, "OPAQUE_FIELD_ID_CHIP_SKU");
    check_byte_vector_field(GpuOpaqueDataType::CHIP_SKU_MOD, "OPAQUE_FIELD_ID_CHIP_SKU_MOD");
    check_byte_vector_field(GpuOpaqueDataType::CPRINFO, "OPAQUE_FIELD_ID_CPRINFO");
    check_byte_vector_field(GpuOpaqueDataType::DRIVER_VERSION, "OPAQUE_FIELD_ID_DRIVER_VERSION");
    check_byte_vector_field(GpuOpaqueDataType::FWID, "OPAQUE_FIELD_ID_FWID");
    check_byte_vector_field(GpuOpaqueDataType::GPU_INFO, "OPAQUE_FIELD_ID_GPU_INFO");
    check_byte_vector_field(GpuOpaqueDataType::NVDEC0_STATUS, "OPAQUE_FIELD_ID_NVDEC0_STATUS");
    check_byte_vector_field(GpuOpaqueDataType::PROJECT, "OPAQUE_FIELD_ID_PROJECT");
    check_byte_vector_field(GpuOpaqueDataType::PROJECT_SKU, "OPAQUE_FIELD_ID_PROJECT_SKU");
    check_byte_vector_field(GpuOpaqueDataType::PROJECT_SKU_MOD, "OPAQUE_FIELD_ID_PROJECT_SKU_MOD");
    check_byte_vector_field(GpuOpaqueDataType::PROTECTED_PCIE_STATUS, "OPAQUE_FIELD_ID_PROTECTED_PCIE_STATUS");
    check_byte_vector_field(GpuOpaqueDataType::VBIOS_VERSION, "OPAQUE_FIELD_ID_VBIOS_VERSION");

    // Special handling for MSRSCNT (uint32_vector)
    const GpuParsedOpaqueFieldData* msrscnt_field_data = nullptr;
    error = gpu_parser.get_field(GpuOpaqueDataType::MSRSCNT, msrscnt_field_data);
    ASSERT_EQ(error, Error::Ok) << "Failed to get field: MSRSCNT";
    ASSERT_EQ(msrscnt_field_data->get_type(), GpuParsedFieldType::UINT32_VECTOR) << "Field MSRSCNT is not a uint32 vector.";
    std::vector<uint32_t> expected_msrscnt = expected_opaque_fields["OPAQUE_FIELD_ID_MSRSCNT"].get<std::vector<uint32_t>>();
    const std::vector<uint32_t>* actual_msrscnt = nullptr;
    ASSERT_EQ(msrscnt_field_data->get_uint32_vector(actual_msrscnt), Error::Ok) << "Failed to get uint32 vector for field: MSRSCNT";
    EXPECT_EQ(*actual_msrscnt, expected_msrscnt) << "Mismatch for opaque field: MSRSCNT";
}

TEST_F(GpuSpdmRespTest, ParseAndVerifyMeasurementRecords) {
    parse_and_verify_measurement_records(m_msg, m_expected_values_json);
}
