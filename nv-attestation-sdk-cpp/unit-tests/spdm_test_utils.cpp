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

#include "spdm_test_utils.h"

#include <iomanip>
#include <sstream>

#include "nv_attestation/log.h"

namespace nvattestation {

void parse_and_verify_spdm_response(
    const nvattestation::SpdmMeasurementResponseMessage11& msg,
    const nlohmann::json& expected_values_json) {
    ASSERT_FALSE(expected_values_json.is_null()) << "Expected values JSON is null. SetUp might have failed.";

    LOG_DEBUG(msg);
    // Assertions based on unit-tests/testdata/spdm_parsed_output.json
    EXPECT_EQ(msg.get_spdm_version(), static_cast<uint8_t>(std::stoul(expected_values_json["SPDMVersion"].get<std::string>(), nullptr, 16)));
    EXPECT_EQ(msg.get_request_response_code(), static_cast<uint8_t>(std::stoul(expected_values_json["RequestResponseCode"].get<std::string>(), nullptr, 16)));
    EXPECT_EQ(msg.get_param1(), static_cast<uint8_t>(std::stoul(expected_values_json["Param1"].get<std::string>(), nullptr, 16)));
    EXPECT_EQ(msg.get_param2(), static_cast<uint8_t>(std::stoul(expected_values_json["Param2"].get<std::string>(), nullptr, 16)));
    EXPECT_EQ(msg.get_number_of_blocks(), expected_values_json["NumberOfBlocks"].get<uint8_t>());
    EXPECT_EQ(msg.get_measurement_record_length(), expected_values_json["MeasurementRecordLength"].get<uint32_t>());

    // Nonce
    const std::string expected_nonce_hex = expected_values_json["Nonce"].get<std::string>();
    std::vector<uint8_t> expected_nonce_bytes = hex_string_to_bytes(expected_nonce_hex.substr(2)); // substr(2) to remove "0x"
    std::array<uint8_t, 32> actual_nonce_array = msg.get_nonce(); 
    std::vector<uint8_t> actual_nonce_vec(actual_nonce_array.begin(), actual_nonce_array.end());
    EXPECT_EQ(actual_nonce_vec, expected_nonce_bytes);
    
    EXPECT_EQ(msg.get_opaque_data_length(), expected_values_json["OpaqueLength"].get<uint16_t>());

    // Signature
    const std::string expected_signature_hex = expected_values_json["Signature"].get<std::string>();
    std::vector<uint8_t> expected_signature_bytes = hex_string_to_bytes(expected_signature_hex.substr(2)); // substr(2) to remove "0x"
    EXPECT_EQ(msg.get_signature(), expected_signature_bytes);
}

void parse_and_verify_measurement_records(
    const nvattestation::SpdmMeasurementResponseMessage11& msg,
    const nlohmann::json& expected_values_json) {
    ASSERT_FALSE(expected_values_json.is_null()) << "Expected values JSON is null. SetUp might have failed.";

    auto record_parser = msg.get_parsed_measurement_records();

    LOG_DEBUG(record_parser);

    const nlohmann::json& expected_measurement_record = expected_values_json["MeasurementRecord"];
    const nlohmann::json& expected_blocks_json = expected_measurement_record["MeasurementBlocks"];

    // Verify number of blocks reported by the message header matches the number of blocks in the JSON.
    uint8_t expected_num_blocks = expected_measurement_record["NumberOfBlocks"].get<uint8_t>();
    uint8_t actual_num_blocks = msg.get_number_of_blocks();
   
    ASSERT_EQ(actual_num_blocks, expected_num_blocks) << "Mismatch in the number of measurement blocks processed by the parser versus expected in JSON.";

    // Iterate through the expected measurement blocks from the JSON
    for (auto it = expected_blocks_json.begin(); it != expected_blocks_json.end(); ++it) {
        const std::string& block_key_str = it.key(); // e.g., "1", "2", ...
        const nlohmann::json& expected_block_json = it.value();

        uint8_t block_index;
        try {
            block_index = static_cast<uint8_t>(std::stoul(block_key_str));
        } catch (const std::exception& e) {
            GTEST_FAIL() << "Invalid block key in JSON: " << block_key_str << ". " << e.what();
            continue; 
        }

        DmtfMeasurementBlock actual_block;
        Error error = record_parser.get_dmtf_measurement_block(block_index, actual_block);
        ASSERT_EQ(error, Error::Ok) << "Failed to get DMTF measurement block for index " << static_cast<int>(block_index);

        // Verify DMTFSpecMeasurementValueType
        uint8_t expected_value_type = expected_block_json["DMTFSpecMeasurementValueType"].get<uint8_t>();
        EXPECT_EQ(actual_block.get_measurement_value_type(), expected_value_type) 
            << "Mismatch for DMTFSpecMeasurementValueType in block index " << static_cast<int>(block_index);

        // Verify DMTFSpecMeasurementValueSize
        uint16_t expected_value_size = expected_block_json["DMTFSpecMeasurementValueSize"].get<uint16_t>();
        EXPECT_EQ(actual_block.get_measurement_value_size(), expected_value_size)
            << "Mismatch for DMTFSpecMeasurementValueSize in block index " << static_cast<int>(block_index);

        // Verify DMTFSpecMeasurementValue
        const std::string expected_value_hex = expected_block_json["DMTFSpecMeasurementValue"].get<std::string>();
        std::vector<uint8_t> expected_value_bytes = hex_string_to_bytes(
            expected_value_hex.rfind("0x", 0) == 0 ? expected_value_hex.substr(2) : expected_value_hex);
        
        std::vector<uint8_t> actual_value_bytes = actual_block.get_measurement_value();
        EXPECT_EQ(actual_value_bytes, expected_value_bytes)
            << "Mismatch for DMTFSpecMeasurementValue in block index " << static_cast<int>(block_index);
    }
}
}  // namespace nvattestation 