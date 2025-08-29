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
 * @file spdm_resp.cpp
 * @brief Implements the SpdmMeasurementResponseMessage class for parsing and representing
 *        SPDM GET_MEASUREMENTS response messages.
 */
#include <vector>
#include <string>
#include <cstdint>
#include <array>
#include <iomanip> 
#include <sstream> 
#include <algorithm> 
#include <memory>   
#include <ostream>  

#include "nv_attestation/spdm/spdm_resp.hpp" 
#include "nv_attestation/spdm/spdm_opaque_data_parser.hpp" 
#include "nv_attestation/spdm/spdm_measurement_records.hpp"
#include "nv_attestation/error.h"
#include "nv_attestation/log.h"
#include "nv_attestation/spdm/utils.h" 
#include "nv_attestation/utils.h"


namespace nvattestation {

/**
 * @brief Constructor.
 */
SpdmMeasurementResponseMessage11::SpdmMeasurementResponseMessage11() = default;

/**
 * @brief Factory method implementation.
 *        Refer to spdm_resp.hpp for detailed documentation.
 */
Error SpdmMeasurementResponseMessage11::create(
    const std::vector<uint8_t>& response_data,
    size_t signature_length,
    SpdmMeasurementResponseMessage11& out_message) {
    return out_message.parse(response_data, signature_length);
}

/**
 * @brief Parses the SPDM GET_MEASUREMENTS response data.
 *        Refer to spdm_resp.hpp for detailed documentation.
 */
Error SpdmMeasurementResponseMessage11::parse( // NOLINT(readability-function-cognitive-complexity)
    const std::vector<uint8_t>& response_data,
    size_t signature_length) {
    size_t current_offset = 0;

    // SPDMVersion (1 byte)
    if (!can_read_buffer(response_data, current_offset, kSpdmVersionSize, "SPDMVersion")) {
        return Error::SpdmParseError;
    }
    m_spdm_version = response_data[current_offset];
    if (m_spdm_version != SPDM_VERSION_1_1) {
        LOG_ERROR("SPDMVersion is not " << to_hex_string(SPDM_VERSION_1_1) << " (1.1). Actual version: " << to_hex_string(m_spdm_version));
        return Error::SpdmParseError;
    }
    current_offset += kSpdmVersionSize;

    // RequestResponseCode (1 byte)
    if (!can_read_buffer(response_data, current_offset, kRequestResponseCodeSize, "RequestResponseCode")) {
        return Error::SpdmParseError;
    }
    m_request_response_code = response_data[current_offset];
    if (m_request_response_code != SPDM_RES_CODE_MEASUREMENTS) {
        LOG_ERROR("RequestResponseCode is not " << to_hex_string(SPDM_RES_CODE_MEASUREMENTS) << " (MEASUREMENTS). Actual code: " << to_hex_string(m_request_response_code));
        return Error::SpdmParseError;
    }
    current_offset += kRequestResponseCodeSize;

    // Param1 (1 byte)
    if (!can_read_buffer(response_data, current_offset, kParam1Size, "Param1")) {
        return Error::SpdmParseError;
    } 
    m_param1 = response_data[current_offset];
    current_offset += kParam1Size;

    // Param2 (1 byte)
    if (!can_read_buffer(response_data, current_offset, kParam2Size, "Param2")) {
        return Error::SpdmParseError;
    }
    m_param2 = response_data[current_offset];
    current_offset += kParam2Size;

    // NumberOfBlocks (1 byte)
    if (!can_read_buffer(response_data, current_offset, kNumberOfBlocksSize, "NumberOfBlocks")) {
        return Error::SpdmParseError;
    } 
    m_number_of_blocks = response_data[current_offset];
    current_offset += kNumberOfBlocksSize;

    if (m_number_of_blocks == 0) {
        LOG_ERROR("NumberOfBlocks is 0. This is not a valid SPDM GET_MEASUREMENTS response.");
        return Error::SpdmParseError;
    }

    // MeasurementRecordLength (3 bytes, little-endian)
    if (!can_read_buffer(response_data, current_offset, kMeasurementRecordLengthSize, "MeasurementRecordLength")) {
        return Error::SpdmParseError;
    }
    if (!read_little_endian(response_data, current_offset, kMeasurementRecordLengthSize, m_measurement_record_length)) {
        // read_little_endian doesn't log, so we log context here
        LOG_ERROR("Failed to parse MeasurementRecordLength (3-byte LE value).");
        return Error::SpdmParseError;
    }
    current_offset += kMeasurementRecordLengthSize;

    // MeasurementRecord (variable length: m_measurement_record_length)
    if (!checked_assign(m_measurement_record_data, response_data, current_offset, m_measurement_record_length, "MeasurementRecord")) {
        return Error::SpdmParseError;
    }
    current_offset += m_measurement_record_length;

    // Parse MeasurementRecord
    std::unique_ptr<SpdmMeasurementRecordParser> measurement_record_parser = SpdmMeasurementRecordParser::create(m_measurement_record_data, m_number_of_blocks);
    if (!measurement_record_parser) {
        LOG_ERROR("Failed to parse MeasurementRecord.");
        return Error::SpdmMeasurementRecordParseError;
    }
    m_parsed_measurement_records = std::move(measurement_record_parser);

    // Nonce (32 bytes)
    if (!checked_copy_n(m_nonce, response_data, current_offset, kNonceSize, "Nonce")) {
        return Error::SpdmParseError;
    }
    current_offset += kNonceSize;

    // OpaqueLength (2 bytes, little-endian)
    if (!can_read_buffer(response_data, current_offset, kOpaqueLengthSize, "OpaqueLength")) {
        return Error::SpdmParseError;
    }
    if (!read_little_endian(response_data, current_offset, kOpaqueLengthSize, m_opaque_data_length)) {
        LOG_ERROR("Failed to parse OpaqueLength (2-byte LE value).");
        return Error::SpdmParseError;
    }
    current_offset += kOpaqueLengthSize;

    // OpaqueData (variable length: m_opaque_data_length)
    if (!checked_assign(m_opaque_data, response_data, current_offset, m_opaque_data_length, "OpaqueData")) {
       return Error::SpdmParseError; 
    }
    current_offset += m_opaque_data_length;

    if(m_opaque_data.empty()) {
        LOG_ERROR("OpaqueData is empty but is required for SPDM GET_MEASUREMENTS response.");
        return Error::SpdmParseError;
    }

    // Attempt to parse the opaque data if it exists
    Error error = OpaqueDataParser::create(m_opaque_data, m_parsed_opaque_data);
    if (error != Error::Ok) {
        // Error already logged by OpaqueDataParser, but we can indicate context.
        LOG_ERROR("Failed to parse the OpaqueData field within SPDM GET_MEASUREMENTS response.");
        return Error::SpdmOpaqueDataParseError;
    }
    
    // Signature
    if (!checked_assign(m_signature, response_data, current_offset, signature_length, "Signature")) {
        return Error::SpdmParseError;
    } 
    current_offset += signature_length;

    if (current_offset != response_data.size()) {
        LOG_ERROR("SPDM GET_MEASUREMENTS response has " << (response_data.size() - current_offset) << " trailing bytes.");
        return Error::SpdmParseError;
    }

    return Error::Ok;
}

Error SpdmMeasurementResponseMessage11::get_parsed_opaque_data(const std::vector<ParsedOpaqueFieldData>*& out_parsed_opaque_data) const {
    const std::vector<ParsedOpaqueFieldData>* fields_ptr = nullptr;
    Error error = m_parsed_opaque_data.get_all_fields(fields_ptr);
    if (error != Error::Ok) {
        return error;
    }
    out_parsed_opaque_data = fields_ptr;
    return Error::Ok;
}

std::ostream& operator<<(std::ostream& os, const SpdmMeasurementResponseMessage11& msg) {
    // Helper to convert array to vector for to_hex_string, or adapt to_hex_string for arrays
    auto array_to_hex_string = [](const auto& arr) {
        std::vector<uint8_t> vec(arr.begin(), arr.end());
        return to_hex_string(vec);
    };

    os << "--- SPDM GET_MEASUREMENT Response Message ---\n";
    os << "SPDMVersion             : " << to_hex_string(msg.m_spdm_version) << "\n";
    os << "RequestResponseCode     : " << to_hex_string(msg.m_request_response_code) << "\n";
    os << "Param1                  : " << to_hex_string(msg.m_param1) << "\n";
    os << "Param2                  : " << to_hex_string(msg.m_param2) << "\n";
    os << "NumberOfBlocks          : " << static_cast<int>(msg.m_number_of_blocks) << "\n"; // Python prints as int
    os << "MeasurementRecordLength : " << msg.m_measurement_record_length << "\n";
    
    os << "MeasurementRecordData (" << msg.m_measurement_record_data.size() << " bytes): " 
       << (msg.m_measurement_record_data.empty() ? "(empty)" : to_hex_string(msg.m_measurement_record_data)) << "\n";

    os << "Nonce (32 bytes)        : " << array_to_hex_string(msg.m_nonce) << "\n";
    
    os << "OpaqueLength            : " << msg.m_opaque_data_length << "\n";
    os << "OpaqueData (" << msg.m_opaque_data.size() << " bytes)    : " 
       << (msg.m_opaque_data.empty() ? "(empty)" : to_hex_string(msg.m_opaque_data)) << "\n";

    // Print parsed opaque data
    os << msg.m_parsed_opaque_data << "\n"; 

    os << "Signature (" << msg.m_signature.size() << " bytes)       : " 
       << (msg.m_signature.empty() ? "(empty)" : to_hex_string(msg.m_signature)) << "\n";
    os << "--- End SPDM GET_MEASUREMENT Response Message ---"; // No newline at the very end, common practice.
    return os;
}

} // namespace nvattestation
