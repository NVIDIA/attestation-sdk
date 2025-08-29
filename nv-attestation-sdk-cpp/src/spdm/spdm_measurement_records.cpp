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

#include <utility> 
#include <ostream> 
#include <iomanip> 
#include <sstream> 

// This SDK headers
#include "nv_attestation/log.h"  
#include "nv_attestation/error.h" 
#include "nv_attestation/spdm/spdm_measurement_records.hpp"
#include "nv_attestation/spdm/utils.h"               
#include "nv_attestation/utils.h"

namespace nvattestation {

bool DmtfMeasurementBlock::parse(const std::vector<uint8_t>& data, size_t& offset) {
    // Parse DMTFSpecMeasurementValueType (1 byte)
    if (!can_read_buffer(data, offset, kDmtfSpecMeasurementValueTypeSize, "DMTFSpecMeasurementValueType")) {
        return false;
    }
    m_type = data[offset];
    offset += kDmtfSpecMeasurementValueTypeSize;

    // Parse DMTFSpecMeasurementValueSize (2 bytes, little-endian)
    if (!read_little_endian(data, offset, kDmtfSpecMeasurementValueSizeSize, m_value_size)) {
        LOG_ERROR("Failed to read DMTFSpecMeasurementValueSize.");
        return false;
    }
    offset += kDmtfSpecMeasurementValueSizeSize;

    // Parse DMTFSpecMeasurementValue (DMTFSpecMeasurementValueSize bytes)
    if (!checked_assign(m_value, data, offset, m_value_size, "DMTFSpecMeasurementValue")) {
        return false;
    };
    offset += m_value_size;

    return true;
}

std::unique_ptr<DmtfMeasurementBlock> DmtfMeasurementBlock::create(const std::vector<uint8_t>& data, size_t offset) {
    auto dmtf_value = std::unique_ptr<DmtfMeasurementBlock>(new DmtfMeasurementBlock());
    if (!dmtf_value->parse(data, offset)) {
        // Error should have been logged by parse() or its helper functions.
        return nullptr;
    }
    return dmtf_value;
}

/**
 * @brief Factory method implementation.
 *        Refer to spdm_measurement_block.hpp for detailed documentation.
 */
std::unique_ptr<SpdmMeasurementRecordParser> SpdmMeasurementRecordParser::create(
    const std::vector<uint8_t>& record_data,
    uint8_t num_blocks) {
    
    // Allocate using std::make_unique for safer memory management.
    auto parser = std::unique_ptr<SpdmMeasurementRecordParser>(new SpdmMeasurementRecordParser());
    if (!parser->parse(record_data, num_blocks)) {
        // msg will be automatically deleted when it goes out of scope if parse fails.
        // Error should have been logged by parse() or its helper functions.
        return nullptr;
    }
    return parser;
}

bool SpdmMeasurementRecordParser::parse_measurement_block(const std::vector<uint8_t>& record_data, size_t& offset) {
    // Parse Index (1 byte)
    if (!can_read_buffer(record_data, offset, kIndexSize, "MeasurementBlock Index")) {
        return false;
    }
    uint8_t index = record_data[offset];
    if (index < 1) {
        LOG_ERROR("MeasurementBlock Index is out of bounds. parsed Index: " + std::to_string(index));
        return false;
    }
    offset += kIndexSize;

    // Parse MeasurementSpecification (1 byte)
    if (!can_read_buffer(record_data, offset, kMeasurementSpecificationSize, "MeasurementSpecification")) {
        return false;
    }
    uint8_t measurement_specification = record_data[offset];
    offset += kMeasurementSpecificationSize;

    if (measurement_specification != kMeasurementSpecification) {
        LOG_ERROR("MeasurementSpecification is not DMTF-specified.");
        return false;
    }

    // Parse MeasurementSize (2 bytes, little-endian)
    if (!can_read_buffer(record_data, offset, kMeasurementSizeSize, "MeasurementSize")) {
        return false;
    }
    uint16_t measurement_size = 0;
    if (!read_little_endian(record_data, offset, kMeasurementSizeSize, measurement_size)) {
        LOG_ERROR("Failed to read MeasurementSize for block.");
        return false;
    }
    offset += kMeasurementSizeSize;

    // Parse Measurement (MeasurementSize bytes)
    std::vector<uint8_t> measurement_hash;
    if(!checked_assign(measurement_hash, record_data, offset, measurement_size, "Measurement data")) {
        return false;
    }
    offset += measurement_size;

    std::unique_ptr<DmtfMeasurementBlock> dmtf_measurement_value = DmtfMeasurementBlock::create(measurement_hash, 0);
    if (!dmtf_measurement_value) {
        LOG_ERROR("Failed to parse DMTF measurement value within block index " + std::to_string(index) + ".");
        return false;
    }
    
    m_dmtf_measurement_blocks[index] = std::move(dmtf_measurement_value);
    return true;
}

bool SpdmMeasurementRecordParser::parse(const std::vector<uint8_t>& record_data, uint8_t num_blocks) {
    if (num_blocks == 0 && !record_data.empty()) {
        LOG_ERROR("Measurement record data present but NumberOfBlocks is zero.");
        return false;
    }
    if (num_blocks > 0 && record_data.empty()) {
        LOG_ERROR("NumberOfBlocks is non-zero but measurement record data is empty.");
        return false;
    }
    if (num_blocks == 0 && record_data.empty()) {
        // This is valid: no blocks, no data.
        return true;
    }

    m_num_blocks = num_blocks;
    m_dmtf_measurement_blocks.clear();
    size_t offset = 0;

    for (uint8_t i = 0; i < num_blocks; ++i) {
        if (!parse_measurement_block(record_data, offset)) {
            return false;
        }
    }

    // After parsing all blocks, check if the entire record_data was consumed.
    if (offset != record_data.size()) {
        std::stringstream error_msg;
        error_msg << "Measurement record parsing did not consume the entire data. "
                  << "Expected: " << record_data.size() << " bytes, Parsed: " << offset << " bytes.";
        LOG_ERROR(error_msg.str());
        return false;
    }

    return true;
}

std::ostream& operator<<(std::ostream& os, const DmtfMeasurementBlock& dmtf_measurement) {
    os << "    DMTFSpecMeasurementValueType : " << to_hex_string(dmtf_measurement.m_type) << "\n"
       << "    DMTFSpecMeasurementValueSize : " << dmtf_measurement.m_value_size << "\n"
       << "    DMTFSpecMeasurementValue     : " << (dmtf_measurement.m_value.empty() ? "(empty)" : to_hex_string(dmtf_measurement.m_value));
    return os;
}

std::ostream& operator<<(std::ostream& os, const SpdmMeasurementRecordParser& parser) {
    os << "--- SPDM Measurement Record ---";
    
    const auto& measurement_blocks = parser.get_all_measurement_blocks();
    
    if (measurement_blocks.empty()) {
        os << "\n  (No measurement blocks or parsing failed)";
    } else {
        for (const auto& pair : measurement_blocks) {
            uint8_t index = pair.first;
            const auto& measurement_block_ptr = pair.second;
            
            os << "\n  ----------------------------------------\n"
               << "  Measurement Block index : " << static_cast<int>(index + 1) << "\n";
            
            if (measurement_block_ptr) {
                os << *measurement_block_ptr; // Calls DmtfMeasurementBlock's operator<<
            } else {
                os << "    (Null measurement block)";
            }
        }
    }
    return os;
}

} // namespace nvattestation 