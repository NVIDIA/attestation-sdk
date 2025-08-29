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

#include <vector>
#include <unordered_map>
#include <string>
#include <cstdint>
#include <memory> 
#include <ostream> 

// This SDK headers
#include "nv_attestation/log.h" 
#include "nv_attestation/error.h" 
#include "nv_attestation/utils.h"

namespace nvattestation {

/**
 * @brief Represents a DMTF-specified measurement value.
 * Structure based on DMTF SPDM specification (e.g., DSP0274).
 */
struct DmtfMeasurementBlock {
    uint8_t m_type{};
    uint16_t m_value_size{};
    std::vector<uint8_t> m_value;

    static std::unique_ptr<DmtfMeasurementBlock> create(const std::vector<uint8_t>& data, size_t offset);

    uint8_t get_measurement_value_type() const { return m_type; }
    uint16_t get_measurement_value_size() const { return m_value_size; }
    const std::vector<uint8_t>& get_measurement_value() const { return m_value; }

private:
    /**
     * @brief Parses the raw DMTF measurement data.
     * @param data The byte vector containing the raw DMTF measurement data block.
     * @param offset Current offset into the data vector.
     * @return True if parsing was successful, false otherwise.
     */
    bool parse(const std::vector<uint8_t>& data, size_t& offset);

    static const size_t kDmtfSpecMeasurementValueTypeSize = 1;
    static const size_t kDmtfSpecMeasurementValueSizeSize = 2; // Little-endian
};

// Forward declaration for ostream operator
std::ostream& operator<<(std::ostream& os, const DmtfMeasurementBlock& dmtf_measurement);

/**
 * @brief Parses the SPDM Measurement Record data.
 * The Measurement Record consists of one or more Measurement Blocks.
 */
class SpdmMeasurementRecordParser {
public:
    static std::unique_ptr<SpdmMeasurementRecordParser> create(const std::vector<uint8_t>& record_data, uint8_t num_blocks);

    Error get_dmtf_measurement_block(uint8_t index, DmtfMeasurementBlock& out_measurement_block) const {
        auto it = m_dmtf_measurement_blocks.find(index);
        if (it == m_dmtf_measurement_blocks.end()) {
            LOG_ERROR("measurement block with index " + std::to_string(index) + " is not present.");
            return Error::SpdmFieldNotFound;
        }
        out_measurement_block = *(it->second);
        return Error::Ok;
    }
    
    const std::unordered_map<uint8_t, std::shared_ptr<const DmtfMeasurementBlock>>& get_all_measurement_blocks() const { return m_dmtf_measurement_blocks; }

    /**
     * @brief Constant indicating the DMTF specified measurement type.
     * Bit 0 = 1 indicates DMTF-specified measurement.
     */
    static constexpr uint8_t kMeasurementSpecificationDmtf = 1;

private: 
    static const size_t kIndexSize = 1;
    static const size_t kMeasurementSpecificationSize = 1;
    static const size_t kMeasurementSizeSize = 2; // Little-endian

    static const uint8_t kMeasurementSpecification = 0x01;

    uint8_t m_num_blocks;

    /**
     * @brief Parses the entire measurement record data.
     * @param record_data The raw byte vector containing the complete measurement record.
     * @param num_blocks The number of measurement blocks expected, as indicated by
     *                   the NumberOfBlocks field in the SPDM GET_MEASUREMENTS response.
     * @return True if parsing all blocks was successful, false otherwise.
     */
    bool parse(const std::vector<uint8_t>& record_data, uint8_t num_blocks);

    bool parse_measurement_block(const std::vector<uint8_t>& record_data, size_t& offset);

    // Map from index to measurement block for efficient lookup
    std::unordered_map<uint8_t, std::shared_ptr<const DmtfMeasurementBlock>> m_dmtf_measurement_blocks;

};

// Forward declaration for ostream operator
std::ostream& operator<<(std::ostream& os, const SpdmMeasurementRecordParser& parser);

} // namespace nvattestation 