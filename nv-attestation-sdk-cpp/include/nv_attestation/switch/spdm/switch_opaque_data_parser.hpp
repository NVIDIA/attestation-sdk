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

#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <map>
#include <iosfwd> 
#include <memory>

#include "nv_attestation/error.h"
#include "nv_attestation/spdm/spdm_opaque_data_parser.hpp"

namespace nvattestation {

enum class SwitchOpaqueDataType : uint16_t {
    CERT_ISSUER_NAME                = 1,
    CERT_AUTHORITY_KEY_IDENTIFIER   = 2,
    DRIVER_VERSION                  = 3,
    GPU_INFO                        = 4,
    SKU                             = 5,
    VBIOS_VERSION                   = 6,
    MANUFACTURER_ID                 = 7,
    TAMPER_DETECTION                = 8,
    SMC                             = 9,
    VPR                             = 10,
    NVDEC0_STATUS                   = 11,
    MSRSCNT                         = 12,
    CPRINFO                         = 13,
    BOARD_ID                        = 14,
    CHIP_SKU                        = 15,
    CHIP_SKU_MOD                    = 16,
    PROJECT                         = 17,
    PROJECT_SKU                     = 18,
    PROJECT_SKU_MOD                 = 19,
    FWID                            = 20,
    PROTECTED_PCIE_STATUS           = 21,
    DEVICE_PDI                      = 22,
    DISABLED_PORTS                  = 23,
    SWITCH_POSITION_ID              = 24,
    SWITCH_LOCK_STATUS              = 25,
    SWITCH_GPU_PDIS                 = 26,
    SWITCH_PORTS                    = 27,
    INVALID                         = 255,
    UNKNOWN                         = 0 // Placeholder for types not explicitly listed or successfully parsed. Using 0 as it's less likely to collide.
};

inline bool is_valid_switch_opaque_data_type(uint16_t data_type_val_raw) {
    return (1 <= data_type_val_raw) && (data_type_val_raw <= 27);
}

// Function to convert SwitchOpaqueDataType to string (for debugging/logging)
std::string to_string(SwitchOpaqueDataType type);

namespace SwitchOpaqueFieldSizes {
    static constexpr size_t PDI_DATA_SIZE = 8;
    static constexpr size_t MSR_COUNT_ELEMENT_SIZE = 4;
    static constexpr size_t PORT_ID_SIZE = 1;
    static constexpr size_t TOTAL_NUMBER_OF_PDI = 8;
}

enum class SwitchParsedFieldType {
    UNINITIALIZED,
    BYTE_VECTOR,
    UINT32_VECTOR,
    PDI_VECTOR,
    PORT_VECTOR,
    UNKNOWN
};

// Define a type for storing the parsed opaque data fields.
class SwitchParsedOpaqueFieldData {
public:
    SwitchParsedOpaqueFieldData();

    // Constructor for byte_vector
    SwitchParsedOpaqueFieldData(const std::vector<uint8_t>& data);

    // Constructor for uint32_vector
    SwitchParsedOpaqueFieldData(const std::vector<uint32_t>& data);

    // Constructor for pdi_vector
    SwitchParsedOpaqueFieldData(const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE>>& data);

    // Constructor for port_vector
    SwitchParsedOpaqueFieldData(const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE>>& data);

    // Factory methods for creating ParsedOpaqueFieldData with error checking
    static Error create(const std::vector<uint8_t>& data, SwitchParsedOpaqueFieldData& out_field);

    static Error create(const std::vector<uint32_t>& data, SwitchParsedOpaqueFieldData& out_field);

    static Error create(const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE>>& data, SwitchParsedOpaqueFieldData& out_field);

    static Error create(const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE>>& data, SwitchParsedOpaqueFieldData& out_field);

    void clear();

    SwitchParsedFieldType get_type() const;

    Error get_byte_vector(const std::vector<uint8_t>*& out_data) const;

    Error get_uint32_vector(const std::vector<uint32_t>*& out_data) const;

    Error get_pdi_vector(const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE>>*& out_data) const;

    Error get_port_vector(const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE>>*& out_data) const;

private:
    SwitchParsedFieldType m_active_type;
    std::vector<uint8_t> m_byte_data;
    std::vector<uint32_t> m_uint32_data;
    std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE>> m_pdi_data;
    std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE>> m_port_data;
};

class SwitchOpaqueDataParser {
    public: 
        static Error create(const std::vector<ParsedOpaqueFieldData>& opaque_fields, SwitchOpaqueDataParser& out_parser);

        Error get_field(SwitchOpaqueDataType type, const SwitchParsedOpaqueFieldData*& out_field) const;
        const std::map<SwitchOpaqueDataType, SwitchParsedOpaqueFieldData>& get_all_fields() const;
    private:
        static Error parse_msr_count_internal(const std::vector<uint8_t>& data_bytes, std::vector<uint32_t>& out_msr_counts);
        static Error parse_pdis_internal(const std::vector<uint8_t>& data_bytes, std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE>>& out_pdis, std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE>>& out_switch_ports);
        static Error parse_floorswept_ports_internal(const std::vector<uint8_t>& data_bytes, std::vector<uint8_t>& out_disabled_ports);

        std::map<SwitchOpaqueDataType, SwitchParsedOpaqueFieldData> m_fields;
};

inline SwitchParsedFieldType get_switch_opaque_field_type(SwitchOpaqueDataType source_type) {
    static const std::map<SwitchOpaqueDataType, SwitchParsedFieldType> expected_type_map = {
        {SwitchOpaqueDataType::CERT_ISSUER_NAME, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::CERT_AUTHORITY_KEY_IDENTIFIER, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::DRIVER_VERSION, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::GPU_INFO, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::SKU, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::VBIOS_VERSION, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::MANUFACTURER_ID, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::TAMPER_DETECTION, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::SMC, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::VPR, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::NVDEC0_STATUS, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::MSRSCNT, SwitchParsedFieldType::UINT32_VECTOR}, // Special type
        {SwitchOpaqueDataType::CPRINFO, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::BOARD_ID, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::CHIP_SKU, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::CHIP_SKU_MOD, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::PROJECT, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::PROJECT_SKU, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::PROJECT_SKU_MOD, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::FWID, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::PROTECTED_PCIE_STATUS, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::DEVICE_PDI, SwitchParsedFieldType::BYTE_VECTOR}, // Special type
        {SwitchOpaqueDataType::DISABLED_PORTS, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::SWITCH_POSITION_ID, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::SWITCH_LOCK_STATUS, SwitchParsedFieldType::BYTE_VECTOR},
        {SwitchOpaqueDataType::SWITCH_GPU_PDIS, SwitchParsedFieldType::PDI_VECTOR},
        {SwitchOpaqueDataType::SWITCH_PORTS, SwitchParsedFieldType::PORT_VECTOR}
        // SwitchOpaqueDataType::INVALID and SwitchOpaqueDataType::UNKNOWN are not explicitly mapped,
        // they will default to BYTE_VECTOR if encountered during parsing and data is present.
    };
    auto it = expected_type_map.find(source_type);
    if (it == expected_type_map.end()) {
        return SwitchParsedFieldType::UNKNOWN;
    }
    return it->second;
}

std::ostream& operator<<(std::ostream& os, const SwitchOpaqueDataParser& parser) ;

}