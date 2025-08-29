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
#include <array>
#include <map>

#include "nv_attestation/error.h"
#include "nv_attestation/spdm/spdm_opaque_data_parser.hpp"

namespace nvattestation {

enum class GpuOpaqueDataType : uint16_t {
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
    SWITCH_PDI                      = 22,
    FLOORSWEPT_PORTS                = 23,
    POSITION_ID                     = 24,
    LOCK_SWITCH_STATUS              = 25,
    GPU_LINK_CONN                   = 32,
    SYS_ENABLE_STATUS               = 33,
    OPAQUE_DATA_VERSION             = 34,
    CHIP_INFO                       = 35,
    FEATURE_FLAG                    = 36,
    INVALID                         = 255,
    UNKNOWN                         = 0 // Placeholder for types not explicitly listed or successfully parsed. Using 0 as it's less likely to collide.
};

inline bool is_valid_gpu_opaque_data_type(uint16_t data_type_val_raw) {
    return (1 <= data_type_val_raw) && (data_type_val_raw <= 36);
}

// Function to convert GpuOpaqueDataType to string (for debugging/logging)
std::string to_string(GpuOpaqueDataType type);

namespace GpuOpaqueFieldSizes {
    static constexpr size_t PDI_DATA_SIZE = 8;
    static constexpr size_t MSR_COUNT_ELEMENT_SIZE = 4;
}

enum class GpuParsedFieldType {
    UNINITIALIZED,
    BYTE_VECTOR,
    UINT32_VECTOR,
    PDI_VECTOR,
    UNKNOWN
};

// Define a type for storing the parsed opaque data fields.
class GpuParsedOpaqueFieldData {
public:
    GpuParsedOpaqueFieldData();

    // Constructor for byte_vector
    GpuParsedOpaqueFieldData(const std::vector<uint8_t>& data);

    // Constructor for uint32_vector
    GpuParsedOpaqueFieldData(const std::vector<uint32_t>& data);

    // Constructor for pdi_vector
    GpuParsedOpaqueFieldData(const std::vector<std::array<uint8_t, GpuOpaqueFieldSizes::PDI_DATA_SIZE>>& data);

    // Factory methods for creating ParsedOpaqueFieldData with error checking
    static Error create(const std::vector<uint8_t>& data, GpuParsedOpaqueFieldData& out_field);

    static Error create(const std::vector<uint32_t>& data, GpuParsedOpaqueFieldData& out_field);

    static Error create(const std::vector<std::array<uint8_t, GpuOpaqueFieldSizes::PDI_DATA_SIZE>>& data, GpuParsedOpaqueFieldData& out_field);

    void clear();

    GpuParsedFieldType get_type() const;

    Error get_byte_vector(const std::vector<uint8_t>*& out_data) const;

    Error get_uint32_vector(const std::vector<uint32_t>*& out_data) const;

    Error get_pdi_vector(const std::vector<std::array<uint8_t, GpuOpaqueFieldSizes::PDI_DATA_SIZE>>*& out_data) const;

private:
    GpuParsedFieldType m_active_type;
    std::vector<uint8_t> m_byte_data;
    std::vector<uint32_t> m_uint32_data;
    std::vector<std::array<uint8_t, GpuOpaqueFieldSizes::PDI_DATA_SIZE>> m_pdi_data;
};

class GpuOpaqueDataParser {
    public: 
        static Error create(const std::vector<ParsedOpaqueFieldData>& opaque_fields, GpuOpaqueDataParser& out_parser);

        Error get_field(GpuOpaqueDataType type, const GpuParsedOpaqueFieldData*& out_field) const;
        const std::map<GpuOpaqueDataType, GpuParsedOpaqueFieldData>& get_all_fields() const;
    private:
        static Error parse_msr_count_internal(const std::vector<uint8_t>& data_bytes, std::vector<uint32_t>& out_msr_counts);
        static Error parse_switch_pdis_internal(const std::vector<uint8_t>& data_bytes, std::vector<std::array<uint8_t, GpuOpaqueFieldSizes::PDI_DATA_SIZE>>& out_switch_pdis);

        std::map<GpuOpaqueDataType, GpuParsedOpaqueFieldData> m_fields;
};

inline GpuParsedFieldType get_gpu_opaque_field_type(GpuOpaqueDataType source_type) {
    static const std::map<GpuOpaqueDataType, GpuParsedFieldType> expected_type_map = {
        {GpuOpaqueDataType::CERT_ISSUER_NAME, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::CERT_AUTHORITY_KEY_IDENTIFIER, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::DRIVER_VERSION, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::GPU_INFO, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::SKU, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::VBIOS_VERSION, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::MANUFACTURER_ID, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::TAMPER_DETECTION, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::SMC, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::VPR, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::NVDEC0_STATUS, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::MSRSCNT, GpuParsedFieldType::UINT32_VECTOR}, // Special type
        {GpuOpaqueDataType::CPRINFO, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::BOARD_ID, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::CHIP_SKU, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::CHIP_SKU_MOD, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::PROJECT, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::PROJECT_SKU, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::PROJECT_SKU_MOD, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::FWID, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::PROTECTED_PCIE_STATUS, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::SWITCH_PDI, GpuParsedFieldType::PDI_VECTOR}, // Special type
        {GpuOpaqueDataType::FLOORSWEPT_PORTS, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::POSITION_ID, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::LOCK_SWITCH_STATUS, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::GPU_LINK_CONN, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::SYS_ENABLE_STATUS, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::OPAQUE_DATA_VERSION, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::CHIP_INFO, GpuParsedFieldType::BYTE_VECTOR},
        {GpuOpaqueDataType::FEATURE_FLAG, GpuParsedFieldType::BYTE_VECTOR}
        // GpuOpaqueDataType::INVALID and GpuOpaqueDataType::UNKNOWN are not explicitly mapped,
        // they will default to BYTE_VECTOR if encountered during parsing and data is present.
    };
    auto it = expected_type_map.find(source_type);
    if (it == expected_type_map.end()) {
        return GpuParsedFieldType::UNKNOWN;
    }
    return it->second;
}

std::ostream& operator<<(std::ostream& os, const GpuOpaqueDataParser& parser) ;

}