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

#include <sstream>

#include "nv_attestation/gpu/spdm/gpu_opaque_data_parser.hpp"
#include "nv_attestation/log.h"
#include "nv_attestation/error.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/spdm/utils.h"

namespace nvattestation {


std::string to_string(GpuOpaqueDataType type) {
    switch (type) {
        case GpuOpaqueDataType::CERT_ISSUER_NAME: return "OPAQUE_FIELD_ID_CERT_ISSUER_NAME";
        case GpuOpaqueDataType::CERT_AUTHORITY_KEY_IDENTIFIER: return "OPAQUE_FIELD_ID_CERT_AUTHORITY_KEY_IDENTIFIER";
        case GpuOpaqueDataType::DRIVER_VERSION: return "OPAQUE_FIELD_ID_DRIVER_VERSION";
        case GpuOpaqueDataType::GPU_INFO: return "OPAQUE_FIELD_ID_GPU_INFO";
        case GpuOpaqueDataType::SKU: return "OPAQUE_FIELD_ID_SKU";
        case GpuOpaqueDataType::VBIOS_VERSION: return "OPAQUE_FIELD_ID_VBIOS_VERSION";
        case GpuOpaqueDataType::MANUFACTURER_ID: return "OPAQUE_FIELD_ID_MANUFACTURER_ID";
        case GpuOpaqueDataType::TAMPER_DETECTION: return "OPAQUE_FIELD_ID_TAMPER_DETECTION";
        case GpuOpaqueDataType::SMC: return "OPAQUE_FIELD_ID_SMC";
        case GpuOpaqueDataType::VPR: return "OPAQUE_FIELD_ID_VPR";
        case GpuOpaqueDataType::NVDEC0_STATUS: return "OPAQUE_FIELD_ID_NVDEC0_STATUS";
        case GpuOpaqueDataType::MSRSCNT: return "OPAQUE_FIELD_ID_MSRSCNT";
        case GpuOpaqueDataType::CPRINFO: return "OPAQUE_FIELD_ID_CPRINFO";
        case GpuOpaqueDataType::BOARD_ID: return "OPAQUE_FIELD_ID_BOARD_ID";
        case GpuOpaqueDataType::CHIP_SKU: return "OPAQUE_FIELD_ID_CHIP_SKU";
        case GpuOpaqueDataType::CHIP_SKU_MOD: return "OPAQUE_FIELD_ID_CHIP_SKU_MOD";
        case GpuOpaqueDataType::PROJECT: return "OPAQUE_FIELD_ID_PROJECT";
        case GpuOpaqueDataType::PROJECT_SKU: return "OPAQUE_FIELD_ID_PROJECT_SKU";
        case GpuOpaqueDataType::PROJECT_SKU_MOD: return "OPAQUE_FIELD_ID_PROJECT_SKU_MOD";
        case GpuOpaqueDataType::FWID: return "OPAQUE_FIELD_ID_FWID";
        case GpuOpaqueDataType::PROTECTED_PCIE_STATUS: return "OPAQUE_FIELD_ID_PROTECTED_PCIE_STATUS";
        case GpuOpaqueDataType::SWITCH_PDI: return "OPAQUE_FIELD_ID_SWITCH_PDI";
        case GpuOpaqueDataType::FLOORSWEPT_PORTS: return "OPAQUE_FIELD_ID_FLOORSWEPT_PORTS";
        case GpuOpaqueDataType::POSITION_ID: return "OPAQUE_FIELD_ID_POSITION_ID";
        case GpuOpaqueDataType::LOCK_SWITCH_STATUS: return "OPAQUE_FIELD_ID_LOCK_SWITCH_STATUS";
        case GpuOpaqueDataType::GPU_LINK_CONN: return "OPAQUE_FIELD_ID_GPU_LINK_CONN";
        case GpuOpaqueDataType::SYS_ENABLE_STATUS: return "OPAQUE_FIELD_ID_SYS_ENABLE_STATUS";
        case GpuOpaqueDataType::OPAQUE_DATA_VERSION: return "OPAQUE_FIELD_ID_OPAQUE_DATA_VERSION";
        case GpuOpaqueDataType::CHIP_INFO: return "OPAQUE_FIELD_ID_CHIP_INFO";
        case GpuOpaqueDataType::FEATURE_FLAG: return "OPAQUE_FIELD_ID_FEATURE_FLAG";
        case GpuOpaqueDataType::INVALID: return "OPAQUE_FIELD_ID_INVALID";
        case GpuOpaqueDataType::UNKNOWN: return "OPAQUE_FIELD_ID_UNKNOWN";
        default: {
            std::stringstream ss;
            ss << "UNKNOWN_OPAQUE_TYPE(0x" << std::hex << static_cast<uint16_t>(type) << ")";
            return ss.str();
        }
    }
}

std::string to_string(GpuParsedFieldType type) {
    switch (type) {
        case GpuParsedFieldType::BYTE_VECTOR: return "BYTE_VECTOR";
        case GpuParsedFieldType::UINT32_VECTOR: return "UINT32_VECTOR";
        case GpuParsedFieldType::PDI_VECTOR: return "PDI_VECTOR";
        case GpuParsedFieldType::UNKNOWN: return "UNKNOWN";
        default: {
            std::stringstream ss;
            ss << "UNKNOWN_PARSED_FIELD_TYPE(0x" << std::hex << static_cast<uint16_t>(type) << ")";
            return ss.str();
        }
    }
}

GpuParsedOpaqueFieldData::GpuParsedOpaqueFieldData() : m_active_type(GpuParsedFieldType::UNINITIALIZED) {
}

GpuParsedFieldType GpuParsedOpaqueFieldData::get_type() const {
    return m_active_type;
}

Error GpuParsedOpaqueFieldData::create(const std::vector<uint8_t>& data, GpuParsedOpaqueFieldData& out_field) {
    out_field.m_byte_data = data;
    out_field.m_active_type = GpuParsedFieldType::BYTE_VECTOR;
    return Error::Ok;
}

Error GpuParsedOpaqueFieldData::create(const std::vector<uint32_t>& data, GpuParsedOpaqueFieldData& out_field) {
    out_field.m_uint32_data = data;
    out_field.m_active_type = GpuParsedFieldType::UINT32_VECTOR;
    return Error::Ok;
}

Error GpuParsedOpaqueFieldData::create(const std::vector<std::array<uint8_t, GpuOpaqueFieldSizes::PDI_DATA_SIZE>>& data, GpuParsedOpaqueFieldData& out_field) {
    out_field.m_pdi_data = data;
    out_field.m_active_type = GpuParsedFieldType::PDI_VECTOR;
    return Error::Ok;
}

Error GpuParsedOpaqueFieldData::get_byte_vector(const std::vector<uint8_t>*& out_data) const {
    if (m_active_type != GpuParsedFieldType::BYTE_VECTOR) {
        LOG_ERROR("Invalid field type for get_byte_vector. Expected BYTE_VECTOR, got " << to_string(m_active_type));
        return Error::SpdmFieldNotFound;
    }
    out_data = &m_byte_data;
    return Error::Ok;
}

Error GpuParsedOpaqueFieldData::get_uint32_vector(const std::vector<uint32_t>*& out_data) const {
    if (m_active_type != GpuParsedFieldType::UINT32_VECTOR) {
        LOG_ERROR("Invalid field type for get_uint32_vector. Expected UINT32_VECTOR, got " << to_string(m_active_type));
        return Error::SpdmFieldNotFound;
    }
    out_data = &m_uint32_data;
    return Error::Ok;
}

Error GpuParsedOpaqueFieldData::get_pdi_vector(const std::vector<std::array<uint8_t, GpuOpaqueFieldSizes::PDI_DATA_SIZE>>*& out_data) const {
    if (m_active_type != GpuParsedFieldType::PDI_VECTOR) {
        LOG_ERROR("Invalid field type for get_pdi_vector. Expected PDI_VECTOR, got " << to_string(m_active_type));
        return Error::SpdmFieldNotFound;
    }
    out_data = &m_pdi_data;
    return Error::Ok;
}

Error GpuOpaqueDataParser::parse_msr_count_internal(
    const std::vector<uint8_t>& data_bytes, 
    std::vector<uint32_t>& out_msr_counts) {
    
    if (data_bytes.size() % GpuOpaqueFieldSizes::MSR_COUNT_ELEMENT_SIZE != 0) {
        LOG_ERROR("Invalid size of measurement count field data. Size: " 
            << data_bytes.size() << ", expected multiple of " << GpuOpaqueFieldSizes::MSR_COUNT_ELEMENT_SIZE);
        return Error::InternalError;
    }

    out_msr_counts.clear();
    size_t num_elements = data_bytes.size() / GpuOpaqueFieldSizes::MSR_COUNT_ELEMENT_SIZE;
    out_msr_counts.reserve(num_elements);

    for (size_t i = 0; i < num_elements; ++i) {
        size_t offset = i * GpuOpaqueFieldSizes::MSR_COUNT_ELEMENT_SIZE;
        uint32_t count_val = 0;
        if (!read_little_endian(data_bytes, offset, GpuOpaqueFieldSizes::MSR_COUNT_ELEMENT_SIZE, count_val)) {
            // This should not happen if size check passed, but good for robustness.
            LOG_ERROR("Failed to read MSR count element at index " << i);
            return Error::InternalError;
        }
        out_msr_counts.push_back(count_val);
    }
    return Error::Ok;
}


Error GpuOpaqueDataParser::parse_switch_pdis_internal(
    const std::vector<uint8_t>& data_bytes, 
    std::vector<std::array<uint8_t, GpuOpaqueFieldSizes::PDI_DATA_SIZE>>& out_switch_pdis) {

    if (data_bytes.size() % GpuOpaqueFieldSizes::PDI_DATA_SIZE != 0) {
        LOG_ERROR("Invalid size of switch PDI data. Size: "
            << data_bytes.size() << ", expected multiple of " << GpuOpaqueFieldSizes::PDI_DATA_SIZE);
        return Error::InternalError;
    }

    out_switch_pdis.clear();
    size_t num_elements = data_bytes.size() / GpuOpaqueFieldSizes::PDI_DATA_SIZE;
    out_switch_pdis.reserve(num_elements);

    for (size_t i = 0; i < num_elements; ++i) {
        std::array<uint8_t, GpuOpaqueFieldSizes::PDI_DATA_SIZE> pdi_element{};
        size_t offset = i * GpuOpaqueFieldSizes::PDI_DATA_SIZE;
        if (!checked_copy_n(pdi_element, data_bytes, offset, GpuOpaqueFieldSizes::PDI_DATA_SIZE, "PDI Data")) {
            return Error::InternalError;
        }
        out_switch_pdis.push_back(pdi_element);
    }
    return Error::Ok;
}

Error GpuOpaqueDataParser::create(const std::vector<ParsedOpaqueFieldData>& opaque_fields, GpuOpaqueDataParser& out_parser) {
    out_parser.m_fields.clear();
    for (const auto& field : opaque_fields) {
        if (!is_valid_gpu_opaque_data_type(field.get_type())) {
            LOG_ERROR("Invalid GPU opaque data type: " << field.get_type());
            return Error::BadArgument;
        }
        GpuOpaqueDataType type = static_cast<GpuOpaqueDataType>(field.get_type());

        const std::vector<uint8_t>* data = nullptr;
        Error error = field.get_data(data);
        if (error != Error::Ok) {
            return error;
        }
        
        GpuParsedOpaqueFieldData parsed_field;
        if (type == GpuOpaqueDataType::MSRSCNT) {
            std::vector<uint32_t> msr_counts;
            error = parse_msr_count_internal(*data, msr_counts);
            if (error != Error::Ok) {
                return error;
            }
            error = GpuParsedOpaqueFieldData::create(msr_counts, parsed_field);
            if (error != Error::Ok) {
                return error;
            }
        }
        else if (type == GpuOpaqueDataType::SWITCH_PDI) {
            std::vector<std::array<uint8_t, GpuOpaqueFieldSizes::PDI_DATA_SIZE>> switch_pdis;
            error = parse_switch_pdis_internal(*data, switch_pdis);
            if (error != Error::Ok) {
                return error;
            }
            error = GpuParsedOpaqueFieldData::create(switch_pdis, parsed_field);
            if (error != Error::Ok) {
                return error;
            }
        } else {
            error = GpuParsedOpaqueFieldData::create(*data, parsed_field);
            if (error != Error::Ok) {
                return error;
            }
        }

        out_parser.m_fields[type] = parsed_field;
    }
    return Error::Ok;
}

Error GpuOpaqueDataParser::get_field(GpuOpaqueDataType type, const GpuParsedOpaqueFieldData*& out_field) const {
    auto it = m_fields.find(type);
    if (it == m_fields.end()) {
        return Error::SpdmFieldNotFound;
    }
    out_field = &it->second;
    return Error::Ok;
}

const std::map<GpuOpaqueDataType, GpuParsedOpaqueFieldData>& GpuOpaqueDataParser::get_all_fields() const {
    return m_fields;
}

std::ostream& operator<<(std::ostream& os, const GpuOpaqueDataParser& parser) {
    os << "--- Parsed GPU Opaque Data ---";
    for (const auto& pair : parser.get_all_fields()) {
        const auto& type = pair.first;
        const auto& field = pair.second;
        os << "\n" << to_string(type) << " (" << to_string(field.get_type()) << "): ";
        
        switch (field.get_type()) {
            case GpuParsedFieldType::BYTE_VECTOR: {
                const std::vector<uint8_t>* byte_data = nullptr;
                Error error = field.get_byte_vector(byte_data);
                if (error == Error::Ok && byte_data != nullptr) {
                    os << to_hex_string(*byte_data);
                } else {
                    os << "[ERROR: Failed to get byte vector data]";
                }
                break;
            }
            case GpuParsedFieldType::UINT32_VECTOR: {
                const std::vector<uint32_t>* uint32_data = nullptr;
                Error error = field.get_uint32_vector(uint32_data);
                if (error == Error::Ok && uint32_data != nullptr) {
                    os << "[";
                    for (size_t i = 0; i < uint32_data->size(); ++i) {
                        if (i > 0) {
                            os << ", ";
                        }
                        os << (*uint32_data)[i];
                    }
                    os << "]";
                } else {
                    os << "[ERROR: Failed to get uint32 vector data]";
                }
                break;
            }
            case GpuParsedFieldType::PDI_VECTOR: {
                const std::vector<std::array<uint8_t, GpuOpaqueFieldSizes::PDI_DATA_SIZE>>* pdi_data = nullptr;
                Error error = field.get_pdi_vector(pdi_data);
                if (error == Error::Ok && pdi_data != nullptr) {
                    os << "[";
                    for (size_t i = 0; i < pdi_data->size(); ++i) {
                        if (i > 0) {
                            os << ", ";
                        }
                        os << to_hex_string((*pdi_data)[i]);
                    }
                    os << "]";
                } else {
                    os << "[ERROR: Failed to get PDI vector data]";
                }
                break;
            }
            case GpuParsedFieldType::UNINITIALIZED:
                os << "[UNINITIALIZED]";
                break;
            case GpuParsedFieldType::UNKNOWN:
                os << "[UNKNOWN TYPE]";
                break;
            default:
                os << "[UNSUPPORTED TYPE]";
                break;
        }
    }
    return os;
}

}