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
#include <climits>

#include "nv_attestation/switch/spdm/switch_opaque_data_parser.hpp"
#include "nv_attestation/log.h"
#include "nv_attestation/error.h"
#include "nv_attestation/utils.h"
#include "nv_attestation/spdm/utils.h"

namespace nvattestation {


std::string to_string(SwitchOpaqueDataType type) {
    switch (type) {
        case SwitchOpaqueDataType::CERT_ISSUER_NAME: return "OPAQUE_FIELD_ID_CERT_ISSUER_NAME";
        case SwitchOpaqueDataType::CERT_AUTHORITY_KEY_IDENTIFIER: return "OPAQUE_FIELD_ID_CERT_AUTHORITY_KEY_IDENTIFIER";
        case SwitchOpaqueDataType::DRIVER_VERSION: return "OPAQUE_FIELD_ID_DRIVER_VERSION";
        case SwitchOpaqueDataType::GPU_INFO: return "OPAQUE_FIELD_ID_GPU_INFO";
        case SwitchOpaqueDataType::SKU: return "OPAQUE_FIELD_ID_SKU";
        case SwitchOpaqueDataType::VBIOS_VERSION: return "OPAQUE_FIELD_ID_VBIOS_VERSION";
        case SwitchOpaqueDataType::MANUFACTURER_ID: return "OPAQUE_FIELD_ID_MANUFACTURER_ID";
        case SwitchOpaqueDataType::TAMPER_DETECTION: return "OPAQUE_FIELD_ID_TAMPER_DETECTION";
        case SwitchOpaqueDataType::SMC: return "OPAQUE_FIELD_ID_SMC";
        case SwitchOpaqueDataType::VPR: return "OPAQUE_FIELD_ID_VPR";
        case SwitchOpaqueDataType::NVDEC0_STATUS: return "OPAQUE_FIELD_ID_NVDEC0_STATUS";
        case SwitchOpaqueDataType::MSRSCNT: return "OPAQUE_FIELD_ID_MSRSCNT";
        case SwitchOpaqueDataType::CPRINFO: return "OPAQUE_FIELD_ID_CPRINFO";
        case SwitchOpaqueDataType::BOARD_ID: return "OPAQUE_FIELD_ID_BOARD_ID";
        case SwitchOpaqueDataType::CHIP_SKU: return "OPAQUE_FIELD_ID_CHIP_SKU";
        case SwitchOpaqueDataType::CHIP_SKU_MOD: return "OPAQUE_FIELD_ID_CHIP_SKU_MOD";
        case SwitchOpaqueDataType::PROJECT: return "OPAQUE_FIELD_ID_PROJECT";
        case SwitchOpaqueDataType::PROJECT_SKU: return "OPAQUE_FIELD_ID_PROJECT_SKU";
        case SwitchOpaqueDataType::PROJECT_SKU_MOD: return "OPAQUE_FIELD_ID_PROJECT_SKU_MOD";
        case SwitchOpaqueDataType::FWID: return "OPAQUE_FIELD_ID_FWID";
        case SwitchOpaqueDataType::PROTECTED_PCIE_STATUS: return "OPAQUE_FIELD_ID_PROTECTED_PCIE_STATUS";
        case SwitchOpaqueDataType::DEVICE_PDI: return "OPAQUE_FIELD_ID_DEVICE_PDI";
        case SwitchOpaqueDataType::DISABLED_PORTS: return "OPAQUE_FIELD_ID_DISABLED_PORTS";
        case SwitchOpaqueDataType::SWITCH_POSITION_ID: return "OPAQUE_FIELD_ID_SWITCH_POSITION_ID";
        case SwitchOpaqueDataType::SWITCH_LOCK_STATUS: return "OPAQUE_FIELD_ID_SWITCH_LOCK_STATUS";
        case SwitchOpaqueDataType::SWITCH_GPU_PDIS: return "OPAQUE_FIELD_ID_SWITCH_GPU_PDIS";
        case SwitchOpaqueDataType::SWITCH_PORTS: return "OPAQUE_FIELD_ID_SWITCH_PORT";
        case SwitchOpaqueDataType::INVALID: return "OPAQUE_FIELD_ID_INVALID";
        case SwitchOpaqueDataType::UNKNOWN: return "OPAQUE_FIELD_ID_UNKNOWN";
        default: {
            std::stringstream ss;
            ss << "UNKNOWN_OPAQUE_TYPE(0x" << std::hex << static_cast<uint16_t>(type) << ")";
            return ss.str();
        }
    }
}

std::string to_string(SwitchParsedFieldType type) {
    switch (type) {
        case SwitchParsedFieldType::BYTE_VECTOR: return "BYTE_VECTOR";
        case SwitchParsedFieldType::UINT32_VECTOR: return "UINT32_VECTOR";
        case SwitchParsedFieldType::PDI_VECTOR: return "PDI_VECTOR";
        case SwitchParsedFieldType::PORT_VECTOR: return "PORT_VECTOR";
        case SwitchParsedFieldType::UNKNOWN: return "UNKNOWN";
        default: {
            std::stringstream ss;
            ss << "UNKNOWN_PARSED_FIELD_TYPE(0x" << std::hex << static_cast<uint16_t>(type) << ")";
            return ss.str();
        }
    }
}

SwitchParsedOpaqueFieldData::SwitchParsedOpaqueFieldData() : m_active_type(SwitchParsedFieldType::UNINITIALIZED) {
}

SwitchParsedFieldType SwitchParsedOpaqueFieldData::get_type() const {
    return m_active_type;
}

Error SwitchParsedOpaqueFieldData::create(const std::vector<uint8_t>& data, SwitchParsedOpaqueFieldData& out_field) {
    out_field.m_byte_data = data;
    out_field.m_active_type = SwitchParsedFieldType::BYTE_VECTOR;
    return Error::Ok;
}

Error SwitchParsedOpaqueFieldData::create(const std::vector<uint32_t>& data, SwitchParsedOpaqueFieldData& out_field) {
    out_field.m_uint32_data = data;
    out_field.m_active_type = SwitchParsedFieldType::UINT32_VECTOR;
    return Error::Ok;
}

Error SwitchParsedOpaqueFieldData::create(const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE>>& data, SwitchParsedOpaqueFieldData& out_field) {
    out_field.m_pdi_data = data;
    out_field.m_active_type = SwitchParsedFieldType::PDI_VECTOR;
    return Error::Ok;
}


Error SwitchParsedOpaqueFieldData::create(const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE>>& data, SwitchParsedOpaqueFieldData& out_field) {
    out_field.m_port_data = data;
    out_field.m_active_type = SwitchParsedFieldType::PORT_VECTOR;
    return Error::Ok;
}


Error SwitchParsedOpaqueFieldData::get_byte_vector(const std::vector<uint8_t>*& out_data) const {
    if (m_active_type != SwitchParsedFieldType::BYTE_VECTOR) {
        LOG_ERROR("Invalid field type for get_byte_vector. Expected BYTE_VECTOR, got " << to_string(m_active_type));
        return Error::SpdmFieldNotFound;
    }
    out_data = &m_byte_data;
    return Error::Ok;
}

Error SwitchParsedOpaqueFieldData::get_uint32_vector(const std::vector<uint32_t>*& out_data) const {
    if (m_active_type != SwitchParsedFieldType::UINT32_VECTOR) {
        LOG_ERROR("Invalid field type for get_uint32_vector. Expected UINT32_VECTOR, got " << to_string(m_active_type));
        return Error::SpdmFieldNotFound;
    }
    out_data = &m_uint32_data;
    return Error::Ok;
}

Error SwitchParsedOpaqueFieldData::get_pdi_vector(const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE>>*& out_data) const {
    if (m_active_type != SwitchParsedFieldType::PDI_VECTOR) {
        LOG_ERROR("Invalid field type for get_pdi_vector. Expected PDI_VECTOR, got " << to_string(m_active_type));
        return Error::SpdmFieldNotFound;
    }
    out_data = &m_pdi_data;
    return Error::Ok;
}

Error SwitchParsedOpaqueFieldData::get_port_vector(const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE>>*& out_data) const {
    if (m_active_type != SwitchParsedFieldType::PORT_VECTOR) {
        LOG_ERROR("Invalid field type for get_port_vector. Expected PORT_VECTOR, got " << to_string(m_active_type));
        return Error::SpdmFieldNotFound;
    }
    out_data = &m_port_data;
    return Error::Ok;
}

Error SwitchOpaqueDataParser::parse_msr_count_internal(
    const std::vector<uint8_t>& data_bytes, 
    std::vector<uint32_t>& out_msr_counts) {
    
    if (data_bytes.size() % SwitchOpaqueFieldSizes::MSR_COUNT_ELEMENT_SIZE != 0) {
        LOG_ERROR("Invalid size of measurement count field data. Size: " 
            << data_bytes.size() << ", expected multiple of " << SwitchOpaqueFieldSizes::MSR_COUNT_ELEMENT_SIZE);
        return Error::InternalError;
    }

    out_msr_counts.clear();
    size_t num_elements = data_bytes.size() / SwitchOpaqueFieldSizes::MSR_COUNT_ELEMENT_SIZE;
    out_msr_counts.reserve(num_elements);

    for (size_t i = 0; i < num_elements; ++i) {
        size_t offset = i * SwitchOpaqueFieldSizes::MSR_COUNT_ELEMENT_SIZE;
        uint32_t count_val = 0;
        if (!read_little_endian(data_bytes, offset, SwitchOpaqueFieldSizes::MSR_COUNT_ELEMENT_SIZE, count_val)) {
            // This should not happen if size check passed, but good for robustness.
            LOG_ERROR("Failed to read MSR count element at index " << i);
            return Error::InternalError;
        }
        out_msr_counts.push_back(count_val);
    }
    return Error::Ok;
}


Error SwitchOpaqueDataParser::parse_pdis_internal(
    const std::vector<uint8_t>& data_bytes, 
    std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE>>& out_pdis, 
    std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE>>& out_switch_ports) {

    out_pdis.clear();
    out_switch_ports.clear();
    out_pdis.reserve(SwitchOpaqueFieldSizes::TOTAL_NUMBER_OF_PDI);

    for (size_t i = 0; i < SwitchOpaqueFieldSizes::TOTAL_NUMBER_OF_PDI; ++i) {
        std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE> pdi_element{};
        size_t offset = i * SwitchOpaqueFieldSizes::PDI_DATA_SIZE;
        if (!checked_copy_n(pdi_element, data_bytes, offset, SwitchOpaqueFieldSizes::PDI_DATA_SIZE, "PDI Data")) {
            return Error::InternalError;
        }
        out_pdis.push_back(pdi_element);
    }

    size_t offset = SwitchOpaqueFieldSizes::TOTAL_NUMBER_OF_PDI * SwitchOpaqueFieldSizes::PDI_DATA_SIZE;
    while (offset < data_bytes.size()) {
        std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE> port_element{};
        if (!checked_copy_n(port_element, data_bytes, offset, SwitchOpaqueFieldSizes::PORT_ID_SIZE, "PORT Data")) {
            return Error::InternalError;
        }
        out_switch_ports.push_back(port_element);
        offset += SwitchOpaqueFieldSizes::PORT_ID_SIZE;
    }

    return Error::Ok;
}

Error SwitchOpaqueDataParser::parse_floorswept_ports_internal(
    const std::vector<uint8_t>& data_bytes, 
    std::vector<uint8_t>& out_disabled_ports) {
    
    out_disabled_ports.clear();
    for (uint8_t byte_val : data_bytes) {
        for (int i = CHAR_BIT - 1; i >= 0; --i) {
            if (((byte_val >> i) & 1) != 0) {
                out_disabled_ports.insert(out_disabled_ports.end(), 4, 1);
            } else {
                out_disabled_ports.insert(out_disabled_ports.end(), 4, 0);
            }
        }
    }
    return Error::Ok;
}

Error SwitchOpaqueDataParser::create(const std::vector<ParsedOpaqueFieldData>& opaque_fields, SwitchOpaqueDataParser& out_parser) {
    out_parser.m_fields.clear();
    for (const auto& field : opaque_fields) {
        if (!is_valid_switch_opaque_data_type(field.get_type())) {
            LOG_ERROR("Invalid SWITCH opaque data type: " << field.get_type());
            return Error::BadArgument;
        }
        SwitchOpaqueDataType type = static_cast<SwitchOpaqueDataType>(field.get_type());

        const std::vector<uint8_t>* data = nullptr;
        Error error = field.get_data(data);
        if (error != Error::Ok) {
            return error;
        }
        
        SwitchParsedOpaqueFieldData parsed_field;
        if (type == SwitchOpaqueDataType::MSRSCNT) {
            std::vector<uint32_t> msr_counts;
            error = parse_msr_count_internal(*data, msr_counts);
            if (error != Error::Ok) {
                return error;
            }
            error = SwitchParsedOpaqueFieldData::create(msr_counts, parsed_field);
            if (error != Error::Ok) {
                return error;
            }
        }
        else if (type == SwitchOpaqueDataType::SWITCH_GPU_PDIS) {
            std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE>> pdis;
            std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE>> ports;
            Error error = parse_pdis_internal(*data, pdis, ports);
            if (error != Error::Ok) {
                return error;
            }

            error = SwitchParsedOpaqueFieldData::create(pdis, parsed_field);
            if (error != Error::Ok) {
                return error;
            }

            SwitchParsedOpaqueFieldData port_field_data;
            error = SwitchParsedOpaqueFieldData::create(ports, port_field_data);
            if (error != Error::Ok) {
                return error;
            }
            out_parser.m_fields[SwitchOpaqueDataType::SWITCH_PORTS] = port_field_data;
        } else if (type == SwitchOpaqueDataType::DISABLED_PORTS) {
            std::vector<uint8_t> disabled_ports;
            Error error = parse_floorswept_ports_internal(*data, disabled_ports);
            if (error != Error::Ok) {
                return error;
            }
            error = SwitchParsedOpaqueFieldData::create(disabled_ports, parsed_field);
            if (error != Error::Ok) {
                return error;
            }
        } else {
            error = SwitchParsedOpaqueFieldData::create(*data, parsed_field);
            if (error != Error::Ok) {
                return error;
            }
        }

        out_parser.m_fields[type] = parsed_field;
    }
    return Error::Ok;
}

Error SwitchOpaqueDataParser::get_field(SwitchOpaqueDataType type, const SwitchParsedOpaqueFieldData*& out_field) const {
    auto it = m_fields.find(type);
    if (it == m_fields.end()) {
        return Error::SpdmFieldNotFound;
    }
    out_field = &it->second;
    return Error::Ok;
}

const std::map<SwitchOpaqueDataType, SwitchParsedOpaqueFieldData>& SwitchOpaqueDataParser::get_all_fields() const {
    return m_fields;
}

std::ostream& operator<<(std::ostream& os, const SwitchOpaqueDataParser& parser) {
    os << "--- Parsed SWITCH Opaque Data ---";
    for (const auto& pair : parser.get_all_fields()) {
        const auto& type = pair.first;
        const auto& field = pair.second;
        os << "\n" << to_string(type) << " (" << to_string(field.get_type()) << "): ";
        
        switch (field.get_type()) {
            case SwitchParsedFieldType::BYTE_VECTOR: {
                const std::vector<uint8_t>* byte_data = nullptr;
                Error error = field.get_byte_vector(byte_data);
                if (error == Error::Ok && byte_data != nullptr) {
                    os << to_hex_string(*byte_data);
                } else {
                    os << "[ERROR: Failed to get byte vector data]";
                }
                break;
            }
            case SwitchParsedFieldType::UINT32_VECTOR: {
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
            case SwitchParsedFieldType::PORT_VECTOR: {
                const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PORT_ID_SIZE>>* port_data = nullptr;
                Error error = field.get_port_vector(port_data);
                if (error == Error::Ok && port_data != nullptr) {
                    os << "[";
                    for (size_t i = 0; i < port_data->size(); ++i) {
                        if (i > 0) {
                            os << ", ";
                        }
                        os << to_hex_string((*port_data)[i]);
                    }
                    os << "]";
                } else {
                    os << "[ERROR: Failed to get PORT vector data]";
                }
                break;
            }
            case SwitchParsedFieldType::PDI_VECTOR: {
                const std::vector<std::array<uint8_t, SwitchOpaqueFieldSizes::PDI_DATA_SIZE>>* pdi_data = nullptr;
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
            case SwitchParsedFieldType::UNINITIALIZED:
                os << "[UNINITIALIZED]";
                break;
            case SwitchParsedFieldType::UNKNOWN:
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