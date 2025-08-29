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
#include <iomanip>  
#include <algorithm> 
#include <ostream>  
#include <cctype>   
#include <variant>  
#include <memory>   

#include "nv_attestation/spdm/spdm_opaque_data_parser.hpp"
#include "nv_attestation/error.h"
#include "nv_attestation/log.h"
#include "nv_attestation/spdm/utils.h"
#include "nv_attestation/utils.h"

namespace nvattestation {

//todo: return more specific error codes instead of InternalError

ParsedOpaqueFieldData::ParsedOpaqueFieldData() : m_type(0) {
}

ParsedOpaqueFieldData::ParsedOpaqueFieldData(uint16_t type, const std::vector<uint8_t>& data) : m_data(data), m_type(type) {
}

Error ParsedOpaqueFieldData::get_data(const std::vector<uint8_t>*& out_data) const {
    out_data = &m_data;
    return Error::Ok;
}

uint16_t ParsedOpaqueFieldData::get_type() const {
    return m_type;
}

Error ParsedOpaqueFieldData::create(const std::vector<uint8_t>& data, uint16_t type, ParsedOpaqueFieldData& out_field) {
    out_field.m_data = data;
    out_field.m_type = type;
    return Error::Ok;
}

OpaqueDataParser::OpaqueDataParser() {
}

Error OpaqueDataParser::create(const std::vector<uint8_t>& opaque_raw_data, OpaqueDataParser& out_parser) {
    return out_parser.parse(opaque_raw_data);
}

Error OpaqueDataParser::get_all_fields(const std::vector<ParsedOpaqueFieldData>*& out_fields) const {
    out_fields = &m_fields;
    return Error::Ok;
}

Error OpaqueDataParser::parse(const std::vector<uint8_t>& raw_data) { // NOLINT(readability-function-cognitive-complexity)
    size_t current_offset = 0;

    while (current_offset < raw_data.size()) {
        // DataType (2 bytes)
        if (!can_read_buffer(raw_data, current_offset, OpaqueFieldSizes::DATA_TYPE_SIZE, "DataType")) {
            return Error::InternalError;
        }
        uint16_t data_type_val_raw = 0;
        if (!read_little_endian(raw_data, current_offset, OpaqueFieldSizes::DATA_TYPE_SIZE, data_type_val_raw)) {
             LOG_ERROR("Failed to read Opaque DataType.");
             return Error::InternalError;
        }
        current_offset += OpaqueFieldSizes::DATA_TYPE_SIZE;

        // DataSize (2 bytes)
        if (!can_read_buffer(raw_data, current_offset, OpaqueFieldSizes::DATA_SIZE_FIELD_SIZE, "DataSize")) { 
            return Error::InternalError;
        }
        uint16_t data_size = 0;
        if (!read_little_endian(raw_data, current_offset, OpaqueFieldSizes::DATA_SIZE_FIELD_SIZE, data_size)) {
            LOG_ERROR("Failed to read Opaque DataSize for type " << to_hex_string(data_type_val_raw));
            return Error::InternalError;
        }
        current_offset += OpaqueFieldSizes::DATA_SIZE_FIELD_SIZE;

        // Data (variable length: data_size)
        std::vector<uint8_t> value_bytes;
        if (!checked_assign(value_bytes, raw_data, current_offset, data_size, "Data")) { 
            return Error::InternalError;
        }
        current_offset += data_size;

        ParsedOpaqueFieldData field_data;
        Error error = ParsedOpaqueFieldData::create(value_bytes, data_type_val_raw, field_data);
        if (error != Error::Ok) {
            return error;
        }
        m_fields.push_back(field_data);

    }
    if (current_offset != raw_data.size()) {
        LOG_ERROR("OpaqueData has " << (raw_data.size() - current_offset) << " trailing bytes after parsing.");
        return Error::InternalError;
    }

    return Error::Ok;
}

std::ostream& operator<<(std::ostream& os, const OpaqueDataParser& parser) { // NOLINT(readability-function-cognitive-complexity)
    os << "--- Parsed Opaque Data ---";
    const std::vector<ParsedOpaqueFieldData>* fields_ptr = nullptr;
    Error error = parser.get_all_fields(fields_ptr);
    if (error != Error::Ok) {
        os << "\n(Failed to get all fields)";
        return os;
    }
    if (fields_ptr == nullptr || fields_ptr->empty()) {
        os << "\n(No fields parsed or opaque data was empty)";
        return os;
    }

    for (const auto& field : *fields_ptr) {
        os << "\n  " << to_hex_string(field.get_type()) << " (" << static_cast<uint16_t>(field.get_type()) << "): ";
        const std::vector<uint8_t>* data = nullptr;
        Error error = field.get_data(data);
        if (error != Error::Ok) {
            os << "\n(Failed to get data)";
            continue;
        }
        os << to_hex_string(*data);
    }
    return os;
}

} // namespace nvattestation