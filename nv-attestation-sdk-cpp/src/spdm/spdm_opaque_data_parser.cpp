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

ParsedOpaqueFieldData::ParsedOpaqueFieldData() {
}

ParsedOpaqueFieldData::ParsedOpaqueFieldData(uint16_t type, const std::vector<uint8_t>& data)
    : m_data(data), m_type(type) {
}

Error ParsedOpaqueFieldData::get_data(const std::vector<uint8_t>*& out_data) const {
    out_data = &m_data;
    return Error::Ok;
}

uint16_t ParsedOpaqueFieldData::get_type() const {
    return m_type;
}

uint16_t ParsedOpaqueFieldData::get_value_type() const {
    return m_value_type;
}

Error ParsedOpaqueFieldData::create(const std::vector<uint8_t>& data, uint16_t type,
                                    ParsedOpaqueFieldData& out_field) {
    out_field.m_data       = data;
    out_field.m_type       = type;
    out_field.m_value_type = 0;
    return Error::Ok;
}

Error ParsedOpaqueFieldData::create(const std::vector<uint8_t>& data, uint16_t type,
                                    uint16_t value_type, ParsedOpaqueFieldData& out_field) {
    out_field.m_data       = data;
    out_field.m_type       = type;
    out_field.m_value_type = value_type;
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

OpaqueDataFormatVersion OpaqueDataParser::get_format_version() const {
    return m_format_version;
}

bool OpaqueDataParser::has_nvdaod_header(const std::vector<uint8_t>& raw_data) {
    if (raw_data.size() < OpaqueFieldSizes::HEADER_SIZE) {
        return false;
    }
    for (size_t idx = 0; idx < OPAQUE_DATA_MAGIC.size(); ++idx) {
        if (raw_data[idx] != OPAQUE_DATA_MAGIC[idx]) {
            return false;
        }
    }
    return true;
}

Error OpaqueDataParser::parse(const std::vector<uint8_t>& raw_data) {
    m_fields.clear();
    m_format_version = OpaqueDataFormatVersion{};

    if (has_nvdaod_header(raw_data)) {
        uint16_t profile = 0;
        if (!read_little_endian(raw_data, OpaqueFieldSizes::HEADER_PROFILE_OFFSET,
                                OpaqueFieldSizes::DATA_SIZE_FIELD_SIZE, profile)) {
            LOG_ERROR("Failed to read opaque data header profile");
            return Error::InternalError;
        }
        if (profile != OPAQUE_DATA_REQUIRED_PROFILE) {
            LOG_ERROR("Unsupported opaque data profile: " << profile);
            return Error::BadArgument;
        }

        // Major/minor are recorded but not gated here: the header major converges with the
        // legacy format's version field into a single bound check in GpuOpaqueDataParser::create.
        m_format_version.major = raw_data[OpaqueFieldSizes::HEADER_MAJOR_OFFSET];
        m_format_version.minor = raw_data[OpaqueFieldSizes::HEADER_MINOR_OFFSET];
        m_format_version.has_header = true;
        return parse_tlv_entries(raw_data, OpaqueFieldSizes::HEADER_SIZE, true);
    }
    return parse_tlv_entries(raw_data, 0U, false);
}

Error OpaqueDataParser::parse_tlv_entries(const std::vector<uint8_t>& raw_data, // NOLINT(readability-function-cognitive-complexity)
                                           size_t start_offset, bool has_value_type) {
    size_t offset = start_offset;
    while (offset < raw_data.size()) {
        if (!can_read_buffer(raw_data, offset, OpaqueFieldSizes::DATA_TYPE_SIZE, "DataType")) {
            return Error::InternalError;
        }
        uint16_t type = 0;
        if (!read_little_endian(raw_data, offset, OpaqueFieldSizes::DATA_TYPE_SIZE, type)) {
            LOG_ERROR("Failed to read Opaque DataType.");
            return Error::InternalError;
        }
        offset += OpaqueFieldSizes::DATA_TYPE_SIZE;

        uint16_t value_type = 0;
        if (has_value_type) {
            if (!can_read_buffer(raw_data, offset, OpaqueFieldSizes::DATA_VALUE_TYPE_SIZE, "DataValueType")) {
                return Error::InternalError;
            }
            if (!read_little_endian(raw_data, offset, OpaqueFieldSizes::DATA_VALUE_TYPE_SIZE, value_type)) {
                return Error::InternalError;
            }
            offset += OpaqueFieldSizes::DATA_VALUE_TYPE_SIZE;
        }

        if (!can_read_buffer(raw_data, offset, OpaqueFieldSizes::DATA_SIZE_FIELD_SIZE, "DataSize")) {
            return Error::InternalError;
        }
        uint16_t data_size = 0;
        if (!read_little_endian(raw_data, offset, OpaqueFieldSizes::DATA_SIZE_FIELD_SIZE, data_size)) {
            LOG_ERROR("Failed to read Opaque DataSize for type " << to_hex_string(type));
            return Error::InternalError;
        }
        offset += OpaqueFieldSizes::DATA_SIZE_FIELD_SIZE;

        std::vector<uint8_t> value_bytes;
        if (!checked_assign(value_bytes, raw_data, offset, data_size, "Data")) {
            return Error::InternalError;
        }
        offset += data_size;

        ParsedOpaqueFieldData field;
        Error err = ParsedOpaqueFieldData::create(value_bytes, type, value_type, field);
        if (err != Error::Ok) {
            return err;
        }
        m_fields.push_back(field);
    }

    if (offset != raw_data.size()) {
        LOG_ERROR("OpaqueData has " << (raw_data.size() - offset) << " trailing bytes");
        return Error::InternalError;
    }
    return Error::Ok;
}

Error OpaqueDataParser::parse_as_legacy_for_test(const std::vector<uint8_t>& raw_data) {
    OpaqueDataParser tmp;
    return tmp.parse_tlv_entries(raw_data, 0U, false);
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