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
#include <string>
#include <cstdint>
#include <map>
#include <array>
#include <iosfwd> 
#include <memory> 

#include "nv_attestation/error.h"

namespace nvattestation {

struct OpaqueDataFormatVersion {
    uint8_t major      = 0;
    uint8_t minor      = 0;
    bool    has_header = false;
};

class OpaqueFieldSizes {
public:
    static constexpr size_t DATA_TYPE_SIZE            = 2;
    static constexpr size_t DATA_VALUE_TYPE_SIZE      = 2;
    static constexpr size_t DATA_SIZE_FIELD_SIZE      = 2;
    static constexpr size_t HEADER_MAGIC_SIZE         = 6;
    static constexpr size_t HEADER_SIZE               = 12;
    static constexpr size_t HEADER_PROFILE_OFFSET     = 6;
    static constexpr size_t HEADER_MAJOR_OFFSET       = 8;
    static constexpr size_t HEADER_MINOR_OFFSET       = 9;
};

static constexpr std::array<uint8_t, OpaqueFieldSizes::HEADER_MAGIC_SIZE> OPAQUE_DATA_MAGIC = {
    0x4EU, 0x56U, 0x44U, 0x41U, 0x4FU, 0x44U  // NVDAOD
};
static constexpr uint16_t OPAQUE_DATA_REQUIRED_PROFILE = 0U;


class ParsedOpaqueFieldData {
public:
    ParsedOpaqueFieldData();
    ParsedOpaqueFieldData(uint16_t type, const std::vector<uint8_t>& data);

    static Error create(const std::vector<uint8_t>& data, uint16_t type,
                        ParsedOpaqueFieldData& out_field);
    static Error create(const std::vector<uint8_t>& data, uint16_t type, uint16_t value_type,
                        ParsedOpaqueFieldData& out_field);

    Error    get_data(const std::vector<uint8_t>*& out_data) const;
    uint16_t get_type() const;
    uint16_t get_value_type() const;

private:
    std::vector<uint8_t> m_data;
    uint16_t             m_type       = 0;
    uint16_t             m_value_type = 0;
};


class OpaqueDataParser {
public:
    OpaqueDataParser();

    static Error create(const std::vector<uint8_t>& opaque_raw_data, OpaqueDataParser& out_parser);
    Error get_all_fields(const std::vector<ParsedOpaqueFieldData>*& out_fields) const;
    OpaqueDataFormatVersion get_format_version() const;

    static Error parse_as_legacy_for_test(const std::vector<uint8_t>& raw_data);

private:
    static bool has_nvdaod_header(const std::vector<uint8_t>& raw_data);
    Error parse(const std::vector<uint8_t>& raw_data);
    Error parse_tlv_entries(const std::vector<uint8_t>& raw_data,
                            size_t start_offset, bool has_value_type);

    std::vector<ParsedOpaqueFieldData> m_fields;
    OpaqueDataFormatVersion            m_format_version;
};

// Overload for printing the parsed opaque data (useful for debugging)
std::ostream& operator<<(std::ostream& os, const OpaqueDataParser& parser);

} // namespace nvattestation 