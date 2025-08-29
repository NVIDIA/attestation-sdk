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


class OpaqueFieldSizes {
public:
    static constexpr size_t DATA_TYPE_SIZE = 2;
    static constexpr size_t DATA_SIZE_FIELD_SIZE = 2;
};


// Define a type for storing the parsed opaque data fields.
class ParsedOpaqueFieldData {
public:
    ParsedOpaqueFieldData();

    // Constructor for byte_vector
    ParsedOpaqueFieldData(uint16_t type, const std::vector<uint8_t>& data);

    static Error create(const std::vector<uint8_t>& data, uint16_t type, ParsedOpaqueFieldData& out_field);
    Error get_data(const std::vector<uint8_t>*& out_data) const;
    uint16_t get_type() const;
private:
    std::vector<uint8_t> m_data;
    uint16_t m_type; // because data type size for opaque field is 2 bytes
};


class OpaqueDataParser {
public:
    /**
     * @brief Default constructor creates an empty parser.
     * Use the create() method to populate with data.
     */
    OpaqueDataParser();

    /**
     * @brief Factory method to create and parse opaque data.
     * @param opaque_raw_data The raw byte vector of the opaque data field.
     * @param out_parser Reference to OpaqueDataParser to populate.
     * @return Error::Ok if parsing is successful, appropriate error code otherwise.
     */
    static Error create(const std::vector<uint8_t>& opaque_raw_data, OpaqueDataParser& out_parser);
    Error get_all_fields(const std::vector<ParsedOpaqueFieldData>*& out_fields) const;

private:
    // Private constructor, use create() instead.
    Error parse(const std::vector<uint8_t>& raw_data);
    std::vector<ParsedOpaqueFieldData> m_fields;
};

// Overload for printing the parsed opaque data (useful for debugging)
std::ostream& operator<<(std::ostream& os, const OpaqueDataParser& parser);

} // namespace nvattestation 