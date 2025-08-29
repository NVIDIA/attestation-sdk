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
#include <array>
#include <sstream> // For std::stringstream
#include <algorithm>
#include "nv_attestation/log.h" // For LOG_PUSH_ERROR
#include "nv_attestation/error.h" // For Error enum
#include "nv_attestation/utils.h" 

namespace nvattestation {

constexpr uint8_t SPDM_VERSION_1_1 = 0x11;
constexpr uint8_t SPDM_REQ_CODE_GET_MEASUREMENTS = 0xe0;
constexpr uint8_t SPDM_RES_CODE_MEASUREMENTS = 0x60;









/**
 * @brief Assigns a range from one vector to another, checking for integer overflows.
 * @param target The target vector to assign to.
 * @param source The source vector to assign from.
 * @param u_offset The starting offset in the source vector.
 * @param u_length The number of bytes to assign from the source vector.
 * @param field_name The name of the field being parsed, for logging purposes.
 * @return true if the assignment was successful, false otherwise.
 */
static bool checked_assign(
    std::vector<uint8_t> &target,
    const std::vector<uint8_t> &source,
    size_t u_offset,
    size_t u_length,
    const char* field_name) {
    if (!can_read_buffer(source, u_offset, u_length, field_name)) {
        return false;
    }
    std::vector<uint8_t>::difference_type offset =
        static_cast<std::vector<uint8_t>::difference_type>(u_offset);
    if (offset < 0) {
        LOG_ERROR("Detected integer overflow calculating offset for: " << field_name);
        return false;
    }
    std::vector<uint8_t>::difference_type length =
     static_cast<std::vector<uint8_t>::difference_type>(u_length);
    if (length < 0) {
        LOG_ERROR("Detected integer overflow calculating length for: " << field_name);
        return false;
    }
    target.assign(source.begin() + offset, source.begin() + offset + length);
    return true;
}

/**
 * @brief Copies a range from a vector to an array, checking for integer overflows.
 * @param target The target array to copy to.
 * @param source The source vector to copy from.
 * @param u_offset The starting offset in the source vector.
 * @param u_length The number of bytes to copy from the source vector.
 * @param field_name The name of the field being parsed, for logging purposes.
 * @return true if the copy was successful, false otherwise.
 */
template <size_t N>
static bool checked_copy_n(
    std::array<uint8_t, N> &target,
    const std::vector<uint8_t> &source,
    size_t u_offset,
    size_t u_length,
    const char* field_name) {
    if (u_length > N) {
        LOG_ERROR("Array too small for: " << field_name);
        return false;
    }
    if (!can_read_buffer(source, u_offset, u_length, field_name)) {
        return false;
    }
    std::vector<uint8_t>::difference_type offset =
        static_cast<std::vector<uint8_t>::difference_type>(u_offset);
    if (offset < 0) {
        LOG_ERROR("Detected integer overflow calculating offset for: " << field_name);
        return false;
    }
    std::vector<uint8_t>::difference_type length =
     static_cast<std::vector<uint8_t>::difference_type>(u_length);
    if (length < 0) {
        LOG_ERROR("Detected integer overflow calculating length for: " << field_name);
        return false;
    }
    std::copy_n(source.begin() + offset, length, target.data());
    return true;
}
} // namespace nvattestation
