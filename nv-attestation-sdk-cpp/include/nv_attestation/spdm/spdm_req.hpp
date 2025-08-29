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

#include <cstddef>
#include <cstdint>
#include <array>
#include <vector>
#include <memory>

#include "nv_attestation/error.h"
#include "nv_attestation/utils.h"

namespace nvattestation {

class SpdmMeasurementRequestMessage11 {
    static const size_t kSpdmVersionSize = 1;
    static const size_t kRequestResponseCodeSize = 1;
    static const size_t kParam1Size = 1;
    static const size_t kParam2Size = 1;
    static const size_t kNonceSize = 32;
    static const size_t kSlotIDParamSize = 1;
    static const size_t kRequestLength = 37; // 1 + 1 + 1 + 1 + 32 + 1
public:
    static Error create(const std::vector<uint8_t>& request_data, SpdmMeasurementRequestMessage11& out_message);

    // Getter methods
    uint8_t get_spdm_version() const { return m_spdm_version; }
    uint8_t get_request_response_code() const { return m_request_response_code; }
    uint8_t get_param1() const { return m_param1; }
    uint8_t get_param2() const { return m_param2; }
    const std::array<uint8_t, kNonceSize>& get_nonce() const { return m_nonce; }
    uint8_t get_slot_id_param() const { return m_slot_id_param; }
    static size_t get_request_length() { return kRequestLength; }

private:

    uint8_t m_spdm_version;
    uint8_t m_request_response_code;
    uint8_t m_param1;
    uint8_t m_param2;
    std::array<uint8_t, kNonceSize> m_nonce;
    uint8_t m_slot_id_param;

    Error parse(const std::vector<uint8_t>& request_data);
    
};

}