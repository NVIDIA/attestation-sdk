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

#include "nv_attestation/spdm/spdm_req.hpp"
#include "nv_attestation/spdm/utils.h"
#include "nv_attestation/log.h"
#include "nv_attestation/utils.h"

namespace nvattestation {

Error SpdmMeasurementRequestMessage11::create(const std::vector<uint8_t>& request_data, SpdmMeasurementRequestMessage11& out_message) {
    return out_message.parse(request_data);
}

Error SpdmMeasurementRequestMessage11::parse(const std::vector<uint8_t>& request_data) {
    if (request_data.size() != kRequestLength) {
        LOG_ERROR("SPDM Measurement Request Message11: Invalid request data size");
        return Error::SpdmRequestParseError;
    }

    size_t offset = 0;
    if(!can_read_buffer(request_data, offset, kSpdmVersionSize, "SPDMVersion")) { return Error::SpdmRequestParseError; }
    m_spdm_version = request_data[offset];
    offset += kSpdmVersionSize;

    if (m_spdm_version != SPDM_VERSION_1_1) {
        LOG_ERROR("SPDMVersion is not " << to_hex_string(SPDM_VERSION_1_1) << " (1.1). Actual version: " << to_hex_string(m_spdm_version));
        return Error::SpdmRequestParseError;
    }

    if(!can_read_buffer(request_data, offset, kRequestResponseCodeSize, "RequestResponseCode")) { return Error::SpdmRequestParseError; }
    m_request_response_code = request_data[offset];
    offset += kRequestResponseCodeSize;

    if (m_request_response_code != SPDM_REQ_CODE_GET_MEASUREMENTS) {
        LOG_ERROR("RequestResponseCode is not " << to_hex_string(SPDM_REQ_CODE_GET_MEASUREMENTS) << " (GET_MEASUREMENTS). Actual code: " << to_hex_string(m_request_response_code));
        return Error::SpdmRequestParseError;
    }

    if(!can_read_buffer(request_data, offset, kParam1Size, "Param1")) { return Error::SpdmRequestParseError; }
    m_param1 = request_data[offset];
    offset += kParam1Size;

    if(!can_read_buffer(request_data, offset, kParam2Size, "Param2")) { return Error::SpdmRequestParseError; }
    m_param2 = request_data[offset];
    offset += kParam2Size;

    if (!checked_copy_n(m_nonce, request_data, offset, kNonceSize, "Nonce")) {
       return Error::SpdmRequestParseError; 
    }
    offset += kNonceSize;

    if(!can_read_buffer(request_data, offset, kSlotIDParamSize, "SlotIDParam")) { return Error::SpdmRequestParseError; }
    m_slot_id_param = request_data[offset];
    offset += kSlotIDParamSize;

    if (offset != kRequestLength) {
        LOG_ERROR("trailing bytes after parsing in SPDM Measurement Request Message11");
        return Error::SpdmRequestParseError;
    }

    return Error::Ok;
}

}
